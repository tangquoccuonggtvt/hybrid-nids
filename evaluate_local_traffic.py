"""Evaluate local operational traffic with the official Hybrid-NIDS detector.

This script runs nids_detector.py on a local CSV or PCAP sample and summarizes
alert volume. It intentionally does not compute accuracy, precision, recall, or
F1 because operational traffic is normally unlabeled.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_DETECTOR = ROOT / "nids_detector.py"
DEFAULT_ALERTS = ROOT / "logs" / "local_traffic_alerts.jsonl"
DEFAULT_REPORT = ROOT / "logs" / "local_traffic_evaluation.json"
DETECTOR_COMPLETED_RE = re.compile(r"Hoàn tất(?: CSV)?:\s*(\d+)\s*flow,\s*(\d+)\s*alert", re.IGNORECASE)
METHODOLOGICAL_NOTE = (
    "Local operational traffic is treated as unlabeled data; this report "
    "summarizes alert volume and entities only, and does not compute accuracy, "
    "precision, recall, F1-score, or ROC-AUC."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the official Hybrid-NIDS detector on local traffic and export "
            "an unlabeled operational evaluation report."
        )
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input-csv", type=Path, help="Local flow CSV to evaluate.")
    input_group.add_argument("--pcap", type=Path, help="Local PCAP to evaluate.")
    parser.add_argument("--detector", type=Path, default=DEFAULT_DETECTOR)
    parser.add_argument("--model", type=Path, default=None, help="Model artifact passed to nids_detector.py.")
    parser.add_argument("--schema", type=Path, default=None, help="Feature schema passed to nids_detector.py.")
    parser.add_argument("--metadata", type=Path, default=None, help="Metadata/threshold artifact passed to nids_detector.py.")
    parser.add_argument("--threshold", type=float, default=None, help="Optional attack threshold override.")
    parser.add_argument("--output-alerts", type=Path, default=DEFAULT_ALERTS)
    parser.add_argument("--output-report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--tail-lines", type=int, default=30)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the local evaluation alert/report files before running.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return (ROOT / path).resolve()


def count_csv_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _ in reader)


def iter_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line_no, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
    return records


def top_counter(records: list[dict[str, Any]], key: str, limit: int = 10) -> list[dict[str, Any]]:
    counter = Counter(str(record.get(key, "")) for record in records if record.get(key) not in (None, ""))
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def summarize_alert_grouping(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Gom cụm cảnh báo theo thực thể mạng để tránh khuếch đại số liệu.

    Detector sinh 1 cảnh báo cho mỗi flow, nên một hành vi liên tục (ví dụ một
    phiên quét cổng) có thể tạo ra hàng trăm flow-alert dù chỉ tương ứng với
    MỘT cặp host đáng chú ý. Báo cáo theo "số flow-alert" vì thế phóng đại mức
    cảnh báo. Hàm này quy đổi flow-alert sang số thực thể riêng biệt.
    """

    def _val(record: dict[str, Any], key: str) -> str:
        value = record.get(key)
        return "" if value in (None, "") else str(value)

    src_ips = {_val(r, "src_ip") for r in records if _val(r, "src_ip")}
    src_dst_pairs = {
        (_val(r, "src_ip"), _val(r, "dst_ip"))
        for r in records
        if _val(r, "src_ip") and _val(r, "dst_ip")
    }
    five_tuples = {
        (_val(r, "src_ip"), _val(r, "dst_ip"), _val(r, "dst_port"), _val(r, "protocol"))
        for r in records
        if _val(r, "src_ip") and _val(r, "dst_ip")
    }

    flow_alert_count = len(records)
    distinct_src_dst = len(src_dst_pairs)
    amplification = (
        flow_alert_count / distinct_src_dst if distinct_src_dst > 0 else None
    )

    return {
        "flow_alert_count": flow_alert_count,
        "distinct_alerted_src_ip": len(src_ips),
        "distinct_alerted_src_dst_pairs": distinct_src_dst,
        "distinct_alerted_five_tuples": len(five_tuples),
        "flow_alerts_per_src_dst_pair": amplification,
        "note": (
            "Số flow-alert phản ánh số dòng flow, không phải số vụ việc. "
            "Số cặp (src_ip, dst_ip) riêng biệt gần với số vụ việc vận hành hơn."
        ),
    }


def summarize_alerts(records: list[dict[str, Any]], input_flow_count: int | None) -> dict[str, Any]:
    scores = [
        float(record["attack_score"])
        for record in records
        if isinstance(record.get("attack_score"), (int, float))
    ]
    thresholds = sorted(
        {
            round(float(record["threshold"]), 12)
            for record in records
            if isinstance(record.get("threshold"), (int, float))
        }
    )

    alert_count = len(records)
    alert_rate = None
    if input_flow_count and input_flow_count > 0:
        alert_rate = alert_count / input_flow_count

    return {
        "alert_count": alert_count,
        "input_flow_count": input_flow_count,
        "alert_rate": alert_rate,
        "severity_counts": dict(Counter(str(record.get("severity", "UNKNOWN")) for record in records)),
        "action_counts": dict(Counter(str(record.get("action", "UNKNOWN")) for record in records)),
        "protocol_counts": dict(Counter(str(record.get("protocol", "UNKNOWN")) for record in records)),
        "application_counts": dict(Counter(str(record.get("application_name", "UNKNOWN")) for record in records)),
        "top_src_ip": top_counter(records, "src_ip"),
        "top_dst_ip": top_counter(records, "dst_ip"),
        "top_dst_port": top_counter(records, "dst_port"),
        "top_src_port": top_counter(records, "src_port"),
        "attack_score": {
            "min": min(scores) if scores else None,
            "max": max(scores) if scores else None,
            "mean": statistics.fmean(scores) if scores else None,
            "median": statistics.median(scores) if scores else None,
        },
        "threshold_values": thresholds,
    }


def tail_text(text: str | None, tail_lines: int) -> list[str]:
    if not text:
        return []
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-tail_lines:]


def parse_detector_flow_count(stdout: str | None) -> int | None:
    if not stdout:
        return None
    matches = DETECTOR_COMPLETED_RE.findall(stdout)
    if not matches:
        return None
    flow_count, _alert_count = matches[-1]
    return int(flow_count)


def main() -> None:
    args = parse_args()
    detector = resolve_path(args.detector)
    output_alerts = resolve_path(args.output_alerts)
    output_report = resolve_path(args.output_report)
    input_path = resolve_path(args.input_csv or args.pcap)
    input_type = "csv" if args.input_csv else "pcap"

    if not detector.exists():
        raise FileNotFoundError(f"Detector not found: {detector}")
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    output_alerts.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)
    if output_alerts.exists() and not args.overwrite:
        raise FileExistsError(f"Output alerts already exists; use --overwrite: {output_alerts}")
    if output_report.exists() and not args.overwrite:
        raise FileExistsError(f"Output report already exists; use --overwrite: {output_report}")
    if args.overwrite:
        output_alerts.write_text("", encoding="utf-8")
        output_report.write_text("", encoding="utf-8")

    input_flow_count = count_csv_rows(input_path) if input_type == "csv" else None
    command = [
        args.python,
        str(detector),
        "--once",
        "--output-log",
        str(output_alerts),
        "--disable-discord",
        "--disable-telegram",
    ]
    if args.model:
        command.extend(["--model", str(resolve_path(args.model))])
    if args.schema:
        command.extend(["--schema", str(resolve_path(args.schema))])
    if args.metadata:
        command.extend(["--metadata", str(resolve_path(args.metadata))])
    if args.threshold is not None:
        command.extend(["--threshold", str(args.threshold)])
    if input_type == "csv":
        command.extend(["--input-csv", str(input_path)])
    else:
        command.extend(["--pcap", str(input_path)])

    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    runtime_seconds = time.perf_counter() - started

    if input_type == "pcap":
        parsed_flow_count = parse_detector_flow_count(completed.stdout)
        if parsed_flow_count is not None:
            input_flow_count = parsed_flow_count

    alerts = iter_jsonl(output_alerts)
    summary = summarize_alerts(alerts, input_flow_count)
    grouping = summarize_alert_grouping(alerts)
    status = "completed" if completed.returncode == 0 else "failed"

    report = {
        "created_at": utc_now(),
        "status": status,
        "input_type": input_type,
        "input_path": str(input_path.relative_to(ROOT) if input_path.is_relative_to(ROOT) else input_path),
        "detector": str(detector.relative_to(ROOT) if detector.is_relative_to(ROOT) else detector),
        "model": str(resolve_path(args.model)) if args.model else None,
        "schema": str(resolve_path(args.schema)) if args.schema else None,
        "metadata": str(resolve_path(args.metadata)) if args.metadata else None,
        "threshold_override": args.threshold,
        "output_alerts": str(
            output_alerts.relative_to(ROOT) if output_alerts.is_relative_to(ROOT) else output_alerts
        ),
        "runtime_seconds": runtime_seconds,
        "detector_returncode": completed.returncode,
        "command": command,
        "methodological_note": METHODOLOGICAL_NOTE,
        "label_status": "unlabeled_operational_traffic",
        "classification_metrics_computed": False,
        "detector_stdout_tail": tail_text(completed.stdout, args.tail_lines),
        "detector_stderr_tail": tail_text(completed.stderr, args.tail_lines),
        "alert_grouping": grouping,
        **summary,
    }

    output_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)

    print(f"[+] Local traffic evaluation report: {output_report}")
    print(f"[+] Local traffic alerts: {output_alerts}")
    print(f"[+] Alerts: {summary['alert_count']}")
    if summary["alert_rate"] is not None:
        print(f"[+] Alert rate: {summary['alert_rate']:.6f}")
    print(f"[+] Flow-alerts: {grouping['flow_alert_count']}")
    print(f"[+] Distinct alerted src->dst pairs: {grouping['distinct_alerted_src_dst_pairs']}")
    print(f"[+] Distinct alerted src IPs: {grouping['distinct_alerted_src_ip']}")
    if grouping["flow_alerts_per_src_dst_pair"] is not None:
        print(f"[+] Flow-alerts per src->dst pair: {grouping['flow_alerts_per_src_dst_pair']:.2f}")
    print("[+] Classification metrics computed: False")


if __name__ == "__main__":
    main()
