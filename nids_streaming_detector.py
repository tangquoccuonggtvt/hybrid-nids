"""In-memory streaming detector for Hybrid-NIDS.

This script is intentionally separate from nids_detector.py. The official
thesis metrics still come from the RF-41 hold-out CSV evaluation. This module
addresses the operational Disk I/O bottleneck by allowing NFStreamer to read a
live interface directly, extract flow features in memory, predict by batch, and
write only compact JSONL alerts/metrics.

Examples:
    python nids_streaming_detector.py --source "Wi-Fi" --duration-seconds 300
    python nids_streaming_detector.py --source ./pcap_traffic/sample.pcapng
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from artifact_security import load_trusted_model

from nids_detector import (
    import_nfstream,
    load_feature_schema,
    load_json,
    load_threshold,
    predict_batch,
    write_alerts_to_disk,
)
from nids_features import FEATURE_COLUMNS as PCAP_FEATURE_COLUMNS, FlowContextWindow, extract_features_from_flow, extract_metadata_from_flow


ROOT = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Hybrid-NIDS inference directly from an NFStreamer source "
            "without writing intermediate PCAP/CSV files."
        )
    )
    parser.add_argument(
        "--source",
        required=True,
        help=(
            "NFStreamer source. Use a live interface name for in-memory mode "
            "or a PCAP/PCAPNG path for offline smoke testing."
        ),
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=ROOT / "models" / "rf21_schema_gap" / "nids_rf21_schema_gap_pipeline.pkl",
        help="Operational PCAP/live model. Defaults to RF-21 because the live extractor emits the reduced schema.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=ROOT / "models" / "rf21_schema_gap" / "feature_schema_rf21.json",
        help="Feature schema matching the operational PCAP/live model.",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=ROOT / "models" / "rf21_schema_gap" / "metadata_rf21.json",
        help="Metadata/threshold matching the operational PCAP/live model.",
    )
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--context-window-seconds", type=float, default=100.0)
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=None,
        help=(
            "Optional wall-clock limit for live sources. For PCAP files the "
            "script normally exits when the file is consumed."
        ),
    )
    parser.add_argument("--output-alerts", type=Path, default=ROOT / "logs" / "streaming_alerts.jsonl")
    parser.add_argument("--output-metrics", type=Path, default=ROOT / "logs" / "streaming_metrics.json")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--bpf-filter", default="", help="BPF filter (vd 'net 192.168.10.0/24') de gioi han pham vi phan tich.")
    return parser.parse_args()


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else (ROOT / path).resolve()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def source_kind(source: str) -> str:
    path = Path(source)
    if path.exists() and path.is_file():
        return "pcap_file"
    return "live_interface"


def write_metrics(path: Path, metrics: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")


def percentile(values: list[float], q: float) -> float | None:
    """Return a deterministic percentile without adding a NumPy dependency."""
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def main() -> None:
    args = parse_args()
    batch_size = max(1, int(args.batch_size))
    output_alerts = resolve(args.output_alerts)
    output_metrics = resolve(args.output_metrics)

    if args.overwrite:
        output_alerts.parent.mkdir(parents=True, exist_ok=True)
        output_alerts.write_text("", encoding="utf-8")
        output_metrics.parent.mkdir(parents=True, exist_ok=True)
        output_metrics.write_text("", encoding="utf-8")
    elif output_alerts.exists() or output_metrics.exists():
        raise FileExistsError("Output exists; use --overwrite to replace streaming output files.")

    model_path = resolve(args.model)
    schema_path = resolve(args.schema)
    metadata_path = resolve(args.metadata)
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema not found: {schema_path}")

    pipeline = load_trusted_model(model_path, metadata_path if metadata_path.exists() else None)
    schema = load_feature_schema(schema_path)
    metadata = load_json(metadata_path) if metadata_path.exists() else {}
    threshold = load_threshold(metadata_path if metadata_path.exists() else None, args.threshold)

    required_features = set(schema.get("feature_columns", []))
    extractable_features = set(PCAP_FEATURE_COLUMNS)
    missing_from_extractor = sorted(required_features - extractable_features)
    if missing_from_extractor:
        raise ValueError(
            "Schema mismatch ở streaming PCAP/live: extractor hiện chỉ sinh được "
            f"{len(PCAP_FEATURE_COLUMNS)} feature, nhưng schema/model yêu cầu các feature chưa trích xuất được: "
            f"{missing_from_extractor}. Hãy dùng model/schema RF-21 cho PCAP/live hoặc xây dựng extractor tương ứng."
        )

    NFStreamer = import_nfstream()
    context_window = FlowContextWindow(window_seconds=float(args.context_window_seconds))
    # idle/active timeout ngan de flow xuat ra nhanh trong che do live/demo.
    # Mac dinh NFStream idle=120s, active=1800s -> flow phai "het han" moi duoc yield,
    # khien canh bao xuat hien rat cham. Cho phep chinh qua bien moi truong.
    _idle = int(os.getenv("NFS_IDLE_TIMEOUT", "15"))
    _active = int(os.getenv("NFS_ACTIVE_TIMEOUT", "30"))
    # BPF filter: chi phan tich traffic trong pham vi lab (HOME_NET), loai bo
    # luu luong internet (vd TLS ra ngoai) gay canh bao gia. Vd: "net 192.168.10.0/24".
    # Cau hinh qua --bpf-filter hoac bien moi truong NIDS_BPF_FILTER / HOME_NET.
    _bpf = args.bpf_filter or os.getenv("NIDS_BPF_FILTER", "")
    if not _bpf:
        _home = os.getenv("HOME_NET", "").strip()
        if _home:
            _bpf = f"net {_home}"
    _nfs_kwargs = dict(source=args.source, statistical_analysis=True,
                       idle_timeout=_idle, active_timeout=_active)
    if _bpf:
        _nfs_kwargs["bpf_filter"] = _bpf
        print(f"[i] BPF filter ap dung: {_bpf}", flush=True)
    streamer = NFStreamer(**_nfs_kwargs)

    started = time.perf_counter()
    deadline = started + float(args.duration_seconds) if args.duration_seconds else None
    batch_features: list[dict[str, Any]] = []
    batch_metadata: list[dict[str, Any]] = []
    total_flows = 0
    total_alerts = 0
    total_batches = 0
    inference_seconds_total = 0.0
    batch_latency_ms: list[float] = []

    def flush_batch() -> None:
        nonlocal batch_features, batch_metadata, total_alerts, total_batches
        nonlocal inference_seconds_total
        if not batch_features:
            return
        batch_flow_count = len(batch_features)
        inference_started = time.perf_counter()
        alerts, _aggregated = predict_batch(batch_features, batch_metadata, pipeline, schema, metadata, threshold)
        inference_seconds = time.perf_counter() - inference_started
        write_alerts_to_disk(alerts, output_alerts)
        total_alerts += len(alerts)
        total_batches += 1
        inference_seconds_total += inference_seconds
        batch_latency_ms.append(inference_seconds * 1000.0)
        batch_features = []
        batch_metadata = []
        elapsed_seconds = time.perf_counter() - started
        # Ghi snapshot sau từng batch để web panel quan sát được khi detector còn chạy.
        write_metrics(
            output_metrics,
            {
                "created_at": utc_now(),
                "status": "running",
                "source": args.source,
                "source_kind": source_kind(args.source),
                "flows": total_flows,
                "alerts": total_alerts,
                "batches": total_batches,
                "last_batch_flows": batch_flow_count,
                "last_batch_latency_ms": inference_seconds * 1000.0,
                "inference_seconds_total": inference_seconds_total,
                "inference_latency_ms_per_flow": (
                    inference_seconds_total * 1000.0 / total_flows if total_flows else None
                ),
                "throughput_flows_per_second": (
                    total_flows / elapsed_seconds if elapsed_seconds > 0 else None
                ),
            },
        )

    for flow in streamer:
        if deadline is not None and time.perf_counter() >= deadline:
            break
        batch_features.append(extract_features_from_flow(flow, context_window))
        batch_metadata.append(extract_metadata_from_flow(flow))
        total_flows += 1
        if len(batch_features) >= batch_size:
            flush_batch()

    flush_batch()
    runtime_seconds = time.perf_counter() - started
    throughput = total_flows / runtime_seconds if runtime_seconds > 0 else None

    metrics = {
        "created_at": utc_now(),
        "source": args.source,
        "source_kind": source_kind(args.source),
        "model": str(model_path),
        "schema": str(schema_path),
        "metadata": str(metadata_path) if metadata_path.exists() else None,
        "threshold": threshold,
        "batch_size": batch_size,
        "duration_seconds_requested": args.duration_seconds,
        "runtime_seconds": runtime_seconds,
        "flows": total_flows,
        "alerts": total_alerts,
        "alert_rate": (total_alerts / total_flows) if total_flows else None,
        "batches": total_batches,
        "throughput_flows_per_second": throughput,
        "inference_seconds_total": inference_seconds_total,
        "inference_latency_ms_per_flow": (
            inference_seconds_total * 1000.0 / total_flows if total_flows else None
        ),
        "batch_latency_ms": {
            "mean": (sum(batch_latency_ms) / len(batch_latency_ms)) if batch_latency_ms else None,
            "p50": percentile(batch_latency_ms, 0.50),
            "p95": percentile(batch_latency_ms, 0.95),
            "p99": percentile(batch_latency_ms, 0.99),
            "max": max(batch_latency_ms) if batch_latency_ms else None,
        },
        "status": "completed",
        "output_alerts": str(output_alerts),
        "methodological_note": (
            "This is an operational streaming/in-memory run. It reduces "
            "intermediate PCAP/CSV disk writes, but it does not compute "
            "accuracy, precision, recall, or F1 unless ground-truth labels are "
            "available."
        ),
    }
    write_metrics(output_metrics, metrics)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    main()


