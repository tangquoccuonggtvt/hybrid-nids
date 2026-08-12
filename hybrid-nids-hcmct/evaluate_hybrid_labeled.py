"""Đánh giá CÓ NHÃN cho Hybrid-NIDS trên tấn công tự sinh trong lab.

Bối cảnh
--------
Trong lab, tấn công do chính học viên sinh ra từ một máy Kali có IP tĩnh, tới
một máy đích có IP tĩnh, trong các cửa sổ thời gian đã ghi lại. Do đó có thể
gán NHÃN ground truth cho từng flow/cảnh báo và tính Precision/Recall/F1/FPR
cho ba nhánh: Suricata (luật), Random Forest (ML) và Hybrid (sau dung hợp).

Điểm quan trọng về gán nhãn (đọc kỹ)
-----------------------------------
CSV do `pcap_to_flow_csv.py` sinh có `start_utc` và `end_utc`. Detector giữ lại
`start_utc` trong cảnh báo AI khi replay PCAP, nhờ đó nhãn và cửa sổ tương quan
được đối chiếu theo thời gian gốc của flow. Với nguồn cũ không có timestamp,
script vẫn khớp theo bộ định danh mạng nhưng phải ghi nhận hạn chế này trong
artifact kết quả.

Đơn vị đánh giá
---------------
Đơn vị là "sự kiện" = tuple (src_ip, dst_ip, dst_port, proto). Mỗi sự kiện có
một nhãn ground truth (attack/normal). Mỗi nhánh coi là "đã cảnh báo" cho một
sự kiện nếu có >=1 cảnh báo khớp bộ định danh đó. Cách này công bằng giữa nhánh
sinh nhiều alert (RF) và nhánh sinh ít alert (Suricata), và tránh phụ thuộc vào
việc trích flow của NFStream có khớp 1-1 với flow của Suricata hay không.

Đầu vào
-------
--attack-windows   labeling/attack_windows.csv  (ground truth do bạn ghi)
--flows            lab_run_flows.csv            (CSV flow đưa vào detector; để liệt kê toàn bộ sự kiện normal)
--ai-alerts        logs/ai_alerts.jsonl         (từ nids_detector.py)
--suricata-eve     eve.json                     (từ Suricata)
--hybrid-alerts    logs/hybrid_alerts.jsonl     (từ hybrid_alert_fusion.py, có --include-unmatched)

Đầu ra
------
--out-json         logs/hybrid_labeled_metrics.json
--out-md           logs/hybrid_labeled_metrics.md   (bảng dán thẳng vào Chương 3)

Cách dùng
---------
python evaluate_hybrid_labeled.py \
  --attack-windows labeling/attack_windows.csv \
  --flows lab_run_flows.csv \
  --ai-alerts logs/ai_alerts.jsonl \
  --suricata-eve eve.json \
  --hybrid-alerts logs/hybrid_alerts.jsonl \
  --out-json logs/hybrid_labeled_metrics.json \
  --out-md logs/hybrid_labeled_metrics.md

Yêu cầu: chỉ dùng thư viện chuẩn Python (không cần cài thêm).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# --------------------------------------------------------------------------- #
# Chuẩn hóa
# --------------------------------------------------------------------------- #

PROTO_ALIASES = {"6": "tcp", "17": "udp", "1": "icmp"}


def norm_proto(value: Any) -> str:
    text = str(value or "-").strip().lower()
    return PROTO_ALIASES.get(text, text)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def parse_ts(value: Any) -> datetime | None:
    """Parse timestamp ISO8601 (dùng cho eve.json của Suricata)."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Suricata: 2026-06-27T16:03:07.422362+0700  -> chèn dấu ':' vào offset
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Ground truth
# --------------------------------------------------------------------------- #

@dataclass
class AttackWindow:
    scenario: str
    attacker_ip: str
    target_ip: str
    port_lo: int
    port_hi: int
    proto: str
    start: datetime | None
    end: datetime | None
    label: str  # "attack" hoặc "normal"


def _first(mapping: dict, *keys: str, default: str = "") -> str:
    """Lấy giá trị của cột đầu tiên tồn tại trong nhiều tên cột đồng nghĩa.

    Cho phép đọc được nhiều biến thể header attack_windows.csv:
      - attacker_ip / srcip / src_ip
      - target_ip / dstip / dst_ip
    """
    for k in keys:
        v = mapping.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return default


def norm_label(value: str) -> str:
    """Chuẩn hóa nhãn về 'attack' / 'normal'.

    Console tấn công ghi nhãn dạng '1'/'0'; template khác dùng chữ.
    Quy ước: 1/attack/malicious/mal -> attack; 0/normal/benign -> normal.
    Bỏ trống mặc định 'attack' (giữ hành vi cũ cho cửa sổ tấn công).
    """
    text = (value or "").strip().lower()
    if text in ("", "attack", "1", "malicious", "mal", "true", "positive"):
        return "attack"
    if text in ("normal", "0", "benign", "false", "negative"):
        return "normal"
    return text


def load_attack_windows(path: Path) -> list[AttackWindow]:
    """Đọc file ground truth.

    Cột kỳ vọng (header, không phân biệt hoa thường); chấp nhận nhiều biến thể:
      scenario, attacker_ip, target_ip, dst_port, proto, start_utc, end_utc, label
    - attacker_ip cũng chấp nhận: srcip, src_ip
    - target_ip   cũng chấp nhận: dstip, dst_ip
    - label chấp nhận cả dạng số 1/0 lẫn chữ attack/normal (xem norm_label).

    dst_port chấp nhận:
      - một số:          80
      - dải:             1-1000
      - '*' hoặc rỗng:   khớp mọi cổng
    label mặc định 'attack' nếu bỏ trống.
    """
    rows: list[AttackWindow] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [c.strip().lower() for c in (reader.fieldnames or [])]
        for raw in reader:
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            port_field = r.get("dst_port", "").strip()
            if port_field in ("", "*", "any"):
                lo, hi = 0, 65535
            elif "-" in port_field:
                a, b = port_field.split("-", 1)
                lo, hi = safe_int(a, 0), safe_int(b, 65535)
            else:
                lo = hi = safe_int(port_field, 0)
            rows.append(
                AttackWindow(
                    scenario=r.get("scenario", ""),
                    attacker_ip=_first(r, "attacker_ip", "srcip", "src_ip"),
                    target_ip=_first(r, "target_ip", "dstip", "dst_ip"),
                    port_lo=lo,
                    port_hi=hi,
                    proto=norm_proto(r.get("proto", "")),
                    start=parse_ts(r.get("start_utc")),
                    end=parse_ts(r.get("end_utc")),
                    label=norm_label(r.get("label", "")),
                )
            )
    return rows


def ip_eq(a: str, b: str) -> bool:
    """So sánh IP: chỉ '*'/'any' là wildcard khớp mọi IP; còn lại so bằng.

    LƯU Ý: KHÔNG coi chuỗi rỗng là wildcard. Nếu ground truth thiếu IP (ví dụ
    do đọc nhầm tên cột srcip/dstip), việc coi rỗng = 'khớp mọi IP' sẽ ÂM THẦM
    gán nhãn sai cho toàn bộ sự kiện. Rỗng ở đây phải KHÔNG khớp để lỗi lộ ra
    thay vì bị che giấu.
    """
    a = (a or "").strip()
    b = (b or "").strip()
    if a in ("*", "any") or b in ("*", "any"):
        return True
    if a == "" or b == "":
        return False
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def label_event(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    windows: list[AttackWindow],
    start: datetime | None = None,
    end: datetime | None = None,
) -> str:
    """Trả về 'attack' nếu khớp bất kỳ cửa sổ attack; nếu chỉ khớp cửa sổ
    normal thì 'normal'; nếu không khớp gì thì 'normal' (traffic nền)."""
    proto = norm_proto(proto)
    matched_attack = False
    for w in windows:
        if start is not None and w.start is not None and w.end is not None:
            flow_end = end or start
            if start > w.end or flow_end < w.start:
                continue
        if not ip_eq(w.attacker_ip, src_ip):
            continue
        if not ip_eq(w.target_ip, dst_ip):
            continue
        if w.proto not in ("", "*", "any") and w.proto != proto:
            continue
        if not (w.port_lo <= dst_port <= w.port_hi):
            continue
        if w.label == "attack":
            matched_attack = True
    return "attack" if matched_attack else "normal"


# --------------------------------------------------------------------------- #
# Đọc các nguồn cảnh báo -> tập "sự kiện đã cảnh báo" theo bộ định danh
# --------------------------------------------------------------------------- #

EventKey = tuple[str, str, int, str]  # (src_ip, dst_ip, dst_port, proto)


def event_key(src_ip: str, dst_ip: str, dst_port: Any, proto: Any) -> EventKey:
    return (str(src_ip).strip(), str(dst_ip).strip(), safe_int(dst_port), norm_proto(proto))


def read_jsonl(path: Path) -> Iterable[dict]:
    if not path or not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def ai_alert_events(path: Path) -> set[EventKey]:
    keys: set[EventKey] = set()
    for rec in read_jsonl(path):
        keys.add(event_key(rec.get("src_ip", ""), rec.get("dst_ip", ""),
                            rec.get("dst_port", 0), rec.get("protocol", rec.get("proto", ""))))
    return keys


def suricata_events(path: Path) -> set[EventKey]:
    """Đọc eve.json/eve.jsonl, chỉ lấy record event_type == 'alert'."""
    keys: set[EventKey] = set()
    for rec in read_jsonl(path):
        if rec.get("event_type") != "alert":
            continue
        keys.add(event_key(rec.get("src_ip", ""), rec.get("dest_ip", rec.get("dst_ip", "")),
                            rec.get("dest_port", rec.get("dst_port", 0)),
                            rec.get("proto", rec.get("protocol", ""))))
    return keys


def hybrid_operational_events(
    path: Path,
) -> tuple[set[EventKey], set[EventKey], set[EventKey], dict[str, int]]:
    """Tách coverage vận hành, tương quan thật và tín hiệu demo.

    Coverage Hybrid là hợp của ba action vận hành: correlated, AI-only và
    Suricata-only. HYBRID_PLUS_DEMO_ALERT bị loại khỏi metric chính thức.
    """
    operational_keys: set[EventKey] = set()
    correlated_keys: set[EventKey] = set()
    demo_keys: set[EventKey] = set()
    operational_actions = {
        "HYBRID_CORRELATED_ALERT",
        "AI_ONLY_ALERT",
        "SURICATA_ONLY_ALERT",
    }
    action_counts: dict[str, int] = {
        "HYBRID_CORRELATED_ALERT": 0,
        "AI_ONLY_ALERT": 0,
        "SURICATA_ONLY_ALERT": 0,
        "HYBRID_PLUS_DEMO_ALERT": 0,
    }
    for rec in read_jsonl(path):
        action = str(rec.get("action", "")).upper()
        if action not in action_counts:
            continue
        action_counts[action] += 1
        key = event_key(
            rec.get("src_ip", ""),
            rec.get("dst_ip", ""),
            rec.get("dst_port", 0),
            rec.get("protocol", rec.get("proto", "")),
        )
        if action in operational_actions:
            operational_keys.add(key)
        if action == "HYBRID_CORRELATED_ALERT":
            correlated_keys.add(key)
        elif action == "HYBRID_PLUS_DEMO_ALERT":
            demo_keys.add(key)
    return operational_keys, correlated_keys, demo_keys, action_counts


# --------------------------------------------------------------------------- #
# Không gian sự kiện: liệt kê toàn bộ sự kiện quan sát được từ flow CSV
# --------------------------------------------------------------------------- #

def load_flow_events(path: Path) -> dict[EventKey, list[tuple[datetime | None, datetime | None]]]:
    """Trả về thời gian quan sát của từng event key trong flow CSV."""
    events: dict[EventKey, list[tuple[datetime | None, datetime | None]]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [c.strip().lower() for c in (reader.fieldnames or [])]
        for row in reader:
            r = {(k or "").strip().lower(): v for k, v in row.items()}
            src = r.get("srcip") or r.get("src_ip") or ""
            dst = r.get("dstip") or r.get("dst_ip") or ""
            dport = r.get("dsport") or r.get("dst_port") or 0
            proto = r.get("proto") or r.get("protocol") or ""
            k = event_key(src, dst, dport, proto)
            events.setdefault(k, []).append(
                (parse_ts(r.get("start_utc")), parse_ts(r.get("end_utc")))
            )
    return events


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Tính confusion + metric
# --------------------------------------------------------------------------- #

@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    def as_dict(self) -> dict:
        return {
            "TP": self.tp, "FP": self.fp, "FN": self.fn, "TN": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
        }


def evaluate_branch(labels: dict[EventKey, str], alerted: set[EventKey]) -> Confusion:
    c = Confusion()
    for key, lab in labels.items():
        fired = key in alerted
        if lab == "attack" and fired:
            c.tp += 1
        elif lab == "attack" and not fired:
            c.fn += 1
        elif lab == "normal" and fired:
            c.fp += 1
        else:
            c.tn += 1
    return c


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="Đánh giá có nhãn cho Hybrid-NIDS trên tấn công lab.")
    ap.add_argument("--attack-windows", required=True, type=Path)
    ap.add_argument("--flows", required=True, type=Path, help="CSV flow đưa vào detector (chứa srcip/dstip/dsport/proto).")
    ap.add_argument("--ai-alerts", required=True, type=Path)
    ap.add_argument("--suricata-eve", required=True, type=Path)
    ap.add_argument("--hybrid-alerts", required=True, type=Path)
    ap.add_argument("--out-json", type=Path, default=Path("logs/hybrid_labeled_metrics.json"))
    ap.add_argument("--out-md", type=Path, default=Path("logs/hybrid_labeled_metrics.md"))
    ap.add_argument("--out-csv", type=Path, default=Path("logs/hybrid_labeled_metrics.csv"))
    args = ap.parse_args()

    windows = load_attack_windows(args.attack_windows)
    if not windows:
        raise SystemExit(
            "[X] Ground truth khong co dong du lieu, chi co header. "
            "Khong the tinh TP/FP/FN/TN cho phien nay."
        )

    # 1) Không gian sự kiện = mọi flow quan sát được
    events = load_flow_events(args.flows)

    # 2) Gán nhãn ground truth cho từng sự kiện
    labels: dict[EventKey, str] = {}
    has_flow_timestamps = any(
        start is not None for observations in events.values() for start, _end in observations
    )
    for key, observations in events.items():
        src, dst, dport, proto = key
        labels[key] = (
            "attack"
            if any(
                label_event(src, dst, dport, proto, windows, start, end) == "attack"
                for start, end in observations
            )
            else "normal"
        )

    n_attack = sum(1 for v in labels.values() if v == "attack")
    n_normal = sum(1 for v in labels.values() if v == "normal")

    # 3) Tập sự kiện đã cảnh báo theo từng nhánh
    ai_keys = ai_alert_events(args.ai_alerts)
    suri_keys = suricata_events(args.suricata_eve)
    hybrid_keys, correlated_keys, demo_keys, hybrid_action_counts = hybrid_operational_events(
        args.hybrid_alerts
    )

    # Chỉ giữ các key thuộc không gian sự kiện đã quan sát (tránh key lạ)
    ai_keys &= set(labels)
    suri_keys &= set(labels)
    hybrid_keys &= set(labels)
    correlated_keys &= set(labels)
    demo_keys &= set(labels)

    # 4) Confusion + metric cho 3 nhánh
    results = {
        "Suricata (rule-only)": evaluate_branch(labels, suri_keys),
        "Random Forest (ML-only, live)": evaluate_branch(labels, ai_keys),
        "Hybrid operational coverage": evaluate_branch(labels, hybrid_keys),
    }

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "event_space": {
            "total_events": len(labels),
            "attack_events": n_attack,
            "normal_events": n_normal,
        },
        "branches": {name: conf.as_dict() for name, conf in results.items()},
        "hybrid_evidence": hybrid_action_counts,
        "true_correlated_unique_events": len(correlated_keys),
        "hybrid_plus_demo_unique_events_excluded": len(demo_keys),
        "ground_truth_time_aware": has_flow_timestamps,
        "input_sha256": {
            "attack_windows": sha256_file(args.attack_windows),
            "flows": sha256_file(args.flows),
            "ai_alerts": sha256_file(args.ai_alerts),
            "suricata_eve": sha256_file(args.suricata_eve),
            "hybrid_alerts": sha256_file(args.hybrid_alerts),
        },
        "note": (
            "Đơn vị đánh giá là sự kiện (src_ip, dst_ip, dst_port, proto). "
            "Nhãn ground truth được đối chiếu theo thời gian flow và bộ định danh mạng khi "
            "CSV có start_utc/end_utc. Hybrid operational coverage là hợp của "
            "HYBRID_CORRELATED_ALERT, AI_ONLY_ALERT và SURICATA_ONLY_ALERT. "
            "HYBRID_PLUS_DEMO_ALERT bị loại khỏi mọi metric chính thức."
        ),
    }

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["branch", "TP", "FP", "FN", "TN", "precision", "recall", "f1", "fpr"])
        for name, conf in results.items():
            d = conf.as_dict()
            writer.writerow(
                [name, d["TP"], d["FP"], d["FN"], d["TN"], d["precision"], d["recall"], d["f1"], d["fpr"]]
            )

    # 5) Bảng markdown để dán vào Chương 3
    lines = []
    lines.append("### Đánh giá có nhãn trên tấn công lab tự sinh\n")
    lines.append(f"- Tổng sự kiện: **{len(labels)}** "
                 f"(attack: **{n_attack}**, normal: **{n_normal}**)\n")
    lines.append(
        f"- Sự kiện tương quan thật RF+Suricata: **{len(correlated_keys)}**; "
        f"Hybrid+ Demo bị loại khỏi metric: **{len(demo_keys)}**\n"
    )
    lines.append("| Nhánh | TP | FP | FN | TN | Precision | Recall | F1 | FPR |")
    lines.append("|-------|---:|---:|---:|---:|:---------:|:------:|:--:|:---:|")
    for name, conf in results.items():
        d = conf.as_dict()
        lines.append(
            f"| {name} | {d['TP']} | {d['FP']} | {d['FN']} | {d['TN']} | "
            f"{d['precision']:.4f} | {d['recall']:.4f} | {d['f1']:.4f} | {d['fpr']:.4f} |"
        )
    lines.append("")
    lines.append("> Đơn vị: sự kiện (src_ip, dst_ip, dst_port, proto). Nhãn ground truth từ "
                 "attack_windows.csv; ưu tiên đối chiếu thời gian flow khi có start_utc/end_utc. "
                 "Đây là đánh giá tương đối trên cùng phiên lab, không phải hiệu năng tuyệt đối "
                 "trên lưu lượng vận hành thật.")
    lines.append(
        "> Hybrid operational coverage là hợp cảnh báo vận hành của hai nhánh. "
        "HYBRID_PLUS_DEMO_ALERT không tham gia TP/FP/FN/TN."
    )
    args.out_md.write_text("\n".join(lines), encoding="utf-8")

    # In ra console
    print("=" * 60)
    print(f"Không gian sự kiện: {len(labels)} (attack={n_attack}, normal={n_normal})")
    print("=" * 60)
    for name, conf in results.items():
        d = conf.as_dict()
        print(f"{name:32s} P={d['precision']:.4f} R={d['recall']:.4f} "
              f"F1={d['f1']:.4f} FPR={d['fpr']:.4f} "
              f"(TP={d['TP']} FP={d['FP']} FN={d['FN']} TN={d['TN']})")
    print("=" * 60)
    print(f"[+] Đã ghi: {args.out_json}")
    print(f"[+] Đã ghi: {args.out_md}")


if __name__ == "__main__":
    main()
