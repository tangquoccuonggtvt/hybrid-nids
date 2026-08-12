"""Real-time dashboard for the official Hybrid-NIDS model.

The dashboard replays flow records from a CSV file and runs the trained
Random Forest pipeline in near real time. This is safer and more reproducible
for thesis evaluation than launching real attacks on a live network.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from artifact_security import load_trusted_model
import numpy as np
import pandas as pd
import sklearn

from nids_detector import (
    load_feature_schema,
    metadata_from_dataframe,
    prepare_features,
    severity_from_score,
)


for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")


DEFAULT_MODEL = Path("./models/nids_rf_pipeline.pkl")
DEFAULT_METADATA = Path("./models/metadata.json")
DEFAULT_SCHEMA = Path("./models/feature_schema_model.json")
DEFAULT_INPUT = Path("./UNSW_NB15_Splitted_CLEAN/unsw_nb15_test_holdout.csv")
DEFAULT_ALERT_LOG = Path("./logs/realtime_dashboard_alerts.jsonl")
REQUIRED_SKLEARN_VERSION = "1.6.1"


@dataclass(frozen=True)
class DashboardConfig:
    model_path: Path
    metadata_path: Path
    schema_path: Path
    input_csv: Path
    alert_log: Path
    host: str
    port: int
    batch_size: int
    rows_per_second: float
    max_events: int


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DashboardState:
    def __init__(self, config: DashboardConfig) -> None:
        self.config = config
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None

        if sklearn.__version__ != REQUIRED_SKLEARN_VERSION:
            raise RuntimeError(
                "Môi trường Python không khớp model artifact. "
                f"Model được khóa với scikit-learn=={REQUIRED_SKLEARN_VERSION}, "
                f"nhưng runtime hiện tại là scikit-learn=={sklearn.__version__}. "
                "Hãy chạy bằng C:\\Users\\Admin\\anaconda3\\python.exe hoặc cài lại requirements.txt."
            )
        if sys.version_info >= (3, 14):
            raise RuntimeError(
                "Python 3.14 chưa phù hợp để load model artifact hiện tại. "
                "Hãy chạy bằng Python 3.13/3.12 với scikit-learn==1.6.1."
            )

        self.pipeline = load_trusted_model(config.model_path, config.metadata_path)
        self.metadata = load_json(config.metadata_path)
        self.schema = load_feature_schema(config.schema_path)
        self.threshold = float(self.metadata.get("threshold", 0.5))

        self.started_at: str | None = None
        self.replay_started_perf: float | None = None
        self.last_update: str | None = None
        self.running = False
        self.finished = False
        self.error: str | None = None

        self.total_flows = 0
        self.predicted_attack = 0
        self.predicted_normal = 0
        self.score_sum = 0.0
        self.latency_samples_ms: deque[float] = deque(maxlen=1000)
        self.throughput_samples: deque[float] = deque(maxlen=1000)

        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.has_labels = False

        self.severity_counts: Counter[str] = Counter()
        self.top_src: Counter[str] = Counter()
        self.top_dst_port: Counter[str] = Counter()
        self.timeline: deque[dict[str, Any]] = deque(maxlen=config.max_events)
        self.recent_alerts: deque[dict[str, Any]] = deque(maxlen=100)
        self.attack_detection_stats: dict[str, dict[str, Any]] = {}

        config.alert_log.parent.mkdir(parents=True, exist_ok=True)

    def reset(self) -> None:
        with self.lock:
            self.started_at = None
            self.replay_started_perf = None
            self.last_update = None
            self.running = False
            self.finished = False
            self.error = None
            self.total_flows = 0
            self.predicted_attack = 0
            self.predicted_normal = 0
            self.score_sum = 0.0
            self.latency_samples_ms.clear()
            self.throughput_samples.clear()
            self.tp = self.fp = self.tn = self.fn = 0
            self.has_labels = False
            self.severity_counts.clear()
            self.top_src.clear()
            self.top_dst_port.clear()
            self.timeline.clear()
            self.recent_alerts.clear()
            self.attack_detection_stats.clear()

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        self.reset()
        self.worker = threading.Thread(target=self._run_replay, daemon=True)
        self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        with self.lock:
            self.running = False
            self.last_update = utc_now()

    def _run_replay(self) -> None:
        with self.lock:
            self.running = True
            self.finished = False
            self.started_at = utc_now()
            self.replay_started_perf = time.perf_counter()
            self.last_update = self.started_at

        try:
            for chunk in pd.read_csv(self.config.input_csv, low_memory=False, chunksize=self.config.batch_size):
                if self.stop_event.is_set():
                    break
                self._process_chunk(chunk)
                if self.config.rows_per_second > 0:
                    sleep_seconds = len(chunk) / self.config.rows_per_second
                    time.sleep(max(0.0, sleep_seconds))
        except Exception as exc:  # noqa: BLE001 - dashboard should expose errors instead of crashing silently.
            logging.exception("Dashboard replay failed: %s", exc)
            with self.lock:
                self.error = str(exc)
        finally:
            with self.lock:
                self.running = False
                self.finished = not self.stop_event.is_set() and self.error is None
                self.last_update = utc_now()

    def _process_chunk(self, chunk: pd.DataFrame) -> None:
        X = prepare_features(chunk, self.schema)
        batch_meta = metadata_from_dataframe(chunk)
        labels = None
        attack_categories: list[str] | None = None
        if "label" in [str(c).lower().strip() for c in chunk.columns]:
            normalized = chunk.copy()
            normalized.columns = normalized.columns.str.lower().str.strip()
            labels = pd.to_numeric(normalized["label"], errors="coerce").fillna(0).astype(int).to_numpy()
            if "attack_cat" in normalized.columns:
                attack_categories = normalized["attack_cat"].fillna("Không rõ").astype(str).str.strip().to_list()

        start = time.perf_counter()
        scores = self.pipeline.predict_proba(X)[:, 1]
        elapsed = time.perf_counter() - start
        predictions = (scores >= self.threshold).astype(int)

        latency_ms_per_flow = (elapsed / max(len(chunk), 1)) * 1000
        throughput = len(chunk) / elapsed if elapsed > 0 else 0.0
        now = utc_now()

        alerts_to_write: list[dict[str, Any]] = []
        attack_count = int(predictions.sum())
        normal_count = int(len(predictions) - attack_count)

        severity_counts = Counter()
        top_src = Counter()
        top_dst_port = Counter()
        recent_alerts: list[dict[str, Any]] = []
        attack_detection_updates: dict[str, dict[str, Any]] = {}

        tp = fp = tn = fn = 0
        for idx, pred in enumerate(predictions):
            score = safe_float(scores[idx])
            meta = batch_meta[idx]
            actual = None
            if labels is not None:
                actual = int(labels[idx])
                if pred == 1 and actual == 1:
                    tp += 1
                elif pred == 1 and actual == 0:
                    fp += 1
                elif pred == 0 and actual == 0:
                    tn += 1
                elif pred == 0 and actual == 1:
                    fn += 1

            attack_category = ""
            if attack_categories is not None and idx < len(attack_categories):
                attack_category = attack_categories[idx].strip() or "Không rõ"
                if attack_category.lower() == "normal":
                    attack_category = "Normal"
            if actual == 1 and attack_category and attack_category != "Normal":
                category_stats = attack_detection_updates.setdefault(
                    attack_category,
                    {
                        "actual_seen": 0,
                        "alerts": 0,
                        "first_detection_seconds": None,
                        "first_score": None,
                    },
                )
                category_stats["actual_seen"] += 1

            if int(pred) != 1:
                continue

            severity = severity_from_score(score)
            if actual == 1 and attack_category and attack_category != "Normal":
                category_stats = attack_detection_updates.setdefault(
                    attack_category,
                    {
                        "actual_seen": 0,
                        "alerts": 0,
                        "first_detection_seconds": None,
                        "first_score": None,
                    },
                )
                category_stats["alerts"] += 1
                if category_stats["first_detection_seconds"] is None and self.replay_started_perf is not None:
                    category_stats["first_detection_seconds"] = time.perf_counter() - self.replay_started_perf
                    category_stats["first_score"] = round(score, 6)
            alert = {
                "timestamp_utc": now,
                "src_ip": str(meta.get("src_ip", "")),
                "src_port": int(meta.get("src_port", 0)),
                "dst_ip": str(meta.get("dst_ip", "")),
                "dst_port": int(meta.get("dst_port", 0)),
                "protocol": str(meta.get("protocol", "")),
                "application_name": str(meta.get("application_name", "")),
                "attack_score": round(score, 6),
                "threshold": self.threshold,
                "severity": severity,
                "attack_category": attack_category or "Không rõ",
            }
            severity_counts[severity] += 1
            top_src[alert["src_ip"] or "không rõ"] += 1
            top_dst_port[str(alert["dst_port"])] += 1
            alerts_to_write.append(alert)
            recent_alerts.append(alert)

        if alerts_to_write:
            with self.config.alert_log.open("a", encoding="utf-8") as file:
                for alert in alerts_to_write:
                    file.write(json.dumps(alert, ensure_ascii=False) + "\n")

        with self.lock:
            self.total_flows += int(len(chunk))
            self.predicted_attack += attack_count
            self.predicted_normal += normal_count
            self.score_sum += float(np.sum(scores))
            self.latency_samples_ms.append(float(latency_ms_per_flow))
            self.throughput_samples.append(float(throughput))
            self.tp += tp
            self.fp += fp
            self.tn += tn
            self.fn += fn
            self.has_labels = self.has_labels or labels is not None
            self.severity_counts.update(severity_counts)
            self.top_src.update(top_src)
            self.top_dst_port.update(top_dst_port)
            for category, update in attack_detection_updates.items():
                current = self.attack_detection_stats.setdefault(
                    category,
                    {
                        "actual_seen": 0,
                        "alerts": 0,
                        "first_detection_seconds": None,
                        "first_score": None,
                    },
                )
                current["actual_seen"] += int(update["actual_seen"])
                current["alerts"] += int(update["alerts"])
                if current["first_detection_seconds"] is None and update["first_detection_seconds"] is not None:
                    current["first_detection_seconds"] = float(update["first_detection_seconds"])
                    current["first_score"] = update["first_score"]
            for alert in recent_alerts[-50:]:
                self.recent_alerts.appendleft(alert)
            self.timeline.append(
                {
                    "timestamp": now,
                    "flows": int(len(chunk)),
                    "alerts": attack_count,
                    "latency_ms_per_flow": float(latency_ms_per_flow),
                    "throughput_flows_per_second": float(throughput),
                }
            )
            self.last_update = now

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            total = max(self.total_flows, 1)
            precision = self.tp / max(self.tp + self.fp, 1)
            recall = self.tp / max(self.tp + self.fn, 1)
            f1 = (2 * precision * recall / max(precision + recall, 1e-12)) if self.has_labels else 0.0
            fpr = self.fp / max(self.fp + self.tn, 1)
            avg_score = self.score_sum / total
            avg_latency = float(np.mean(self.latency_samples_ms)) if self.latency_samples_ms else 0.0
            avg_throughput = float(np.mean(self.throughput_samples)) if self.throughput_samples else 0.0
            attack_detection = []
            for category, stats in self.attack_detection_stats.items():
                actual_seen = int(stats["actual_seen"])
                alerts = int(stats["alerts"])
                attack_detection.append(
                    {
                        "category": category,
                        "actual_seen": actual_seen,
                        "alerts": alerts,
                        "detection_rate": alerts / max(actual_seen, 1),
                        "first_detection_seconds": stats["first_detection_seconds"],
                        "first_score": stats["first_score"],
                    }
                )
            attack_detection.sort(
                key=lambda item: (
                    item["first_detection_seconds"] is None,
                    item["first_detection_seconds"] if item["first_detection_seconds"] is not None else 999999,
                    item["category"],
                )
            )

            return {
                "running": self.running,
                "finished": self.finished,
                "error": self.error,
                "started_at": self.started_at,
                "last_update": self.last_update,
                "model_name": self.metadata.get("model_name", "Hybrid-NIDS"),
                "threshold": self.threshold,
                "input_csv": str(self.config.input_csv),
                "alert_log": str(self.config.alert_log),
                "total_flows": self.total_flows,
                "predicted_attack": self.predicted_attack,
                "predicted_normal": self.predicted_normal,
                "alert_rate": self.predicted_attack / total,
                "average_attack_score": avg_score,
                "latency_ms_per_flow": avg_latency,
                "throughput_flows_per_second": avg_throughput,
                "has_labels": self.has_labels,
                "confusion_matrix": {
                    "tn": self.tn,
                    "fp": self.fp,
                    "fn": self.fn,
                    "tp": self.tp,
                },
                "live_metrics": {
                    "precision": precision if self.has_labels else None,
                    "recall": recall if self.has_labels else None,
                    "f1_score": f1 if self.has_labels else None,
                    "false_positive_rate": fpr if self.has_labels else None,
                },
                "severity_counts": dict(self.severity_counts),
                "top_src": self.top_src.most_common(8),
                "top_dst_port": self.top_dst_port.most_common(8),
                "timeline": list(self.timeline),
                "recent_alerts": list(self.recent_alerts)[:30],
                "attack_detection": attack_detection,
            }


HTML_PAGE = r"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Bảng điều khiển thời gian thực - Hybrid-NIDS</title>
  <style>
    :root {
      --bg: #f6f7fb;
      --panel: #ffffff;
      --text: #172033;
      --muted: #667085;
      --line: #d8deea;
      --accent: #2563eb;
      --danger: #dc2626;
      --ok: #059669;
      --warn: #d97706;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
    }
    h1 { margin: 0; font-size: 22px; }
    .subtitle { color: var(--muted); font-size: 13px; margin-top: 4px; }
    .controls { display: flex; gap: 8px; flex-wrap: wrap; }
    button {
      border: 1px solid var(--line);
      background: #fff;
      padding: 9px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
    }
    button.primary { background: var(--accent); border-color: var(--accent); color: white; }
    button.danger { background: var(--danger); border-color: var(--danger); color: white; }
    main { padding: 18px 24px 28px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-width: 0;
    }
    .metric-label { color: var(--muted); font-size: 12px; }
    .metric-value { font-size: 25px; font-weight: 750; margin-top: 6px; }
    .metric-note { color: var(--muted); font-size: 12px; margin-top: 5px; }
    .section {
      margin-top: 14px;
      display: grid;
      grid-template-columns: 1.25fr 1fr;
      gap: 14px;
    }
    .section h2 { margin: 0 0 10px; font-size: 17px; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 8px 6px;
      text-align: left;
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 650; }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--muted);
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: var(--warn);
    }
    .dot.running { background: var(--ok); }
    .dot.error { background: var(--danger); }
    canvas { width: 100%; height: 220px; border: 1px solid var(--line); border-radius: 6px; }
    .mono { font-family: Consolas, "Courier New", monospace; }
    .badges { display: flex; gap: 8px; flex-wrap: wrap; }
    .badge {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 5px 8px;
      font-size: 12px;
      color: var(--muted);
      background: #fff;
    }
    @media (max-width: 1100px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .section { grid-template-columns: 1fr; }
    }
    @media (max-width: 640px) {
      header { align-items: flex-start; flex-direction: column; }
      .grid { grid-template-columns: 1fr; }
      main { padding: 14px; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Bảng điều khiển thời gian thực Hybrid-NIDS (Real-time Dashboard)</h1>
      <div class="subtitle">Giám sát suy luận Random Forest (Inference Monitoring) phục vụ đánh giá luận văn</div>
    </div>
    <div class="controls">
      <button class="primary" onclick="postControl('/control/start')">Bắt đầu (Start)</button>
      <button onclick="postControl('/control/stop')">Dừng (Stop)</button>
      <button class="danger" onclick="postControl('/control/reset')">Đặt lại (Reset)</button>
    </div>
  </header>
  <main>
    <div class="card" style="margin-bottom:14px">
      <div class="status"><span id="status-dot" class="dot"></span><span id="status-text">Đang kết nối (Connecting)...</span></div>
      <div class="subtitle mono" id="source-line"></div>
      <div class="badges" style="margin-top:10px">
        <span class="badge" id="model-badge"></span>
        <span class="badge" id="threshold-badge"></span>
        <span class="badge" id="alert-log-badge"></span>
      </div>
    </div>

    <div class="grid">
      <div class="card"><div class="metric-label">Tổng số luồng (Total Flows)</div><div class="metric-value" id="total-flows">0</div><div class="metric-note">Số bản ghi luồng đã xử lý (Processed Flow Records)</div></div>
      <div class="card"><div class="metric-label">Số cảnh báo (Alerts)</div><div class="metric-value" id="alerts">0</div><div class="metric-note">Luồng được dự đoán là tấn công (Predicted Attacks)</div></div>
      <div class="card"><div class="metric-label">Tỷ lệ cảnh báo (Alert Rate)</div><div class="metric-value" id="alert-rate">0%</div><div class="metric-note">Tỷ lệ luồng bị cảnh báo (Alerted Flow Ratio)</div></div>
      <div class="card"><div class="metric-label">Thông lượng (Throughput)</div><div class="metric-value" id="throughput">0</div><div class="metric-note">Số luồng xử lý mỗi giây (Flows per Second)</div></div>
      <div class="card"><div class="metric-label">Độ trễ (Latency)</div><div class="metric-value" id="latency">0</div><div class="metric-note">Mili-giây trên mỗi luồng (Milliseconds per Flow)</div></div>
      <div class="card"><div class="metric-label">Độ chính xác cảnh báo (Precision)</div><div class="metric-value" id="precision">Chưa có (N/A)</div><div class="metric-note">Tính khi CSV có nhãn (Requires Labels)</div></div>
      <div class="card"><div class="metric-label">Độ bao phủ phát hiện (Recall)</div><div class="metric-value" id="recall">Chưa có (N/A)</div><div class="metric-note">Tính khi CSV có nhãn (Requires Labels)</div></div>
      <div class="card"><div class="metric-label">Điểm F1 (F1-score)</div><div class="metric-value" id="f1">Chưa có (N/A)</div><div class="metric-note">Tính khi CSV có nhãn (Requires Labels)</div></div>
    </div>

    <div class="section">
      <div class="card">
        <h2>Dòng thời gian cảnh báo (Alert Timeline)</h2>
        <canvas id="timeline" width="900" height="260"></canvas>
      </div>
      <div class="card">
        <h2>Ma trận nhầm lẫn (Confusion Matrix)</h2>
        <table>
          <thead><tr><th>Nhãn thật / Dự đoán (Actual / Predicted)</th><th>Bình thường (Normal)</th><th>Tấn công (Attack)</th></tr></thead>
          <tbody>
            <tr><th>Bình thường (Normal)</th><td id="tn">0</td><td id="fp">0</td></tr>
            <tr><th>Tấn công (Attack)</th><td id="fn">0</td><td id="tp">0</td></tr>
          </tbody>
        </table>
        <div class="subtitle" style="margin-top:10px">Tỷ lệ cảnh báo sai (False Positive Rate - FPR): <span id="fpr">Chưa có (N/A)</span></div>
      </div>
    </div>

    <div class="section">
      <div class="card">
        <h2>Thời gian phát hiện theo loại tấn công (Detection Time by Attack Type)</h2>
        <canvas id="detection-time" width="900" height="260"></canvas>
      </div>
      <div class="card">
        <h2>Chi tiết phát hiện (Detection Details)</h2>
        <table>
          <thead><tr><th>Loại tấn công (Attack Type)</th><th>Cảnh báo đầu tiên (First Alert)</th><th>Cảnh báo (Alerts)</th><th>Tỷ lệ phát hiện (Detection Rate)</th></tr></thead>
          <tbody id="attack-detection"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="card">
        <h2>Cảnh báo gần đây (Recent Alerts)</h2>
        <table>
          <thead><tr><th>Thời gian (Time)</th><th>Điểm (Score)</th><th>Mức độ (Severity)</th><th>Loại (Type)</th><th>Nguồn (Source)</th><th>Cổng đích (Destination Port)</th><th>Dịch vụ (Service)</th></tr></thead>
          <tbody id="recent-alerts"></tbody>
        </table>
      </div>
      <div class="card">
        <h2>Thực thể nổi bật (Top Entities)</h2>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px">
          <div>
            <h3 style="font-size:14px">Nguồn nhiều cảnh báo nhất (Top Sources)</h3>
            <table><tbody id="top-src"></tbody></table>
          </div>
          <div>
            <h3 style="font-size:14px">Cổng đích nhiều cảnh báo nhất (Top Destination Ports)</h3>
            <table><tbody id="top-port"></tbody></table>
          </div>
        </div>
      </div>
    </div>
  </main>
  <script>
    let latest = null;
    const unavailableText = 'Chưa có (N/A)';
    const unknownText = 'không rõ (Unknown)';
    const severityText = {
      CRITICAL: 'Nghiêm trọng (Critical)',
      HIGH: 'Cao (High)',
      MEDIUM: 'Trung bình (Medium)',
      LOW: 'Thấp (Low)'
    };
    function fmt(n, digits=0) {
      if (n === null || n === undefined) return unavailableText;
      return Number(n).toLocaleString(undefined, {maximumFractionDigits: digits, minimumFractionDigits: digits});
    }
    function pct(n) {
      if (n === null || n === undefined) return unavailableText;
      return (Number(n) * 100).toFixed(2) + '%';
    }
    function secondsText(n) {
      if (n === null || n === undefined) return unavailableText;
      return Number(n).toFixed(2) + ' giây (seconds)';
    }
    async function postControl(path) {
      await fetch(path, {method: 'POST'});
    }
    function drawTimeline(items) {
      const canvas = document.getElementById('timeline');
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0,0,canvas.width,canvas.height);
      ctx.strokeStyle = '#d8deea';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(40, 20); ctx.lineTo(40, 220); ctx.lineTo(870, 220); ctx.stroke();
      if (!items || items.length === 0) return;
      const maxAlerts = Math.max(1, ...items.map(x => x.alerts));
      const step = 830 / Math.max(items.length - 1, 1);
      ctx.strokeStyle = '#2563eb';
      ctx.lineWidth = 2;
      ctx.beginPath();
      items.forEach((item, i) => {
        const x = 40 + i * step;
        const y = 220 - (item.alerts / maxAlerts) * 180;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
      ctx.fillStyle = '#dc2626';
      items.forEach((item, i) => {
        const x = 40 + i * step;
        const y = 220 - (item.alerts / maxAlerts) * 180;
        ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
      });
      ctx.fillStyle = '#667085';
      ctx.font = '12px Segoe UI';
      ctx.fillText('cảnh báo mỗi lô (alerts per batch)', 44, 16);
    }
    function drawDetectionTime(rows) {
      const canvas = document.getElementById('detection-time');
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0,0,canvas.width,canvas.height);
      ctx.strokeStyle = '#d8deea';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(150, 28); ctx.lineTo(150, 220); ctx.lineTo(870, 220); ctx.stroke();
      const detected = (rows || []).filter(x => x.first_detection_seconds !== null && x.first_detection_seconds !== undefined).slice(0, 8);
      if (detected.length === 0) {
        ctx.fillStyle = '#667085';
        ctx.font = '14px Segoe UI';
        ctx.fillText('Chưa có cảnh báo theo loại tấn công (No attack-type alerts yet)', 170, 120);
        return;
      }
      const maxSeconds = Math.max(1, ...detected.map(x => Number(x.first_detection_seconds)));
      const barHeight = Math.min(24, 150 / detected.length);
      detected.forEach((item, i) => {
        const y = 48 + i * (barHeight + 8);
        const width = Math.max(4, (Number(item.first_detection_seconds) / maxSeconds) * 650);
        ctx.fillStyle = '#0f766e';
        ctx.fillRect(150, y, width, barHeight);
        ctx.fillStyle = '#172033';
        ctx.font = '12px Segoe UI';
        ctx.fillText(String(item.category).slice(0, 18), 12, y + barHeight - 6);
        ctx.font = 'bold 12px Segoe UI';
        ctx.fillText(Number(item.first_detection_seconds).toFixed(2) + 's', 160 + width, y + barHeight - 6);
      });
      ctx.fillStyle = '#667085';
      ctx.font = '12px Segoe UI';
      ctx.fillText('thời gian tới cảnh báo đầu tiên, giây (time to first alert, seconds)', 154, 18);
    }
    function fillPairs(id, rows) {
      const el = document.getElementById(id);
      el.innerHTML = '';
      (rows || []).forEach(([k, v]) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td class="mono">${k || unknownText}</td><td>${fmt(v)}</td>`;
        el.appendChild(tr);
      });
      if (!rows || rows.length === 0) el.innerHTML = '<tr><td colspan="2">Chưa có dữ liệu (No Data)</td></tr>';
    }
    function renderAttackDetection(rows) {
      const tbody = document.getElementById('attack-detection');
      tbody.innerHTML = '';
      (rows || []).slice(0, 10).forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${item.category || unknownText}</td><td>${secondsText(item.first_detection_seconds)}</td><td>${fmt(item.alerts)} / ${fmt(item.actual_seen)}</td><td>${pct(item.detection_rate)}</td>`;
        tbody.appendChild(tr);
      });
      if (!rows || rows.length === 0) tbody.innerHTML = '<tr><td colspan="4">Chưa có dữ liệu theo loại tấn công (No Attack-Type Data)</td></tr>';
    }
    function render(data) {
      latest = data;
      const dot = document.getElementById('status-dot');
      dot.className = 'dot' + (data.running ? ' running' : data.error ? ' error' : '');
      document.getElementById('status-text').textContent = data.error ? ('Lỗi (Error): ' + data.error) : data.running ? 'Đang chạy (Running)' : data.finished ? 'Đã hoàn tất (Completed)' : 'Sẵn sàng (Ready)';
      document.getElementById('source-line').textContent = 'Dữ liệu đầu vào (Input): ' + data.input_csv;
      document.getElementById('model-badge').textContent = 'Mô hình (Model): Random Forest Hybrid-NIDS';
      document.getElementById('threshold-badge').textContent = 'Ngưỡng phát hiện (Threshold): ' + Number(data.threshold).toFixed(6);
      document.getElementById('alert-log-badge').textContent = 'Nhật ký cảnh báo (Alert Log): ' + data.alert_log;
      document.getElementById('total-flows').textContent = fmt(data.total_flows);
      document.getElementById('alerts').textContent = fmt(data.predicted_attack);
      document.getElementById('alert-rate').textContent = pct(data.alert_rate);
      document.getElementById('throughput').textContent = fmt(data.throughput_flows_per_second, 2);
      document.getElementById('latency').textContent = fmt(data.latency_ms_per_flow, 4);
      document.getElementById('precision').textContent = data.has_labels ? pct(data.live_metrics.precision) : unavailableText;
      document.getElementById('recall').textContent = data.has_labels ? pct(data.live_metrics.recall) : unavailableText;
      document.getElementById('f1').textContent = data.has_labels ? pct(data.live_metrics.f1_score) : unavailableText;
      document.getElementById('fpr').textContent = data.has_labels ? pct(data.live_metrics.false_positive_rate) : unavailableText;
      document.getElementById('tn').textContent = fmt(data.confusion_matrix.tn);
      document.getElementById('fp').textContent = fmt(data.confusion_matrix.fp);
      document.getElementById('fn').textContent = fmt(data.confusion_matrix.fn);
      document.getElementById('tp').textContent = fmt(data.confusion_matrix.tp);
      drawTimeline(data.timeline || []);
      drawDetectionTime(data.attack_detection || []);
      renderAttackDetection(data.attack_detection || []);
      const tbody = document.getElementById('recent-alerts');
      tbody.innerHTML = '';
      (data.recent_alerts || []).forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${(a.timestamp_utc || '').slice(11,19)}</td><td>${Number(a.attack_score).toFixed(4)}</td><td>${severityText[a.severity] || a.severity || unknownText}</td><td>${a.attack_category || unknownText}</td><td class="mono">${a.src_ip || unknownText}</td><td>${a.dst_port}</td><td>${a.application_name || ''}</td>`;
        tbody.appendChild(tr);
      });
      if (!data.recent_alerts || data.recent_alerts.length === 0) tbody.innerHTML = '<tr><td colspan="7">Chưa có cảnh báo (No Alerts)</td></tr>';
      fillPairs('top-src', data.top_src);
      fillPairs('top-port', data.top_dst_port);
    }
    const events = new EventSource('/events');
    events.onmessage = event => render(JSON.parse(event.data));
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    state: DashboardState

    def _send_json(self, obj: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/api/status":
            self._send_json(self.state.snapshot())
            return
        if path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            while True:
                try:
                    payload = json.dumps(self.state.snapshot(), ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(1)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    break
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/control/start":
            self.state.start()
            self._send_json({"ok": True, "action": "start"})
            return
        if path == "/control/stop":
            self.state.stop()
            self._send_json({"ok": True, "action": "stop"})
            return
        if path == "/control/reset":
            self.state.stop()
            self.state.reset()
            self._send_json({"ok": True, "action": "reset"})
            return
        self.send_error(404)

    def log_message(self, fmt: str, *args: Any) -> None:
        logging.info("%s - %s", self.address_string(), fmt % args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bảng điều khiển thời gian thực Hybrid-NIDS.")
    parser.add_argument("--model", default=str(DEFAULT_MODEL))
    parser.add_argument("--metadata", default=str(DEFAULT_METADATA))
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    parser.add_argument("--input-csv", default=str(DEFAULT_INPUT))
    parser.add_argument("--alert-log", default=str(DEFAULT_ALERT_LOG))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8050)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--rows-per-second", type=float, default=1000.0)
    parser.add_argument("--max-events", type=int, default=240)
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> DashboardConfig:
    return DashboardConfig(
        model_path=Path(args.model),
        metadata_path=Path(args.metadata),
        schema_path=Path(args.schema),
        input_csv=Path(args.input_csv),
        alert_log=Path(args.alert_log),
        host=args.host,
        port=args.port,
        batch_size=max(1, int(args.batch_size)),
        rows_per_second=max(0.0, float(args.rows_per_second)),
        max_events=max(10, int(args.max_events)),
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")
    config = build_config(parse_args())
    state = DashboardState(config)
    DashboardHandler.state = state
    server = ThreadingHTTPServer((config.host, config.port), DashboardHandler)
    url = f"http://{config.host}:{config.port}"
    print(f"[+] Bảng điều khiển Hybrid-NIDS (Dashboard): {url}")
    print("[+] Bấm Bắt đầu (Start) trên dashboard để bắt đầu mô phỏng thời gian thực.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        state.stop()
        print("\n[+] Đã dừng dashboard (Stopped).")


if __name__ == "__main__":
    main()
