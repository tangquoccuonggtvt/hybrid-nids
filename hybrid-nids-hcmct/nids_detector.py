"""Detector NIDS batch inference.

Thiết kế có hai đường suy luận tách biệt để tránh schema mismatch:
1. CSV flow chính thức: mặc định dùng RF-41 và schema 41 feature của UNSW-NB15.
2. PCAP/live vận hành: mặc định dùng RF-21 vì extractor NFStreamer hiện chỉ sinh
   được tập feature rút gọn. Nhánh PCAP kiểm tra fail-closed; nếu schema/model yêu
   cầu feature mà extractor không sinh được, chương trình dừng thay vì tự fill 0.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from artifact_security import load_trusted_model
import numpy as np
import pandas as pd

from nids_features import FEATURE_COLUMNS as PCAP_FEATURE_COLUMNS, FlowContextWindow, extract_features_from_flow, extract_metadata_from_flow

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

class SchemaMismatchError(ValueError):
    """Lỗi cấu hình schema/model không khớp với extractor PCAP/live."""


@dataclass(frozen=True)
class DetectorConfig:
    model_path: Path
    metadata_path: Path | None
    schema_path: Path
    input_csv: Path | None
    pcap_path: Path
    output_log: Path
    failed_dir: Path
    threshold: float | None
    batch_size: int
    context_window_seconds: float
    once: bool
    delete_after_success: bool
    sleep_seconds: float
    webhook_url: str | None
    disable_discord: bool
    min_alert_score_for_discord: float
    telegram_bot_token: str | None
    telegram_chat_id: str | None
    disable_telegram: bool
    min_alert_score_for_telegram: float


def parse_args() -> DetectorConfig:
    parser = argparse.ArgumentParser(description="NIDS detector đọc flow CSV/PCAP và ghi alert JSONL.")
    parser.add_argument("--model", default=os.getenv("NIDS_MODEL_PATH"))
    parser.add_argument("--metadata", default=os.getenv("NIDS_METADATA_PATH"))
    parser.add_argument("--schema", default=os.getenv("NIDS_SCHEMA_PATH"))
    parser.add_argument("--input-csv", default=os.getenv("NIDS_INPUT_CSV"), help="CSV flow records cần suy luận. Đây là chế độ chính thức.")
    parser.add_argument("--pcap", default=os.getenv("NIDS_TARGET_PCAP", "./pcap_traffic/nmap_data.pcap"))
    parser.add_argument("--output-log", default=os.getenv("NIDS_OUTPUT_LOG", "./logs/ai_alerts.jsonl"))
    parser.add_argument("--failed-dir", default=os.getenv("NIDS_FAILED_DIR", "./failed_pcaps"))
    parser.add_argument("--threshold", type=float, default=None, help="Ngưỡng attack probability. Nếu bỏ trống, đọc từ metadata hoặc dùng 0.80.")
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("NIDS_BATCH_SIZE", "4096")))
    parser.add_argument("--context-window-seconds", type=float, default=float(os.getenv("NIDS_CONTEXT_WINDOW_SECONDS", "100")))
    parser.add_argument("--once", action="store_true", help="Xử lý một lần rồi thoát, phù hợp test thủ công.")
    parser.add_argument("--delete-after-success", action="store_true", help="Xóa PCAP sau khi xử lý thành công. Mặc định không xóa để an toàn.")
    parser.add_argument("--sleep-seconds", type=float, default=float(os.getenv("NIDS_SLEEP_SECONDS", "2")))
    parser.add_argument("--webhook-url", default=os.getenv("DISCORD_NIDS_WEBHOOK"))
    parser.add_argument("--disable-discord", action="store_true")
    parser.add_argument("--min-alert-score-for-discord", type=float, default=float(os.getenv("NIDS_DISCORD_MIN_SCORE", "0.90")))
    parser.add_argument("--telegram-bot-token", default=os.getenv("TELEGRAM_BOT_TOKEN"))
    parser.add_argument("--telegram-chat-id", default=os.getenv("TELEGRAM_CHAT_ID"))
    parser.add_argument("--disable-telegram", action="store_true")
    parser.add_argument("--min-alert-score-for-telegram", type=float, default=float(os.getenv("NIDS_TELEGRAM_MIN_SCORE", "0.90")))
    args = parser.parse_args()

    input_csv = Path(args.input_csv) if args.input_csv else None
    if input_csv is not None:
        default_model = "./models/nids_rf_pipeline.pkl"
        default_schema = "./models/feature_schema_model.json"
        default_metadata = "./models/metadata.json"
    else:
        default_model = "./models/rf21_schema_gap/nids_rf21_schema_gap_pipeline.pkl"
        default_schema = "./models/rf21_schema_gap/feature_schema_rf21.json"
        default_metadata = "./models/rf21_schema_gap/metadata_rf21.json"

    return DetectorConfig(
        model_path=Path(args.model or default_model),
        metadata_path=Path(args.metadata or default_metadata),
        schema_path=Path(args.schema or default_schema),
        input_csv=input_csv,
        pcap_path=Path(args.pcap),
        output_log=Path(args.output_log),
        failed_dir=Path(args.failed_dir),
        threshold=args.threshold,
        batch_size=max(1, args.batch_size),
        context_window_seconds=args.context_window_seconds,
        once=args.once,
        delete_after_success=args.delete_after_success,
        sleep_seconds=max(0.2, args.sleep_seconds),
        webhook_url=args.webhook_url,
        disable_discord=args.disable_discord,
        min_alert_score_for_discord=args.min_alert_score_for_discord,
        telegram_bot_token=args.telegram_bot_token,
        telegram_chat_id=args.telegram_chat_id,
        disable_telegram=args.disable_telegram,
        min_alert_score_for_telegram=args.min_alert_score_for_telegram,
    )


def load_threshold(metadata_path: Path | None, cli_threshold: float | None) -> float:
    if cli_threshold is not None:
        return float(cli_threshold)
    if metadata_path and metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            threshold = metadata.get("threshold")
            if threshold is not None:
                return float(threshold)
        except Exception as exc:  # noqa: BLE001 - metadata lỗi không nên làm detector chết.
            logging.warning("Không đọc được threshold từ metadata %s: %s", metadata_path, exc)
    return 0.80


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_feature_schema(schema_path: Path) -> dict:
    if not schema_path.exists():
        raise FileNotFoundError(f"Không tìm thấy schema: {schema_path}")
    schema = load_json(schema_path)
    required_keys = {"numeric_features", "categorical_features", "feature_columns"}
    missing = required_keys - set(schema)
    if missing:
        raise ValueError(f"Schema thiếu khóa bắt buộc: {sorted(missing)}")
    return schema


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()
    rename_map = {
        "smeansz": "smean",
        "dmeansz": "dmean",
        "sintpkt": "sinpkt",
        "dintpkt": "dinpkt",
        "res_bdy_len": "response_body_len",
        "ct_src_ ltm": "ct_src_ltm",
    }
    df = df.rename(columns=rename_map)
    return df.loc[:, ~df.columns.duplicated()]


def prepare_features(df: pd.DataFrame, schema: dict) -> pd.DataFrame:
    """Chuẩn hóa feature đúng schema model chính thức, không tự tạo cột thiếu."""
    work = normalize_columns(df)
    feature_columns = list(schema["feature_columns"])
    numeric_features = list(schema["numeric_features"])
    categorical_features = list(schema["categorical_features"])

    missing = sorted(set(feature_columns) - set(work.columns))
    if missing:
        raise ValueError(
            "Input thiếu feature bắt buộc so với model chính thức: "
            f"{missing}. Không tự fill 0 để tránh suy luận sai schema."
        )

    X = work[feature_columns].copy()

    for col in numeric_features:
        X[col] = pd.to_numeric(X[col], errors="coerce")
        X[col] = X[col].replace([np.inf, -np.inf], np.nan)
        X[col] = X[col].fillna(0)
        X[col] = X[col].clip(lower=0)

    for col in categorical_features:
        X[col] = X[col].fillna("unknown").astype(str).str.lower().str.strip()

    return X


def load_system_artifacts(config: DetectorConfig) -> tuple[Any, dict, dict, float]:
    """Nạp full pipeline model, metadata/schema và kiểm tra tính nhất quán cơ bản."""
    for path in [config.model_path, config.schema_path]:
        if not path.exists():
            raise FileNotFoundError(f"Không tìm thấy artifact: {path}")

    metadata = load_json(config.metadata_path) if config.metadata_path and config.metadata_path.exists() else {}
    pipeline = load_trusted_model(
        config.model_path,
        config.metadata_path if config.metadata_path and config.metadata_path.exists() else None,
    )
    schema = load_feature_schema(config.schema_path)

    feature_columns = list(schema["feature_columns"])
    model_features = getattr(pipeline, "n_features_in_", len(feature_columns))
    if int(model_features) != len(feature_columns):
        raise ValueError(f"Pipeline cần {model_features} feature nhưng schema có {len(feature_columns)} cột.")

    threshold = load_threshold(config.metadata_path, config.threshold)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"Threshold phải nằm trong [0, 1], nhận được: {threshold}")
    logging.info("[+] Đã nạp full pipeline/schema. Threshold attack = %.3f", threshold)
    return pipeline, schema, metadata, threshold


def import_nfstream() -> Any:
    """Import NFStreamer trễ để các script schema/evaluate không cần cài nfstream."""
    try:
        from nfstream import NFStreamer  # type: ignore
    except ImportError as exc:
        raise ImportError("Chưa cài nfstream. Cài bằng: pip install nfstream") from exc
    return NFStreamer


def send_discord_alert_batch(
    aggregated_alerts: dict[str, dict[str, Any]],
    webhook_url: str | None,
    *,
    disabled: bool,
) -> None:
    """Gửi alert tổng hợp. Không dùng @everyone mặc định để tránh spam."""
    if disabled or not webhook_url or not aggregated_alerts:
        return

    for src_ip, info in aggregated_alerts.items():
        message = format_discord_alert(src_ip, info)
        payload = {"content": message}
        try:
            req = urllib.request.Request(webhook_url)
            req.add_header("Content-Type", "application/json; charset=utf-8")
            req.add_header("User-Agent", "Hybrid-NIDS/1.0")
            urllib.request.urlopen(req, json.dumps(payload).encode("utf-8"), timeout=5)
        except Exception as exc:  # noqa: BLE001 - gửi alert lỗi không làm hỏng inference.
            logging.error("Lỗi gửi Discord: %s", exc)


def severity_vi(severity: str) -> str:
    mapping = {
        "CRITICAL": "KHẨN CẤP (CRITICAL)",
        "HIGH": "CAO (HIGH)",
        "MEDIUM": "TRUNG BÌNH (MEDIUM)",
        "LOW": "THẤP (LOW)",
    }
    return mapping.get(severity, severity)


def format_target_ports(info: dict[str, Any]) -> str:
    ports = sorted(info.get("dst_ports", []))
    return ", ".join(str(port) for port in ports[:10]) if ports else "không rõ"


def format_discord_alert(src_ip: str, info: dict[str, Any]) -> str:
    severity = str(info.get("severity", "MEDIUM"))
    dst_ports = format_target_ports(info)
    top_score = float(info.get("max_score", 0.0))
    return (
        "⚠️ **PHÁT HIỆN HÀNH VI XÂM NHẬP!** ⚠️\n"
        f"🚨 **IP nguồn tấn công:** `{src_ip}`\n"
        f"📊 **Tổng số luồng độc hại:** `{int(info.get('count', 0))}` flows\n"
        f"🔎 **Các cổng mục tiêu:** `{dst_ports}`\n"
        f"🧠 **Điểm AI cao nhất:** `{top_score:.3f}`\n"
        f"🛡️ **Mức độ nghiêm trọng:** **{severity_vi(severity)}**"
    )


def format_telegram_alert(src_ip: str, info: dict[str, Any]) -> str:
    severity = str(info.get("severity", "MEDIUM"))
    dst_ports = format_target_ports(info)
    top_score = float(info.get("max_score", 0.0))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        "🏫 TRƯỜNG CAO ĐẲNG GIAO THÔNG VẬN TẢI TP.HCM\n"
        "🛡️ HỆ THỐNG PHÁT HIỆN XÂM NHẬP LAI (HYBRID-NIDS)\n\n"
        "🚨 CẢNH BÁO AN NINH: PHÁT HIỆN TẤN CÔNG! 🚨\n\n"
        "📌 Đơn vị giám sát: Khoa CNTT\n"
        f"🔴 Mức độ nghiêm trọng: {severity_vi(severity)}\n"
        "🧠 Lõi phân tích AI: Random Forest\n"
        f"🎯 IP nguồn tấn công: {src_ip}\n"
        f"📊 Tổng số luồng độc hại: {int(info.get('count', 0))} flows\n"
        f"🔎 Các cổng dịch vụ bị nhắm mục tiêu: {dst_ports}\n"
        f"📈 Điểm AI cao nhất: {top_score:.3f}\n\n"
        f"🗓️ Mốc thời gian ghi nhận: {timestamp}\n\n"
        "⚠️ KHUYẾN NGHỊ VẬN HÀNH: Kiểm tra nguồn lưu lượng, rà soát tường lửa "
        "và đối chiếu log Suricata để xác minh sự kiện."
    )


def send_telegram_alert_batch(
    aggregated_alerts: dict[str, dict[str, Any]],
    bot_token: str | None,
    chat_id: str | None,
    *,
    disabled: bool,
) -> None:
    if disabled or not bot_token or not chat_id or not aggregated_alerts:
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    for src_ip, info in aggregated_alerts.items():
        payload = {
            "chat_id": chat_id,
            "text": format_telegram_alert(src_ip, info),
            "disable_web_page_preview": True,
        }
        try:
            req = urllib.request.Request(url)
            req.add_header("Content-Type", "application/json; charset=utf-8")
            req.add_header("User-Agent", "Hybrid-NIDS/1.0")
            urllib.request.urlopen(req, json.dumps(payload).encode("utf-8"), timeout=8)
        except Exception as exc:  # noqa: BLE001 - gửi alert lỗi không làm hỏng inference.
            logging.error("Lỗi gửi Telegram: %s", exc)


def severity_from_score(score: float) -> str:
    if score >= 0.95:
        return "CRITICAL"
    if score >= 0.90:
        return "HIGH"
    if score >= 0.80:
        return "MEDIUM"
    return "LOW"


def predict_batch(
    batch_features: pd.DataFrame | list[dict[str, Any]],
    batch_metadata: list[dict[str, Any]],
    pipeline: Any,
    schema: dict,
    metadata: dict,
    threshold: float,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Predict một batch bằng full pipeline và trả về alert chi tiết + alert gom nhóm."""
    if isinstance(batch_features, list) and not batch_features:
        return [], {}
    if isinstance(batch_features, pd.DataFrame) and batch_features.empty:
        return [], {}

    df_batch = pd.DataFrame(batch_features)
    X_batch = prepare_features(df_batch, schema)

    if hasattr(pipeline, "predict_proba"):
        scores = pipeline.predict_proba(X_batch)[:, 1]
        predictions = (scores >= threshold).astype(int)
    else:
        predictions = pipeline.predict(X_batch)
        scores = np.asarray(predictions, dtype=float)

    alerts: list[dict[str, Any]] = []
    aggregated: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "dst_ports": set(), "max_score": 0.0, "severity": "LOW"})
    now = datetime.now(timezone.utc).isoformat()

    for idx, pred in enumerate(predictions):
        if int(pred) != 1:
            continue
        score = float(scores[idx])
        meta = batch_metadata[idx]
        severity = severity_from_score(score)
        # Khi replay PCAP/CSV, giữ timestamp gốc của flow để tương quan đúng với
        # EVE JSON của Suricata. Đường live vẫn rơi về thời điểm suy luận nếu
        # nguồn trích xuất không cung cấp start_utc.
        flow_start_utc = str(meta.get("start_utc") or "").strip()
        event_timestamp = flow_start_utc or now
        alert = {
            "timestamp_utc": event_timestamp,
            "timestamp_source": "flow_start_utc" if flow_start_utc else "inference_utc",
            "src_ip": meta["src_ip"],
            "src_port": meta["src_port"],
            "dst_ip": meta["dst_ip"],
            "dst_port": meta["dst_port"],
            "protocol": meta["protocol"],
            "application_name": meta.get("application_name", ""),
            "action": "ATTACK_DETECTED",
            "attack_score": round(score, 6),
            "threshold": threshold,
            "severity": severity,
        }
        alerts.append(alert)

        bucket = aggregated[str(meta["src_ip"])]
        bucket["count"] += 1
        bucket["dst_ports"].add(int(meta["dst_port"]))
        bucket["max_score"] = max(float(bucket["max_score"]), score)
        if ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(severity) > ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(bucket["severity"]):
            bucket["severity"] = severity

    return alerts, dict(aggregated)


def safe_int(value: Any, default: int = 0) -> int:
    converted = pd.to_numeric(value, errors="coerce")
    if pd.isna(converted):
        return default
    return int(converted)


def safe_text(value: Any, default: str = "") -> str:
    if value is None or pd.isna(value):
        return default
    return str(value)


def metadata_from_dataframe(df: pd.DataFrame) -> list[dict[str, Any]]:
    work = normalize_columns(df)
    result: list[dict[str, Any]] = []
    for _, row in work.iterrows():
        result.append(
            {
                "src_ip": row.get("srcip", row.get("src_ip", "")),
                "src_port": safe_int(row.get("sport", row.get("src_port", 0))),
                "dst_ip": row.get("dstip", row.get("dst_ip", "")),
                "dst_port": safe_int(row.get("dsport", row.get("dst_port", 0))),
                "protocol": safe_text(row.get("proto", row.get("protocol", ""))),
                "application_name": safe_text(row.get("service", "")),
                "start_utc": safe_text(
                    row.get(
                        "start_utc",
                        row.get("timestamp_utc", row.get("@timestamp", "")),
                    )
                ),
                "end_utc": safe_text(row.get("end_utc", "")),
                "session_id": safe_text(row.get("session_id", "")),
            }
        )
    return result


def process_csv_once(
    csv_path: Path,
    pipeline: Any,
    schema: dict,
    metadata: dict,
    threshold: float,
    config: DetectorConfig,
) -> list[dict[str, Any]]:
    """Đọc CSV flow records, predict theo batch/chunk và ghi alert."""
    if not csv_path.exists() or csv_path.stat().st_size <= 0:
        raise FileNotFoundError(f"CSV không tồn tại hoặc rỗng: {csv_path}")

    all_alerts: list[dict[str, Any]] = []
    total_rows = 0
    logging.info("[*] Suy luận flow CSV: %s", csv_path)

    for chunk in pd.read_csv(csv_path, low_memory=False, chunksize=config.batch_size):
        batch_metadata = metadata_from_dataframe(chunk)
        alerts, aggregated = predict_batch(chunk, batch_metadata, pipeline, schema, metadata, threshold)
        all_alerts.extend(alerts)
        write_alerts_to_disk(alerts, config.output_log)
        filtered_for_discord = {
            src_ip: info
            for src_ip, info in aggregated.items()
            if float(info.get("max_score", 0.0)) >= config.min_alert_score_for_discord
        }
        filtered_for_telegram = {
            src_ip: info
            for src_ip, info in aggregated.items()
            if float(info.get("max_score", 0.0)) >= config.min_alert_score_for_telegram
        }
        send_discord_alert_batch(filtered_for_discord, config.webhook_url, disabled=config.disable_discord)
        send_telegram_alert_batch(
            filtered_for_telegram,
            config.telegram_bot_token,
            config.telegram_chat_id,
            disabled=config.disable_telegram,
        )
        total_rows += len(chunk)

    logging.info("[+] Hoàn tất CSV: %s flow, %s alert.", total_rows, len(all_alerts))
    return all_alerts


def write_alerts_to_disk(alerts: Iterable[dict[str, Any]], log_output_path: Path) -> None:
    alerts = list(alerts)
    if not alerts:
        return
    log_output_path.parent.mkdir(parents=True, exist_ok=True)
    with log_output_path.open("a", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert, ensure_ascii=False) + "\n")


def process_pcap_once(
    pcap_path: Path,
    pipeline: Any,
    schema: dict,
    metadata: dict,
    threshold: float,
    config: DetectorConfig,
) -> list[dict[str, Any]]:
    """Đọc một PCAP, predict theo batch, ghi/gửi alert và trả về danh sách alert."""
    if not pcap_path.exists() or pcap_path.stat().st_size <= 0:
        logging.info("PCAP chưa tồn tại hoặc rỗng: %s", pcap_path)
        return []

    required_features = set(schema.get("feature_columns", []))
    extractable_features = set(PCAP_FEATURE_COLUMNS)
    missing_from_extractor = sorted(required_features - extractable_features)
    if missing_from_extractor:
        raise SchemaMismatchError("Schema mismatch ở nhánh PCAP/live: extractor hiện chỉ sinh được "
            f"{len(PCAP_FEATURE_COLUMNS)} feature, nhưng schema/model yêu cầu các feature chưa trích xuất được: "
            f"{missing_from_extractor}. Hãy dùng model/schema RF-21 cho PCAP/live hoặc xây dựng extractor tương ứng."
        )

    NFStreamer = import_nfstream()
    context_window = FlowContextWindow(window_seconds=config.context_window_seconds)
    batch_features: list[dict[str, Any]] = []
    batch_metadata: list[dict[str, Any]] = []
    all_alerts: list[dict[str, Any]] = []
    total_flows = 0

    logging.info("[*] Phân tích PCAP: %s", pcap_path)
    streamer = NFStreamer(source=str(pcap_path), statistical_analysis=True)

    def flush_batch() -> None:
        nonlocal batch_features, batch_metadata, all_alerts
        alerts, aggregated = predict_batch(batch_features, batch_metadata, pipeline, schema, metadata, threshold)
        all_alerts.extend(alerts)
        write_alerts_to_disk(alerts, config.output_log)
        filtered_for_discord = {
            src_ip: info
            for src_ip, info in aggregated.items()
            if float(info.get("max_score", 0.0)) >= config.min_alert_score_for_discord
        }
        filtered_for_telegram = {
            src_ip: info
            for src_ip, info in aggregated.items()
            if float(info.get("max_score", 0.0)) >= config.min_alert_score_for_telegram
        }
        send_discord_alert_batch(filtered_for_discord, config.webhook_url, disabled=config.disable_discord)
        send_telegram_alert_batch(
            filtered_for_telegram,
            config.telegram_bot_token,
            config.telegram_chat_id,
            disabled=config.disable_telegram,
        )
        batch_features = []
        batch_metadata = []

    for flow in streamer:
        batch_features.append(extract_features_from_flow(flow, context_window))
        batch_metadata.append(extract_metadata_from_flow(flow))
        total_flows += 1
        if len(batch_features) >= config.batch_size:
            flush_batch()

    if batch_features:
        flush_batch()

    logging.info("[+] Hoàn tất: %s flow, %s alert.", total_flows, len(all_alerts))
    return all_alerts


def move_failed_pcap(pcap_path: Path, failed_dir: Path) -> None:
    failed_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = failed_dir / f"{pcap_path.stem}_{timestamp}{pcap_path.suffix}"
    try:
        shutil.move(str(pcap_path), str(target))
        logging.error("Đã chuyển PCAP lỗi sang: %s", target)
    except Exception as exc:  # noqa: BLE001
        logging.error("Không thể chuyển PCAP lỗi: %s", exc)


def monitor_loop(config: DetectorConfig, pipeline: Any, schema: dict, metadata: dict, threshold: float) -> None:
    logging.info("[+] NIDS detector đang chạy. once=%s input_csv=%s pcap=%s", config.once, config.input_csv, config.pcap_path)
    if config.input_csv is not None:
        process_csv_once(config.input_csv, pipeline, schema, metadata, threshold, config)
        return

    while True:
        try:
            if config.pcap_path.exists() and config.pcap_path.stat().st_size > 0:
                # Chờ ngắn để tiến trình ghi PCAP có cơ hội đóng file.
                time.sleep(1.0)
                process_pcap_once(config.pcap_path, pipeline, schema, metadata, threshold, config)
                if config.delete_after_success:
                    config.pcap_path.unlink(missing_ok=True)
                    logging.info("Đã xóa PCAP sau xử lý thành công: %s", config.pcap_path)
        except SchemaMismatchError as exc:
            logging.exception("Lỗi cấu hình schema/model cho PCAP/live: %s", exc)
            if config.once:
                raise
        except Exception as exc:  # noqa: BLE001
            logging.exception("Lỗi xử lý PCAP: %s", exc)
            if config.pcap_path.exists():
                move_failed_pcap(config.pcap_path, config.failed_dir)
            if config.once:
                raise
        if config.once:
            break
        time.sleep(config.sleep_seconds)


def main() -> None:
    config = parse_args()
    config.output_log.parent.mkdir(parents=True, exist_ok=True)
    pipeline, schema, metadata, threshold = load_system_artifacts(config)
    monitor_loop(config, pipeline, schema, metadata, threshold)


if __name__ == "__main__":
    main()








