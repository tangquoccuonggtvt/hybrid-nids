"""Forward Hybrid-NIDS fused alerts to Telegram/Discord with rate limiting.

This script tails a JSONL alert file, usually logs/hybrid_alerts.jsonl, and sends
selected alerts to optional channels configured by environment variables:

- DISCORD_NIDS_WEBHOOK
- TELEGRAM_BOT_TOKEN
- TELEGRAM_CHAT_ID

It is intentionally separate from detection/fusion so lab evaluation can run
without spamming external channels.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

HIGH_SEVERITIES = {"CRITICAL", "HIGH"}
DEFAULT_ACTIONS = {"HYBRID_CORRELATED_ALERT", "HYBRID_PLUS_DEMO_ALERT"}

SEVERITY_MAP = {
    "CRITICAL": ("🔴", "KHẨN CẤP (CRITICAL)"),
    "HIGH": ("🟠", "CAO (HIGH)"),
    "MEDIUM": ("🟡", "TRUNG BÌNH (MEDIUM)"),
    "LOW": ("🟢", "THẤP (LOW)"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Forward Hybrid-NIDS alerts to Telegram/Discord.")
    parser.add_argument("--input", type=Path, default=ROOT / "logs" / "hybrid_alerts.jsonl")
    parser.add_argument("--discord-webhook", default=os.getenv("DISCORD_NIDS_WEBHOOK", ""))
    parser.add_argument("--telegram-bot-token", default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--telegram-chat-id", default=os.getenv("TELEGRAM_CHAT_ID", ""))
    parser.add_argument("--cooldown-seconds", type=int, default=int(os.getenv("ALERT_COOLDOWN_SECONDS", "60")))
    parser.add_argument("--min-ai-score", type=float, default=float(os.getenv("ALERT_MIN_AI_SCORE", "0.90")))
    parser.add_argument("--send-ai-only", action="store_true", default=os.getenv("ALERT_SEND_AI_ONLY", "0") == "1")
    parser.add_argument("--send-suricata-only", action="store_true", default=os.getenv("ALERT_SEND_SURICATA_ONLY", "0") == "1")
    parser.add_argument("--start-at-end", action="store_true", help="Start tailing at EOF instead of sending old alerts.")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    return parser.parse_args()


def nested(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = record
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def alert_key(record: dict[str, Any]) -> tuple[str, str, str, str, str]:
    src = str(record.get("src_ip") or nested(record, "source", "ip", default="unknown"))
    dst = str(record.get("dest_ip") or nested(record, "destination", "ip", default="unknown"))
    port = str(record.get("dest_port") or nested(record, "destination", "port", default="unknown"))
    proto = str(record.get("proto") or nested(record, "network", "transport", default="unknown"))
    action = str(record.get("action") or "unknown")
    return action, src, dst, port, proto


def should_send(record: dict[str, Any], args: argparse.Namespace) -> bool:
    action = str(record.get("action") or "")
    severity = str(record.get("severity") or "").upper()
    ai_score_raw = nested(record, "ai", "attack_score", default=record.get("attack_score"))
    try:
        ai_score = float(ai_score_raw)
    except (TypeError, ValueError):
        ai_score = 0.0

    if action in DEFAULT_ACTIONS:
        return True
    if severity in HIGH_SEVERITIES:
        return True
    if action == "AI_ONLY_ALERT" and args.send_ai_only and ai_score >= args.min_ai_score:
        return True
    if action == "SURICATA_ONLY_ALERT" and args.send_suricata_only:
        return True
    return False


def format_telegram(record: dict[str, Any]) -> str:
    """Format canh bao cho Telegram - co header truong, chi tiet day du."""
    action = record.get("action", "UNKNOWN")
    severity = str(record.get("severity", "UNKNOWN")).upper()
    ts = record.get("@timestamp") or record.get("timestamp") or record.get("timestamp_utc") or "unknown"
    src = record.get("src_ip") or nested(record, "source", "ip", default="unknown")
    dst = record.get("dest_ip") or nested(record, "destination", "ip", default="unknown")
    dport = record.get("dest_port") or nested(record, "destination", "port", default="?")
    proto = record.get("proto") or nested(record, "network", "transport", default="?")
    score = nested(record, "ai", "attack_score", default=record.get("attack_score"))
    sig = nested(record, "suricata", "signature", default="")
    total_flows = record.get("total_flows") or record.get("flow_count") or 1
    target_ports = record.get("target_ports") or record.get("dest_ports") or [dport]

    sev_icon, sev_text = SEVERITY_MAP.get(severity, ("⚪", severity))

    # Xac dinh loai phan tich
    if action == "HYBRID_CORRELATED_ALERT":
        ai_layer = "Hybrid (Suricata + Random Forest)"
    elif action == "HYBRID_PLUS_DEMO_ALERT":
        ai_layer = "Hybrid+ Demo (Suricata + ground truth lab; RF chưa xác nhận)"
    elif action == "AI_ONLY_ALERT":
        ai_layer = "Random Forest"
    elif action == "SURICATA_ONLY_ALERT":
        ai_layer = "Suricata (rule-based)"
    else:
        ai_layer = action

    # Format target ports
    if isinstance(target_ports, list):
        ports_str = ", ".join(str(p) for p in target_ports[:8])
    else:
        ports_str = str(target_ports)

    lines = [
        "🛡️ TRƯỜNG CAO ĐẲNG GIAO THÔNG VẬN TẢI TP.HCM",
        "🖥️ HỆ THỐNG PHÁT HIỆN XÂM NHẬP LAI (HYBRID-NIDS)",
        "",
        "🚨 CẢNH BÁO AN NINH: PHÁT HIỆN TẤN CÔNG! 🚨",
        "",
        "✏️ Đơn vị giám sát: Khoa CNTT",
        f"{sev_icon} Mức độ nghiêm trọng: {sev_text}",
        f"🧠 Lớp phân tích AI: {ai_layer}",
        f"🎯 IP nguồn tấn công: {src}",
        f"📊 Tổng số luồng độc hại: {total_flows} flows",
        f"🔍 Các cổng dịch vụ bị nhắm mục tiêu: {ports_str}",
    ]
    if score is not None:
        try:
            lines.append(f"📈 Điểm AI cao nhất: {float(score):.3f}")
        except (TypeError, ValueError):
            lines.append(f"📈 Điểm AI cao nhất: {score}")
    if sig:
        lines.append(f"📝 Suricata signature: {sig}")
    lines.append(f"📅 Mốc thời gian ghi nhận: {ts}")
    lines.append("")
    lines.append("⚠️ KHUYẾN NGHỊ VẬN HÀNH: Kiểm tra nguồn lưu lượng, rà soát tường lửa và đối chiếu log Suricata để xác minh sự kiện.")
    return "\n".join(lines)


def format_discord(record: dict[str, Any]) -> str:
    """Format canh bao cho Discord - dung embed-style voi emoji."""
    action = record.get("action", "UNKNOWN")
    severity = str(record.get("severity", "UNKNOWN")).upper()
    ts = record.get("@timestamp") or record.get("timestamp") or record.get("timestamp_utc") or "unknown"
    src = record.get("src_ip") or nested(record, "source", "ip", default="unknown")
    dst = record.get("dest_ip") or nested(record, "destination", "ip", default="unknown")
    dport = record.get("dest_port") or nested(record, "destination", "port", default="?")
    score = nested(record, "ai", "attack_score", default=record.get("attack_score"))
    sig = nested(record, "suricata", "signature", default="")
    total_flows = record.get("total_flows") or record.get("flow_count") or 1
    target_ports = record.get("target_ports") or record.get("dest_ports") or [dport]

    sev_icon, sev_text = SEVERITY_MAP.get(severity, ("⚪", severity))

    # Xac dinh loai phan tich
    if action == "HYBRID_CORRELATED_ALERT":
        ai_layer = "Hybrid (Suricata + Random Forest)"
    elif action == "HYBRID_PLUS_DEMO_ALERT":
        ai_layer = "Hybrid+ Demo (Suricata + ground truth lab; RF chưa xác nhận)"
    elif action == "AI_ONLY_ALERT":
        ai_layer = "Random Forest"
    elif action == "SURICATA_ONLY_ALERT":
        ai_layer = "Suricata (rule-based)"
    else:
        ai_layer = action

    if isinstance(target_ports, list):
        ports_str = ", ".join(str(p) for p in target_ports[:8])
    else:
        ports_str = str(target_ports)

    lines = [
        "🛡️ **TRƯỜNG CAO ĐẲNG GIAO THÔNG VẬN TẢI TP.HCM**",
        "🖥️ HỆ THỐNG PHÁT HIỆN XÂM NHẬP LAI (HYBRID-NIDS)",
        "",
        "🚨 **CẢNH BÁO AN NINH: PHÁT HIỆN TẤN CÔNG!** 🚨",
        "",
        "✏️ Đơn vị giám sát: Khoa CNTT",
        f"{sev_icon} Mức độ nghiêm trọng: **{sev_text}**",
        f"🧠 Lớp phân tích AI: {ai_layer}",
        f"🎯 IP nguồn tấn công: `{src}`",
        f"📊 Tổng số luồng độc hại: **{total_flows}** flows",
        f"🔍 Các cổng dịch vụ bị nhắm mục tiêu: {ports_str}",
    ]
    if score is not None:
        try:
            lines.append(f"🧬 Điểm AI cao nhất: **{float(score):.3f}**")
        except (TypeError, ValueError):
            lines.append(f"🧬 Điểm AI cao nhất: **{score}**")
    if sig:
        lines.append(f"📝 Suricata: {sig}")
    lines.append(f"📅 Mốc thời gian ghi nhận: {ts}")
    lines.append("")
    lines.append("⚠️ **KHUYẾN NGHỊ:** Kiểm tra nguồn lưu lượng, rà soát tường lửa và đối chiếu log Suricata.")
    return "\n".join(lines)


def format_message(record: dict[str, Any]) -> str:
    """Legacy plain-text fallback (khong dung nua nhung giu lai de tuong thich)."""
    action = record.get("action", "UNKNOWN")
    severity = record.get("severity", "UNKNOWN")
    ts = record.get("@timestamp") or record.get("timestamp") or record.get("timestamp_utc") or "unknown-time"
    src = record.get("src_ip") or nested(record, "source", "ip", default="unknown")
    dst = record.get("dest_ip") or nested(record, "destination", "ip", default="unknown")
    dport = record.get("dest_port") or nested(record, "destination", "port", default="unknown")
    proto = record.get("proto") or nested(record, "network", "transport", default="unknown")
    score = nested(record, "ai", "attack_score", default=record.get("attack_score"))
    sig = nested(record, "suricata", "signature", default="")

    lines = [
        "[Hybrid-NIDS Alert]",
        f"Time: {ts}",
        f"Action: {action}",
        f"Severity: {severity}",
        f"Flow: {src} -> {dst}:{dport}/{proto}",
    ]
    if score is not None:
        lines.append(f"AI score: {score}")
    if sig:
        lines.append(f"Suricata: {sig}")
    return "\n".join(lines)


def send_discord(webhook: str, message: str) -> None:
    if not webhook:
        return
    payload = json.dumps({"content": message}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(webhook, data=payload, headers={
        "Content-Type": "application/json",
        "User-Agent": "Hybrid-NIDS/2.0",
    })
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - user-provided webhook.
        resp.read()


def send_telegram(token: str, chat_id: str, message: str) -> None:
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - official Telegram endpoint.
        resp.read()


def follow_jsonl(path: Path, start_at_end: bool, poll_seconds: float):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with path.open("r", encoding="utf-8") as file:
        if start_at_end:
            file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def main() -> int:
    args = parse_args()
    if not args.discord_webhook and not (args.telegram_bot_token and args.telegram_chat_id):
        print("[!] No Discord/Telegram channel configured. Set env variables first.")
        print("    DISCORD_NIDS_WEBHOOK, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID")

    last_sent: dict[tuple[str, str, str, str, str], float] = {}
    print("[+] Hybrid-NIDS multi-channel alert forwarder")
    print(f"[+] Input: {args.input}")
    print(f"[+] Cooldown: {args.cooldown_seconds}s")
    print(f"[+] Discord: {'configured' if args.discord_webhook else 'not set'}")
    print(f"[+] Telegram: {'configured' if args.telegram_bot_token else 'not set'}")

    for record in follow_jsonl(args.input, args.start_at_end, args.poll_seconds):
        if not should_send(record, args):
            continue
        key = alert_key(record)
        now = time.time()
        if now - last_sent.get(key, 0) < args.cooldown_seconds:
            continue
        try:
            # Telegram: format chi tiet co header truong
            tg_msg = format_telegram(record)
            send_telegram(args.telegram_bot_token, args.telegram_chat_id, tg_msg)

            # Discord: format compact voi markdown bold
            dc_msg = format_discord(record)
            send_discord(args.discord_webhook, dc_msg)

            last_sent[key] = now
            print(f"[+] Sent alert: {key}")
        except Exception as exc:  # noqa: BLE001 - forwarding must not stop detection.
            print(f"[!] Send failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
