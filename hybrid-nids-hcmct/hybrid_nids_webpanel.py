#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 HYBRID-NIDS WEB CONTROL PANEL  (v2 - full features)
============================================================================
Bang dieu khien do hoa (web) cho may NIDS Ubuntu.

TINH NANG:
  DIEU KHIEN
    - Start / Stop / Restart toan bo he thong (Suricata + RF-21 + Fusion + Alert)
    - Bat / Tat day canh bao Telegram + Discord
    - Gui thu canh bao (kiem tra ket noi)
    - Mo Kibana
  GIAM SAT
    - Trang thai 4 dich vu (tu cap nhat 5s)
    - Bang canh bao realtime tu hybrid_alerts.jsonl (to mau theo muc do)
    - Bieu do so canh bao theo thoi gian (SVG thuan, khong can internet)
    - Bo loc canh bao theo muc do / IP / loai
  MO HINH (cho demo bao ve de an)
    - Model Card: Accuracy, Precision, Recall, F1, FPR, ROC-AUC... (models/metrics.json)
  PHIEN DEMO
    - Bat dau / Ket thuc phien: danh dau moc thoi gian, dem canh bao trong phien
    - Xuat bao cao phien (trang in duoc -> luu PDF)
  VAN HANH THAT
    - Suc khoe may: CPU / RAM / Disk (doc /proc, os.statvfs - thu vien chuan)
    - Xem + Sua cau hinh .env ngay tren web (secret duoc che)
  BAO MAT
    - Dang nhap HTTP Basic Auth (bat bang PANEL_USER + PANEL_PASS)

Chinh sach canh bao: day HYBRID_CORRELATED_ALERT, HYBRID_PLUS_DEMO_ALERT
trong phien lab co nhan, va moi canh bao CRITICAL/HIGH ra Telegram/Discord.

Cach chay:
    python3 hybrid_nids_webpanel.py
    python3 hybrid_nids_webpanel.py --host 0.0.0.0 --port 8080
    PANEL_USER=admin PANEL_PASS=matkhau python3 hybrid_nids_webpanel.py   # bat dang nhap
============================================================================
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import hmac
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import secrets
import hashlib
from http.cookies import SimpleCookie

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
CONTROL_SCRIPT = SCRIPTS / "nids_system_control.sh"
LOG_DIR = ROOT / "logs"
MODELS_DIR = ROOT / "models"
FUSED_ALERT_LOG = Path(os.getenv("FUSED_ALERT_LOG", str(LOG_DIR / "hybrid_alerts.jsonl")))
ENV_FILE = Path(os.getenv("ENV_FILE", str(ROOT / "deployment" / "hybrid-nids.env")))
METRICS_FILE = MODELS_DIR / "metrics.json"
STREAMING_METRICS_FILE = Path(
    os.getenv("STREAMING_METRICS_FILE", str(LOG_DIR / "streaming_metrics.json"))
)

DEFAULT_KIBANA_PORT = os.getenv("KIBANA_PORT", "5601")
DEFAULT_ES_INDEX_PATTERN = os.getenv(
    "ES_INDEX_PATTERN",
    "hybrid-nids-alerts-*",
)

HIGH_SEVERITIES = {"CRITICAL", "HIGH"}
FORWARD_ACTIONS = {"HYBRID_CORRELATED_ALERT", "HYBRID_PLUS_DEMO_ALERT"}
SENSITIVE_KEYS = {"TELEGRAM_BOT_TOKEN", "DISCORD_NIDS_WEBHOOK", "ES_PASSWORD", "TELEGRAM_CHAT_ID"}
# Cac khoa .env cho phep sua tu giao dien (khong cho sua secret/path he thong tuy tien)
EDITABLE_KEYS = [
    "NIDS_INTERFACE", "NIDS_IP", "HOME_NET", "KIBANA_URL",
    "ALERT_CHANNELS_ENABLED", "ALERT_COOLDOWN_SECONDS", "ALERT_MIN_AI_SCORE",
    "HYBRID_FUSION_WINDOW_SECONDS",
]

# Bao mat: neu dat PANEL_USER + PANEL_PASS thi bat dang nhap
# Doc PANEL_USER/PASS tu .env file hoac OS env
def _read_panel_auth():
    p = Path(os.getenv("ENV_FILE", str(Path(__file__).resolve().parent / "deployment" / "hybrid-nids.env")))
    if p.exists():
        d = {}
        for raw in p.read_text(encoding="utf-8", errors="replace").replace("\r", "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
        return d.get("PANEL_USER", ""), d.get("PANEL_PASS", "")
    return "", ""
_pu, _pp = _read_panel_auth()
PANEL_USER = os.getenv("PANEL_USER", "") or _pu
PANEL_PASS = os.getenv("PANEL_PASS", "") or _pp

# Phien demo (luu trong bo nho tien trinh)
SESSION = {"active": False, "started_at": None, "label": "", "operator": ""}

# --- Danh sach tai khoan quan tri ---
# Khong hardcode mat khau trong ma nguon. Tai khoan mac dinh dung PANEL_USER/PANEL_PASS.
# Neu can tai khoan phu khi demo, khai bao qua bien moi truong PANEL_PASS_CUONG/PANEL_PASS_LAM/PANEL_PASS_HUY.
USERS = {
    "admin": {"password": PANEL_PASS, "name": "Quản trị viên"},
    "cuong": {"password": os.getenv("PANEL_PASS_CUONG"), "name": "Tăng Quốc Cường"},
    "lam": {"password": os.getenv("PANEL_PASS_LAM"), "name": "Huỳnh Hoàng Lam"},
    "huy": {"password": os.getenv("PANEL_PASS_HUY"), "name": "Nguyễn Hữu Hoàng Huy"},
}


def expected_password_for(username: str) -> str | None:
    """Tra ve mat khau da cau hinh cho user; None nghia la user bi tat."""
    if username == PANEL_USER:
        return PANEL_PASS
    info = USERS.get(username)
    if not info:
        return None
    pw = info.get("password")
    return str(pw) if pw else None

# --- Session store (token -> username) ---
ACTIVE_SESSIONS: dict[str, str] = {}

# --- Audit Log (nhat ky hanh dong) ---
AUDIT_LOG: list[dict] = []  # [{timestamp, user, action, detail}]

def audit(user: str, action: str, detail: str = ""):
    """Ghi nhat ky hanh dong."""
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "user": user, "action": action, "detail": detail}
    AUDIT_LOG.append(entry)
    if len(AUDIT_LOG) > 500:
        AUDIT_LOG.pop(0)

# --- Session History (lich su phien giam sat) ---
SESSION_HISTORY: list[dict] = []  # [{started_at, ended_at, operator, label, alert_count}]
HEALTH_HISTORY: deque[dict[str, Any]] = deque(maxlen=180)

# --- Whitelist / Blacklist ---
WHITELIST: set[str] = set()
BLACKLIST: set[str] = set()

def load_ip_lists():
    """Load whitelist/blacklist tu file."""
    wl_path = LOG_DIR / "whitelist.txt"
    bl_path = LOG_DIR / "blacklist.txt"
    if wl_path.exists():
        WHITELIST.update(l.strip() for l in wl_path.read_text().splitlines() if l.strip())
    if bl_path.exists():
        BLACKLIST.update(l.strip() for l in bl_path.read_text().splitlines() if l.strip())

def save_ip_lists():
    """Luu whitelist/blacklist ra file."""
    wl_path = LOG_DIR / "whitelist.txt"
    bl_path = LOG_DIR / "blacklist.txt"
    wl_path.write_text("\n".join(sorted(WHITELIST)) + "\n")
    bl_path.write_text("\n".join(sorted(BLACKLIST)) + "\n")


# --- Elasticsearch query helper ---
def es_query(index_pattern: str, query_body: dict, size: int = 0) -> dict | None:
    """Query Elasticsearch. Returns parsed JSON or None on error."""
    env = load_env_file(ENV_FILE)
    es_url = env.get("ES_URL", "http://127.0.0.1:9200")
    es_user = env.get("ES_USER", "elastic")
    es_pass = env.get("ES_PASSWORD", env.get("ELASTIC_PASSWORD", ""))
    url = f"{es_url}/{index_pattern}/_search"
    payload = json.dumps({**query_body, "size": size}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    if es_user and es_pass:
        import base64 as _b64
        cred = _b64.b64encode(f"{es_user}:{es_pass}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _es_hit_count(resp: dict | None) -> int:
    if not resp:
        return 0
    total = resp.get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        return int(total.get("value", 0) or 0)
    return int(total or 0)


def _es_count_range(index_pattern: str, gte: str, report_time_zone: str) -> int:
    return _es_count_range_field(index_pattern, "@timestamp", gte, report_time_zone)


def _es_count_range_field(index_pattern: str, field: str, gte: str, report_time_zone: str) -> int:
    query = {
        "query": {
            "range": {
                field: {
                    "gte": gte,
                    "lte": "now",
                    "time_zone": report_time_zone,
                }
            }
        },
        "track_total_hits": True,
    }
    return _es_hit_count(es_query(index_pattern, query, size=0))


def _parse_es_datetime(value: Any) -> datetime | None:
    """Parse Elasticsearch date fields to UTC datetime for local dashboard counts."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1_000_000_000_000:
            ts = ts / 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            return None

    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def es_dashboard_summary() -> dict | None:
    """Get alert counts from Elasticsearch using the same index pattern as Kibana."""
    env = load_env_file(ENV_FILE)
    index_pattern = env.get("ES_INDEX_PATTERN") or DEFAULT_ES_INDEX_PATTERN
    report_time_zone = env.get("REPORT_TIME_ZONE", "+07:00")
    result = {
        "today": 0,
        "week": 0,
        "month": 0,
        "total": 0,
        "top_ips": [],
        "severity": {},
        "source": "elasticsearch",
        "index_pattern": index_pattern,
        "window_note": "24h/7d/30d tinh theo @timestamp cua Elasticsearch; tu doi chieu timestamp_utc khi can.",
    }

    # Dem tat ca document canh bao trong index Hybrid, khong loc attack_score.
    # Suricata-only alert khong co top-level attack_score nen neu loc field nay se lech Kibana.
    q_total = {"query": {"match_all": {}}, "track_total_hits": True}
    resp = es_query(index_pattern, q_total, size=0)
    if not resp:
        return None  # ES unavailable, fallback to file
    result["total"] = _es_hit_count(resp)

    # Dem cua so thoi gian bang Elasticsearch truoc de khop voi Kibana.
    result["today"] = _es_count_range(index_pattern, "now-24h", report_time_zone)
    result["week"] = _es_count_range(index_pattern, "now-7d", report_time_zone)
    result["month"] = _es_count_range(index_pattern, "now-30d", report_time_zone)
    if result["total"] and result["today"] == result["week"] == result["month"] == 0:
        # Mot so pipeline cu co the dung timestamp_utc thay vi @timestamp.
        result["today"] = _es_count_range_field(index_pattern, "timestamp_utc", "now-24h", report_time_zone)
        result["week"] = _es_count_range_field(index_pattern, "timestamp_utc", "now-7d", report_time_zone)
        result["month"] = _es_count_range_field(index_pattern, "timestamp_utc", "now-30d", report_time_zone)

    # Lay document trong 30 ngay de tinh top IP/muc do. Neu khong co cua so thoi gian,
    # fallback sang match_all de van hien du lieu tong quan thay vi de trong.
    q_docs = {
        "query": {"range": {"@timestamp": {"gte": "now-30d", "lte": "now", "time_zone": report_time_zone}}},
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "src_ip", "source_ip", "source", "severity", "action",
            "@timestamp", "timestamp_utc"
        ],
    }
    docs_resp = es_query(index_pattern, q_docs, size=20000)
    if result["total"] and _es_hit_count(docs_resp) == 0:
        q_docs["query"] = {"range": {"timestamp_utc": {"gte": "now-30d", "lte": "now", "time_zone": report_time_zone}}}
        docs_resp = es_query(index_pattern, q_docs, size=20000)
    if result["total"] and _es_hit_count(docs_resp) == 0:
        q_docs["query"] = {"match_all": {}}
        docs_resp = es_query(index_pattern, q_docs, size=20000)

    src_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    now_utc = datetime.now(timezone.utc)
    cut_24h = now_utc - timedelta(hours=24)
    cut_7d = now_utc - timedelta(days=7)
    cut_30d = now_utc - timedelta(days=30)
    seen_timestamps = 0
    local_today = 0
    local_week = 0
    local_month = 0

    for hit in docs_resp.get("hits", {}).get("hits", []) if docs_resp else []:
        src = hit.get("_source", {}) or {}
        src_ip = src.get("src_ip") or src.get("source_ip")
        if not src_ip and isinstance(src.get("source"), dict):
            src_ip = src["source"].get("ip")
        severity = str(src.get("severity") or "").upper()
        if src_ip:
            src_counts[str(src_ip)] += 1
        if severity:
            severity_counts[severity] += 1

        ts = _parse_es_datetime(src.get("@timestamp") or src.get("timestamp_utc"))
        if not ts:
            continue
        seen_timestamps += 1
        if ts >= cut_24h:
            local_today += 1
        if ts >= cut_7d:
            local_week += 1
        if ts >= cut_30d:
            local_month += 1
        else:
            if result["month"]:
                continue

    if seen_timestamps:
        # Doi chieu lai bang timestamp doc truc tiep tu document. Cach nay giup web panel
        # khong bi hien 0 neu Elasticsearch range query bi lech mapping/timezone so voi Kibana.
        result["today"] = max(result["today"], local_today)
        result["week"] = max(result["week"], local_week, result["today"])
        result["month"] = max(result["month"], local_month, result["week"])

    result["top_ips"] = [
        {"ip": ip, "count": count}
        for ip, count in src_counts.most_common(5)
    ]
    result["severity"] = dict(severity_counts)
    result["sample_size"] = len(docs_resp.get("hits", {}).get("hits", [])) if docs_resp else 0

    return result


def es_alert_trend_24h() -> list[dict]:
    """Get hourly alert counts for last 24h from ES."""
    env = load_env_file(ENV_FILE)
    report_time_zone = env.get("REPORT_TIME_ZONE", "+07:00")
    q = {
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "hourly": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "time_zone": report_time_zone,
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": "now-23h/h",
                        "max": "now/h"
                    }
                }
            }
        }
    }
    index_pattern = env.get("ES_INDEX_PATTERN") or DEFAULT_ES_INDEX_PATTERN
    resp = es_query(index_pattern, q, size=0)
    if not resp:
        return None
    buckets = resp.get("aggregations", {}).get("hourly", {}).get("buckets", [])
    return [
        {
            "hour": str(bucket.get("key_as_string", ""))[11:16],
            "count": int(bucket.get("doc_count", 0)),
        }
        for bucket in buckets
    ]


LOGIN_HTML = """<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Đăng nhập - Hybrid-NIDS</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:linear-gradient(135deg,#0B192C 0%,#1b3a5c 50%,#0f2744 100%);
     font-family:'Segoe UI',system-ui,-apple-system,sans-serif}
.login-card{background:#fff;border-radius:16px;padding:48px 40px;width:380px;
            box-shadow:0 20px 60px rgba(0,0,0,.3);text-align:center}
.logo-wrap{margin-bottom:24px}
.logo-wrap svg{width:64px;height:64px}
.title{font-size:22px;font-weight:900;color:#0B192C;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.subtitle{font-size:16px;color:#1f2937;margin-bottom:6px;font-weight:700}
.subtitle2{font-size:15px;color:#4b5563;margin-bottom:28px;font-weight:600}
.field{margin-bottom:16px;text-align:left}
.field label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px;text-transform:uppercase;letter-spacing:.3px}
.field input{width:100%;padding:12px 14px;border:1.5px solid #d1d5db;border-radius:10px;font-size:15px;
             outline:none;transition:border-color .2s}
.field input:focus{border-color:#1d4ed8;box-shadow:0 0 0 3px rgba(29,78,216,.1)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#0B192C,#1d4ed8);color:#fff;
     border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;
     margin-top:8px;transition:opacity .2s;text-transform:uppercase;letter-spacing:.5px}
.btn:hover{opacity:.9}
.btn:active{transform:translateY(1px)}
.err{color:#dc2626;font-size:13px;margin-top:12px;min-height:18px}
.footer{margin-top:24px;font-size:11px;color:#9ca3af}
</style></head><body>
<div class="login-card">
  <div class="logo-wrap">
    <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z" fill="#0B192C"/>
      <path d="M32 8l-20 10v14c0 12.2 8.6 23.6 20 27.2 11.4-3.6 20-15 20-27.2V18L32 8z" fill="#1d4ed8" opacity=".3"/>
      <circle cx="32" cy="28" r="4" fill="#fff"/><circle cx="22" cy="36" r="3" fill="#fff" opacity=".7"/>
      <circle cx="42" cy="36" r="3" fill="#fff" opacity=".7"/><circle cx="32" cy="44" r="3" fill="#fff" opacity=".7"/>
      <line x1="32" y1="32" x2="22" y2="36" stroke="#fff" stroke-width="1.5" opacity=".5"/>
      <line x1="32" y1="32" x2="42" y2="36" stroke="#fff" stroke-width="1.5" opacity=".5"/>
      <line x1="32" y1="32" x2="32" y2="44" stroke="#fff" stroke-width="1.5" opacity=".5"/>
    </svg>
  </div>
  <div class="title">Hệ thống Hybrid-NIDS</div>
  <div class="subtitle">Trường Cao đẳng GTVT TP.HCM</div>
  <div class="subtitle2">Bảng điều khiển giám sát</div>
  <form method="POST" action="/login">
    <div class="field"><label>Tài khoản</label><input type="text" name="username" autocomplete="username" autofocus required></div>
    <div class="field"><label>Mật khẩu</label><input type="password" name="password" autocomplete="current-password" required></div>
    <button type="submit" class="btn">Đăng nhập</button>
    <div class="err" id="err">__ERR__</div>
  </form>
  <div class="footer">Hybrid-NIDS v2.0 &middot; Suricata + Random Forest</div>
</div>
</body></html>"""



# --------------------------------------------------------------------------
# Tien ich chung
# --------------------------------------------------------------------------
def utc_now() -> str:
    """Giờ local có timezone offset (khớp timestamp Suricata eve.json)."""
    return datetime.now().astimezone().isoformat()


def normalize_session_label(value: Any) -> str:
    """Chuẩn hóa tên phiên để dùng an toàn trên giao diện và tiêu đề báo cáo."""
    label = " ".join(str(value or "").replace("\x00", "").split())
    if not label:
        label = datetime.now().astimezone().strftime("Demo Hybrid-NIDS %d-%m-%Y %H-%M-%S")
    return label[:100]


def load_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").replace('\r', '').splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip()
    except Exception:
        pass
    return data


def save_env_file(path, data: dict):
    """Ghi lai file .env."""
    try:
        lines = []
        # Doc file goc, chi thay doi gia tri da co
        orig_path = Path(path)
        if orig_path.exists():
            for line in orig_path.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("#") or "=" not in line:
                    lines.append(line)
                else:
                    key, _, _ = line.partition("=")
                    k = key.strip()
                    if k in data:
                        lines.append(f"{k}={data[k]}")
                    else:
                        lines.append(line)
        else:
            for k, v in data.items():
                lines.append(f"{k}={v}")
        orig_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "\u2022" * len(value)
    return value[:4] + "\u2022" * (len(value) - 8) + value[-4:]


def is_using_control_script() -> bool:
    return CONTROL_SCRIPT.exists() and os.name != "nt"


def run_control(action: str, timeout: int = 120) -> dict[str, Any]:
    if not is_using_control_script():
        return {
            "ok": False, "action": action,
            "output": ("Khong tim thay scripts/nids_system_control.sh hoac dang chay tren "
                       "Windows. Panel dieu khien chi hoat dong day du tren may NIDS Ubuntu."),
        }
    env = os.environ.copy()
    env.update(load_env_file(ENV_FILE))
    env.setdefault("ALERT_SEND_AI_ONLY", "0")
    env["ALERT_SEND_SURICATA_ONLY"] = "0"
    env.setdefault("ALERT_CHANNELS_ENABLED", "1")
    try:
        proc = subprocess.run(["bash", str(CONTROL_SCRIPT), action],
                              capture_output=True, text=True, timeout=timeout,
                              env=env, cwd=str(ROOT))
        out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        return {"ok": proc.returncode == 0, "action": action, "output": out.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "action": action, "output": f"Qua thoi gian cho ({timeout}s)."}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "action": action, "output": f"Loi: {exc}"}


LAB_EVAL_SCRIPT = SCRIPTS / "run_lab_eval.sh"
LAB_EVAL_MD = LOG_DIR / "hybrid_labeled_metrics.md"




# ============================================================
# PLAN B: Đánh giá live từ dữ liệu phiên hiện tại
# ============================================================

def _parse_ts(s: str):
    """Parse ISO timestamp, ho tro ca format +0700 va +07:00 va Z."""
    import re as _re
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    s = _re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', s)
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

KALI_IP = os.getenv("KALI_IP", "192.168.10.101")
EVE_JSON = Path(os.getenv("EVE_JSON", "/var/log/suricata/eve.json"))
AI_ALERTS_LOG = LOG_DIR / "ai_alerts.jsonl"

def run_live_eval(session_start: str = "", session_end: str = "") -> dict[str, Any]:
    """Đánh giá Hybrid LIVE dựa trên dữ liệu phiên hiện tại.

    Thay vì đọc file PCAP/flow cũ, function này:
    1. Đọc eve.json (dùng subprocess sudo nếu cần) → trích flow + alert trong phiên
    2. Đọc ai_alerts.jsonl → alert AI trong khung thời gian
    3. Ground truth: src_ip == KALI_IP → attack
    4. Tính metrics 3 nhánh: Suricata / RF / Hybrid (correlated)
    """
    import json as _json
    from datetime import datetime, timezone, timedelta

    # Xác định khung thời gian phiên
    if not session_start:
        session_start = SESSION.get("started_at", "")
    if not session_end:
        if SESSION_HISTORY:
            session_end = SESSION_HISTORY[-1].get("ended_at", "")
        if not session_end:
            session_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not session_start:
        return {"ok": False, "output": "Chưa có phiên nào được bắt đầu. Hãy bấm 'Bắt đầu phiên' trước."}

    # Parse thời gian
    def parse_iso(s):
        r = _parse_ts(s)
        return r if r else (datetime.now(timezone.utc) - timedelta(hours=1))

    t_start = parse_iso(session_start)
    t_end = parse_iso(session_end)
    t_start_ext = t_start - timedelta(seconds=10)
    t_end_ext = t_end + timedelta(seconds=30)

    # === 1. Đọc eve.json: dùng subprocess sudo để tránh permission denied ===
    EventKey = tuple  # (src_ip, dst_ip, dst_port, proto)
    all_flows: set = set()
    suricata_alert_keys: set = set()

    try:
        eve_path = EVE_JSON
        if not eve_path.exists():
            return {"ok": False, "output": f"Không tìm thấy {eve_path}"}

        # Thử đọc trực tiếp, nếu permission denied thì dùng sudo
        raw = ""
        try:
            file_size = eve_path.stat().st_size
            read_bytes = min(file_size, 50 * 1024 * 1024)
            with eve_path.open("rb") as fh:
                fh.seek(max(0, file_size - read_bytes))
                if file_size > read_bytes:
                    fh.readline()
                raw = fh.read().decode("utf-8", errors="replace")
        except PermissionError:
            # Dùng sudo tail để đọc
            try:
                proc = subprocess.run(
                    ["sudo", "-n", "tail", "-c", "52428800", str(eve_path)],
                    capture_output=True, text=True, timeout=30)
                raw = proc.stdout or ""
            except Exception as e2:
                return {"ok": False, "output": f"Không đọc được eve.json (cần quyền): {e2}"}

        if not raw:
            return {"ok": False, "output": "eve.json trống hoặc không đọc được."}

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except Exception:
                continue

            ts_str = obj.get("timestamp", "")
            if not ts_str:
                continue
            ts = _parse_ts(ts_str)
            if ts is None:
                continue

            if ts < t_start_ext or ts > t_end_ext:
                continue

            event_type = obj.get("event_type", "")
            src = obj.get("src_ip", "")
            dst = obj.get("dest_ip", "")
            dport = obj.get("dest_port", 0)
            proto = (obj.get("proto", "") or "").upper()

            if not src or not dst:
                continue

            key = (src, dst, int(dport) if dport else 0, proto)

            if event_type != "stats":
                all_flows.add(key)

            if event_type == "alert":
                suricata_alert_keys.add(key)

    except Exception as exc:
        return {"ok": False, "output": f"Lỗi đọc eve.json: {exc}"}

    # === 2. Đọc ai_alerts.jsonl ===
    ai_alert_keys: set = set()
    try:
        ai_path = AI_ALERTS_LOG
        if ai_path.exists():
            raw_ai = ""
            try:
                file_size = ai_path.stat().st_size
                read_bytes = min(file_size, 20 * 1024 * 1024)
                with ai_path.open("rb") as fh:
                    fh.seek(max(0, file_size - read_bytes))
                    if file_size > read_bytes:
                        fh.readline()
                    raw_ai = fh.read().decode("utf-8", errors="replace")
            except PermissionError:
                try:
                    proc = subprocess.run(
                        ["sudo", "-n", "tail", "-c", "20971520", str(ai_path)],
                        capture_output=True, text=True, timeout=30)
                    raw_ai = proc.stdout or ""
                except Exception:
                    pass

            for line in raw_ai.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except Exception:
                    continue

                ts_str = obj.get("timestamp", "") or obj.get("detected_at", "")
                if ts_str:
                    ts = _parse_ts(ts_str)
                    if ts is not None:
                        if ts < t_start_ext or ts > t_end_ext:
                            continue

                src = obj.get("src_ip", "") or obj.get("srcip", "")
                dst = obj.get("dst_ip", "") or obj.get("dstip", "")
                dport = obj.get("dst_port", 0) or obj.get("dsport", 0)
                proto = (obj.get("proto", "") or obj.get("protocol", "") or "").upper()
                if src and dst:
                    ai_alert_keys.add((src, dst, int(dport) if dport else 0, proto))
    except Exception:
        pass

    # === 3. Hybrid correlated = Suricata AND AI cùng key ===
    hybrid_keys = suricata_alert_keys & ai_alert_keys

    # === 4. Ground truth: src_ip == KALI_IP → attack ===
    labels: dict = {}
    for key in all_flows:
        src_ip = key[0]
        if src_ip == KALI_IP:
            labels[key] = "attack"
        else:
            labels[key] = "normal"

    n_attack = sum(1 for v in labels.values() if v == "attack")
    n_normal = sum(1 for v in labels.values() if v == "normal")

    if len(labels) == 0:
        return {"ok": False, "output": "Không tìm thấy flow nào trong khung thời gian phiên. Kiểm tra: 1) Suricata đang chạy trên ens18, 2) Đã chạy attack từ Kali trước khi kết thúc phiên."}

    # === 5. Tính metrics ===
    def calc_metrics(alert_keys: set, all_labels: dict) -> dict:
        tp = fp = fn = tn = 0
        for key, label in all_labels.items():
            predicted = key in alert_keys
            if label == "attack":
                if predicted:
                    tp += 1
                else:
                    fn += 1
            else:
                if predicted:
                    fp += 1
                else:
                    tn += 1
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                "Precision": precision, "Recall": recall, "F1": f1, "FPR": fpr}

    suri_in_scope = suricata_alert_keys & set(labels.keys())
    ai_in_scope = ai_alert_keys & set(labels.keys())
    hybrid_in_scope = hybrid_keys & set(labels.keys())

    results = {
        "Suricata (rule-only)": calc_metrics(suri_in_scope, labels),
        "Random Forest (ML-only, live)": calc_metrics(ai_in_scope, labels),
        "Hybrid (CORRELATED)": calc_metrics(hybrid_in_scope, labels),
    }

    # === 6. Tạo bảng markdown ===
    md_lines = []
    md_lines.append("### Đánh giá có nhãn trên tấn công lab tự sinh\n")
    md_lines.append(f"- Tổng sự kiện: **{len(labels)}** (attack: **{n_attack}**, normal: **{n_normal}**)")
    md_lines.append(f"- Phiên: {session_start} → {session_end}")
    md_lines.append(f"- Kali IP (ground truth attack): {KALI_IP}\n")
    md_lines.append("| Nhánh | TP | FP | FN | TN | Precision | Recall | F1 | FPR |")
    md_lines.append("|-------|---:|---:|---:|---:|:---------:|:------:|:--:|:---:|")
    for branch, m in results.items():
        tp, fp, fn, tn = m["TP"], m["FP"], m["FN"], m["TN"]
        prec, rec, f1v, fpr = m["Precision"], m["Recall"], m["F1"], m["FPR"]
        md_lines.append(
            f"| {branch} | {tp} | {fp} | {fn} | {tn} "
            f"| {prec:.4f} | {rec:.4f} | {f1v:.4f} | {fpr:.4f} |"
        )
    md_lines.append("")
    md_lines.append("> Đơn vị: sự kiện (src_ip, dst_ip, dst_port, proto). "
                    "Nhãn ground truth: mọi flow có src_ip = Kali IP là attack. "
                    "Đây là đánh giá tương đối giữa ba nhánh trên lưu lượng live trong phiên.")

    md_text = "\n".join(md_lines)

    # Lưu ra file
    try:
        out_path = LOG_DIR / "hybrid_labeled_metrics.md"
        out_path.write_text(md_text, encoding="utf-8")
    except Exception:
        pass

    return {"ok": True, "output": md_text, "metrics": results,
            "total_events": len(labels), "attack": n_attack, "normal": n_normal}



def run_lab_eval(timeout: int = 900) -> dict[str, Any]:
    """Chay danh gia Hybrid CO NHAN 3 nhanh (scripts/run_lab_eval.sh).

    Sinh logs/hybrid_labeled_metrics.md — bang Recall/FPR/F1 cua Suricata /
    Random Forest / Hybrid. Day la bang dinh luong chung minh co che lai.
    """
    if os.name == "nt" or not LAB_EVAL_SCRIPT.exists():
        return {
            "ok": False,
            "output": ("Khong tim thay scripts/run_lab_eval.sh hoac dang chay tren Windows. "
                       "Danh gia co nhan chi chay tren may NIDS Ubuntu sau khi da co "
                       "PCAP, eve.json va labeling/attack_windows.csv."),
        }
    env = os.environ.copy()
    env.update(load_env_file(ENV_FILE))
    try:
        proc = subprocess.run(["bash", str(LAB_EVAL_SCRIPT)],
                              capture_output=True, text=True, timeout=timeout,
                              env=env, cwd=str(ROOT))
        out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        return {"ok": proc.returncode == 0, "output": out.strip()[-8000:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"Qua thoi gian cho ({timeout}s). Kiem tra lai dau vao."}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "output": f"Loi: {exc}"}


def read_lab_eval_md() -> str:
    """Doc bang ket qua danh gia co nhan (neu da chay)."""
    if not LAB_EVAL_MD.exists():
        return ""
    try:
        return LAB_EVAL_MD.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def tail_jsonl(path: Path, limit: int = 200) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, 1024 * 1024)
            fh.seek(size - block)
            chunk = fh.read().decode("utf-8", errors="replace")
        lines = [ln for ln in chunk.splitlines() if ln.strip()]
        records: list[dict[str, Any]] = []
        for ln in lines[-limit:]:
            try:
                records.append(json.loads(ln))
            except Exception:
                continue
        records.reverse()
        return records
    except Exception:
        return []


def nested(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = record
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return default if cur is None else cur


def parse_ts(ts: str) -> float | None:
    if not ts:
        return None
    try:
        clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except Exception:
        return None


def normalize_alert(rec: dict[str, Any]) -> dict[str, Any]:
    action = str(rec.get("action") or "")
    severity = str(rec.get("severity") or "").upper()
    src = str(rec.get("src_ip") or nested(rec, "source", "ip", default="?"))
    dst = str(rec.get("dest_ip") or rec.get("dst_ip") or nested(rec, "destination", "ip", default="?"))
    port = str(rec.get("dest_port") or rec.get("dst_port") or nested(rec, "destination", "port", default="?"))
    proto = str(rec.get("proto") or rec.get("protocol") or nested(rec, "network", "transport", default="?"))
    ts = str(rec.get("timestamp_utc") or rec.get("timestamp") or rec.get("@timestamp") or "")
    score = nested(rec, "ai", "attack_score", default=rec.get("attack_score"))
    try:
        score = round(float(score), 4)
    except (TypeError, ValueError):
        score = None
    category = str(rec.get("attack_category") or rec.get("signature") or nested(rec, "alert", "signature", default="") or "")
    forwarded = action in FORWARD_ACTIONS or severity in HIGH_SEVERITIES
    return {"timestamp": ts, "epoch": parse_ts(ts), "action": action or "-",
            "severity": severity or "-", "src": src, "dst": dst, "port": port,
            "proto": proto, "score": score, "category": category, "forwarded": forwarded}


def send_test_telegram(token: str, chat_id: str, text: str) -> tuple[bool, str]:
    token = token.strip().rstrip('\r\n')
    chat_id = chat_id.strip().rstrip('\r\n')
    if not token or not chat_id:
        return False, "Thieu TELEGRAM_BOT_TOKEN hoac TELEGRAM_CHAT_ID"
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
        with urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=15) as resp:
            return (200 <= resp.status < 300), f"Telegram HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Telegram loi: {exc}"


def send_test_discord(webhook: str, text: str) -> tuple[bool, str]:
    webhook = webhook.strip().rstrip('\r\n')
    if not webhook:
        return False, "Thieu DISCORD_NIDS_WEBHOOK"
    try:
        payload = json.dumps({"content": text}).encode()
        req = urllib.request.Request(webhook, data=payload, headers={
            "Content-Type": "application/json",
            "User-Agent": "Hybrid-NIDS/2.0",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return (200 <= resp.status < 300), f"Discord HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Discord loi: {exc}"


def read_system_health() -> dict[str, Any]:
    """Doc CPU/RAM/Disk bang thu vien chuan (Linux). An toan tren moi OS."""
    health: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": None,
        "mem_percent": None,
        "disk_percent": None,
        "disk_free_gb": None,
        "loadavg": None,
        "packet_drop_total": None,
        "inference_latency_ms_per_flow": None,
        "throughput_flows_per_second": None,
    }
    # Load average (Linux/Mac)
    try:
        la = os.getloadavg()
        health["loadavg"] = [round(x, 2) for x in la]
    except Exception:
        pass
    # RAM tu /proc/meminfo
    try:
        info = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            info[k.strip()] = float(v.strip().split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        if total > 0:
            health["mem_percent"] = round((total - avail) / total * 100, 1)
            health["mem_total_gb"] = round(total / 1024 / 1024, 1)
    except Exception:
        pass
    # CPU tu /proc/stat (2 mau cach nhau ngan)
    try:
        def _cpu():
            parts = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
            vals = list(map(int, parts))
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return sum(vals), idle
        t1, i1 = _cpu(); time.sleep(0.12); t2, i2 = _cpu()
        dt, di = t2 - t1, i2 - i1
        if dt > 0:
            health["cpu_percent"] = round((1 - di / dt) * 100, 1)
    except Exception:
        pass
    # Disk cua thu muc du an
    try:
        st = os.statvfs(str(ROOT))
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total > 0:
            health["disk_percent"] = round((total - free) / total * 100, 1)
            health["disk_free_gb"] = round(free / 1024 ** 3, 1)
            health["disk_total_gb"] = round(total / 1024 ** 3, 1)
    except Exception:
        pass
    # Bộ đếm drop do kernel/NIC cung cấp. Đây là counter tích lũy từ lúc interface lên.
    try:
        env = load_env_file(ENV_FILE)
        interface = env.get("NIDS_INTERFACE", os.getenv("NIDS_INTERFACE", "ens18")).strip()
        stats_root = Path("/sys/class/net") / interface / "statistics"
        counters = {}
        for name in ("rx_dropped", "rx_missed_errors", "tx_dropped"):
            path = stats_root / name
            counters[name] = int(path.read_text().strip()) if path.exists() else 0
        health["interface"] = interface
        health["packet_drop_counters"] = counters
        health["packet_drop_total"] = sum(counters.values())
    except Exception:
        pass
    # Độ trễ suy luận do chính detector ghi; không đồng nhất với độ trễ end-to-end.
    try:
        streaming = json.loads(STREAMING_METRICS_FILE.read_text(encoding="utf-8"))
        health["inference_latency_ms_per_flow"] = streaming.get(
            "inference_latency_ms_per_flow"
        )
        health["throughput_flows_per_second"] = streaming.get(
            "throughput_flows_per_second"
        )
        health["streaming_status"] = streaming.get("status")
        health["streaming_metrics_created_at"] = streaming.get("created_at")
    except Exception:
        pass
    sample = {
        key: health.get(key)
        for key in (
            "timestamp",
            "cpu_percent",
            "mem_percent",
            "disk_percent",
            "packet_drop_total",
            "inference_latency_ms_per_flow",
            "throughput_flows_per_second",
        )
    }
    HEALTH_HISTORY.append(sample)
    health["history"] = list(HEALTH_HISTORY)
    return health


def load_metrics() -> dict[str, Any]:
    if not METRICS_FILE.exists():
        return {"available": False}
    try:
        d = json.load(open(METRICS_FILE, encoding="utf-8"))
        cm = d.get("confusion_matrix", {})
        return {
            "available": True,
            "accuracy": d.get("accuracy"), "balanced_accuracy": d.get("balanced_accuracy"),
            "precision": d.get("precision"), "recall": d.get("recall"),
            "f1": d.get("f1", d.get("f1_score")), "fpr": d.get("fpr"),
            "fnr": d.get("fnr"), "roc_auc": d.get("roc_auc"),
            "threshold": d.get("threshold"),
            "tn": cm.get("tn"), "fp": cm.get("fp"), "fn": cm.get("fn"), "tp": cm.get("tp"),
            "train_size": d.get("train_size"), "test_size": d.get("test_size"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class PanelHandler(BaseHTTPRequestHandler):
    server_version = "HybridNIDSPanel/2.0"

    def log_message(self, *args: Any) -> None:
        return

    # ---- auth ----
    def _get_session_user(self) -> str | None:
        """Doc cookie 'sid' va tra ve username neu session hop le."""
        cookie_hdr = self.headers.get("Cookie", "")
        c = SimpleCookie()
        try:
            c.load(cookie_hdr)
        except Exception:
            return None
        sid = c.get("sid")
        if sid and sid.value in ACTIVE_SESSIONS:
            return ACTIVE_SESSIONS[sid.value]
        return None

    def _auth_ok(self) -> bool:
        """Kiem tra dang nhap bang cookie session."""
        if not (PANEL_USER and PANEL_PASS):
            self._current_user = "admin"
            self._current_name = "Quản trị viên"
            return True
        user = self._get_session_user()
        if user:
            self._current_user = user
            self._current_name = USERS.get(user, {}).get("name", user)
            return True
        return False

    def _require_auth(self) -> bool:
        if self._auth_ok():
            return True
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()
        return False

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    # ---- GET ----
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # Trang login khong can auth
        if path == "/login":
            err = urllib.parse.parse_qs(parsed.query).get("err", [""])[0]
            page = LOGIN_HTML.replace("__ERR__", err)
            self._send(200, page.encode("utf-8"), "text/html")
            return
        if path == "/logout":
            # Xoa session
            cookie_hdr = self.headers.get("Cookie", "")
            c = SimpleCookie()
            try:
                c.load(cookie_hdr)
                sid = c.get("sid")
                if sid and sid.value in ACTIVE_SESSIONS:
                    del ACTIVE_SESSIONS[sid.value]
            except Exception:
                pass
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "sid=; Path=/; Max-Age=0")
            self.end_headers()
            return
        # Yeu cau dang nhap cho moi truy cap
        if PANEL_USER and not self._require_auth():
            return
        if path in ("/", "/index.html"):
            page = INDEX_HTML.replace("__USER__", getattr(self, "_current_name", ""))
            self._send(200, page.encode("utf-8"), "text/html")
            return
        if path == "/report":
            self._send(200, self._report_html().encode("utf-8"), "text/html")
            return
        if path == "/api/status":
            self._json(self._status_payload()); return
        if path == "/api/alerts":
            qs = urllib.parse.parse_qs(parsed.query)
            self._json(self._alerts_payload(int(qs.get("limit", ["200"])[0]))); return
        if path == "/api/metrics":
            self._json(load_metrics()); return
        if path == "/api/health":
            self._json(read_system_health()); return
        if path == "/api/config":
            self._json(self._config_payload()); return
        if path == "/api/session":
            self._json(dict(SESSION)); return
        if path == "/api/lab-eval":
            md = read_lab_eval_md()
            self._json({"available": bool(md), "markdown": md}); return

        # --- Dashboard Summary (ES first, fallback file) ---
        if path == "/api/dashboard-summary":
            es_data = es_dashboard_summary()
            if es_data:
                self._json(es_data); return
            # Fallback: doc tu file JSONL
            alerts = self._alerts_payload(9999)["alerts"]
            now_ts = time.time()
            local_now = datetime.now().astimezone()
            today_start = local_now.replace(
                hour=0, minute=0, second=0, microsecond=0
            ).timestamp()
            week_start = now_ts - 7*86400
            month_start = now_ts - 30*86400
            today_count = sum(1 for a in alerts if (a["epoch"] or 0) >= today_start)
            week_count = sum(1 for a in alerts if (a["epoch"] or 0) >= week_start)
            month_count = sum(1 for a in alerts if (a["epoch"] or 0) >= month_start)
            from collections import Counter as _Counter
            src_counts = _Counter(a["src"] for a in alerts if a["src"])
            top_ips = src_counts.most_common(5)
            sev_counts = _Counter(a["severity"] for a in alerts)
            self._json({
                "today": today_count, "week": week_count, "month": month_count,
                "total": len(alerts),
                "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
                "severity": dict(sev_counts),
                "source": "file",
            }); return

        # --- Alert Trend (ES first, fallback file) ---
        if path == "/api/alert-trend":
            es_hours = es_alert_trend_24h()
            if es_hours:
                self._json({"hours": es_hours, "source": "elasticsearch"}); return
            # Fallback file
            alerts = self._alerts_payload(9999)["alerts"]
            now_ts = time.time()
            hours: dict[int, int] = {}
            for h in range(24):
                hours[h] = 0
            for a in alerts:
                ep = a["epoch"] or 0
                if ep >= now_ts - 86400:
                    hour = int((ep % 86400) / 3600)
                    hours[hour] = hours.get(hour, 0) + 1
            self._json({"hours": [{"hour": h, "count": hours.get(h,0)} for h in range(24)], "source": "file"}); return

        # --- Whitelist / Blacklist ---
        if path == "/api/ip-lists":
            self._json({"whitelist": sorted(WHITELIST), "blacklist": sorted(BLACKLIST)}); return

        # --- Audit Log ---
        if path == "/api/audit-log":
            self._json({"entries": AUDIT_LOG[-100:]}); return

        # --- Session History ---
        if path == "/api/session-history":
            self._json({"sessions": SESSION_HISTORY[-50:]}); return

        # --- Current threshold ---
        if path == "/api/threshold":
            env = load_env_file(ENV_FILE)
            th = env.get("AI_THRESHOLD", "0.8708")
            self._json({"threshold": th}); return

        self._json({"error": "not found"}, 404)

    # ---- POST ----
    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""

        # --- Login POST (khong can auth) ---
        if parsed.path == "/login":
            params = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
            username = (params.get("username", [""])[0]).strip()
            pw = (params.get("password", [""])[0]).strip()
            # Xac thuc: chi user da cau hinh mat khau moi dang nhap duoc.
            authenticated = False
            expected = expected_password_for(username)
            if expected and hmac.compare_digest(pw, expected):
                authenticated = True
            if authenticated:
                token = secrets.token_hex(24)
                ACTIVE_SESSIONS[token] = username
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", f"sid={token}; Path=/; HttpOnly; SameSite=Strict")
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header("Location", "/login?err=Sai+t%C3%A0i+kho%E1%BA%A3n+ho%E1%BA%B7c+m%E1%BA%ADt+kh%E1%BA%A9u")
                self.end_headers()
            return

        # Cac API khac can auth
        if not self._require_auth():
            return
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            body = {}

        if parsed.path == "/api/action":
            allowed = {"start", "stop", "restart", "status", "logs",
                       "alerts-start", "alerts-stop", "alerts-status"}
            action = str(body.get("action", "")).strip()
            if action not in allowed:
                self._json({"ok": False, "output": f"Hanh dong khong hop le: {action}"}, 400); return
            self._json(run_control(action)); return

        if parsed.path == "/api/test-alert":
            self._json(self._test_alert_payload()); return

        if parsed.path == "/api/launch-attack":
            audit(getattr(self, "_current_user", "?"), "launch_attack", "Mô phỏng tấn công từ Kali")
            self._json(self._launch_attack()); return

        # --- Whitelist / Blacklist management ---
        if parsed.path == "/api/ip-lists":
            action = body.get("action", "")  # add_wl, del_wl, add_bl, del_bl
            ip = str(body.get("ip", "")).strip()
            if ip:
                if action == "add_wl":
                    WHITELIST.add(ip); BLACKLIST.discard(ip)
                elif action == "del_wl":
                    WHITELIST.discard(ip)
                elif action == "add_bl":
                    BLACKLIST.add(ip); WHITELIST.discard(ip)
                elif action == "del_bl":
                    BLACKLIST.discard(ip)
                save_ip_lists()
                audit(getattr(self, "_current_user", "?"), f"ip_{action}", ip)
            self._json({"whitelist": sorted(WHITELIST), "blacklist": sorted(BLACKLIST)}); return

        # --- Threshold update ---
        if parsed.path == "/api/threshold":
            new_th = str(body.get("value", "")).strip()
            if new_th:
                try:
                    val = float(new_th)
                    if 0 < val < 1:
                        env = load_env_file(ENV_FILE)
                        env["AI_THRESHOLD"] = f"{val:.4f}"
                        save_env_file(ENV_FILE, env)
                        audit(getattr(self, "_current_user", "?"), "threshold_change", f"{val:.4f}")
                        self._json({"ok": True, "threshold": f"{val:.4f}"}); return
                except ValueError:
                    pass
            self._json({"ok": False, "message": "Giá trị không hợp lệ (0 < threshold < 1)"}); return

        if parsed.path == "/api/run-lab-eval":
            # Bảng chính thức phải chạy cùng PCAP, EVE và attack_windows của một phiên.
            self._json(run_lab_eval()); return

        if parsed.path == "/api/session":
            act = str(body.get("action", "")).strip()
            if act == "start":
                op_name = getattr(self, "_current_name", "Quản trị viên")
                label = normalize_session_label(body.get("label"))
                SESSION.update(active=True, started_at=utc_now(), label=label, operator=op_name)
                audit(getattr(self, "_current_user", "?"), "session_start", f"Phiên: {SESSION['label']}")
            elif act == "rename":
                SESSION["label"] = normalize_session_label(body.get("label"))
                audit(getattr(self, "_current_user", "?"), "session_rename", f"Phiên: {SESSION['label']}")
            elif act == "end":
                # Luu lich su phien
                SESSION_HISTORY.append({
                    "started_at": SESSION.get("started_at", ""),
                    "ended_at": utc_now(),
                    "operator": SESSION.get("operator", ""),
                    "label": SESSION.get("label", ""),
                })
                audit(getattr(self, "_current_user", "?"), "session_end", f"Phiên: {SESSION['label']}")
                SESSION.update(active=False)
            self._json(dict(SESSION)); return

        if parsed.path == "/api/config-update":
            self._json(self._config_update(body.get("values", {}))); return

        self._json({"error": "not found"}, 404)

    # ---- payload helpers ----
    def _status_payload(self) -> dict[str, Any]:
        result = run_control("status", timeout=40)
        text = result.get("output", "")
        services = {
            "suricata": self._svc_state(text, ["Suricata svc", "Suricata local"]),
            "rf21": self._svc_state(text, ["RF-21 stream"]),
            "fusion": self._svc_state(text, ["Hybrid fusion"]),
            "forwarder": self._svc_state(text, ["Alert forward"]),
        }
        any_up = any(v == "running" for v in services.values())
        return {"generated_at": utc_now(), "control_available": is_using_control_script(),
                "system": "running" if any_up else "stopped", "services": services, "raw": text}

    @staticmethod
    def _svc_state(text: str, labels: list[str]) -> str:
        for line in text.splitlines():
            for lb in labels:
                if lb in line:
                    up = ("RUNNING" in line.upper()) or ("ACTIVE" in line.upper() and "INACTIVE" not in line.upper())
                    if up:
                        return "running"
        return "stopped"

    def _alerts_payload(self, limit: int) -> dict[str, Any]:
        # Bang realtime chi hien thi limit dong moi nhat, nhung thong ke phai
        # dem toan bo file de tranh hieu nham "luc nao cung 200".
        display_raw = tail_jsonl(FUSED_ALERT_LOG, limit=limit)
        alerts = [normalize_alert(r) for r in display_raw]

        all_alerts: list[dict[str, Any]] = []
        invalid_lines = 0
        if FUSED_ALERT_LOG.exists():
            try:
                with FUSED_ALERT_LOG.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        try:
                            all_alerts.append(normalize_alert(json.loads(line)))
                        except Exception:
                            invalid_lines += 1
            except Exception:
                all_alerts = alerts[:]
        else:
            all_alerts = alerts[:]

        stats_source = all_alerts
        sev = Counter(a["severity"] for a in stats_source)
        act = Counter(a["action"] for a in stats_source)

        # Bieu do: nhom theo phut, tinh tren toan bo file nhung chi lay 12 phut
        # cuoi theo moc timestamp moi nhat trong log.
        buckets: dict[int, dict[str, int]] = defaultdict(lambda: {"suricata": 0, "ai": 0, "hybrid": 0})
        now = time.time()
        for a in stats_source:
            ep = a["epoch"] or now
            minute = int(ep // 60)
            key = ("hybrid" if a["action"] in {
                       "HYBRID_CORRELATED_ALERT", "HYBRID_PLUS_DEMO_ALERT"
                   }
                   else "suricata" if a["action"] == "SURICATA_ONLY_ALERT"
                   else "ai")
            buckets[minute][key] += 1
        if buckets:
            maxm = max(buckets.keys())
            series = []
            for m in range(maxm - 11, maxm + 1):
                b = buckets.get(m, {"suricata": 0, "ai": 0, "hybrid": 0})
                lbl = datetime.fromtimestamp(m * 60).strftime("%H:%M")
                series.append({"t": lbl, **b})
        else:
            series = []

        # Session-scoped count tinh tren toan bo file.
        sess_count = 0
        if SESSION["active"] and SESSION["started_at"]:
            s0 = parse_ts(SESSION["started_at"])
            if s0:
                sess_count = sum(1 for a in stats_source if (a["epoch"] or 0) >= s0)

        priority_count = sum(1 for a in stats_source if a["forwarded"])
        return {"generated_at": utc_now(),
                "count": len(stats_source),
                "display_count": len(alerts),
                "display_limit": limit,
                "forwarded": priority_count,
                "severity_counts": dict(sev), "action_counts": dict(act),
                "timeline": series, "session_count": sess_count,
                "alerts": alerts, "log_path": str(FUSED_ALERT_LOG),
                "log_exists": FUSED_ALERT_LOG.exists(),
                "stats_scope": "all_file",
                "invalid_lines": invalid_lines}

    def _kibana_url(self, env: dict[str, str]) -> str:
        explicit = env.get("KIBANA_URL") or os.getenv("KIBANA_URL")
        if explicit:
            return explicit.strip()
        port = env.get("KIBANA_PORT") or DEFAULT_KIBANA_PORT
        host_hdr = self.headers.get("Host", "") if hasattr(self, "headers") else ""
        host_ip = host_hdr.split(":")[0] if host_hdr else ""
        if not host_ip:
            host_ip = env.get("NIDS_IP") or "127.0.0.1"
        return f"http://{host_ip}:{port}"

    def _config_payload(self) -> dict[str, Any]:
        env = load_env_file(ENV_FILE)
        display = {k: (mask_secret(v) if k in SENSITIVE_KEYS else v) for k, v in env.items()}
        editable = {k: env.get(k, "") for k in EDITABLE_KEYS}
        return {"env_file": str(ENV_FILE), "env_exists": ENV_FILE.exists(),
                "values": display, "editable": editable, "editable_keys": EDITABLE_KEYS,
                "telegram_ready": bool(env.get("TELEGRAM_BOT_TOKEN")) and bool(env.get("TELEGRAM_CHAT_ID")),
                "discord_ready": bool(env.get("DISCORD_NIDS_WEBHOOK")),
                "kibana_url": self._kibana_url(env),
                "auth_enabled": bool(PANEL_USER and PANEL_PASS),
                "policy": "Day Hybrid that, Hybrid+ Demo co nhan va moi canh bao CRITICAL/HIGH"}

    def _config_update(self, values: dict[str, Any]) -> dict[str, Any]:
        if not ENV_FILE.exists():
            return {"ok": False, "message": f"Chua co file {ENV_FILE}. Tao tu .env.example truoc."}
        # Chi cho phep sua EDITABLE_KEYS
        updates = {k: str(v) for k, v in values.items() if k in EDITABLE_KEYS}
        if not updates:
            return {"ok": False, "message": "Khong co truong hop le de cap nhat."}
        try:
            lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
            seen = set()
            for i, line in enumerate(lines):
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                key = s.split("=", 1)[0].strip()
                if key in updates:
                    lines[i] = f"{key}={updates[key]}"
                    seen.add(key)
            for k, v in updates.items():
                if k not in seen:
                    lines.append(f"{k}={v}")
            ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return {"ok": True, "message": f"Da cap nhat {len(updates)} truong. Khoi dong lai he thong de ap dung.",
                    "updated": list(updates.keys())}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "message": f"Loi ghi file: {exc}"}

    def _test_alert_payload(self) -> dict[str, Any]:
        env = os.environ.copy()
        env.update(load_env_file(ENV_FILE))
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Telegram: format giong canh bao that
        tg_text = (
            "\U0001F6E1\ufe0f TRƯỜNG CAO ĐẲNG GIAO THÔNG VẬN TẢI TP.HCM\n"
            "\U0001F5A5\ufe0f HỆ THỐNG PHÁT HIỆN XÂM NHẬP LAI (HYBRID-NIDS)\n"
            "\n"
            "\U0001F6A8 CẢNH BÁO AN NINH: PHÁT HIỆN TẤN CÔNG! \U0001F6A8\n"
            "\n"
            "\u270f\ufe0f Đơn vị giám sát: Khoa CNTT\n"
            "\U0001F534 Mức độ nghiêm trọng: KHẨN CẤP (CRITICAL)\n"
            "\U0001F9E0 Lớp phân tích AI: Random Forest\n"
            "\U0001F3AF IP nguồn tấn công: 192.168.10.101\n"
            "\U0001F4CA Tổng số luồng độc hại: 5 flows\n"
            "\U0001F50D Các cổng dịch vụ bị nhắm mục tiêu: 22, 80, 443\n"
            "\U0001F4C8 Điểm AI cao nhất: 0.999\n"
            f"\U0001F4C5 Mốc thời gian ghi nhận: {stamp}\n"
            "\n"
            "\u26a0\ufe0f KHUYẾN NGHỊ VẬN HÀNH: Kiểm tra nguồn lưu lượng, "
            "rà soát tường lửa và đối chiếu log Suricata để xác minh sự kiện."
        )
        # Discord: compact bold markdown
        dc_text = (
            "\U0001F6E1\ufe0f **TRƯỜNG CAO ĐẲNG GIAO THÔNG VẬN TẢI TP.HCM**\n"
            "\U0001F5A5\ufe0f HỆ THỐNG PHÁT HIỆN XÂM NHẬP LAI (HYBRID-NIDS)\n"
            "\n"
            "\U0001F6A8 **CẢNH BÁO AN NINH: PHÁT HIỆN TẤN CÔNG!** \U0001F6A8\n"
            "\n"
            "\u270f\ufe0f Đơn vị giám sát: Khoa CNTT\n"
            "\U0001F534 Mức độ nghiêm trọng: **KHẨN CẤP (CRITICAL)**\n"
            "\U0001F9E0 Lớp phân tích AI: Random Forest\n"
            "\U0001F3AF IP nguồn tấn công: `192.168.10.101`\n"
            "\U0001F4CA Tổng số luồng độc hại: **5** flows\n"
            "\U0001F50D Các cổng dịch vụ bị nhắm mục tiêu: 22, 80, 443\n"
            "\U0001F9EC Điểm AI cao nhất: **0.999**\n"
            f"\U0001F4C5 Mốc thời gian ghi nhận: {stamp}\n"
            "\n"
            "\u26a0\ufe0f **KHUYẾN NGHỊ:** Kiểm tra nguồn lưu lượng, rà soát tường lửa và đối chiếu log Suricata."
        )
        tg_ok, tg_msg = send_test_telegram(env.get("TELEGRAM_BOT_TOKEN", ""), env.get("TELEGRAM_CHAT_ID", ""), tg_text)
        dc_ok, dc_msg = send_test_discord(env.get("DISCORD_NIDS_WEBHOOK", ""), dc_text)
        return {"telegram": {"ok": tg_ok, "message": tg_msg}, "discord": {"ok": dc_ok, "message": dc_msg}}

    def _launch_attack(self) -> dict[str, Any]:
        """Kich hoat mo phong tan cong tu Kali (192.168.10.101) qua SSH."""
        kali_ip = "192.168.10.101"
        kali_user = "admin_soc"
        target = load_env_file(ENV_FILE).get("NIDS_LAB_IP", "192.168.10.146")
        remote_command = f"nmap -sS -T3 -p 1-1000 {target}"
        ssh_cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            f"{kali_user}@{kali_ip}",
            remote_command,
        ]
        try:
            subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {
                "ok": True,
                "message": (
                    f"Đã yêu cầu Kali {kali_ip} chạy port scan có kiểm soát tới {target}. "
                    "Web panel không tự ghi cảnh báo; chỉ hiển thị kết quả pipeline thật."
                ),
            }
        except Exception as exc:
            return {
                "ok": False,
                "message": f"Không khởi chạy được lệnh trên Kali: {exc}. Không tạo cảnh báo giả.",
            }


    def _report_html(self) -> str:
        """Trang bao cao phien - in duoc (Ctrl+P -> Save as PDF). Tieng Viet co dau."""
        data = self._alerts_payload(500)
        m = load_metrics()
        env = load_env_file(ENV_FILE)
        s0 = parse_ts(SESSION["started_at"]) if SESSION["started_at"] else None
        rows = [a for a in data["alerts"] if not (s0 and (a["epoch"] or 0) < s0)]
        empty_row = '<tr><td colspan="8" style="text-align:center;color:#888">Không có cảnh báo trong phạm vi phiên.</td></tr>'
        rows_html = "".join(
            ("<tr style='font-weight:700;background:#fff0f0'>" if a["severity"] in ("CRITICAL","HIGH") else "<tr>") +
            "<td>" + html.escape(str(a["timestamp"])) + "</td><td>" + html.escape(a["action"]) +
            "</td><td>" + html.escape(a["severity"]) + "</td><td>" + html.escape(a["src"]) +
            "</td><td>" + html.escape(a["dst"]) + "</td><td>" + html.escape(str(a["port"])) +
            "</td><td>" + html.escape(str(a["score"]) if a["score"] is not None else "-") +
            "</td><td>" + html.escape(a["category"]) + "</td></tr>"
            for a in rows[:300]
        ) or empty_row
        def mv(x, pct=True):
            if x is None:
                return "-"
            return (f"{x*100:.2f}%") if pct else (f"{x:.4f}")
        if m.get("available"):
            metric_block = (
                '<table class="kv">'
                "<tr><td>Accuracy (Độ chính xác)</td><td>" + mv(m["accuracy"]) +
                "</td><td>Precision</td><td>" + mv(m["precision"]) + "</td></tr>"
                "<tr><td>Recall (Độ nhạy)</td><td>" + mv(m["recall"]) +
                "</td><td>F1-score</td><td>" + mv(m["f1"]) + "</td></tr>"
                "<tr><td>FPR (Báo nhầm)</td><td>" + mv(m["fpr"]) +
                "</td><td>ROC-AUC</td><td>" + mv(m["roc_auc"]) + "</td></tr>"
                '<tr><td>Ngưỡng phân loại</td><td colspan="3">' + mv(m.get("threshold"), pct=False) + "</td></tr>"
                "</table>"
            )
        else:
            metric_block = "<p><i>Chưa có models/metrics.json.</i></p>"
        gen = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        session_label = normalize_session_label(SESSION.get("label"))
        sess = ("Từ " + str(SESSION["started_at"])) if SESSION["started_at"] else "Toàn bộ (không giới hạn phiên)"
        logo_html = ""
        logo_path = ROOT / "deployment" / "school_logo.png"
        if logo_path.exists():
            try:
                b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
                logo_html = '<img class="logo" src="data:image/png;base64,' + b64 + '" alt="Logo"/>'
            except Exception:
                logo_html = ""
        iface = html.escape(env.get("NIDS_INTERFACE", "-"))
        home = html.escape(env.get("HOME_NET", "-"))
        n_total = len(rows)
        n_fw = sum(1 for a in rows if a["forwarded"])
        n_crit = sum(1 for a in rows if a["severity"] in ("CRITICAL", "HIGH"))
        parts = []
        parts.append('<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8">')
        parts.append("<title>" + html.escape("Báo cáo Hybrid-NIDS - " + session_label) + "</title>")
        parts.append("<style>")
        parts.append("body{font-family:'Times New Roman',serif;max-width:900px;margin:24px auto;color:#111;padding:0 20px}")
        parts.append(".head{display:flex;align-items:center;gap:16px;border-bottom:2px solid #1a3a6b;padding-bottom:12px;margin-bottom:6px}")
        parts.append(".head .logo{width:74px;height:auto;flex:0 0 auto}")
        parts.append(".head .org{flex:1;text-align:center}")
        parts.append(".head .org .l1{font-size:13px;font-weight:bold;text-transform:uppercase}")
        parts.append(".head .org .l2{font-size:15px;font-weight:bold;text-transform:uppercase;color:#1a3a6b}")
        parts.append("h1{font-size:19px;text-align:center;margin:14px 0 4px}")
        parts.append("h2{font-size:15px;border-bottom:2px solid #333;padding-bottom:4px;margin-top:22px}")
        parts.append(".sub{text-align:center;color:#555;font-size:13px}")
        parts.append("table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}")
        parts.append("th,td{border:1px solid #999;padding:5px 7px;text-align:left} th{background:#eee}")
        parts.append(".kv td{border:1px solid #ccc} .kv td:nth-child(odd){background:#f5f5f5;font-weight:bold;width:22%}")
        parts.append("@media print{.noprint{display:none}}")
        parts.append("button{padding:10px 20px;font-size:14px;cursor:pointer;margin-top:16px}")
        parts.append("</style></head><body>")
        parts.append('<div class="head">' + logo_html + '<div class="org">')
        parts.append('<div class="l1">Ủy ban nhân dân Thành phố Hồ Chí Minh</div>')
        parts.append('<div class="l2">Trường Cao đẳng Giao thông Vận tải TP.HCM</div>')
        parts.append("</div></div>")
        parts.append("<h1>BÁO CÁO PHIÊN GIÁM SÁT HYBRID-NIDS</h1>")
        parts.append('<div class="sub">Hệ thống phát hiện xâm nhập lai (Suricata + Random Forest) · Tạo lúc ' + gen + "</div>")
        parts.append("<h2>1. Thông tin phiên</h2>")
        parts.append('<table class="kv">')
        parts.append("<tr><td>Tên phiên</td><td colspan=\"3\">" + html.escape(session_label) + "</td></tr>")
        parts.append("<tr><td>Người điều hành</td><td>" + html.escape(SESSION.get("operator","") or "—") + "</td><td>Card mạng</td><td>" + iface + "</td></tr>")
        parts.append("<tr><td>Phạm vi</td><td>" + html.escape(sess) + "</td><td></td><td></td></tr>")
        parts.append("<tr><td>Dải mạng bảo vệ</td><td>" + home + "</td><td>Tổng cảnh báo</td><td>" + str(n_total) + "</td></tr>")
        parts.append("<tr><td>Đã đẩy ra kênh</td><td>" + str(n_fw) + "</td><td>CRITICAL/HIGH</td><td>" + str(n_crit) + "</td></tr>")
        parts.append("</table>")
        parts.append("<h2>2. Chỉ số mô hình Random Forest (Kiểm thử tập giữ lại)</h2>")
        parts.append(metric_block)
        parts.append("<h2>3. Danh sách cảnh báo (tối đa 300 dòng)</h2>")
        parts.append("<table><thead><tr><th>Thời gian</th><th>Loại</th><th>Mức độ</th><th>Nguồn</th><th>Đích</th><th>Cổng</th><th>Điểm AI</th><th>Phân loại</th></tr></thead><tbody>")
        parts.append(rows_html)
        parts.append("</tbody></table>")
        parts.append('<p style="margin-top:20px;font-size:11px;color:#666">Báo cáo tự động tạo bởi Hybrid-NIDS Web Control Panel. Dùng làm minh chứng thực nghiệm cho đề án.</p>')
        parts.append('<div style="margin-top:40px;padding-top:20px;border-top:2px solid #333">')
        parts.append('<table style="width:100%;border:none"><tr>')
        parts.append('<td style="width:50%;border:none;text-align:center;padding-top:40px">')
        parts.append('<strong>NGƯỜI LẬP BÁO CÁO</strong><br><br><br><br><br>' + html.escape(getattr(self, "_current_name", "") or "...") + '</td>')
        parts.append('<td style="width:50%;border:none;text-align:center;padding-top:40px">')
        parts.append('<strong>XÁC NHẬN CỦA ĐƠN VỊ</strong><br><br><br><br><br>.....................................</td>')
        parts.append('</tr></table></div>')
        parts.append('<button class="noprint" onclick="window.print()">In / Lưu PDF</button>')
        parts.append("</body></html>")
        return "".join(parts)


# --------------------------------------------------------------------------
# HTML giao dien chinh
# --------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Bảng điều khiển · Hybrid-NIDS · </title>
<style>
  :root{--bg:#eef2f8;--panel:#ffffff;--panel2:#f7f9fc;--line:#d8e0ee;--text:#12233f;
        --muted:#5c6b86;--navy:#17315c;--accent:#1e4fa3;--accent2:#2f6fd0;
        --ok:#1f9d57;--warn:#c9820a;--crit:#c8354a;--high:#d1587a;--soft:#eaf0fa}
  *{box-sizing:border-box}
  body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,Roboto,sans-serif;
       background:var(--bg);color:var(--text);min-height:100vh}
  header{display:flex;align-items:center;gap:18px;padding:18px 28px;
         position:sticky;top:0;position:relative;background:linear-gradient(135deg,#0B192C 0%,#1b3a5c 100%);z-index:10;box-shadow:0 2px 12px rgba(11,25,44,.4)}
  .logo{width:48px;height:48px;border-radius:12px;background:rgba(255,255,255,.08);border:1px solid rgba(0,255,200,.3);display:grid;place-items:center;box-shadow:0 0 12px rgba(0,255,200,.2)}
  .logo svg{width:28px;height:28px;filter:drop-shadow(0 0 4px rgba(0,255,200,.5))}
  header h1{font-size:20px;margin:0;color:#fff;font-weight:800;letter-spacing:.5px;font-family:'Inter','Segoe UI',sans-serif}
  header h1 .hl-suri{color:#ff6b35} header h1 .hl-ai{color:#00d4aa}
  .sub{color:rgba(255,255,255,.7);font-size:12px;margin-top:6px;display:flex;gap:8px}
  .sub .tag{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.15);padding:2px 10px;border-radius:12px;font-size:11px}
  .sysbadge{margin-left:auto;display:flex;align-items:center;gap:8px;padding:8px 14px;border-radius:99px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.15);color:#fff;font-weight:600;font-size:13px}
  .dot{width:10px;height:10px;border-radius:50%;background:var(--muted)}
  .dot.on{background:var(--ok);box-shadow:0 0 8px var(--ok)}.dot.off{background:var(--crit)}
  main{padding:20px 26px;max-width:1320px;margin:0 auto;display:grid;gap:16px}
  .grid{display:grid;gap:16px}.cols{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .row3{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:16px}
  .ops-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
  .ops-chart{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px;min-width:0}
  .ops-chart h3{font-size:12px;color:var(--navy);margin:0 0 4px}
  .ops-chart .value{font-size:12px;color:var(--muted);min-height:18px}
  .ops-chart svg{display:block;width:100%;height:100px;margin-top:6px;overflow:visible}
  .ops-chart .axis{stroke:#cbd5e1;stroke-width:1}
  .ops-chart .line-a{fill:none;stroke:#2f6fd0;stroke-width:2}
  .ops-chart .line-b{fill:none;stroke:#c9820a;stroke-width:2}
  .ops-chart .line-c{fill:none;stroke:#c8354a;stroke-width:2}
  @media(max-width:900px){.row2,.row3,.ops-grid{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 1px 3px rgba(23,49,92,.05)}
  .card h2{font-size:14px;text-transform:uppercase;letter-spacing:.5px;color:var(--navy);margin:0 0 14px;font-weight:800}
  .btns{display:flex;flex-wrap:wrap;gap:10px}
  button{cursor:pointer;border:0;border-radius:10px;padding:11px 16px;font-size:14px;font-weight:600;
         color:#fff;background:var(--navy);transition:filter .15s;display:inline-flex;align-items:center;gap:7px}
  button svg{width:15px;height:15px;flex:0 0 auto}
  button:active{transform:translateY(1px)}button:hover{filter:brightness(1.08)}
  .b-start{background:var(--ok)}
  .b-stop{background:var(--crit)}
  .b-restart{background:var(--warn)}
  .b-alert{background:var(--accent)}
  .b-test{background:var(--accent2)}
  .b-kibana{background:var(--navy)}
  .b-ghost{background:#fff;color:var(--navy);border:1px solid var(--line)}
  .b-mute{background:#6b7280;color:#fff} .b-refresh{background:#dc2626;color:#fff}
  .card [style*="grid-template-columns"] button{min-height:48px;display:inline-flex;align-items:center;justify-content:center;text-align:center;padding:8px 10px;line-height:1.2}
  .svc{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;background:var(--panel2);
       border:1px solid var(--line);margin-bottom:8px}
  .svc .name{font-weight:600}.svc .state{margin-left:auto;font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px}
  .state.running{color:#fff;background:var(--ok)}.state.stopped{color:#fff;background:#8395b0}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
  th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px;position:sticky;top:0;background:var(--panel2)}
  tr:hover td{background:var(--soft)}
  .tag{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px}
  .sev-CRITICAL{color:#fff;background:var(--crit)}.sev-HIGH{color:#fff;background:var(--high)}
  .sev-MEDIUM{color:#5a3b06;background:#f7dca0}.sev-LOW,.sev-\-{color:#3d4a63;background:#dde4f0}
  .fw{color:var(--accent);font-weight:700}.muted{color:var(--muted)}
  .tablewrap{max-height:420px;overflow:auto;border-radius:12px;border:1px solid var(--line)}
  .tablewrap table{width:100%;border-collapse:collapse;font-size:13px}
  .tablewrap th{background:var(--navy);color:#fff;font-weight:700;padding:10px 12px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.3px}
  .tablewrap td{padding:8px 12px;border-bottom:1px solid var(--line)}
  .kv{display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px dashed var(--line);font-size:13px}
  .kv .k{color:var(--muted)}.kv .v{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;text-align:right}
  #toast{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px;z-index:50}
  .t{padding:12px 16px;border-radius:10px;font-size:13px;font-weight:600;box-shadow:0 8px 24px rgba(23,49,92,.18);animation:pop .2s}
  .t.ok{background:#e5f4ec;color:#137a41;border:1px solid #b6e0c7}.t.err{background:#fbe7ea;color:#a52338;border:1px solid #f0c2ca}
  @keyframes pop{from{opacity:0;transform:translateY(8px)}to{opacity:1}}
  .pill{font-size:11px;padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
  .pill.on{color:#137a41;border-color:#b6e0c7;background:#e5f4ec}.pill.off{color:#a52338;border-color:#f0c2ca;background:#fbe7ea}
  pre{white-space:pre-wrap;background:#0f1f3a;border:1px solid var(--line);border-radius:10px;padding:12px;font-size:12px;color:#cfe0f7;max-height:200px;overflow:auto}
  .stat{font-size:24px;font-weight:800;color:var(--navy)}.statlabel{color:var(--muted);font-size:12px}
  .metric{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center}
  .metric .v{font-size:22px;font-weight:800;color:var(--navy)}.metric .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
  .bar{height:8px;border-radius:6px;background:#e0e7f2;overflow:hidden;margin-top:6px}
  .bar>i{display:block;height:100%;border-radius:6px}
  input,select{background:#fff;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:8px 10px;font-size:13px;width:100%}
  input:focus,select:focus{outline:none;border-color:var(--accent)}
  label{font-size:12px;color:var(--muted);display:block;margin:8px 0 3px}
  .chartwrap{width:100%;overflow-x:auto}
  .legend{display:flex;gap:14px;font-size:12px;color:var(--muted);margin-top:6px}
  .lg{display:inline-flex;align-items:center;gap:5px}.sw{width:11px;height:11px;border-radius:3px;display:inline-block}
  .filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
  .filters input,.filters select{width:auto;min-width:120px}
</style>
</head>
<body>
<header>
  <div class="logo"><svg viewBox="0 0 32 32" fill="none" stroke="#00ffc8" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M16 30s10-5 10-13V7l-10-4-10 4v10c0 8 10 13 10 13z" fill="rgba(0,255,200,.08)"/><circle cx="16" cy="14" r="2" fill="#00ffc8"/><circle cx="11" cy="18" r="1.5" fill="#ff6b35"/><circle cx="21" cy="18" r="1.5" fill="#ff6b35"/><line x1="16" y1="14" x2="11" y2="18" stroke-width="1"/><line x1="16" y1="14" x2="21" y2="18" stroke-width="1"/><circle cx="8" cy="22" r="1" fill="#00ffc8" opacity=".6"/><circle cx="24" cy="22" r="1" fill="#00ffc8" opacity=".6"/><line x1="11" y1="18" x2="8" y2="22" stroke-width=".8" opacity=".6"/><line x1="21" y1="18" x2="24" y2="22" stroke-width=".8" opacity=".6"/></svg></div>
  <div><h1>BẢNG ĐIỀU KHIỂN HYBRID-NIDS</h1>
    <div class="sub"><span class="tag">🛡️ <span class="hl-suri">SURICATA</span> + <span class="hl-ai">AI FOREST</span></span><span class="tag">🏫 Mạng trường học</span></div></div>
  <div class="sysbadge" style="position:absolute;left:50%;transform:translateX(-50%)"><span id="sysdot" class="dot"></span><span id="systext">Đang kiểm tra…</span></div>
  <div id="user-badge" style="display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.12);padding:6px 14px;border-radius:20px;margin-left:auto">
    <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" style="width:16px;height:16px"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    <span id="user-name" style="color:#fff;font-size:13px;font-weight:600">__USER__</span>
    <a href="/logout" style="color:rgba(255,255,255,.6);font-size:14px;margin-left:6px;text-decoration:none" title="Đăng xuất">⏻</a>
  </div>
</header>

<main>
  <!-- Dieu khien -->
  <section class="card">
    <h2>Điều khiển hệ thống</h2>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">
      <button class="b-start"   onclick="act('start')" style="width:100%"><svg viewBox="0 0 24 24" fill="currentColor"><polygon points="6 4 20 12 6 20 6 4"/></svg>Khởi động toàn bộ</button>
      <button class="b-stop"    onclick="act('stop')" style="width:100%"><svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>Dừng toàn bộ</button>
      <button class="b-restart" onclick="act('restart')" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>Khởi động lại</button>
      <button class="b-alert"   onclick="act('alerts-start')" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>Bật cảnh báo</button>
      <button class="b-mute"    onclick="act('alerts-stop')" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0 1 18 8"/><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/><path d="M18 8a6 6 0 0 0-9.33-5"/><line x1="1" y1="1" x2="23" y2="23"/></svg>Tắt cảnh báo</button>
      <button class="b-test"    onclick="testAlert()" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 6-10 7L2 6"/></svg>Gửi thử cảnh báo</button>
      <button class="b-kibana"  id="btn-kibana" onclick="openKibana()" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>Mở Kibana</button>
      <button class="b-refresh" onclick="refreshAll()" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>Làm mới</button>
    </div>
    <pre id="actionlog" style="margin-top:14px;display:none"></pre>
  </section>

  <div class="row3">
    <!-- Trang thai -->
    <section class="card">
      <h2>Trạng thái dịch vụ</h2>
      <div class="svc"><span class="name">Suricata (nhánh luật)</span><span id="svc-suricata" class="state stopped">—</span></div>
      <div class="svc"><span class="name">RF-21 (nhánh AI)</span><span id="svc-rf21" class="state stopped">—</span></div>
      <div class="svc"><span class="name">Dung hợp lai (Hybrid Fusion)</span><span id="svc-fusion" class="state stopped">—</span></div>
      <div class="svc"><span class="name">Đẩy cảnh báo (Forwarder)</span><span id="svc-forwarder" class="state stopped">—</span></div>
    </section>
    <!-- Suc khoe may -->
    <section class="card">
      <h2>Giám sát hiệu năng máy NIDS</h2>
      <div style="font-size:13px">
        <div>CPU <span id="h-cpu" class="muted">—</span><div class="bar"><i id="h-cpu-bar" style="width:0;background:var(--accent2)"></i></div></div>
        <div style="margin-top:10px">RAM <span id="h-mem" class="muted">—</span><div class="bar"><i id="h-mem-bar" style="width:0;background:var(--accent)"></i></div></div>
        <div style="margin-top:10px">Đĩa <span id="h-disk" class="muted">—</span><div class="bar"><i id="h-disk-bar" style="width:0;background:var(--warn)"></i></div></div>
        <div class="muted" id="h-extra" style="margin-top:10px;font-size:12px"></div>
      </div>
    </section>
    <!-- Phien demo -->
    <section class="card">
      <h2>Phiên demo</h2>
      <label for="session-label">Tên phiên / tên file báo cáo</label>
      <div style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;margin-bottom:10px">
        <input id="session-label" maxlength="100" placeholder="Ví dụ: Demo Port Scan 26-07-2026"/>
        <button class="b-ghost" onclick="sessAction('rename')" title="Lưu tên phiên">Lưu tên</button>
      </div>
      <div id="sess-state" class="muted" style="font-size:13px;margin-bottom:6px">Chưa có phiên đang chạy.</div>
      <div id="sess-operator" style="font-size:12px;color:#374151;margin-bottom:4px;display:none">👤 <span id="sess-op-name"></span></div>
      <div id="sess-timer" style="font-size:12px;color:var(--accent2);font-weight:600;margin-bottom:10px;display:none">⏱️ 00:00</div>
      <div class="stat" id="sess-count" style="color:var(--accent2)">0</div>
      <div class="statlabel">cảnh báo trong phiên</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px">
        <button class="b-start" onclick="sessAction('start')" style="width:100%"><svg viewBox="0 0 24 24" fill="currentColor"><polygon points="6 4 20 12 6 20 6 4"/></svg>Bắt đầu phiên</button>
        <button class="b-stop" onclick="sessAction('end')" style="width:100%"><svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>Kết thúc phiên</button>
        <button class="b-alert" onclick="launchAttack()" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Mô phỏng<br>tấn công</button>
        <button class="b-kibana" onclick="window.open('/report','_blank')" style="width:100%"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>Xuất báo cáo</button>
      </div>
    </section>
  </div>

  <section class="card">
    <h2>Xu hướng hiệu năng vận hành</h2>
    <p class="muted" style="font-size:12px;margin-top:-6px">
      CPU/RAM lấy từ máy NIDS; packet drop lấy từ bộ đếm NIC/kernel; độ trễ chỉ phản ánh suy luận RF-21, không phải độ trễ end-to-end.
    </p>
    <div class="ops-grid">
      <div class="ops-chart">
        <h3>CPU và RAM (%)</h3>
        <div class="value" id="ops-resource-value">Chưa có mẫu đo.</div>
        <svg id="ops-resource-chart" viewBox="0 0 300 100" preserveAspectRatio="none" aria-label="Biểu đồ CPU RAM"></svg>
      </div>
      <div class="ops-chart">
        <h3>Packet drop tích lũy</h3>
        <div class="value" id="ops-drop-value">Chưa đọc được bộ đếm interface.</div>
        <svg id="ops-drop-chart" viewBox="0 0 300 100" preserveAspectRatio="none" aria-label="Biểu đồ packet drop"></svg>
      </div>
      <div class="ops-chart">
        <h3>Độ trễ suy luận RF-21</h3>
        <div class="value" id="ops-latency-value">Chưa có metrics từ detector.</div>
        <svg id="ops-latency-chart" viewBox="0 0 300 100" preserveAspectRatio="none" aria-label="Biểu đồ độ trễ suy luận"></svg>
      </div>
    </div>
  </section>

    <!-- Thong ke tong quan -->
  <section class="card">
      <h2>Thống kê tổng quan</h2>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:8px">
        <div style="text-align:center;padding:16px;background:var(--panel2);border-radius:10px;border:1px solid var(--line)">
          <div class="stat" id="dash-today" style="color:var(--accent2)">0</div><div class="statlabel">Cảnh báo 24 giờ</div></div>
        <div style="text-align:center;padding:16px;background:var(--panel2);border-radius:10px;border:1px solid var(--line)">
          <div class="stat" id="dash-week" style="color:var(--warn)">0</div><div class="statlabel">Cảnh báo 7 ngày</div></div>
        <div style="text-align:center;padding:16px;background:var(--panel2);border-radius:10px;border:1px solid var(--line)">
          <div class="stat" id="dash-month" style="color:var(--navy)">0</div><div class="statlabel">Cảnh báo 30 ngày</div></div>
        <div style="text-align:center;padding:16px;background:var(--panel2);border-radius:10px;border:1px solid var(--line)">
          <div class="stat" id="dash-total">0</div><div class="statlabel">Tổng cảnh báo</div></div>
      </div>
      <div id="dash-source" class="muted" style="font-size:12px;margin-bottom:16px">Nguồn thống kê: đang tải...</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div>
          <h3 style="font-size:13px;color:var(--navy);margin-bottom:8px">Top IP nguồn tấn công</h3>
          <table class="tablewrap" style="width:100%"><thead><tr><th>IP</th><th>Số lần</th></tr></thead>
          <tbody id="dash-top-ips"><tr><td colspan="2" class="muted">Đang tải...</td></tr></tbody></table>
        </div>
        <div>
          <h3 style="font-size:13px;color:var(--navy);margin-bottom:8px">Phân bố mức độ</h3>
          <div id="dash-severity" class="muted">Đang tải...</div>
        </div>
      </div>
    </section>

    <!-- Bieu do xu huong canh bao -->
    <section class="card">
      <h2>Xu hướng cảnh báo (24 giờ)</h2>
      <div id="alert-trend-chart" style="display:grid;grid-template-columns:repeat(24,1fr);gap:2px;align-items:end;height:120px;padding:10px 0;border-bottom:1px solid var(--line)">
      </div>
      <div style="display:flex;justify-content:space-between;font-size:10px;color:#9ca3af;margin-top:4px">
        <span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span>
      </div>
    </section>



  <!-- Danh gia Hybrid co nhan -->
  <section class="card">
    <h2>Đánh giá định lượng ba nhánh trên cùng phiên lab</h2>
    <div class="btns">
      <button class="b-start" onclick="runLabEval()"><svg viewBox="0 0 24 24" fill="currentColor"><polygon points="6 4 20 12 6 20 6 4"/></svg>Chạy đánh giá phiên lab</button>
      <button class="b-alert" onclick="downloadLabEval()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>Tải bảng kết quả</button>
    </div>
    <p class="muted" style="font-size:12px;margin-top:8px">Ba nhánh được đối chiếu trên cùng PCAP, cùng nhãn thời gian và cùng đơn vị sự kiện. Hybrid+ demo bị loại khỏi toàn bộ metric chính thức.</p>
    <pre id="labeval-log" style="margin-top:10px;display:none"></pre>
    <div id="labeval-table" style="margin-top:12px"><span class="muted">Chưa có kết quả. Bấm "Tải bảng kết quả" nếu đã chạy trước đó.</span></div>
  </section>

  <!-- Model Card -->
  <section class="card">
    <h2 style="font-size:18px;font-weight:700;border-bottom:2px solid var(--accent2);padding-bottom:8px">CHỈ SỐ HIỆU NĂNG MÔ HÌNH RANDOM FOREST</h2>
    <div id="metric-cards"><div class="muted">Đang tải…</div></div>
  </section>
  <!-- MITRE ATT&CK Mapping -->
  <section class="card">
    <h2>Ánh xạ MITRE ATT&CK</h2>
    <p style="font-size:12px;color:#52637a;margin:4px 0 12px;">Các kịch bản lab được đối chiếu với MITRE ATT&CK Enterprise để hỗ trợ giải thích cảnh báo và phạm vi phát hiện của từng nhánh.</p>
    <div class="tablewrap" style="overflow:hidden">
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr>
            <th>Vector / kịch bản lab</th>
            <th>Technique ID</th>
            <th>Tactic</th>
            <th>Nhánh phát hiện chính</th>
            <th>Vai trò trong demo</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Quét cổng / dò quét mạng</strong></td>
            <td><code>T1046</code></td>
            <td>Discovery</td>
            <td><span class="tag">Suricata</span> <span class="tag sev-LOW">RF-21</span></td>
            <td>Tạo nhiều flow ngắn để kiểm tra khả năng giám sát.</td>
          </tr>
          <tr>
            <td><strong>Brute-force SSH/RDP</strong></td>
            <td><code>T1110</code></td>
            <td>Credential Access</td>
            <td><span class="tag">Suricata</span></td>
            <td>Minh họa cảnh báo rule-based theo dịch vụ.</td>
          </tr>
          <tr>
            <td><strong>DoS / DDoS có kiểm soát</strong></td>
            <td><code>T1498</code></td>
            <td>Impact</td>
            <td><span class="tag">Suricata</span> <span class="tag sev-LOW">RF-21</span></td>
            <td>Quan sát cảnh báo theo tải và kiểm tra dashboard.</td>
          </tr>
          <tr>
            <td><strong>Fuzzing HTTP</strong></td>
            <td><code>T1190</code></td>
            <td>Initial Access</td>
            <td><span class="tag">Suricata</span></td>
            <td>Đối chiếu với nhóm Fuzzers đã phân tích trong báo cáo.</td>
          </tr>
          <tr>
            <td><strong>Di chuyển ngang</strong></td>
            <td><code>T1021</code></td>
            <td>Lateral Movement</td>
            <td><span class="tag sev-LOW">RF-21</span></td>
            <td>Hướng mở rộng khi có thêm telemetry nội bộ.</td>
          </tr>
          <tr>
            <td><strong>Trích xuất dữ liệu</strong></td>
            <td><code>T1048</code></td>
            <td>Exfiltration</td>
            <td><span class="tag sev-LOW">RF-21</span></td>
            <td>Hướng mở rộng theo mẫu lưu lượng bất thường.</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p style="font-size:11px;color:#7b8797;margin-top:10px;">Nguồn tham chiếu: MITRE ATT&CK Enterprise Matrix, 2024. Bảng này dùng để giải thích phạm vi demo, không thay thế cho đánh giá định lượng ở phiên lab.</p>
  </section>


  <!-- Bieu do + thong ke -->
  <div class="row2">
    <section class="card">
      <h2>Cảnh báo theo thời gian (12 phút gần nhất)</h2>
      <div class="chartwrap"><svg id="chart" width="100%" height="220" viewBox="0 0 640 220" preserveAspectRatio="xMidYMid meet"></svg></div>
      <div class="legend">
        <span class="lg"><span class="sw" style="background:#ef4444"></span>Dung hợp tương quan</span>
        <span class="lg"><span class="sw" style="background:#22d3ee"></span>AI-only</span>
        <span class="lg"><span class="sw" style="background:#f59e0b"></span>Suricata-only</span>
      </div>
      <div class="muted" style="font-size:12px;margin-top:8px">Biểu đồ chỉ lấy 12 phút gần nhất. Nhánh nào không phát sinh cảnh báo trong khoảng này sẽ hiển thị bằng 0.</div>
    </section>
    <section class="card">
      <h2>Thống kê cảnh báo</h2>
      <div class="grid cols" style="gap:12px">
        <div><div id="st-total" class="stat">0</div><div class="statlabel">Tổng trong file</div></div>
        <div><div id="st-fw" class="stat" style="color:var(--accent2)">0</div><div class="statlabel">Ưu tiên gửi</div></div>
        <div><div id="st-crit" class="stat" style="color:var(--crit)">0</div><div class="statlabel">CRITICAL</div></div>
        <div><div id="st-high" class="stat" style="color:var(--high)">0</div><div class="statlabel">HIGH</div></div>
      </div>
      <div class="muted" id="alertsrc" style="margin-top:12px;font-size:12px"></div>
    </section>
  </div>

  <!-- Bang canh bao -->
  <section class="card">
    <h2>Cảnh báo thời gian thực <span class="pill" id="autopill">tự cập nhật 5s</span></h2>
    <div class="filters">
      <select id="f-sev" onchange="renderAlerts()"><option value="">Mọi mức độ</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
      <select id="f-act" onchange="renderAlerts()"><option value="">Mọi loại</option><option value="HYBRID_CORRELATED_ALERT">Dung hợp tương quan</option><option value="HYBRID_PLUS_DEMO_ALERT">Hybrid+ demo</option><option value="AI_ONLY_ALERT">AI-only (RF-21)</option><option value="SURICATA_ONLY_ALERT">Suricata-only</option></select>
      <input id="f-ip" placeholder="Lọc theo IP…" oninput="renderAlerts()"/>
      <label style="display:inline-flex;align-items:center;gap:6px;margin:0"><input type="checkbox" id="f-fw" style="width:auto" onchange="renderAlerts()"/> Chỉ cảnh báo ưu tiên</label>
    </div>
    <div class="tablewrap">
      <table><thead><tr>
        <th>Thời gian (UTC)</th><th>Loại</th><th>Mức độ</th><th>Nguồn</th><th>Đích</th>
        <th>Cổng</th><th>Proto</th><th>Điểm AI</th><th>Phân loại</th><th>Đẩy?</th>
      </tr></thead><tbody id="alertbody">
        <tr><td colspan="10" class="muted">Chưa có cảnh báo.</td></tr>
      </tbody></table>
    </div>
  </section>

  

    

    <!-- Whitelist / Blacklist -->
    <section class="card">
      <h2>Quản lý IP (Whitelist / Blacklist)</h2>
      <div style="display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:12px">
        <input type="text" id="ip-input" placeholder="Nhập địa chỉ IP (ví dụ: 192.168.10.50)" style="padding:10px 14px;border:1.5px solid var(--line);border-radius:8px;font-size:14px">
        <div style="display:flex;gap:6px">
          <button class="b-start" onclick="ipAction('add_wl')" style="font-size:12px;margin-top:0">+ Whitelist</button>
          <button class="b-stop" onclick="ipAction('add_bl')" style="font-size:12px;margin-top:0">+ Blacklist</button>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div>
          <h3 style="font-size:13px;color:var(--ok);margin-bottom:8px">✅ Whitelist (tin cậy)</h3>
          <div id="wl-list" class="muted" style="font-size:13px;max-height:150px;overflow-y:auto">Đang tải...</div>
        </div>
        <div>
          <h3 style="font-size:13px;color:var(--crit);margin-bottom:8px">🚫 Blacklist (chặn)</h3>
          <div id="bl-list" class="muted" style="font-size:13px;max-height:150px;overflow-y:auto">Đang tải...</div>
        </div>
      </div>
    </section>

    <!-- Dieu chinh nguong AI -->
    <section class="card">
      <h2>Nhật ký hành động</h2>
      <div style="max-height:250px;overflow-y:auto">
        <table class="tablewrap" style="width:100%"><thead><tr><th>Thời gian</th><th>Người dùng</th><th>Hành động</th><th>Chi tiết</th></tr></thead>
        <tbody id="audit-log-body"><tr><td colspan="4" class="muted">Đang tải...</td></tr></tbody></table>
      </div>
    </section>

    <!-- Lich su phien -->
    <section class="card">
      <h2>Lịch sử phiên giám sát</h2>
      <div style="max-height:200px;overflow-y:auto">
        <table class="tablewrap" style="width:100%"><thead><tr><th>Bắt đầu</th><th>Kết thúc</th><th>Người điều hành</th><th>Tên phiên</th></tr></thead>
        <tbody id="session-history-body"><tr><td colspan="4" class="muted">Chưa có phiên nào.</td></tr></tbody></table>
      </div>
    </section>


    <section class="card">
    <h2>Cấu hình (.env)</h2>
    <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
      <span class="pill" id="tg-pill">Telegram: —</span>
      <span class="pill" id="dc-pill">Discord: —</span>
      <span class="pill" id="auth-pill">Đăng nhập: —</span>
      <span class="pill on">Chính sách: HYBRID + CRITICAL/HIGH</span>
    </div>
    <div class="row2">
      <div>
        <h2 style="font-size:12px">Sửa nhanh</h2>
        <div id="editform"></div>
        <button class="b-start" style="margin-top:12px" onclick="saveConfig()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>Lưu cấu hình</button>
      </div>
      <div>
        <h2 style="font-size:12px">Toàn bộ (chỉ đọc, secret đã che)</h2>
        <div id="cfgbody" class="muted">Đang tải…</div>
      </div>
    </div>
    <div class="muted" style="margin-top:10px;font-size:12px" id="cfgfile"></div>
  </section>

    <!-- Thong ke tong quan -->
</main>

<div id="toast"></div>

<script>
let _alerts=[], _kibanaUrl="", _editKeys=[];
function toast(msg,ok=true){const box=document.getElementById('toast');const el=document.createElement('div');
  el.className='t '+(ok?'ok':'err');el.textContent=msg;box.appendChild(el);
  setTimeout(()=>{el.style.opacity='0';setTimeout(()=>el.remove(),300)},3800);}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
})[c]);}
function fmt(x){return Number(x||0).toLocaleString('vi-VN');}
function actionLabel(action){
  const labels={
    'HYBRID_CORRELATED_ALERT':'Dung hợp tương quan',
    'HYBRID_PLUS_DEMO_ALERT':'Hybrid+ demo',
    'AI_ONLY_ALERT':'AI-only (RF-21)',
    'SURICATA_ONLY_ALERT':'Suricata-only'
  };
  return labels[action] || action || '—';
}
function branchLabel(name){
  const raw=String(name||'');
  const low=raw.toLowerCase();
  if(low.includes('hybrid correlated')) return 'Dung hợp tương quan';
  if(low.includes('random forest')) return 'Random Forest (AI-only, RF-21)';
  if(low.includes('suricata')) return 'Suricata-only (nhánh luật)';
  return raw || '—';
}
function friendlyText(s){
  return String(s||'')
    .replace(/HYBRID_PLUS_DEMO_ALERT/g,'Hybrid+ demo')
    .replace(/HYBRID_CORRELATED_ALERT/g,'Dung hợp tương quan')
    .replace(/AI_ONLY_ALERT/g,'AI-only (RF-21)')
    .replace(/SURICATA_ONLY_ALERT/g,'Suricata-only')
    .replace(/Hybrid correlated \(AND\)/g,'Dung hợp tương quan')
    .replace(/Hybrid correlated/g,'Dung hợp tương quan')
    .replace(/Hybrid vận hành/g,'Dung hợp tương quan');
}
async function api(path,opts){
  const fetchOpts=Object.assign({credentials:'same-origin',cache:'no-store'}, opts||{});
  const r=await fetch(path,fetchOpts);
  const ct=(r.headers.get('content-type')||'').toLowerCase();
  if(!ct.includes('application/json')){
    if(r.redirected || r.url.includes('/login')){location.href='/login';}
    throw new Error('Máy chủ không trả JSON (HTTP '+r.status+'). Kiểm tra đăng nhập hoặc dịch vụ web panel.');
  }
  const data=await r.json();
  if(!r.ok){throw new Error(data.error||data.message||('HTTP '+r.status));}
  return data;
}
function openKibana(){window.open(_kibanaUrl||("http://"+location.hostname+":5601"),"_blank");}

async function act(action){
  toast('Đang thực hiện: '+action+' …',true);
  const log=document.getElementById('actionlog');
  try{const res=await api('/api/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
    log.style.display='block';log.textContent=(res.output||'(không có output)');
    toast(res.ok?('✔ '+action+' xong'):('✖ '+action+' lỗi'),!!res.ok);
    setTimeout(refreshStatus,800);
  }catch(e){toast('Lỗi mạng: '+e,false);}
}
async function testAlert(){
  toast('Đang gửi thử Telegram + Discord…',true);
  try{const res=await api('/api/test-alert',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    toast('Telegram: '+(res.telegram.ok?'OK':'lỗi')+' · '+res.telegram.message,res.telegram.ok);
    toast('Discord: '+(res.discord.ok?'OK':'lỗi')+' · '+res.discord.message,res.discord.ok);
  }catch(e){toast('Lỗi: '+e,false);}
}
async function sessAction(a){
  const input=document.getElementById('session-label');
  const label=(input?.value||'').trim();
  if((a==='start'||a==='rename')&&!label){
    toast('Hãy nhập tên phiên trước.',false);
    if(input)input.focus();
    return;
  }
  try{
    const res=await api('/api/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:a,label})});
    const message=a==='start'?'▶ Đã bắt đầu phiên':a==='rename'?'✓ Đã lưu tên phiên':'■ Đã kết thúc phiên';
    toast(message,true);
    renderSession(res);refreshAlerts();refreshSessionHistory();
  }catch(e){toast('Lỗi: '+e,false);}
}
async function saveConfig(){
  const vals={};for(const k of _editKeys){const el=document.getElementById('edit-'+k);if(el)vals[k]=el.value;}
  const res=await api('/api/config-update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({values:vals})});
  toast(res.message,res.ok);if(res.ok)refreshConfig();
}
function setSvc(id,s){const el=document.getElementById(id);if(!el)return;
  el.className='state '+(s==='running'?'running':'stopped');el.textContent=(s==='running'?'ĐANG CHẠY':'DỪNG');}

async function refreshStatus(){
  try{const s=await api('/api/status');const dot=document.getElementById('sysdot'),txt=document.getElementById('systext');
    if(!s.control_available){dot.className='dot off';txt.textContent='Chỉ chạy đầy đủ trên Ubuntu';}
    else{const up=s.system==='running';dot.className='dot '+(up?'on':'off');txt.textContent=up?'HỆ THỐNG ĐANG CHẠY':'HỆ THỐNG DỪNG';}
    setSvc('svc-suricata',s.services.suricata);setSvc('svc-rf21',s.services.rf21);
    setSvc('svc-fusion',s.services.fusion);setSvc('svc-forwarder',s.services.forwarder);
  }catch(e){}
}
async function refreshHealth(){
  try{const h=await api('/api/health');
    const set=(id,bar,v)=>{const t=document.getElementById(id),b=document.getElementById(bar);
      if(v==null){t.textContent='(không đọc được)';return;}t.textContent=v+'%';
      b.style.width=Math.min(100,v)+'%';b.style.background=v>85?'#ef4444':v>65?'#f59e0b':undefined||b.style.background;};
    set('h-cpu','h-cpu-bar',h.cpu_percent);set('h-mem','h-mem-bar',h.mem_percent);set('h-disk','h-disk-bar',h.disk_percent);
    let ex=[];if(h.disk_free_gb!=null)ex.push('Đĩa trống: '+h.disk_free_gb+' GB');
    if(h.mem_total_gb)ex.push('RAM: '+h.mem_total_gb+' GB');if(h.loadavg)ex.push('Load: '+h.loadavg.join(' / '));
    if(h.packet_drop_total!=null)ex.push('Packet drop: '+Number(h.packet_drop_total).toLocaleString());
    if(h.inference_latency_ms_per_flow!=null)ex.push('RF-21: '+Number(h.inference_latency_ms_per_flow).toFixed(4)+' ms/flow');
    if(h.throughput_flows_per_second!=null)ex.push(Number(h.throughput_flows_per_second).toFixed(1)+' flow/s');
    document.getElementById('h-extra').textContent=ex.join(' · ');
    renderOpsCharts(h);
  }catch(e){}
}
function seriesPoints(values,maxValue){
  const clean=values.map(v=>v==null?null:Number(v));
  const valid=clean.filter(v=>Number.isFinite(v));
  if(!valid.length)return '';
  const max=Math.max(Number(maxValue)||0,...valid,1);
  const n=Math.max(clean.length-1,1);
  return clean.map((v,i)=>{
    if(!Number.isFinite(v))return null;
    const x=(i/n)*300;
    const y=96-(Math.max(0,v)/max)*90;
    return x.toFixed(1)+','+y.toFixed(1);
  }).filter(Boolean).join(' ');
}
function drawOpsChart(id,series,maxValue){
  const svg=document.getElementById(id);if(!svg)return;
  let body='<line class="axis" x1="0" y1="96" x2="300" y2="96"></line>';
  series.forEach((item,i)=>{
    const pts=seriesPoints(item.values,maxValue);
    if(pts)body+='<polyline class="line-'+String.fromCharCode(97+i)+'" points="'+pts+'"></polyline>';
  });
  svg.innerHTML=body;
}
function renderOpsCharts(h){
  const hist=Array.isArray(h.history)?h.history:[];
  drawOpsChart('ops-resource-chart',[
    {values:hist.map(x=>x.cpu_percent)},
    {values:hist.map(x=>x.mem_percent)}
  ],100);
  const rv=document.getElementById('ops-resource-value');
  if(rv)rv.textContent='CPU '+(h.cpu_percent??'—')+'% · RAM '+(h.mem_percent??'—')+'%';

  const drops=hist.map(x=>x.packet_drop_total);
  drawOpsChart('ops-drop-chart',[{values:drops}],null);
  const dv=document.getElementById('ops-drop-value');
  if(dv)dv.textContent=(h.interface?('Interface '+h.interface+' · '):'')+
    (h.packet_drop_total==null?'chưa đọc được':Number(h.packet_drop_total).toLocaleString()+' packet tích lũy');

  drawOpsChart('ops-latency-chart',[
    {values:hist.map(x=>x.inference_latency_ms_per_flow)}
  ],null);
  const lv=document.getElementById('ops-latency-value');
  if(lv)lv.textContent=h.inference_latency_ms_per_flow==null?'Chưa có metrics từ detector':
    Number(h.inference_latency_ms_per_flow).toFixed(4)+' ms/flow · '+
    (h.throughput_flows_per_second==null?'—':Number(h.throughput_flows_per_second).toFixed(1)+' flow/s');
}
function renderSession(s){
  const st=document.getElementById('sess-state');
  const timer=document.getElementById('sess-timer');
  const opDiv=document.getElementById('sess-operator');
  const opName=document.getElementById('sess-op-name');
  const nameInput=document.getElementById('session-label');
  if(nameInput&&document.activeElement!==nameInput&&s.label)nameInput.value=s.label;
  if(s.active){
    st.innerHTML='<span style="color:var(--ok)">● Đang chạy</span> '+(s.label?('· '+esc(s.label)):'')+'<br><span class="muted">Từ: '+esc((s.started_at||'').replace('T',' ').slice(0,19))+'</span>';
    if(s.operator&&opDiv){opDiv.style.display='block';opName.textContent=s.operator;}
    timer.style.display='block';
    if(!window._sessStart)window._sessStart=new Date(s.started_at||Date.now());
    if(!window._sessInterval){window._sessInterval=setInterval(()=>{
      const d=Math.floor((Date.now()-window._sessStart.getTime())/1000);
      const mm=String(Math.floor(d/60)).padStart(2,'0');
      const ss=String(d%60).padStart(2,'0');
      timer.textContent='\u23F1\uFE0F '+mm+':'+ss;
    },1000);}
  }else{
    st.textContent='Chưa có phiên đang chạy.';
    timer.style.display='none';
    if(opDiv)opDiv.style.display='none';
    if(window._sessInterval){clearInterval(window._sessInterval);window._sessInterval=null;window._sessStart=null;}
  }
}
async function launchAttack(){
  if(!confirm('Mô phỏng tấn công từ Kali (192.168.10.101)?\nHệ thống sẽ phát hiện và cảnh báo realtime.'))return;
  toast('Đang kích hoạt mô phỏng tấn công...',true);
  try{
    const res=await api('/api/launch-attack',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    toast(res.ok?'Tấn công đã kích hoạt! Theo dõi cảnh báo...':'Lỗi: '+(res.message||''),res.ok);
  }catch(e){toast('Lỗi kết nối: '+e,false);}
}
async function refreshMetrics(){
  try{const m=await api('/api/metrics');const box=document.getElementById('metric-cards');
    if(!m.available){box.innerHTML='<div class="muted">Chưa có models/metrics.json</div>';return;}
    const pc=(x)=>x==null?'—':(x*100).toFixed(2)+'%';
    const total=(m.tp||0)+(m.fp||0)+(m.fn||0)+(m.tn||0);
    box.innerHTML=`
<div style="font-size:12px;color:#64748b;margin-bottom:16px">Kiểm thử Hold-out UNSW-NB15 · ${total.toLocaleString()} mẫu luồng mạng · Mô hình RF-41 chính thức</div>
<table style="width:100%;table-layout:fixed;border-collapse:collapse">
<tr style="border-bottom:1px solid #e2e8f0">
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${pc(m.accuracy)}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Độ chính xác</div><div style="font-size:10px;color:#94a3b8">(Accuracy)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${pc(m.precision)}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Độ chuẩn xác</div><div style="font-size:10px;color:#94a3b8">(Precision)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${pc(m.recall)}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Độ phủ</div><div style="font-size:10px;color:#94a3b8">(Recall)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${pc(m.f1)}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Điểm F1</div><div style="font-size:10px;color:#94a3b8">(F1-Score)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#e74c3c">${pc(m.fpr)}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Tỉ lệ cảnh báo sai</div><div style="font-size:10px;color:#94a3b8">(FPR)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${pc(m.roc_auc)}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Đường cong ROC</div><div style="font-size:10px;color:#94a3b8">(ROC-AUC)</div></td>
</tr>
<tr>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${m.threshold?m.threshold.toFixed(3):'—'}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Ngưỡng quyết định</div><div style="font-size:10px;color:#94a3b8">(Threshold)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#1b3a5c">${total.toLocaleString()}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Tổng mẫu</div><div style="font-size:10px;color:#94a3b8">(Samples)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#059669">${(m.tp||0).toLocaleString()}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Phát hiện đúng</div><div style="font-size:10px;color:#94a3b8">(True Positive)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#dc2626">${(m.fp||0).toLocaleString()}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Cảnh báo sai</div><div style="font-size:10px;color:#94a3b8">(False Positive)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#ea580c">${(m.fn||0).toLocaleString()}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Bỏ sót tấn công</div><div style="font-size:10px;color:#94a3b8">(False Negative)</div></td>
<td style="text-align:center;padding:20px 6px"><div style="font-size:26px;font-weight:700;color:#059669">${(m.tn||0).toLocaleString()}</div><div style="margin-top:6px;font-size:11px;color:#475569;font-weight:600">Loại bỏ đúng</div><div style="font-size:10px;color:#94a3b8">(True Negative)</div></td>
</tr>
</table>`;
  }catch(e){}
}
function mdTableBlockToHtml(lines){
  if(!lines || !lines.length)return '';
  let html='<div class="tablewrap"><table>';
  let head=true;
  for(const ln of lines){
    if(/^\|[\s:|-]+\|?$/.test(ln)){head=false;continue;}
    const cells=ln.split('|').slice(1,-1).map(c=>c.trim());
    const tag=head?'th':'td';
    html+='<tr>'+cells.map(c=>'<'+tag+'>'+escapeHtml(friendlyText(plainMd(c)))+'</'+tag+'>').join('')+'</tr>';
    head=false;
  }
  return html+'</table></div>';
}
function parseMdTable(lines){
  const rows=(lines||[]).filter(l=>l.startsWith('|')&&!/^\|[\s:|-]+\|?$/.test(l));
  if(rows.length<2)return {headers:[], items:[]};
  const parse=l=>l.split('|').slice(1,-1).map(c=>plainMd(c));
  const headers=parse(rows[0]);
  const items=rows.slice(1).map(r=>{
    const cells=parse(r);const obj={};
    headers.forEach((h,i)=>obj[h]=cells[i]||'');
    return obj;
  });
  return {headers, items};
}
function tableVal(row,name){
  const key=Object.keys(row||{}).find(k=>k.toLowerCase()===name.toLowerCase());
  return key?row[key]:'';
}
function numFmt(v,digits=4){
  const n=parseFloat(String(v||'').replace(',','.'));
  return Number.isFinite(n)?n.toFixed(digits):'0.0000';
}
function pctFmt(v){
  const n=parseFloat(String(v||'').replace(',','.'));
  return Number.isFinite(n)?(n*100).toFixed(2)+'%':'0.00%';
}
function extractMdTables(md){
  const blocks=[];let cur=[];
  for(const raw of md.split('\n')){
    const ln=raw.trim();
    if(ln.startsWith('|')){
      const startsNew=/^\|\s*(Nhánh|Kiểm toán ghép)\s*\|/.test(ln);
      if(cur.length && startsNew){blocks.push(cur);cur=[];}
      cur.push(ln);continue;
    }
    if(cur.length){blocks.push(cur);cur=[];}
  }
  if(cur.length)blocks.push(cur);
  return blocks;
}
function mdSummaryItems(md){
  const keep=['- Tổng flow','- Flow ID','- RF và Hybrid','- Alert tương quan'];
  return md.split('\n').map(l=>l.trim()).filter(l=>keep.some(k=>l.startsWith(k)));
}
function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function plainMd(s){
  return String(s||'')
    .replace(/\\\*/g,'')
    .replace(/\*\*/g,'')
    .replace(/`/g,'')
    .replace(/\\_/g,'_')
    .replace(/\s+/g,' ')
    .trim();
}
function renderLabEval(md){
  const box=document.getElementById('labeval-table');
  const raw=document.getElementById('labeval-log');
  if(raw){raw.style.display='none';raw.textContent='';}
  if(!md){box.innerHTML='<span class="muted">Chưa có kết quả. Chạy đánh giá hoặc kiểm tra logs/hybrid_labeled_metrics.md.</span>';return;}
  let tables=extractMdTables(md);
  if(!tables.length){box.innerHTML='<span class="muted">Chưa đọc được bảng metric từ logs/hybrid_labeled_metrics.md.</span>';return;}
  let metricTable=tables[0]||[];
  let auditTable=tables[1]||[];
  const auditIdx=metricTable.findIndex(l=>/^\|\s*Kiểm toán ghép\s*\|/.test(l));
  if(auditIdx>=0){
    auditTable=metricTable.slice(auditIdx).concat(auditTable);
    metricTable=metricTable.slice(0,auditIdx);
  }
  const summary=mdSummaryItems(md);
  const parsed=parseMdTable(metricTable);
  const branchRows=parsed.items.filter(r=>tableVal(r,'Nhánh')&&!tableVal(r,'Nhánh').toLowerCase().includes('kiểm toán'));
  const labels=['Dữ liệu phiên','Cách ghép','Phạm vi metric','Demo minh họa'];
  const summaryHtml=summary.length?'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;margin:12px 0 14px">'+
    summary.slice(0,4).map((x,i)=>'<div style="padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:#f8fafc;line-height:1.35;min-height:70px">'+
      '<div style="font-size:11px;color:#64748b;font-weight:800;text-transform:uppercase;letter-spacing:.02em;margin-bottom:6px">'+escapeHtml(labels[i]||'Tóm tắt')+'</div>'+
      '<div style="font-size:13px;color:var(--ink)">'+escapeHtml(plainMd(x.replace(/^\-\s*/,'')))+'</div></div>').join('')+
    '</div>':'';
  const branchCards=branchRows.length?'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin:10px 0 14px">'+
    branchRows.map(r=>{
      const name=tableVal(r,'Nhánh');
      const low=name.toLowerCase();
      const color=low.includes('suricata')?'#f59e0b':(low.includes('hybrid')?'#16a34a':'#2563eb');
      const role=low.includes('suricata')?'Nhánh luật':(low.includes('hybrid')?'Dung hợp tương quan':'Nhánh AI RF-21');
      return '<div style="border:1px solid var(--line);border-left:5px solid '+color+';border-radius:10px;background:#fff;padding:14px;box-shadow:0 1px 2px rgba(15,23,42,.04)">'+
        '<div style="display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:10px">'+
          '<div style="font-size:14px;font-weight:900;color:var(--navy)">'+escapeHtml(branchLabel(name))+'</div>'+
          '<span style="font-size:11px;font-weight:800;color:'+color+';background:#f8fafc;border:1px solid var(--line);border-radius:999px;padding:4px 8px">'+role+'</span>'+
        '</div>'+
        '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px">'+
          '<div><div style="font-size:11px;color:#64748b;font-weight:700">Recall</div><div style="font-size:22px;font-weight:900;color:'+color+'">'+pctFmt(tableVal(r,'Recall'))+'</div></div>'+
          '<div><div style="font-size:11px;color:#64748b;font-weight:700">FPR</div><div style="font-size:22px;font-weight:900;color:#dc2626">'+pctFmt(tableVal(r,'FPR'))+'</div></div>'+
          '<div><div style="font-size:11px;color:#64748b;font-weight:700">Precision</div><div style="font-size:15px;font-weight:800">'+pctFmt(tableVal(r,'Precision'))+'</div></div>'+
          '<div><div style="font-size:11px;color:#64748b;font-weight:700">TP / FP / FN</div><div style="font-size:15px;font-weight:800">'+escapeHtml(tableVal(r,'TP'))+' / '+escapeHtml(tableVal(r,'FP'))+' / '+escapeHtml(tableVal(r,'FN'))+'</div></div>'+
        '</div>'+
      '</div>';
    }).join('')+'</div>':'';
  box.innerHTML=
    '<div style="padding:12px 14px;border-left:4px solid #2f6fd0;background:#eff6ff;border-radius:8px;font-size:13px;line-height:1.45;margin-bottom:12px">'+
    '<strong>Kết luận nhanh:</strong> Bảng này đối chiếu Suricata-only, AI-only (RF-21) và dung hợp tương quan trên cùng một phiên lab có nhãn. Hybrid+ demo chỉ dùng để trình diễn, không đưa vào metric chính thức. Kết quả không thay thế đánh giá trên lưu lượng vận hành thật.</div>'+
    summaryHtml+
    branchCards+
    '<details style="margin-top:8px"><summary style="cursor:pointer;font-weight:900;color:var(--navy);font-size:13px">Xem bảng metric chi tiết</summary><div style="margin-top:8px">'+mdTableBlockToHtml(metricTable)+'</div></details>'+
    (auditTable.length?'<details style="margin-top:8px"><summary style="cursor:pointer;font-weight:900;color:var(--navy);font-size:13px">Xem kiểm toán ghép alert-flow</summary><div style="margin-top:8px">'+mdTableBlockToHtml(auditTable)+'</div></details>':'')+
    '<div style="margin-top:10px;padding:10px 14px;background:#f8fafc;border:1px solid var(--line);border-radius:8px;font-size:12px;color:#52637a"><strong>Ghi chú:</strong> Chỉ diễn giải khi PCAP, eve.json và labeling/attack_windows.csv thuộc cùng một phiên. Dung hợp tương quan nghĩa là Suricata và RF-21 cùng xác nhận trên cùng flow hoặc phiên ghép.</div>';
  // Dong tom tat dong tu bang
  try{
    const lines=metricTable.filter(l=>l.startsWith('|')&&!l.includes('---'));
    if(lines.length>=4){
      const parse=l=>l.split('|').map(c=>c.trim()).filter(c=>c);
      const hdr=parse(lines[0]);
      const fprIdx=hdr.findIndex(h=>h.toUpperCase().includes('FPR'));
      const recIdx=hdr.findIndex(h=>h.toUpperCase().includes('RECALL'));
      if(fprIdx>=0){
        const rows=lines.slice(1).map(parse);
        const suri=rows.find(r=>r[0]&&r[0].toLowerCase().includes('suricata'));
        const rf=rows.find(r=>r[0]&&r[0].toLowerCase().includes('forest'));
        const hyb=rows.find(r=>r[0]&&r[0].toLowerCase().includes('hybrid'));
        if(suri&&rf&&hyb){
          const suriFPR=(parseFloat(suri[fprIdx])*100).toFixed(2);
          const rfFPR=(parseFloat(rf[fprIdx])*100).toFixed(2);
          const hybFPR=(parseFloat(hyb[fprIdx])*100).toFixed(2);
          const hybRec=recIdx>=0?parseFloat(hyb[recIdx]).toFixed(4):'N/A';
          box.innerHTML+='<div style="margin-top:12px;padding:10px 14px;background:#eff6ff;border-left:4px solid #2f6fd0;border-radius:6px;font-size:13px"><strong>Nhận xét:</strong> FPR Suricata-only = '+suriFPR+'%; AI-only RF-21 = '+rfFPR+'%; dung hợp tương quan = '+hybFPR+'%. Recall dung hợp = '+hybRec+'. Đây là kết quả đối chiếu trên cùng phiên lab, không phải hiệu năng tuyệt đối trên lưu lượng vận hành thật.</div>';
        }
      }
    }
  }catch(e){}
}
async function loadLabEval(){
  try{const d=await api('/api/lab-eval');
    if(d.available)renderLabEval(d.markdown||'');
  }catch(e){}
}
async function downloadLabEval(){
  try{const d=await api('/api/lab-eval');
    if(!d.available){toast('Chưa có bảng kết quả — hãy chạy đánh giá trước.',false);return;}
    renderLabEval(d.markdown||'');
    const blob=new Blob([d.markdown],{type:'text/markdown'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download='hybrid_labeled_metrics.md';
    document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
    toast('Đã tải bảng kết quả!',true);
  }catch(e){toast('Lỗi tải bảng: '+e,false);}
}
async function runLabEval(){
  const log=document.getElementById('labeval-log');
  log.style.display='block';
  log.textContent='Đang chạy đánh giá phiên lab... Vui lòng chờ, kết quả sẽ cập nhật vào bảng bên dưới.';
  toast('Bắt đầu chạy đánh giá Hybrid theo phiên lab…',true);
  try{const res=await api('/api/run-lab-eval',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    log.style.display='none';log.textContent='';
    toast(res.ok?'✔ Đánh giá xong':'✖ Đánh giá lỗi (xem log)',!!res.ok);
    loadLabEval();
  }catch(e){log.style.display='none';log.textContent='';toast('Lỗi: '+e.message,false);}
}
function drawChart(series){
  const svg=document.getElementById('chart');const W=640,H=220,pad=30;
  svg.innerHTML='';
  if(!series||!series.length){svg.innerHTML='<text x="320" y="110" fill="#8aa0c2" text-anchor="middle">Chưa có dữ liệu</text>';return;}
  const max=Math.max(1,...series.map(s=>s.hybrid+s.ai+s.suricata));
  const bw=(W-pad*2)/series.length*0.6,gap=(W-pad*2)/series.length;
  const colors={suricata:'#f59e0b',ai:'#22d3ee',hybrid:'#ef4444'};
  // truc
  svg.innerHTML+='<line x1="'+pad+'" y1="'+(H-pad)+'" x2="'+(W-pad)+'" y2="'+(H-pad)+'" stroke="#1e2b45"/>';
  series.forEach((s,i)=>{
    const x=pad+i*gap+gap*0.2;let y=H-pad;
    ['suricata','ai','hybrid'].forEach(k=>{const h=(s[k]/max)*(H-pad*2);y-=h;
      if(h>0)svg.innerHTML+='<rect x="'+x+'" y="'+y+'" width="'+bw+'" height="'+h+'" fill="'+colors[k]+'" rx="2"/>';});
    svg.innerHTML+='<text x="'+(x+bw/2)+'" y="'+(H-pad+14)+'" fill="#8aa0c2" font-size="9" text-anchor="middle">'+s.t+'</text>';
    const tot=s.hybrid+s.ai+s.suricata;
    if(tot>0)svg.innerHTML+='<text x="'+(x+bw/2)+'" y="'+(y-4)+'" fill="#e6edf7" font-size="10" text-anchor="middle">'+tot+'</text>';
  });
}
function td(v){const d=document.createElement('td');d.textContent=(v===null||v===undefined||v==='')?'—':v;return d;}
function renderAlerts(){
  const sev=document.getElementById('f-sev').value,actv=document.getElementById('f-act').value,
    ip=document.getElementById('f-ip').value.trim(),fwOnly=document.getElementById('f-fw').checked;
  const body=document.getElementById('alertbody');body.innerHTML='';
  const rows=_alerts.filter(a=>(!sev||a.severity===sev)&&(!actv||a.action===actv)
    &&(!ip||a.src.includes(ip)||a.dst.includes(ip))&&(!fwOnly||a.forwarded));
  if(!rows.length){body.innerHTML='<tr><td colspan="10" class="muted">Không có cảnh báo khớp bộ lọc.</td></tr>';return;}
  for(const a of rows){const tr=document.createElement('tr');
    tr.appendChild(td(a.timestamp));tr.appendChild(td(actionLabel(a.action)));
    const sv=document.createElement('td');sv.innerHTML='<span class="tag sev-'+(a.severity||'-')+'">'+(a.severity||'—')+'</span>';tr.appendChild(sv);
    tr.appendChild(td(a.src));tr.appendChild(td(a.dst));tr.appendChild(td(a.port));
    tr.appendChild(td(a.proto));tr.appendChild(td(a.score));tr.appendChild(td(a.category));
    const fw=document.createElement('td');fw.innerHTML=a.forwarded?'<span class="fw">✔ ưu tiên</span>':'<span class="muted">—</span>';tr.appendChild(fw);
    body.appendChild(tr);}
}
async function refreshAlerts(){
  try{
    const d=await api('/api/alerts?limit=200&_ts='+Date.now());
    _alerts=Array.isArray(d.alerts)?d.alerts:[];
    const sev=d.severity_counts||{};
    const total=Number(d.count??d.total??0);
    const forwarded=Number(d.forwarded??d.priority_count??0);
    const critical=Number(sev.CRITICAL??sev.critical??0);
    const high=Number(sev.HIGH??sev.high??0);
    document.getElementById('st-total').textContent=fmt(total);
    document.getElementById('st-fw').textContent=fmt(forwarded);
    document.getElementById('st-crit').textContent=fmt(critical);
    document.getElementById('st-high').textContent=fmt(high);
    const sess=document.getElementById('sess-count'); if(sess) sess.textContent=d.session_count||0;
    const shown=Number(d.display_count??_alerts.length);
    let visibleNote=' Chưa có cảnh báo hợp lệ trong file.';
    if(total>0 && shown<total){
      visibleNote=' Bảng realtime bên dưới chỉ hiển thị '+fmt(shown)+' cảnh báo mới nhất; tổng trong file là '+fmt(total)+' cảnh báo.';
    }else if(total>0){
      visibleNote=' Bảng realtime bên dưới đang hiển thị toàn bộ '+fmt(total)+' cảnh báo trong file.';
    }
    const src=document.getElementById('alertsrc');
    if(src){
      src.textContent='Nguồn thống kê realtime: '+(d.log_path||'(chưa xác định)')+
        (d.log_exists===false?' (chưa tồn tại).':'.')+visibleNote;
    }
    drawChart(Array.isArray(d.timeline)?d.timeline:[]);
    renderAlerts();
  }catch(e){
    const src=document.getElementById('alertsrc');
    if(src){src.textContent='Lỗi tải thống kê cảnh báo: '+(e&&e.message?e.message:e);}
    console.error('refreshAlerts failed',e);
  }
}
async function refreshConfig(){
  try{const c=await api('/api/config');_kibanaUrl=c.kibana_url||"";_editKeys=c.editable_keys||[];
    const tg=document.getElementById('tg-pill'),dc=document.getElementById('dc-pill'),au=document.getElementById('auth-pill');
    tg.className='pill '+(c.telegram_ready?'on':'off');tg.textContent='Telegram: '+(c.telegram_ready?'sẵn sàng':'chưa cấu hình');
    dc.className='pill '+(c.discord_ready?'on':'off');dc.textContent='Discord: '+(c.discord_ready?'sẵn sàng':'chưa cấu hình');
    au.className='pill '+(c.auth_enabled?'on':'off');au.textContent='Đăng nhập: '+(c.auth_enabled?'BẬT':'tắt');
    const kb=document.getElementById('btn-kibana');if(kb&&_kibanaUrl)kb.title='Mở '+_kibanaUrl;
    // form sua
    const ef=document.getElementById('editform');ef.innerHTML='';
    for(const k of _editKeys){const wrap=document.createElement('div');
      wrap.innerHTML='<label>'+k+'</label><input id="edit-'+k+'" value="'+(c.editable[k]||'').replace(/"/g,'&quot;')+'"/>';ef.appendChild(wrap);}
    // toan bo
    const box=document.getElementById('cfgbody');box.innerHTML='';
    const keys=Object.keys(c.values||{});
    if(!keys.length)box.innerHTML='<span class="muted">Chưa có .env. Sao chép từ deployment/hybrid-nids.env.example</span>';
    for(const k of keys){const row=document.createElement('div');row.className='kv';
      row.innerHTML='<span class="k">'+k+'</span><span class="v">'+(c.values[k]||'∅')+'</span>';box.appendChild(row);}
    document.getElementById('cfgfile').textContent='File: '+c.env_file+(c.env_exists?'':' (chưa tồn tại)');
  }catch(e){}
}
async function refreshSession(){try{renderSession(await api('/api/session'));}catch(e){}}

// --- Dashboard Summary ---
async function refreshDashboard(){
  try{const d=await api('/api/dashboard-summary');
    const fmt=(x)=>(x||0).toLocaleString('vi-VN');
    document.getElementById('dash-today').textContent=fmt(d.today);
    document.getElementById('dash-week').textContent=fmt(d.week);
    document.getElementById('dash-month').textContent=fmt(d.month);
    document.getElementById('dash-total').textContent=fmt(d.total);
    const src=document.getElementById('dash-source');
    if(src){
      const note=d.window_note?'; '+d.window_note:'';
      src.textContent=(d.source==='elasticsearch')
        ? 'Nguồn thống kê: Elasticsearch/Kibana index ' + (d.index_pattern||'hybrid-nids-alerts-*') + note
        : 'Nguồn thống kê: file local logs/hybrid_alerts.jsonl (Elasticsearch chưa sẵn sàng)' + note;
    }
    // Top IPs
    const tbody=document.getElementById('dash-top-ips');
    tbody.innerHTML=(d.top_ips||[]).map(x=>'<tr><td style="font-family:monospace">'+x.ip+'</td><td><strong>'+x.count+'</strong></td></tr>').join('')||'<tr><td colspan="2" class="muted">Không có dữ liệu</td></tr>';
    // Severity
    const sev=d.severity||{};
    const sevDiv=document.getElementById('dash-severity');
    const colors={CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#2563eb',INFO:'#6b7280'};
    sevDiv.innerHTML=Object.entries(sev).map(([k,v])=>'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span style="width:10px;height:10px;border-radius:50%;background:'+(colors[k]||'#999')+'"></span><span style="font-size:13px">'+k+': <strong>'+v+'</strong></span></div>').join('')||'<span class="muted">Không có</span>';
  }catch(e){}
}

// --- Alert Trend Chart ---
async function refreshTrend(){
  try{const d=await api('/api/alert-trend');
    const chart=document.getElementById('alert-trend-chart');
    const hours=d.hours||[];
    const maxV=Math.max(...hours.map(h=>h.count),1);
    chart.innerHTML=hours.map(h=>{
      const pct=Math.max((h.count/maxV)*100,2);
      const color=h.count>0?'var(--accent2)':'#e5e7eb';
      return '<div style="background:'+color+';height:'+pct+'%;border-radius:3px 3px 0 0;min-height:2px" title="'+h.hour+'h: '+h.count+' cảnh báo"></div>';
    }).join('');
  }catch(e){}
}

// --- Whitelist / Blacklist ---
async function refreshIPLists(){
  try{const d=await api('/api/ip-lists');
    const wl=document.getElementById('wl-list');
    const bl=document.getElementById('bl-list');
    wl.innerHTML=(d.whitelist||[]).map(ip=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #f3f4f6"><span style="font-family:monospace">'+ip+'</span><button onclick="ipAction(\'del_wl\',\''+ip+'\') " style="background:none;border:none;color:#dc2626;cursor:pointer;font-size:12px;margin-top:0;padding:2px 6px">✕</button></div>').join('')||'<span class="muted">Trống</span>';
    bl.innerHTML=(d.blacklist||[]).map(ip=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #f3f4f6"><span style="font-family:monospace">'+ip+'</span><button onclick="ipAction(\'del_bl\',\''+ip+'\') " style="background:none;border:none;color:#dc2626;cursor:pointer;font-size:12px;margin-top:0;padding:2px 6px">✕</button></div>').join('')||'<span class="muted">Trống</span>';
  }catch(e){}
}
async function ipAction(action,ip){
  ip=ip||document.getElementById('ip-input').value.trim();
  if(!ip){toast('Nhập địa chỉ IP',false);return;}
  await api('/api/ip-lists',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,ip})});
  document.getElementById('ip-input').value='';
  refreshIPLists();toast('Đã cập nhật!',true);
}

// --- Threshold ---
async function refreshThreshold(){
  try{const d=await api('/api/threshold');
    const val=d.threshold||'0.8708';
    document.getElementById('threshold-slider').value=val;
    document.getElementById('threshold-val').textContent=val;
  }catch(e){}
}
async function saveThreshold(){
  const val=document.getElementById('threshold-slider').value;
  const res=await api('/api/threshold',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:val})});
  if(res.ok)toast('Đã lưu ngưỡng: '+res.threshold,true);
  else toast(res.message||'Lỗi',false);
}

// --- Audit Log ---
async function refreshAuditLog(){
  try{const d=await api('/api/audit-log');
    const tbody=document.getElementById('audit-log-body');
    const entries=(d.entries||[]).slice(-50).reverse();
    tbody.innerHTML=entries.map(e=>'<tr><td style="font-size:12px;white-space:nowrap">'+esc((e.timestamp||'').replace('T',' ').slice(0,19))+'</td><td>'+esc(e.user)+'</td><td>'+esc(e.action)+'</td><td style="font-size:12px">'+esc(e.detail)+'</td></tr>').join('')||'<tr><td colspan="4" class="muted">Chưa có hoạt động</td></tr>';
  }catch(e){}
}

// --- Session History ---
async function refreshSessionHistory(){
  try{const d=await api('/api/session-history');
    const tbody=document.getElementById('session-history-body');
    const sessions=(d.sessions||[]).slice(-20).reverse();
    tbody.innerHTML=sessions.map(s=>'<tr><td style="font-size:12px">'+esc((s.started_at||'').replace('T',' ').slice(0,19))+'</td><td style="font-size:12px">'+esc((s.ended_at||'').replace('T',' ').slice(0,19))+'</td><td>'+esc(s.operator)+'</td><td>'+esc(s.label)+'</td></tr>').join('')||'<tr><td colspan="4" class="muted">Chưa có phiên nào.</td></tr>';
  }catch(e){}
}

function refreshAll(){refreshStatus();refreshAlerts();refreshConfig();refreshMetrics();refreshHealth();refreshSession();loadLabEval();refreshDashboard();refreshTrend();refreshIPLists();refreshThreshold();refreshAuditLog();refreshSessionHistory();}
refreshAll();
setTimeout(refreshAlerts,800);
setInterval(refreshStatus,5000);setInterval(refreshAlerts,5000);
setInterval(refreshHealth,7000);setInterval(refreshConfig,15000);
setInterval(refreshDashboard,10000);setInterval(refreshTrend,15000);setInterval(refreshAuditLog,10000);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Hybrid-NIDS Web Control Panel v2")
    parser.add_argument("--host", default=os.getenv("PANEL_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PANEL_PORT", "8080")))
    parser.add_argument("--open", action="store_true", help="Tu mo trinh duyet")
    args = parser.parse_args()

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass

    load_ip_lists()
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), PanelHandler)
    url_host = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = f"http://{url_host}:{args.port}"
    print("=" * 60)
    print(" HYBRID-NIDS WEB CONTROL PANEL v2")
    print("=" * 60)
    print(f" Dang chay tai : {url}")
    print(f" Truy cap LAN  : http://<IP-may-NIDS>:{args.port}")
    print(f" Control script: {CONTROL_SCRIPT}  ({'OK' if is_using_control_script() else 'KHONG KHA DUNG (khong phai Ubuntu?)'})")
    print(f" Alert log     : {FUSED_ALERT_LOG}")
    print(f" Metrics       : {METRICS_FILE}  ({'co' if METRICS_FILE.exists() else 'chua co'})")
    print(f" Env file      : {ENV_FILE}")
    print(f" Dang nhap     : {'BAT (PANEL_USER/PANEL_PASS)' if (PANEL_USER and PANEL_PASS) else 'tat'}")
    print(" Nhan Ctrl+C de dung.")
    print("=" * 60)

    if args.open:
        def _open():
            time.sleep(1.0)
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Da dung web panel.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
