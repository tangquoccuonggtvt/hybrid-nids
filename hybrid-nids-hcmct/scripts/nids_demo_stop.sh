#!/usr/bin/env bash
# =============================================================================
# nids_demo_stop.sh
# Dung cac tien trinh demo Hybrid-NIDS lab mot cach gon gang.
# =============================================================================
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="$ROOT_DIR/logs/pids"
TCPDUMP_PID="$PID_DIR/lab_tcpdump.pid"
HTTP_PID="$PID_DIR/lab_http.pid"

cd "$ROOT_DIR"
mkdir -p "$PID_DIR" logs

if [ -f "$TCPDUMP_PID" ]; then
  echo "[*] Dung tcpdump PID $(cat "$TCPDUMP_PID")"
  sudo kill -INT "$(cat "$TCPDUMP_PID")" 2>/dev/null || true
  rm -f "$TCPDUMP_PID"
else
  echo "[i] Khong thay PID tcpdump"
fi

if [ -f "$HTTP_PID" ]; then
  echo "[*] Dung HTTP server PID $(cat "$HTTP_PID")"
  sudo kill "$(cat "$HTTP_PID")" 2>/dev/null || true
  rm -f "$HTTP_PID"
else
  echo "[i] Khong thay PID HTTP server"
fi

sudo pkill -f "tcpdump -ni" 2>/dev/null || true
sudo pkill -f "python3 -m http.server 80" 2>/dev/null || true

echo "[OK] Da dung cac tien trinh demo neu co."