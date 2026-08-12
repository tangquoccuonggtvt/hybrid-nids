#!/usr/bin/env bash
# =============================================================================
# nids_demo_start.sh
# Khong dung menu. Bat HTTP target va tcpdump capture cho demo Hybrid-NIDS lab.
# =============================================================================
set -euo pipefail

KALI_IP="${KALI_IP:-192.168.10.101}"
NIDS_LAB_IP="${NIDS_LAB_IP:-192.168.10.146}"
IFACE="${IFACE:-ens18}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP="$ROOT_DIR/pcap_traffic/lab_run.pcap"
PID_DIR="$ROOT_DIR/logs/pids"
HTTP_PID="$PID_DIR/lab_http.pid"
TCPDUMP_PID="$PID_DIR/lab_tcpdump.pid"

cd "$ROOT_DIR"
mkdir -p labeling lab_runs logs pcap_traffic suricata_lab "$PID_DIR"
sudo chown -R "$USER:$USER" labeling lab_runs logs pcap_traffic suricata_lab
find scripts -name "*.sh" -exec sed -i 's/\r$//' {} \;
chmod +x scripts/*.sh 2>/dev/null || true

# Stop tien trinh cu neu con
if [ -f "$TCPDUMP_PID" ]; then
  sudo kill -INT "$(cat "$TCPDUMP_PID")" 2>/dev/null || true
  rm -f "$TCPDUMP_PID"
fi
if [ -f "$HTTP_PID" ] && ! kill -0 "$(cat "$HTTP_PID")" 2>/dev/null; then
  rm -f "$HTTP_PID"
fi

# Bat HTTP server tren NIDS lam target neu chua chay
if [ ! -f "$HTTP_PID" ] || ! kill -0 "$(cat "$HTTP_PID")" 2>/dev/null; then
  echo "[*] Bat HTTP server tren NIDS $NIDS_LAB_IP:80"
  cd /tmp
  sudo nohup python3 -m http.server 80 > "$ROOT_DIR/logs/lab_http.out" 2> "$ROOT_DIR/logs/lab_http.err" &
  echo $! > "$HTTP_PID"
  cd "$ROOT_DIR"
  sleep 1
else
  echo "[i] HTTP server da chay PID $(cat "$HTTP_PID")"
fi

curl -I --max-time 5 "http://$NIDS_LAB_IP/" || true

# Bat tcpdump nen, tach khoi terminal
rm -f "$PCAP" "$ROOT_DIR/eve.json"
echo "[*] Xac thuc sudo de bat tcpdump"
sudo -v
echo "[*] Bat tcpdump nen tren $IFACE -> $PCAP"
nohup sudo -n tcpdump -ni "$IFACE" -w "$PCAP" "host $KALI_IP and host $NIDS_LAB_IP" < /dev/null > "$ROOT_DIR/logs/lab_tcpdump.out" 2> "$ROOT_DIR/logs/lab_tcpdump.err" &
echo $! > "$TCPDUMP_PID"
sleep 1

if kill -0 "$(cat "$TCPDUMP_PID")" 2>/dev/null; then
  echo "[OK] Capture dang chay nen PID $(cat "$TCPDUMP_PID")"
  echo "[NEXT] Qua Kali chay: ~/kali_rf21_traffic_tool.sh $NIDS_LAB_IP"
  echo "[NEXT] Khi Kali chay xong, quay lai NIDS chay: bash scripts/nids_demo_finish.sh"
else
  echo "[X] tcpdump khong chay duoc. Loi:"
  cat "$ROOT_DIR/logs/lab_tcpdump.err" 2>/dev/null || true
  exit 1
fi