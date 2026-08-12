#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
echo "===== PROCESS ====="
ps aux | grep -E "tcpdump|http.server|suricata" | grep -v grep || true
echo "===== FILES ====="
ls -lh pcap_traffic/lab_run.pcap eve.json labeling/attack_windows.csv logs/hybrid_labeled_metrics.md logs/hybrid_alerts.jsonl 2>/dev/null || true
echo "===== TCPDUMP ERR ====="
tail -n 20 logs/lab_tcpdump.err 2>/dev/null || true