#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-deployment/hybrid-nids.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

: "${NIDS_INTERFACE:?Set NIDS_INTERFACE in deployment/hybrid-nids.env}"
: "${PCAP_DIR:=pcap_traffic}"
: "${PCAP_PREFIX:=traffic}"
: "${PCAP_ROTATE_SECONDS:=300}"
: "${PCAP_MAX_FILE_MB:=512}"
: "${HYBRID_NIDS_HOME:=$(pwd)}"
: "${RUN_RETENTION_AFTER_CAPTURE:=true}"

mkdir -p "$PCAP_DIR"

echo "[+] Capturing interface: $NIDS_INTERFACE"
echo "[+] PCAP directory: $PCAP_DIR"
echo "[+] Rotate seconds: $PCAP_ROTATE_SECONDS"
echo "[+] Max PCAP file size: ${PCAP_MAX_FILE_MB}MB"

while true; do
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  target="$PCAP_DIR/${PCAP_PREFIX}_${timestamp}.pcap"
  tmp_target="${target}.tmp"

  echo "[*] Writing $target"
  timeout "$PCAP_ROTATE_SECONDS" tcpdump \
    -i "$NIDS_INTERFACE" \
    -s 0 \
    -C "$PCAP_MAX_FILE_MB" \
    -W 1 \
    -w "$tmp_target" \
    not port 22 || true

  if [[ ! -s "$tmp_target" && -s "${tmp_target}0" ]]; then
    mv "${tmp_target}0" "$tmp_target"
  fi
  rm -f "${tmp_target}"[0-9] 2>/dev/null || true

  if [[ -s "$tmp_target" ]]; then
    mv "$tmp_target" "$target"
    ln -sfn "$(basename "$target")" "$PCAP_DIR/${PCAP_PREFIX}_latest.pcap"
    echo "[+] Rotated latest PCAP: $target"
  else
    rm -f "$tmp_target"
    echo "[!] Empty PCAP skipped."
  fi

  if [[ "$RUN_RETENTION_AFTER_CAPTURE" == "true" && -x "$HYBRID_NIDS_HOME/scripts/retention_cleanup.sh" ]]; then
    "$HYBRID_NIDS_HOME/scripts/retention_cleanup.sh" "$ENV_FILE" --local-only || true
  fi
done
