#!/usr/bin/env bash
# =============================================================================
# check_elk_pipeline.sh
# Kiem tra luong du lieu Hybrid-NIDS -> Logstash -> Elasticsearch -> Kibana.
# Chay TREN MAY NIDS UBUNTU:  bash scripts/check_elk_pipeline.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

ENV_FILE="${ENV_FILE:-deployment/hybrid-nids.env}"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"
LOG_DIR="${LOG_DIR:-$ROOT/logs}"
SURICATA_EVE="${SURICATA_EVE_LOG:-/var/log/suricata/eve.json}"
AI_LOG="${AI_ALERT_LOG:-$LOG_DIR/ai_alerts.jsonl}"
FUSED_LOG="${FUSED_ALERT_LOG:-$LOG_DIR/hybrid_alerts.jsonl}"

pass(){ echo -e "  [ \033[32mOK\033[0m ] $1"; }
warn(){ echo -e "  [\033[33mWARN\033[0m] $1"; }
fail(){ echo -e "  [\033[31mFAIL\033[0m] $1"; }
hdr(){ echo; echo "============================================================"; echo " $1"; echo "============================================================"; }

count_lines(){ [[ -f "$1" ]] && wc -l < "$1" 2>/dev/null || echo 0; }

# --- 1. File nguon canh bao ---
hdr "1) FILE NGUON CANH BAO"
for f in "$SURICATA_EVE" "$AI_LOG" "$FUSED_LOG"; do
  if [[ -f "$f" ]]; then
    n="$(count_lines "$f")"
    if [[ "$n" -gt 0 ]]; then pass "$f ($n dong)"; else warn "$f ton tai nhung TRONG (0 dong)"; fi
  else
    fail "$f KHONG ton tai"
  fi
done

# --- 2. Docker containers ELK ---
hdr "2) DOCKER CONTAINERS ELK"
if command -v docker >/dev/null 2>&1; then
  for c in hybrid-nids-elasticsearch hybrid-nids-logstash hybrid-nids-kibana; do
    state="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
    if [[ "$state" == "running" ]]; then pass "$c: running"
    elif [[ "$state" == "missing" ]]; then fail "$c: khong tim thay (chua 'docker compose up'?)"
    else warn "$c: $state"; fi
  done
else
  warn "Khong co lenh docker tren may nay."
fi

# --- 3. Elasticsearch song? ---
hdr "3) ELASTICSEARCH ($ES_URL)"
if curl -fsS "$ES_URL" >/dev/null 2>&1; then
  pass "Elasticsearch phan hoi."
  health="$(curl -fsS "$ES_URL/_cluster/health" 2>/dev/null)"
  echo "    Cluster health: $(echo "$health" | grep -o '"status":"[^"]*"' || echo '?')"
else
  fail "Khong ket noi duoc Elasticsearch tai $ES_URL"
fi

# --- 4. Cac index Hybrid-NIDS + so document ---
hdr "4) INDEX HYBRID-NIDS TRONG ELASTICSEARCH"
if curl -fsS "$ES_URL" >/dev/null 2>&1; then
  for pat in "hybrid-nids-suricata" "hybrid-nids-ai" "hybrid-nids-fused-alerts"; do
    cnt="$(curl -fsS "$ES_URL/${pat}-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo '')"
    if [[ -n "$cnt" && "$cnt" -gt 0 ]]; then pass "${pat}-*: $cnt document"
    elif [[ -n "$cnt" ]]; then warn "${pat}-*: 0 document (chua co du lieu chay qua)"
    else warn "${pat}-*: chua co index (Logstash chua day du lieu nao)"; fi
  done
  echo
  echo "  Tat ca index hybrid-nids:"
  curl -fsS "$ES_URL/_cat/indices/hybrid-nids-*?h=index,docs.count,store.size&s=index" 2>/dev/null \
    | sed 's/^/    /' || echo "    (khong liet ke duoc)"
else
  warn "Bo qua vi Elasticsearch khong phan hoi."
fi

# --- 5. Kibana song? ---
hdr "5) KIBANA ($KIBANA_URL)"
code="$(curl -s -o /dev/null -w '%{http_code}' "$KIBANA_URL/api/status" 2>/dev/null || echo 000)"
if [[ "$code" == "200" ]]; then pass "Kibana san sang (HTTP 200)."
elif [[ "$code" == "000" ]]; then fail "Khong ket noi duoc Kibana tai $KIBANA_URL"
else warn "Kibana tra ve HTTP $code (co the dang khoi dong)."; fi

# --- 6. Ket luan ---
hdr "KET LUAN NHANH"
echo "  - Neu file nguon co du lieu nhung index 0 document -> kiem tra Logstash:"
echo "      docker logs hybrid-nids-logstash --tail 50"
echo "  - Neu index co document -> mo Kibana va tao Data View:"
echo "      hybrid-nids-fused-alerts-*   (canh bao dung hop)"
echo "      hybrid-nids-suricata-*       (nhanh luat)"
echo "      hybrid-nids-ai-*             (nhanh AI)"
echo "  - Chua co du lieu? Tao luu luong kiem thu tu may Kali/Windows roi chay lai."
echo
