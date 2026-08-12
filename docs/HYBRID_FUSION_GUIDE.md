# Hybrid Alert Fusion Guide

Tài liệu này mô tả thành phần dung hợp cảnh báo giữa Suricata và Random Forest AI
trong codebase Hybrid-NIDS.

## Mục tiêu

`hybrid_alert_fusion.py` tạo một luồng cảnh báo Hybrid thật sự từ hai nguồn:

- Suricata EVE alert: `eve.json` hoặc JSONL tương đương.
- AI alert: `logs/ai_alerts.jsonl` do `nids_detector.py` sinh ra.

Kết quả đầu ra:

- `logs/hybrid_alerts.jsonl`

## Logic dung hợp

Hai cảnh báo được xem là cùng một sự kiện khi cùng các trường:

- `src_ip`
- `dst_ip`
- `dst_port`
- `protocol`

và nằm trong cửa sổ thời gian cấu hình bằng `--window-seconds`.

Kết quả có 3 loại:

- `HYBRID_CORRELATED_ALERT`: Suricata và Random Forest cùng cảnh báo.
- `AI_ONLY_ALERT`: chỉ Random Forest cảnh báo.
- `SURICATA_ONLY_ALERT`: chỉ Suricata cảnh báo.

## Chạy thử bằng dữ liệu mẫu

```powershell
python hybrid_alert_fusion.py `
  --suricata-eve logs\sample_suricata_eve.jsonl `
  --ai-alerts logs\ai_alerts.jsonl `
  --output logs\hybrid_alerts.jsonl `
  --window-seconds 300 `
  --include-unmatched `
  --max-records 20
```

Kết quả mẫu hiện tại:

```text
Suricata alerts: 3
AI alerts: 20
Hybrid correlated: 2
AI only: 18
Suricata only: 1
```

## Chạy trên Ubuntu

Biến cấu hình trong `deployment/hybrid-nids.env`:

```bash
SURICATA_EVE_LOG=/var/log/suricata/eve.json
HYBRID_AI_ALERT_LOG=/opt/hybrid-nids/logs/ai_alerts.jsonl
HYBRID_FUSED_ALERT_LOG=/opt/hybrid-nids/logs/hybrid_alerts.jsonl
HYBRID_FUSION_WINDOW_SECONDS=300
```

Chạy thủ công:

```bash
bash scripts/run_hybrid_fusion_loop.sh deployment/hybrid-nids.env
```

Chạy bằng systemd:

```bash
sudo cp deployment/systemd/hybrid-nids-fusion.service /etc/systemd/system/
sudo sed -i 's|/opt/hybrid-nids|/home/admin_soc/hybrid-nids|g' /etc/systemd/system/hybrid-nids-fusion.service
sudo systemctl daemon-reload
sudo systemctl enable --now hybrid-nids-fusion.service
sudo systemctl status hybrid-nids-fusion.service
```

## Ingest vào Elasticsearch/Kibana

Cấu hình Logstash:

```text
deployment/elk/logstash/pipeline/hybrid_alerts.conf
```

Index đầu ra:

```text
hybrid-nids-fused-alerts-YYYY.MM.dd
```

## Lưu ý học thuật

Thành phần này không tạo metric mới cho Suricata standalone. Nó cung cấp bằng
chứng code cho kiến trúc Hybrid-NIDS ở mức dung hợp cảnh báo vận hành:

```text
Suricata eve.json + AI ai_alerts.jsonl -> hybrid_alerts.jsonl -> Logstash -> Elasticsearch/Kibana
```
