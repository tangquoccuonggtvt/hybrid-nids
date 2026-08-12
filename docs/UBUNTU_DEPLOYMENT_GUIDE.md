# Triển khai vận hành Hybrid-NIDS trên Ubuntu

Tài liệu này mô tả cách triển khai hệ thống theo sơ đồ vận hành:

1. SPAN/mirror port đưa bản sao lưu lượng vào máy Ubuntu.
2. Suricata giám sát theo luật và ghi `eve.json`.
3. PCAP được cắt theo chu kỳ để đưa vào nhánh AI batch.
4. Random Forest suy luận và ghi `logs/ai_alerts.jsonl`, đồng thời có thể gửi Discord/Telegram.
5. Logstash đưa cả Suricata alert và AI alert vào Elasticsearch/Kibana.

Mặc định hệ thống chạy ở chế độ IDS giám sát, không chặn lưu lượng.

Lưu ý học thuật: metric chính thức của luận văn được đánh giá trên hold-out
test với flow CSV khớp schema 41 feature trong `models/feature_schema_model.json`.
Đường PCAP/NFStreamer trong triển khai Ubuntu là nhánh tích hợp vận hành; không
nên báo cáo như tương đương kết quả hold-out nếu schema gap chưa được đóng.

## 1. Chuẩn bị thư mục

Ví dụ đặt project tại:

```bash
sudo mkdir -p /opt/hybrid-nids
sudo chown -R "$USER":"$USER" /opt/hybrid-nids
```

Chép các file code/artifact sang `/opt/hybrid-nids`, tối thiểu gồm:

```text
nids_detector.py
nids_features.py
feature_schema.py
models/nids_rf_pipeline.pkl
models/metadata.json
models/feature_schema_model.json
deployment/
scripts/
requirements.txt
```

## 2. Cài gói hệ thống

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump suricata docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Đăng xuất/đăng nhập lại sau khi thêm user vào group `docker`.

## 3. Cài Python environment

```bash
cd /opt/hybrid-nids
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Lưu ý model artifact hiện được khóa với `scikit-learn==1.6.1`.

## 4. Cấu hình biến môi trường

```bash
cp deployment/hybrid-nids.env.example deployment/hybrid-nids.env
nano deployment/hybrid-nids.env
```

Cần sửa tối thiểu:

```text
NIDS_INTERFACE=eth1
HOME_NET=192.168.10.0/24
HYBRID_NIDS_HOME=/opt/hybrid-nids
```

Nếu dùng Discord/Telegram, điền webhook/token vào file env trên máy thật. Không commit file này lên git.

## 5. Cấu hình Suricata

Copy rules mẫu:

```bash
sudo mkdir -p /etc/suricata/rules
sudo cp deployment/suricata/local.rules /etc/suricata/rules/hybrid-nids-local.rules
```

Sửa `/etc/suricata/suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.10.0/24]"

rule-files:
  - suricata.rules
  - hybrid-nids-local.rules
```

Chạy Suricata trên interface nhận SPAN/mirror:

```bash
sudo suricata -i eth1 -l /var/log/suricata
```

Hoặc tạo service riêng tùy môi trường. Kiểm tra log:

```bash
tail -f /var/log/suricata/eve.json
```

## 6. Chạy ELK

```bash
cd /opt/hybrid-nids/deployment/elk
docker compose up -d
```

Kiểm tra:

```bash
curl http://127.0.0.1:9200
```

Mở Kibana:

```text
http://<IP_UBUNTU>:5601
```

Tạo Data View:

```text
hybrid-nids-suricata-*
hybrid-nids-ai-*
```

## 7. Chạy capture PCAP theo chu kỳ

Chạy thủ công:

```bash
cd /opt/hybrid-nids
sudo bash scripts/capture_pcap_rotate.sh deployment/hybrid-nids.env
```

Script mặc định tạo:

```text
pcap_traffic/traffic_YYYYMMDDTHHMMSSZ.pcap
pcap_traffic/traffic_latest.pcap
```

## 8. Chạy AI detector

Chạy thủ công:

```bash
cd /opt/hybrid-nids
source .venv/bin/activate
python3 nids_detector.py \
  --pcap pcap_traffic/traffic_latest.pcap \
  --output-log logs/ai_alerts.jsonl
```

Hoặc chạy loop:

```bash
bash scripts/run_ai_detector_loop.sh deployment/hybrid-nids.env
```

Script loop sẽ ưu tiên dùng Python tại `.venv/bin/python` và xóa symlink
`traffic_latest.pcap` sau khi xử lý thành công để tránh suy luận lặp lại cùng một
PCAP. File PCAP gốc theo timestamp vẫn được giữ lại để phục vụ đối chiếu.

AI alert sẽ được Logstash đọc từ:

```text
logs/ai_alerts.jsonl
```

## 9. Cài systemd service

```bash
sudo cp deployment/systemd/hybrid-nids-capture.service /etc/systemd/system/
sudo cp deployment/systemd/hybrid-nids-ai-detector.service /etc/systemd/system/
sudo cp deployment/systemd/hybrid-nids-retention.service /etc/systemd/system/
sudo cp deployment/systemd/hybrid-nids-retention.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hybrid-nids-capture.service
sudo systemctl enable --now hybrid-nids-ai-detector.service
sudo systemctl enable --now hybrid-nids-retention.timer
```

Xem trạng thái:

```bash
systemctl status hybrid-nids-capture.service
systemctl status hybrid-nids-ai-detector.service
systemctl status hybrid-nids-retention.timer
journalctl -u hybrid-nids-ai-detector.service -f
```

## 10. Kiến trúc dọn rác 3 lớp

Khi chạy thật trên mạng trường, PCAP có thể tăng rất nhanh, đặc biệt trong tình
huống DDoS. Hệ thống dùng kiến trúc dọn rác 3 lớp:

### Lớp 1 - Giới hạn ngay lúc capture

Trong `deployment/hybrid-nids.env`:

```text
PCAP_ROTATE_SECONDS=300
PCAP_MAX_FILE_MB=512
```

Ý nghĩa:

- `PCAP_ROTATE_SECONDS`: cắt file theo chu kỳ thời gian.
- `PCAP_MAX_FILE_MB`: giới hạn kích thước mỗi file PCAP khi capture.

Script sử dụng:

```text
scripts/capture_pcap_rotate.sh
```

### Lớp 2 - Dọn PCAP/log cục bộ

Cấu hình:

```text
PCAP_RETENTION_HOURS=6
PCAP_MAX_TOTAL_GB=20
PCAP_MIN_FREE_PERCENT=15
PCAP_TMP_MAX_MINUTES=10
JSONL_MAX_MB=512
JSONL_KEEP_LINES=200000
```

Ý nghĩa:

- Xóa PCAP quá tuổi.
- Xóa PCAP cũ nhất khi tổng dung lượng vượt giới hạn.
- Xóa PCAP cũ nhất khi free disk thấp hơn ngưỡng.
- Xóa file `.tmp` bị bỏ dở.
- Rút gọn log JSONL nếu quá lớn.

Chạy thủ công:

```bash
bash scripts/retention_cleanup.sh deployment/hybrid-nids.env
```

Chạy chỉ dọn local, không đụng Elasticsearch:

```bash
bash scripts/retention_cleanup.sh deployment/hybrid-nids.env --local-only
```

### Lớp 3 - Dọn Elasticsearch index

Cấu hình:

```text
ES_URL=http://127.0.0.1:9200
ES_RETENTION_DAYS=30
ES_INDEX_PATTERNS=hybrid-nids-alerts-* hybrid-nids-ai-* hybrid-nids-ai-alerts-* hybrid-nids-suricata-*
```

Nếu Elasticsearch bật xác thực:

```text
ES_USER=elastic
ES_PASSWORD=<password>
ES_INSECURE_SSL=true
```

Timer systemd tự chạy mỗi 5 phút:

```bash
systemctl status hybrid-nids-retention.timer
journalctl -u hybrid-nids-retention.service -f
```

## 11. Kiểm tra luồng dữ liệu

Suricata:

```bash
tail -f /var/log/suricata/eve.json
```

AI:

```bash
tail -f /opt/hybrid-nids/logs/ai_alerts.jsonl
```

Elasticsearch:

```bash
curl "http://127.0.0.1:9200/_cat/indices/hybrid-nids-*?v"
```

Kibana:

- Data View `hybrid-nids-suricata-*`: cảnh báo rule-based.
- Data View `hybrid-nids-alerts-*`: cảnh báo Random Forest.

## 12. Lưu ý vận hành thật

- Chạy trên cổng mirror/SPAN, không đặt inline nếu chưa thiết kế chế độ IPS.
- Không chạy thử tấn công ngoài mạng không được phép.
- Không hard-code webhook/token vào code.
- Kiểm tra dung lượng `pcap_traffic/` định kỳ vì PCAP tăng nhanh.
- Các rule mẫu chỉ phục vụ demo; cần thay bằng ruleset phù hợp môi trường thật.
