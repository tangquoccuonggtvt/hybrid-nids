# Bảo mật tầng giám sát ELK (Elasticsearch + Kibana)

> Vá lời phê phản biện: *"Cấu hình lab thừa nhận chưa bật xác thực ES/Kibana —
> khoảng trống lớn của một đề tài mang danh ATTT."*
> Sau thay đổi này, chính tầng giám sát của Hybrid-NIDS được bảo vệ bằng xác thực
> bắt buộc, loại bỏ nghịch lý "hệ thống bảo vệ mạng nhưng bản thân để cửa mở".

## 1. Đã thay đổi gì

| File | Trước | Sau |
|------|-------|-----|
| `docker-compose.yml` | `xpack.security.enabled=false` (ES mở, không mật khẩu) | `xpack.security.enabled=true` + tài khoản `elastic`/`kibana_system`, mật khẩu qua biến môi trường |
| 3 pipeline Logstash (`ai_alerts.conf`, `hybrid_alerts.conf`, `suricata.conf`) | output ES không xác thực | thêm `user`/`password` lấy từ `${ES_USER}`/`${ES_PASSWORD}` |
| `hybrid-nids.env.example` | `ES_USER=`/`ES_PASSWORD=[REDACTED_PASSWORD] `ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD`, `ES_USER=elastic` |

Nguyên tắc: **không hardcode mật khẩu** trong file cấu hình; tất cả đọc từ
`deployment/hybrid-nids.env` (không commit lên git).

## 2. Các bước bật xác thực (chạy trên máy NIDS Ubuntu)

```bash
cd /opt/hybrid-nids/deployment

# 1. Tạo file .env thật từ mẫu, đặt mật khẩu mạnh
cp hybrid-nids.env.example hybrid-nids.env
nano hybrid-nids.env          # đặt ELASTIC_PASSWORD, KIBANA_SYSTEM_PASSWORD, ES_PASSWORD

# 2. Khởi động ELK có bảo mật
cd elk
docker compose --env-file ../hybrid-nids.env up -d

# 3. Khởi tạo mật khẩu cho tài khoản hệ thống kibana_system (chạy 1 lần)
docker exec -it hybrid-nids-elasticsearch \
  bin/elasticsearch-reset-password -u kibana_system -i
#   -> nhập đúng giá trị KIBANA_SYSTEM_PASSWORD đã đặt trong .env, rồi restart kibana:
docker compose --env-file ../hybrid-nids.env restart kibana
```

## 3. Minh chứng để chụp đưa vào luận văn

**(a) Truy cập KHÔNG xác thực bị từ chối (401):**
```bash
curl -i http://127.0.0.1:9200
# Kỳ vọng: HTTP/1.1 401 Unauthorized  + {"error":{"type":"security_exception",...}}
```

**(b) Truy cập CÓ xác thực thành công:**
```bash
curl -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9200
# Kỳ vọng: JSON thông tin cluster (name, cluster_name, version...)
```

**(c) Kibana yêu cầu đăng nhập:** mở `http://<IP-NIDS>:5601` → xuất hiện màn hình
đăng nhập (trước đây vào thẳng, không hỏi mật khẩu).

Chụp 3 màn hình (a)(b)(c) làm minh chứng cho mục "Bảo mật tầng giám sát" trong báo cáo.

## 4. Đoạn văn đề xuất chèn vào báo cáo (mục bàn về bảo mật hệ giám sát)

> "Nhằm bảo vệ chính tầng giám sát — thành phần lưu trữ toàn bộ cảnh báo và
> nhật ký an ninh — hệ thống bật cơ chế xác thực X-Pack Security của
> Elasticsearch. Mọi truy cập tới Elasticsearch (cổng 9200) và Kibana (cổng
> 5601) đều yêu cầu tài khoản và mật khẩu; Logstash ghi dữ liệu bằng tài khoản
> riêng, Kibana kết nối bằng tài khoản hệ thống `kibana_system` thay vì tài
> khoản siêu quyền. Cách làm này loại bỏ nguy cơ một tác nhân trong mạng nội bộ
> đọc hoặc chỉnh sửa trái phép kho cảnh báo, đồng thời khắc phục hạn chế của
> phiên bản triển khai ban đầu vốn để Elasticsearch ở chế độ không xác thực."

## 5. Lưu ý phòng thủ khi vấn đáp

- Nếu hội đồng hỏi "vì sao ban đầu để mở?": trả lời trung thực rằng bản dựng thử
  nghiệm ban đầu tắt security cho tiện phát triển, và đã được **siết lại trong bản
  triển khai** — đúng quy trình phát triển an toàn (secure by deployment).
- Đây mới là mức xác thực cơ bản (HTTP + mật khẩu). Hướng phát triển tiếp: bật
  TLS (HTTPS) cho ES/Kibana và phân quyền theo vai trò (RBAC) để hoàn thiện.
