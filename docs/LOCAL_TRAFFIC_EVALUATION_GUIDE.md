# Local Traffic Evaluation Guide

Tài liệu này hướng dẫn chạy mô hình Hybrid-NIDS trên traffic cục bộ hoặc traffic
vận hành của đơn vị triển khai. Mục tiêu là bổ sung bằng chứng thực nghiệm cho
bối cảnh mạng thật, không thay thế kết quả hold-out test trên UNSW-NB15.

## Mục Đích

`evaluate_local_traffic.py` chạy `nids_detector.py` trên một file flow CSV hoặc
PCAP cục bộ, sau đó tổng hợp:

- tổng số flow nếu đầu vào là CSV;
- số cảnh báo AI;
- tỷ lệ cảnh báo;
- phân bố mức độ cảnh báo;
- top IP nguồn, IP đích, cổng nguồn, cổng đích;
- thống kê attack score và threshold được dùng.

Traffic cục bộ thường không có nhãn ground truth. Vì vậy báo cáo này không tính
accuracy, precision, recall, F1-score hoặc ROC-AUC.

## Chạy Trên CSV Mẫu

```powershell
python evaluate_local_traffic.py `
  --input-csv sample_flows.csv `
  --output-alerts logs\local_traffic_alerts.jsonl `
  --output-report logs\local_traffic_evaluation.json `
  --overwrite
```

## Chạy Trên PCAP Triển Khai

Lưu ý: chế độ PCAP là đường tích hợp vận hành. Kết quả từ PCAP cục bộ không
thay thế metric chính thức trên hold-out test, và cần được diễn giải cùng báo
cáo schema gap. Với PCAP/NFStream hiện tại, nên dùng mô hình RF-21 vì đây là
mô hình rút gọn theo 21 đặc trưng giao nhau giữa schema chính thức và nhánh
PCAP/NFStream.

```powershell
.\scripts\run_mini_live_test_rf21.ps1 -Pcap ".\pcap_traffic\traffic_latest.pcapng"
```

Lệnh tương đương nếu chạy trực tiếp bằng Python:

```powershell
python evaluate_local_traffic.py `
  --pcap ".\pcap_traffic\traffic_latest.pcapng" `
  --model ".\models\rf21_schema_gap\nids_rf21_schema_gap_pipeline.pkl" `
  --schema ".\models\rf21_schema_gap\feature_schema_rf21.json" `
  --metadata ".\models\rf21_schema_gap\metadata_rf21.json" `
  --output-alerts ".\logs\local_traffic_alerts.jsonl" `
  --output-report ".\logs\local_traffic_evaluation.json" `
  --overwrite
```

## File Đầu Ra

- `logs/local_traffic_alerts.jsonl`: cảnh báo AI sinh ra từ traffic cục bộ.
- `logs/local_traffic_evaluation.json`: báo cáo tổng hợp cho đề án.

## Cách Viết Trong Đề Án

Nên mô tả đây là bước "đánh giá vận hành không nhãn" hoặc "unlabeled local
traffic evaluation". Báo cáo chỉ chứng minh mô hình chạy được trên luồng dữ liệu
cục bộ và sinh cảnh báo có cấu trúc, không chứng minh độ chính xác trên mạng
trường nếu chưa có nhãn xác thực.

Không nên viết:

- "Mô hình đạt accuracy X% trên traffic thật" nếu chưa gán nhãn.
- "Mô hình phát hiện đúng X cuộc tấn công" nếu không có kịch bản tấn công được
  ghi nhận và đối chiếu độc lập.

Nên viết:

- "Mô hình được chạy thử trên traffic cục bộ không nhãn để đánh giá khả năng vận
  hành, tỷ lệ cảnh báo và các thực thể nổi bật."
- "Các chỉ số accuracy/F1 chính thức vẫn lấy từ hold-out test có nhãn trong
  `models/metrics.json`."
