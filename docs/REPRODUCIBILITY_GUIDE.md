# Reproducibility Guide - Hybrid-NIDS Thesis

Tài liệu này mô tả các lệnh chính để tái tạo và kiểm tra kết quả luận văn.

## 1. Kiểm tra artifact chính thức

Chạy trước khi nộp luận văn hoặc demo:

```powershell
python verify_official_artifacts.py
```

Lệnh này kiểm tra:

- model chính thức
- metrics và metadata
- schema
- confusion matrix
- leakage report
- inference contract
- inference benchmark contract

Kết quả mong đợi:

```text
Required files: OK
Metrics/metadata/schema consistency: OK
Leakage report: PASS
Inference contract: OK
Inference benchmark contract: OK
```

## 2. Kiểm tra leakage

Kiểm tra duplicate/hash overlap giữa Development Set và Hold-out Test Set:

```powershell
python check_leakage.py
```

Artifact được cập nhật:

```text
models/leakage_check.json
```

Kết quả mong đợi:

```text
duplicate_hash_count = 0
is_pass = true
```

## 3. Benchmark tốc độ suy luận

Chạy benchmark mà không train lại model:

```powershell
python benchmark_inference.py
```

Artifact được cập nhật:

```text
models/inference_benchmark.json
```

Script này load:

- `models/nids_rf_pipeline.pkl`
- `models/feature_schema_model.json`
- `UNSW_NB15_Splitted_CLEAN/unsw_nb15_test_holdout.csv`

## 4. Suy luận/phát hiện trên flow CSV

Chế độ inference chính thức dùng flow records CSV có cùng schema với model:

```powershell
python nids_detector.py --once --input-csv <flow_records.csv>
```

Mặc định detector dùng:

- `models/nids_rf_pipeline.pkl`
- `models/metadata.json`
- `models/feature_schema_model.json`

Alert được ghi ra:

```text
logs/ai_alerts.jsonl
```

## 5. Dashboard real-time

Chạy dashboard trực quan:

```powershell
python realtime_dashboard.py
```

Hoặc dùng script PowerShell:

```powershell
.\run_realtime_dashboard.ps1
```

Mở trình duyệt tại:

```text
http://127.0.0.1:8050
```

Dashboard dùng cơ chế replay flow CSV để mô phỏng luồng real-time. Cách này phù hợp
với luận văn hơn việc tấn công thật vào hệ thống mạng, vì có thể tái lập và nếu CSV
có nhãn thì đo được TP/FP/TN/FN, precision, recall, F1-score và FPR trong lúc chạy.

## 6. Train lại toàn bộ model

Chỉ chạy khi cần huấn luyện lại từ đầu:

```powershell
python train_model.py
```

Lưu ý: lệnh này tốn thời gian vì có 5-Fold CV để chọn threshold, retrain trên Development Set và đánh giá trên Hold-out Test Set.

Artifact chính được sinh/cập nhật:

- `models/nids_rf_pipeline.pkl`
- `models/metrics.json`
- `models/training_metadata.json`
- `models/metadata.json`
- `models/confusion_matrix.png`
- `models/feature_schema_model.json`
- `models/feature_importance.csv`
- `models/inference_benchmark.json`
- `models/training.log`

## 7. Artifact chính thức

Danh sách artifact chính thức được khóa tại:

```text
OFFICIAL_ARTIFACTS.md
docs/CODEBASE_LOCK.md
```

Không dùng artifact trong `archive/legacy_v3/` để báo cáo kết quả chính thức của luận văn.
