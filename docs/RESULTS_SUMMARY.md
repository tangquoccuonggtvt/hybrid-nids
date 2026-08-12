# Results Summary - Hybrid-NIDS Thesis

Tài liệu này tổng hợp kết quả chính thức từ các artifact đã khóa của codebase. Các số liệu bên dưới được đọc từ file JSON/CSV trong thư mục `models/`, không tự tạo thêm metric.

## 1. Model và dữ liệu

| Mục | Giá trị |
|---|---|
| Model | Hybrid-NIDS Random Forest |
| Thuật toán | RandomForestClassifier |
| Dataset | UNSW-NB15 compatible flow records |
| Development rows | 2,030,129 |
| Hold-out test rows | 508,039 |
| Số feature trước encoding | 41 |
| Numeric features | 35 |
| Categorical features | 6 |
| Threshold | 0.870846 |

## 2. Hold-out test metrics

| Chỉ số | Giá trị |
|---|---:|
| Accuracy | 0.992768 |
| Precision | 0.968823 |
| Recall | 0.973911 |
| F1-score | 0.971360 |
| ROC-AUC | 0.999671 |
| False positive rate | 0.004515 |
| Threshold | 0.870846 |

## 3. Confusion matrix

| True label / Predicted label | Normal | Attack |
|---|---:|---:|
| Normal | 442,060 | 2,005 |
| Attack | 1,669 | 62,305 |

Ảnh confusion matrix chính thức: `models/confusion_matrix.png`.

## 4. Leakage check

| Mục | Giá trị |
|---|---:|
| Development rows | 2,030,129 |
| Test rows | 508,039 |
| Duplicate hash count | 0 |
| Duplicate ratio over test | 0.00000000 |
| PASS | true |

## 5. Inference benchmark

Benchmark file: `models/inference_benchmark.json`. Sample size: `100,000` flow records. Repeats: `5`.

| Batch | Flows | Latency ms/flow | Throughput flows/s |
|---|---:|---:|---:|
| batch_1 | 1 | 49.112680 | 20.36 |
| batch_32 | 32 | 1.907331 | 524.29 |
| batch_128 | 128 | 0.444052 | 2251.99 |
| batch_512 | 512 | 0.118704 | 8424.35 |
| batch_1024 | 1,024 | 0.065988 | 15154.25 |

## 6. Top 20 feature importance

| Hạng | Feature | Importance |
|---:|---|---:|
| 1 | ct_state_ttl | 0.149899 |
| 2 | sttl | 0.141276 |
| 3 | sbytes | 0.066012 |
| 4 | dload | 0.061960 |
| 5 | dmean | 0.055923 |
| 6 | dttl | 0.042484 |
| 7 | dpkts | 0.039564 |
| 8 | state_int | 0.037619 |
| 9 | smean | 0.037197 |
| 10 | dinpkt | 0.036504 |
| 11 | dur | 0.035716 |
| 12 | sload | 0.034364 |
| 13 | ackdat | 0.032025 |
| 14 | dbytes | 0.025567 |
| 15 | tcprtt | 0.022243 |
| 16 | synack | 0.017585 |
| 17 | sinpkt | 0.016678 |
| 18 | ct_dst_sport_ltm | 0.012111 |
| 19 | sloss | 0.011248 |
| 20 | ct_src_ltm | 0.010953 |

Biểu đồ Top 20 feature importance chính thức: `models/feature_importance_top20.png`.

## 7. Ghi chú sử dụng trong luận văn

- Các metric được đánh giá trên Hold-out Test Set.
- Leakage check hiện PASS với duplicate hash count bằng 0.
- Feature importance phản ánh mức đóng góp tương đối của đặc trưng trong Random Forest, không chứng minh quan hệ nhân quả.
- Inference benchmark được đo bằng script riêng `benchmark_inference.py`, không train lại model.
