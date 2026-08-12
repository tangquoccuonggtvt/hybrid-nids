"""
===========================================================
PIPELINE HUẤN LUYỆN HYBRID-NIDS
===========================================================

Mục tiêu:
- Huấn luyện mô hình Random Forest cho hệ thống Hybrid-NIDS.
- Dữ liệu đầu vào là flow records dạng CSV, có nhãn label.
- Bài toán phân loại nhị phân: 0 = Normal, 1 = Attack.
- Không dùng SMOTE vì dễ chậm và tốn RAM trên dữ liệu lớn.
- Không dùng RandomOverSampler để tránh nhân bản mẫu không cần thiết.
- Dùng class_weight="balanced_subsample" trong Random Forest để xử lý mất cân bằng lớp.
- Tự động nhận diện schema dữ liệu.
- Nếu dữ liệu có proto/state/service thì tự xử lý One-Hot Encoding.
- Nếu dữ liệu chỉ toàn số thì chỉ dùng RobustScaler.
- Có Group-aware Stratified 5-Fold CV theo feature hash để tìm threshold.
- Lấy Median Threshold để tăng tính ổn định.
- Retrain trên Full Development Set.
- Đánh giá trên Hold-out Test Set.
- Xuất model, metrics, metadata, feature schema, feature importance, benchmark inference.
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 14):
    raise SystemExit(
        "Python 3.14 hiện không phù hợp với scikit-learn/scipy dùng trong pipeline này.\n"
        "Hãy chạy bằng Python 3.13 hoặc 3.12, ví dụ:\n"
        "  python train_model.py\n"
        "Nếu chạy trong VS Code, chọn interpreter Python 3.13/3.12 thay vì "
        "pythoncore-3.14-64."
    )

import json
import hashlib
import logging
import platform
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

# =========================================================
# 1. CẤU HÌNH CHUNG
# =========================================================

# Thư mục chứa dữ liệu đã chia sẵn
DATA_DIR = Path("./UNSW_NB15_Splitted_CLEAN")

# Thư mục lưu model, metrics, metadata
ARTIFACTS_DIR = Path("./models")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# Seed cố định để tái lập kết quả
RANDOM_STATE = 42

# Phiên bản mô hình
MODEL_VERSION = "final"

# Cột nhãn
TARGET_COLUMN = "label"

# Các cột không đưa vào mô hình
EXCLUDE_COLUMNS = {
    "id",
    "srcip",
    "dstip",
    "src_ip",
    "dst_ip",
    "sport",
    "dsport",
    "src_port",
    "dst_port",
    "stime",
    "ltime",
    "timestamp",
    "time",
    "attack_cat",
    TARGET_COLUMN,
}

# Nếu các cột này tồn tại thì được xem là categorical
PREFERRED_CATEGORICAL_FEATURES = {"proto", "state", "service"}

# Tắt cảnh báo phụ để log gọn hơn
warnings.filterwarnings("ignore")

# Đảm bảo terminal Windows in tiếng Việt tốt hơn
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

# =========================================================
# 2. CẤU TRÚC SCHEMA
# =========================================================

@dataclass
class FeatureSchema:
    """
    Lưu schema đặc trưng dùng cho mô hình.

    numeric_features:
        Các đặc trưng dạng số.

    categorical_features:
        Các đặc trưng dạng phân loại, ví dụ proto/state/service nếu có.

    feature_columns:
        Tổng danh sách đặc trưng theo đúng thứ tự đưa vào model.
    """
    numeric_features: list[str]
    categorical_features: list[str]
    feature_columns: list[str]
    target_column: str
    schema_version: str

# =========================================================
# 3. LOGGING VÀ HÀM TIỆN ÍCH
# =========================================================

def setup_logging() -> logging.Logger:
    """
    Tạo logger vừa in ra màn hình vừa lưu vào file log.
    """
    log_path = ARTIFACTS_DIR / "training.log"

    logger = logging.getLogger("hybrid_nids_training")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


def save_json(obj: dict, path: Path) -> None:
    """
    Lưu dictionary ra file JSON.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def save_confusion_matrix_png(metrics: dict, output_path: Path) -> None:
    """
    Lưu confusion matrix dạng PNG từ metrics hold-out test.
    """
    cm = metrics["confusion_matrix"]
    matrix = np.array(
        [
            [cm["tn"], cm["fp"]],
            [cm["fn"], cm["tp"]],
        ],
        dtype=int,
    )

    labels = ["Normal", "Attack"]
    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(matrix, cmap="Blues")

    ax.set_title("Confusion Matrix - Random Forest Hybrid-NIDS")
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_xticks(np.arange(len(labels)), labels=labels)
    ax.set_yticks(np.arange(len(labels)), labels=labels)

    threshold = matrix.max() / 2
    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            ax.text(
                col,
                row,
                f"{matrix[row, col]:,}",
                ha="center",
                va="center",
                color="white" if matrix[row, col] > threshold else "black",
                fontsize=13,
                fontweight="bold",
            )

    colorbar = fig.colorbar(image, ax=ax)
    colorbar.ax.set_ylabel("Flow count", rotation=-90, va="bottom")
    fig.tight_layout()
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def sha256_file(path: Path) -> str:
    """
    Tính mã SHA256 cho file model.

    Mục đích:
    - Kiểm tra tính toàn vẹn của artifact.
    - Giảm rủi ro model bị thay thế trái phép.
    """
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Chuẩn hóa tên cột:
    - Chuyển về chữ thường.
    - Bỏ khoảng trắng.
    - Đổi một số tên cột phổ biến trong UNSW-NB15 về dạng thống nhất.
    """
    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    rename_map = {
        "smeansz": "smean",
        "dmeansz": "dmean",
        "sintpkt": "sinpkt",
        "dintpkt": "dinpkt",
        "res_bdy_len": "response_body_len",
    }

    df = df.rename(columns=rename_map)

    # Nếu sau rename bị trùng tên cột thì giữ cột đầu tiên
    df = df.loc[:, ~df.columns.duplicated()]

    return df


def find_existing_file(data_dir: Path, candidate_names: list[str]) -> Path:
    """
    Tìm file đầu tiên tồn tại trong danh sách tên ứng viên.
    """
    for name in candidate_names:
        path = data_dir / name
        if path.exists():
            return path

    raise FileNotFoundError(
        "Không tìm thấy file trong các tên sau: "
        + ", ".join(candidate_names)
    )


# =========================================================
# 4. TỰ ĐỘNG NHẬN DIỆN SCHEMA DỮ LIỆU
# =========================================================

def infer_feature_schema(data_dir: Path, logger: logging.Logger) -> FeatureSchema:
    """
    Tự động nhận diện các feature từ file dữ liệu.

    Quy tắc:
    - Loại bỏ label, attack_cat, id, IP, port, timestamp.
    - Cột proto/state/service nếu tồn tại thì xem là categorical.
    - Các cột còn lại nếu chuyển được sang số thì xem là numeric.
    - Các cột chuỗi có số giá trị khác nhau thấp thì xem là categorical.
    - Các cột chuỗi có cardinality cao bị loại để tránh nhiễu.
    """

    candidate_schema_files = [
        "unsw_nb15_train_full.csv",
        "train_full.csv",
        "unsw_nb15_fold1_train.csv",
        "unsw_nb15_fold1_val.csv",
        "unsw_nb15_test_holdout.csv",
        "test_holdout.csv",
        "unsw_test_16467.csv",
    ]

    schema_source = find_existing_file(data_dir, candidate_schema_files)

    logger.info(f"Đang nhận diện schema từ file: {schema_source}")

    df = pd.read_csv(schema_source, low_memory=False, nrows=50000)
    df = normalize_columns(df)

    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"Không tìm thấy cột nhãn '{TARGET_COLUMN}' trong file: {schema_source}")

    numeric_features: list[str] = []
    categorical_features: list[str] = []
    skipped_features: list[str] = []

    for col in df.columns:
        if col in EXCLUDE_COLUMNS:
            continue

        series = df[col]

        # Các cột categorical phổ biến của UNSW-NB15
        if col in PREFERRED_CATEGORICAL_FEATURES:
            categorical_features.append(col)
            continue

        # Thử chuyển sang numeric
        converted = pd.to_numeric(series, errors="coerce")
        numeric_ratio = float(converted.notna().mean())

        if numeric_ratio >= 0.95:
            numeric_features.append(col)
            continue

        # Nếu không numeric nhưng số lượng giá trị khác nhau thấp,
        # có thể xem là categorical
        nunique = int(series.astype(str).nunique(dropna=True))
        if nunique <= 50:
            categorical_features.append(col)
        else:
            skipped_features.append(col)

    if not numeric_features and not categorical_features:
        raise ValueError("Không phát hiện được feature hợp lệ để huấn luyện.")

    feature_columns = numeric_features + categorical_features

    logger.info(f"Số feature numeric: {len(numeric_features)}")
    logger.info(f"Số feature categorical: {len(categorical_features)}")
    logger.info(f"Tổng số feature đầu vào: {len(feature_columns)}")

    if categorical_features:
        logger.info(f"Categorical features: {categorical_features}")

    if skipped_features:
        logger.warning(f"Các cột bị loại vì không phù hợp: {skipped_features}")

    return FeatureSchema(
        numeric_features=numeric_features,
        categorical_features=categorical_features,
        feature_columns=feature_columns,
        target_column=TARGET_COLUMN,
        schema_version=MODEL_VERSION,
    )


# =========================================================
# 5. ĐỌC VÀ KIỂM TRA DỮ LIỆU
# =========================================================

def load_labeled_csv(
    path: str | Path,
    schema: FeatureSchema,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Đọc CSV có nhãn và trả về X, y.

    Hàm này thực hiện:
    - Kiểm tra file tồn tại.
    - Kiểm tra file không rỗng.
    - Chuẩn hóa tên cột.
    - Kiểm tra đủ schema.
    - Ép feature numeric về số.
    - Xử lý NaN, inf.
    - Xử lý categorical nếu có.
    - Kiểm tra label nhị phân 0/1.
    """

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {path}")

    if path.stat().st_size == 0:
        raise ValueError(f"File CSV rỗng: {path}")

    df = pd.read_csv(path, low_memory=False)
    df = normalize_columns(df)

    required_columns = set(schema.feature_columns + [schema.target_column])
    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"Dữ liệu thiếu cột bắt buộc trong file {path}: {sorted(missing)}"
        )

    X = df[schema.feature_columns].copy()

    # Xử lý feature numeric
    for col in schema.numeric_features:
        X[col] = pd.to_numeric(X[col], errors="coerce")
        X[col] = X[col].replace([np.inf, -np.inf], np.nan)
        X[col] = X[col].fillna(0)

        # Phần lớn đặc trưng flow không nên âm
        X[col] = X[col].clip(lower=0)

    # Xử lý feature categorical nếu có
    for col in schema.categorical_features:
        X[col] = (
            X[col]
            .fillna("unknown")
            .astype(str)
            .str.lower()
            .str.strip()
        )

    # Xử lý nhãn
    y = pd.to_numeric(df[schema.target_column], errors="coerce")

    if y.isna().any():
        raise ValueError(f"Cột label có giá trị không hợp lệ trong file: {path}")

    y = y.astype(int)

    unique_labels = set(y.unique())
    if not unique_labels.issubset({0, 1}):
        raise ValueError(
            f"Label phải là nhị phân 0/1. Giá trị hiện có: {sorted(unique_labels)}"
        )

    if len(unique_labels) < 2:
        raise ValueError(
            f"File {path} chỉ có một lớp {sorted(unique_labels)}. "
            "Không đủ để huấn luyện/đánh giá nhị phân."
        )

    return X, y


def get_class_distribution(y: pd.Series | np.ndarray) -> dict:
    """
    Thống kê phân bố lớp Normal/Attack.
    """
    labels, counts = np.unique(y, return_counts=True)
    total = int(np.sum(counts))

    result = {
        "total": total,
        "normal_count": 0,
        "attack_count": 0,
        "normal_ratio": 0.0,
        "attack_ratio": 0.0,
    }

    for label, count in zip(labels, counts):
        if int(label) == 0:
            result["normal_count"] = int(count)
            result["normal_ratio"] = float(count / total)
        elif int(label) == 1:
            result["attack_count"] = int(count)
            result["attack_ratio"] = float(count / total)

    return result


def load_full_development_set(
    data_dir: Path,
    schema: FeatureSchema,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Đọc Full Development Set.

    Ưu tiên:
    1. unsw_nb15_train_full.csv
    2. train_full.csv
    3. Nếu không có, ghép 5 validation fold.

    Lưu ý:
    - Không ghép 5 file fold train vì các fold train có thể trùng mẫu.
    - Nếu dùng 5 validation fold, giả định các validation fold là rời nhau.
    """

    full_train_candidates = [
        "unsw_nb15_train_full.csv",
        "train_full.csv",
    ]

    for name in full_train_candidates:
        path = data_dir / name
        if path.exists():
            logger.info(f"Sử dụng Full Development Set: {path}")
            return load_labeled_csv(path, schema)

    val_paths = [data_dir / f"unsw_nb15_fold{fold}_val.csv" for fold in range(1, 6)]
    missing_val_paths = [str(path) for path in val_paths if not path.exists()]

    if missing_val_paths:
        raise FileNotFoundError(
            "Không tìm thấy Full Development Set và thiếu validation folds: "
            f"{missing_val_paths}"
        )

    logger.warning(
        "Không tìm thấy unsw_nb15_train_full.csv/train_full.csv. "
        "Đang ghép 5 validation folds để tạo Full Development Set."
    )

    X_parts = []
    y_parts = []

    for path in val_paths:
        X_part, y_part = load_labeled_csv(path, schema)
        X_parts.append(X_part)
        y_parts.append(y_part)

    X_dev = pd.concat(X_parts, ignore_index=True)
    y_dev = pd.concat(y_parts, ignore_index=True)

    return X_dev, y_dev


def load_holdout_test_set(
    data_dir: Path,
    schema: FeatureSchema,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series, Path]:
    """
    Đọc Hold-out Test Set.
    """
    test_candidates = [
        "unsw_nb15_test_holdout.csv",
        "test_holdout.csv",
        "unsw_test_16467.csv",
    ]

    test_path = find_existing_file(data_dir, test_candidates)
    logger.info(f"Sử dụng Hold-out Test Set: {test_path}")

    X_test, y_test = load_labeled_csv(test_path, schema)

    return X_test, y_test, test_path


# =========================================================
# 6. XÂY DỰNG PIPELINE HUẤN LUYỆN
# =========================================================

def make_one_hot_encoder() -> OneHotEncoder:
    """
    Tạo OneHotEncoder tương thích nhiều phiên bản scikit-learn.

    Một số bản scikit-learn mới dùng sparse_output.
    Một số bản cũ dùng sparse.
    """
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def build_pipeline(schema: FeatureSchema) -> Pipeline:
    """
    Xây dựng pipeline final.

    Trường hợp 1:
    - Dữ liệu chỉ có numeric features:
      RobustScaler -> RandomForest

    Trường hợp 2:
    - Dữ liệu có thêm categorical features:
      ColumnTransformer:
        numeric -> RobustScaler
        categorical -> OneHotEncoder
      -> RandomForest

    Không dùng SMOTE/RandomOverSampler.
    Dùng class_weight="balanced_subsample" để xử lý mất cân bằng lớp.
    """

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    if schema.categorical_features:
        preprocessor = ColumnTransformer(
            transformers=[
                ("num", RobustScaler(), schema.numeric_features),
                ("cat", make_one_hot_encoder(), schema.categorical_features),
            ],
            remainder="drop",
        )

        pipe = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", model),
            ]
        )
    else:
        pipe = Pipeline(
            steps=[
                ("scaler", RobustScaler()),
                ("classifier", model),
            ]
        )

    return pipe


# =========================================================
# 7. CROSS VALIDATION TÌM THRESHOLD
# =========================================================

def find_best_threshold_from_cv(
    data_dir: Path,
    schema: FeatureSchema,
    logger: logging.Logger,
) -> tuple[float, list[dict], float]:
    """
    Huấn luyện 5 fold và tìm threshold tốt nhất trên từng validation fold.

    Sau đó lấy Median Threshold để dùng cho mô hình cuối.
    """

    start_time = time.perf_counter()
    fold_results: list[dict] = []

    for fold in range(1, 6):
        logger.info(f"Đang huấn luyện fold {fold}/5...")

        train_path = data_dir / f"unsw_nb15_fold{fold}_train.csv"
        val_path = data_dir / f"unsw_nb15_fold{fold}_val.csv"

        X_train, y_train = load_labeled_csv(train_path, schema)
        X_val, y_val = load_labeled_csv(val_path, schema)

        train_dist = get_class_distribution(y_train)
        val_dist = get_class_distribution(y_val)

        logger.info(f"Fold {fold} - Train distribution: {train_dist}")
        logger.info(f"Fold {fold} - Val distribution: {val_dist}")

        pipe = build_pipeline(schema)

        fold_start = time.perf_counter()
        pipe.fit(X_train, y_train)
        fold_train_time = time.perf_counter() - fold_start

        scores = pipe.predict_proba(X_val)[:, 1]

        precision, recall, thresholds = precision_recall_curve(y_val, scores)

        if len(thresholds) == 0:
            best_threshold = 0.5
            y_val_pred = (scores >= best_threshold).astype(int)
            best_f1 = float(f1_score(y_val, y_val_pred, zero_division=0))
        else:
            f1_scores = (
                2 * precision[:-1] * recall[:-1]
                / np.maximum(precision[:-1] + recall[:-1], 1e-12)
            )

            best_idx = int(np.nanargmax(f1_scores))
            best_threshold = float(thresholds[best_idx])
            best_f1 = float(f1_scores[best_idx])
            y_val_pred = (scores >= best_threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_val, y_val_pred, labels=[0, 1]).ravel()

        fpr = float(fp / max(fp + tn, 1e-12))
        fnr = float(fn / max(fn + tp, 1e-12))

        fold_result = {
            "fold": fold,
            "best_threshold": best_threshold,
            "f1": best_f1,
            "precision": float(precision_score(y_val, y_val_pred, zero_division=0)),
            "recall": float(recall_score(y_val, y_val_pred, zero_division=0)),
            "fpr": fpr,
            "fnr": fnr,
            "train_time_seconds": float(fold_train_time),
            "train_distribution": train_dist,
            "validation_distribution": val_dist,
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
        }

        fold_results.append(fold_result)

        logger.info(
            f"Fold {fold} hoàn tất | "
            f"threshold={best_threshold:.6f} | "
            f"F1={best_f1:.6f} | "
            f"FPR={fpr:.6f} | "
            f"time={fold_train_time:.2f}s"
        )

    median_threshold = float(np.median([r["best_threshold"] for r in fold_results]))
    cv_time = time.perf_counter() - start_time

    logger.info(f"Median threshold từ 5 folds = {median_threshold:.6f}")
    logger.info(f"Thời gian CV = {cv_time:.2f}s")

    return median_threshold, fold_results, cv_time


# =========================================================
# 8. ĐÁNH GIÁ MÔ HÌNH
# =========================================================

def evaluate_model(
    pipe: Pipeline,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    threshold: float,
) -> dict:
    """
    Đánh giá mô hình cuối cùng trên Hold-out Test Set.
    """

    scores = pipe.predict_proba(X_test)[:, 1]
    y_pred = (scores >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()

    fpr = float(fp / max(fp + tn, 1e-12))
    fnr = float(fn / max(fn + tp, 1e-12))
    tnr = float(tn / max(tn + fp, 1e-12))

    try:
        roc_auc = float(roc_auc_score(y_test, scores))
    except ValueError:
        roc_auc = None

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "fpr": fpr,
        "false_positive_rate": fpr,
        "fnr": fnr,
        "tnr_specificity": tnr,
        "roc_auc": roc_auc,
        "threshold": float(threshold),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }

    return metrics


# =========================================================
# 9. FEATURE IMPORTANCE
# =========================================================

def get_model_feature_names(pipe: Pipeline, schema: FeatureSchema) -> list[str]:
    """
    Lấy danh sách tên feature sau tiền xử lý.

    Nếu có OneHotEncoder, số lượng feature sau transform sẽ tăng lên.
    Nếu chỉ numeric, danh sách feature giữ nguyên.
    """

    if "preprocessor" in pipe.named_steps:
        preprocessor = pipe.named_steps["preprocessor"]
        feature_names = preprocessor.get_feature_names_out()
        return [str(name) for name in feature_names]

    return schema.feature_columns


def save_feature_importance(
    pipe: Pipeline,
    schema: FeatureSchema,
    output_path: Path,
) -> None:
    """
    Lưu độ quan trọng của đặc trưng từ Random Forest.

    File này rất hữu ích cho luận văn vì giúp giải thích mô hình.
    """

    model = pipe.named_steps["classifier"]
    feature_names = get_model_feature_names(pipe, schema)

    importance_values = model.feature_importances_

    if len(feature_names) != len(importance_values):
        feature_names = [f"feature_{i}" for i in range(len(importance_values))]

    importance_df = pd.DataFrame(
        {
            "feature": feature_names,
            "importance": importance_values,
        }
    ).sort_values("importance", ascending=False)

    importance_df.to_csv(output_path, index=False, encoding="utf-8-sig")


# =========================================================
# 10. BENCHMARK TỐC ĐỘ SUY LUẬN
# =========================================================

def benchmark_inference(pipe: Pipeline, X_test: pd.DataFrame) -> dict:
    """
    Đo tốc độ suy luận của mô hình.

    Kết quả gồm:
    - latency trung bình trên mỗi flow.
    - throughput tính bằng flows/second.
    """

    results = {}

    for batch_size in [1, 32, 128, 512, 1024]:
        sample = X_test.head(min(batch_size, len(X_test)))

        # Warm-up để tránh đo lần gọi đầu tiên
        _ = pipe.predict_proba(sample)

        repeats = 5
        elapsed_times = []

        for _ in range(repeats):
            start = time.perf_counter()
            _ = pipe.predict_proba(sample)
            elapsed = time.perf_counter() - start
            elapsed_times.append(elapsed)

        avg_elapsed = float(np.mean(elapsed_times))
        flows = len(sample)

        latency_ms_per_flow = (avg_elapsed / flows) * 1000
        throughput_fps = flows / avg_elapsed if avg_elapsed > 0 else 0

        results[f"batch_{batch_size}"] = {
            "flows": int(flows),
            "average_time_seconds": float(avg_elapsed),
            "latency_ms_per_flow": float(latency_ms_per_flow),
            "throughput_flows_per_second": float(throughput_fps),
        }

    return results


# =========================================================
# 11. HÀM MAIN
# =========================================================

def main() -> None:
    """
    Quy trình chính:
    1. Nhận diện schema.
    2. Tìm threshold bằng 5-Fold CV.
    3. Retrain trên Full Development Set.
    4. Đánh giá trên Hold-out Test Set.
    5. Lưu model, metrics, metadata, schema, feature importance, benchmark.
    """

    logger = setup_logging()

    logger.info("=" * 70)
    logger.info("PIPELINE HUẤN LUYỆN HYBRID-NIDS - FINAL")
    logger.info("=" * 70)

    total_start = time.perf_counter()

    # -----------------------------------------------------
    # Bước 1: Nhận diện schema
    # -----------------------------------------------------
    logger.info("[1/7] Nhận diện schema dữ liệu...")
    schema = infer_feature_schema(DATA_DIR, logger)

    schema_path = ARTIFACTS_DIR / "feature_schema_model.json"
    save_json(asdict(schema), schema_path)

    # -----------------------------------------------------
    # Bước 2: Tìm threshold bằng Group-aware Stratified 5-Fold CV
    # -----------------------------------------------------
    logger.info("[2/7] Tìm threshold bằng Group-aware Stratified 5-Fold CV theo feature hash...")
    best_threshold, fold_results, cv_time = find_best_threshold_from_cv(
        DATA_DIR,
        schema,
        logger,
    )

    # -----------------------------------------------------
    # Bước 3: Huấn luyện lại trên Full Development Set
    # -----------------------------------------------------
    logger.info("[3/7] Huấn luyện lại trên Full Development Set...")

    X_dev, y_dev = load_full_development_set(DATA_DIR, schema, logger)
    dev_class_distribution = get_class_distribution(y_dev)

    logger.info(f"Development distribution: {dev_class_distribution}")

    final_pipe = build_pipeline(schema)

    final_train_start = time.perf_counter()
    final_pipe.fit(X_dev, y_dev)
    final_train_time = time.perf_counter() - final_train_start

    logger.info(f"Huấn luyện final model hoàn tất sau {final_train_time:.2f}s")

    # -----------------------------------------------------
    # Bước 4: Đánh giá trên Hold-out Test Set
    # -----------------------------------------------------
    logger.info("[4/7] Đánh giá trên Hold-out Test Set...")

    X_test, y_test, test_path = load_holdout_test_set(DATA_DIR, schema, logger)
    test_class_distribution = get_class_distribution(y_test)

    logger.info(f"Test distribution: {test_class_distribution}")

    eval_start = time.perf_counter()
    metrics = evaluate_model(final_pipe, X_test, y_test, best_threshold)
    eval_time = time.perf_counter() - eval_start

    logger.info(f"Đánh giá hoàn tất sau {eval_time:.2f}s")
    logger.info(f"Final metrics: {json.dumps(metrics, ensure_ascii=False)}")

    # -----------------------------------------------------
    # Bước 5: Benchmark tốc độ suy luận
    # -----------------------------------------------------
    logger.info("[5/7] Benchmark tốc độ suy luận...")

    inference_benchmark = benchmark_inference(final_pipe, X_test)
    benchmark_path = ARTIFACTS_DIR / "inference_benchmark.json"
    save_json(inference_benchmark, benchmark_path)

    logger.info(f"Inference benchmark: {json.dumps(inference_benchmark, ensure_ascii=False)}")

    # -----------------------------------------------------
    # Bước 6: Lưu model và các artifact
    # -----------------------------------------------------
    logger.info("[6/7] Lưu model và artifact...")

    model_path = ARTIFACTS_DIR / "nids_rf_pipeline.pkl"
    metrics_path = ARTIFACTS_DIR / "metrics.json"
    metadata_path = ARTIFACTS_DIR / "training_metadata.json"
    metadata_alias_path = ARTIFACTS_DIR / "metadata.json"
    confusion_matrix_path = ARTIFACTS_DIR / "confusion_matrix.png"
    feature_importance_path = ARTIFACTS_DIR / "feature_importance.csv"

    joblib.dump(final_pipe, model_path)
    model_sha256 = sha256_file(model_path)

    metrics["train_size"] = int(len(X_dev))
    metrics["test_size"] = int(len(X_test))

    save_feature_importance(final_pipe, schema, feature_importance_path)
    save_confusion_matrix_png(metrics, confusion_matrix_path)
    save_json(metrics, metrics_path)

    f1_list = [r["f1"] for r in fold_results]
    threshold_list = [r["best_threshold"] for r in fold_results]

    total_time = time.perf_counter() - total_start

    metadata = {
        "model_name": "Hybrid-NIDS Random Forest",
        "model_version": MODEL_VERSION,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "training_date": datetime.now().isoformat(timespec="seconds"),
        "task": "Binary classification: Normal vs Attack",
        "dataset": "UNSW-NB15 compatible flow records",
        "data_dir": str(DATA_DIR),
        "test_file": str(test_path),
        "dataset_paths": {
            "data_dir": str(DATA_DIR),
            "development_file": str(
                DATA_DIR / "unsw_nb15_train_full.csv"
                if (DATA_DIR / "unsw_nb15_train_full.csv").exists()
                else DATA_DIR / "train_full.csv"
            ),
            "test_file": str(test_path),
        },

        "pipeline_type": (
            "Numeric flow features + RobustScaler + RandomForest"
            if not schema.categorical_features
            else "Mixed numeric/categorical features + ColumnTransformer + RandomForest"
        ),

        "model_algorithm": "RandomForestClassifier",
        "random_state": RANDOM_STATE,
        "class_imbalance_strategy": "class_weight='balanced_subsample'",
        "resampling": "None",
        "smote_usage": "None",
        "cv_strategy": "Group-aware Stratified 5-Fold Cross Validation by feature hash on development set",
        "preprocessing_pipeline": (
            "RobustScaler + RandomForest"
            if not schema.categorical_features
            else "ColumnTransformer(numeric=RobustScaler, categorical=OneHotEncoder) + RandomForest"
        ),
        "threshold_strategy": "Median threshold from Group-aware Stratified 5-Fold Cross Validation",
        "threshold": best_threshold,

        "schema": asdict(schema),
        "numeric_features": schema.numeric_features,
        "categorical_features": schema.categorical_features,
        "feature_count_before_encoding": len(schema.feature_columns),
        "numeric_feature_count": len(schema.numeric_features),
        "categorical_feature_count": len(schema.categorical_features),

        "class_distribution": {
            "development": dev_class_distribution,
            "test": test_class_distribution,
        },

        "cv_summary": {
            "mean_f1": float(np.mean(f1_list)),
            "std_f1": float(np.std(f1_list)),
            "median_f1": float(np.median(f1_list)),
            "mean_threshold": float(np.mean(threshold_list)),
            "median_threshold": float(np.median(threshold_list)),
            "std_threshold": float(np.std(threshold_list)),
            "cv_time_seconds": float(cv_time),
        },

        "fold_results": fold_results,
        "final_test_metrics": metrics,

        "timing": {
            "cv_time_seconds": float(cv_time),
            "final_train_time_seconds": float(final_train_time),
            "evaluation_time_seconds": float(eval_time),
            "total_time_seconds": float(total_time),
        },

        "files": {
            "model_file": str(model_path),
            "metrics_file": str(metrics_path),
            "metadata_file": str(metadata_path),
            "metadata_alias_file": str(metadata_alias_path),
            "feature_schema_file": str(schema_path),
            "feature_importance_file": str(feature_importance_path),
            "confusion_matrix_file": str(confusion_matrix_path),
            "inference_benchmark_file": str(benchmark_path),
            "training_log_file": str(ARTIFACTS_DIR / "training.log"),
        },

        "artifact_integrity": {
            "model_sha256": model_sha256,
        },

        "environment": {
            "python": platform.python_version(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "sklearn": sklearn.__version__,
            "sklearn_version": sklearn.__version__,
        },

        "security_note": (
            "Model artifact sử dụng định dạng pickle/joblib. "
            "Chỉ load model từ thư mục tin cậy và nên kiểm tra SHA256 "
            "trước khi dùng trong môi trường production."
        ),

        "thesis_note": (
            "Pipeline này phục vụ huấn luyện offline. "
            "Khi triển khai Hybrid-NIDS thực tế cần bổ sung module inference "
            "nhận flow từ Suricata/Zeek/CICFlowMeter và xuất cảnh báo sang ELK/Kibana."
        ),
    }

    save_json(metadata, metadata_path)
    save_json(metadata, metadata_alias_path)

    # -----------------------------------------------------
    # Bước 7: In kết quả tổng kết
    # -----------------------------------------------------
    logger.info("[7/7] Hoàn tất.")
    logger.info("-" * 70)
    logger.info(f"Model:              {model_path}")
    logger.info(f"Metrics:            {metrics_path}")
    logger.info(f"Metadata:           {metadata_path}")
    logger.info(f"Metadata alias:     {metadata_alias_path}")
    logger.info(f"Feature schema:     {schema_path}")
    logger.info(f"Feature importance: {feature_importance_path}")
    logger.info(f"Confusion matrix:   {confusion_matrix_path}")
    logger.info(f"Benchmark:          {benchmark_path}")
    logger.info(f"SHA256:             {model_sha256}")
    logger.info("-" * 70)

    print("\n===================== FINAL METRICS =====================")
    print(json.dumps(metrics, indent=2, ensure_ascii=False))

    print("\n================= INFERENCE BENCHMARK ===================")
    print(json.dumps(inference_benchmark, indent=2, ensure_ascii=False))

    print("\n[+] Hoàn tất huấn luyện Hybrid-NIDS Final.")


if __name__ == "__main__":
    main()
