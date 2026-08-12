"""
===========================================================
SO SÁNH HIỆU NĂNG CÁC THUẬT TOÁN HỌC MÁY
===========================================================

Thuật toán so sánh:
1. Decision Tree
2. Naive Bayes
3. Logistic Regression
4. SVM RBF Kernel
5. XGBoost
6. MLP Neural Network / Deep Learning baseline
7. Random Forest - mô hình đề xuất

Đầu vào:
- UNSW_NB15_Splitted_CLEAN/unsw_nb15_train_full.csv
- UNSW_NB15_Splitted_CLEAN/unsw_nb15_test_holdout.csv
- models/feature_schema_model.json
- models/nids_rf_pipeline.pkl
- models/metrics.json

Đầu ra:
- models/ml_algorithm_comparison.csv
- models/ml_algorithm_comparison.md
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from artifact_security import load_trusted_model
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
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
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler


# =========================================================
# 1. CẤU HÌNH
# =========================================================

DATA_DIR = Path("./UNSW_NB15_Splitted_CLEAN")
MODELS_DIR = Path("./models")

TRAIN_PATH = DATA_DIR / "unsw_nb15_train_full.csv"
TEST_PATH = DATA_DIR / "unsw_nb15_test_holdout.csv"

FEATURE_SCHEMA_PATH = MODELS_DIR / "feature_schema_model.json"
RF_MODEL_PATH = MODELS_DIR / "nids_rf_pipeline.pkl"
RF_METADATA_PATH = MODELS_DIR / "metadata.json"
RF_METRICS_PATH = MODELS_DIR / "metrics.json"

OUTPUT_CSV = MODELS_DIR / "ml_algorithm_comparison.csv"
OUTPUT_MD = MODELS_DIR / "ml_algorithm_comparison.md"

RANDOM_STATE = 42

# Do SVM RBF và MLP rất nặng nên giới hạn.
SVM_TRAIN_SAMPLE = 80_000
MLP_TRAIN_SAMPLE = None

# XGBoost có thể chạy full, nhưng nếu máy yếu có thể giảm bằng cách đặt XGB_TRAIN_SAMPLE.
# Để None nghĩa là dùng toàn bộ Development Set.
XGB_TRAIN_SAMPLE = None

# Decision Tree, Naive Bayes, Logistic Regression chạy full.
GLOBAL_BASELINE_SAMPLE = None


# =========================================================
# 2. HÀM TIỆN ÍCH
# =========================================================

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    rename_map = {
        "smeansz": "smean",
        "dmeansz": "dmean",
        "sintpkt": "sinpkt",
        "dintpkt": "dinpkt",
        "res_bdy_len": "response_body_len",
        "ct_src_ ltm": "ct_src_ltm",
    }

    df = df.rename(columns=rename_map)
    df = df.loc[:, ~df.columns.duplicated()]
    return df


def fix_col_name(col: str) -> str:
    col = str(col).lower().strip()
    if col == "ct_src_ ltm":
        return "ct_src_ltm"
    return col


def load_schema() -> dict:
    if not FEATURE_SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Không tìm thấy {FEATURE_SCHEMA_PATH}. Hãy chạy train_model.py trước."
        )

    with open(FEATURE_SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)

    numeric_features = [fix_col_name(c) for c in schema["numeric_features"]]
    categorical_features = [fix_col_name(c) for c in schema["categorical_features"]]
    feature_columns = [fix_col_name(c) for c in schema["feature_columns"]]

    return {
        "numeric_features": numeric_features,
        "categorical_features": categorical_features,
        "feature_columns": feature_columns,
        "target_column": schema.get("target_column", "label"),
    }


def load_labeled_csv(path: Path, schema: dict) -> tuple[pd.DataFrame, pd.Series]:
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {path}")

    print(f"[*] Đang đọc: {path}")
    df = pd.read_csv(path, low_memory=False)
    df = normalize_columns(df)

    feature_columns = schema["feature_columns"]
    numeric_features = schema["numeric_features"]
    categorical_features = schema["categorical_features"]
    target_column = schema["target_column"]

    missing = set(feature_columns + [target_column]) - set(df.columns)
    if missing:
        raise ValueError(f"File {path} thiếu cột: {sorted(missing)}")

    X = df[feature_columns].copy()

    for col in numeric_features:
        X[col] = pd.to_numeric(X[col], errors="coerce")
        X[col] = X[col].replace([np.inf, -np.inf], np.nan)
        X[col] = X[col].fillna(0)
        X[col] = X[col].clip(lower=0)

    for col in categorical_features:
        X[col] = (
            X[col]
            .fillna("unknown")
            .astype(str)
            .str.lower()
            .str.strip()
        )

    y = pd.to_numeric(df[target_column], errors="coerce").fillna(0).astype(int)

    return X, y


def stratified_sample(
    X: pd.DataFrame,
    y: pd.Series,
    n_rows: int | None,
    name: str,
) -> tuple[pd.DataFrame, pd.Series]:
    if n_rows is None or len(X) <= n_rows:
        return X, y

    print(f"[!] {name}: lấy mẫu stratified {n_rows:,}/{len(X):,} dòng")

    X_sample, _, y_sample, _ = train_test_split(
        X,
        y,
        train_size=n_rows,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    return X_sample.reset_index(drop=True), y_sample.reset_index(drop=True)


def make_onehot() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def build_preprocessor(schema: dict) -> ColumnTransformer:
    return ColumnTransformer(
        transformers=[
            ("num", RobustScaler(), schema["numeric_features"]),
            ("cat", make_onehot(), schema["categorical_features"]),
        ],
        remainder="drop",
    )


def build_pipeline(estimator: Any, schema: dict) -> Pipeline:
    preprocessor = build_preprocessor(schema)
    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", estimator),
        ]
    )


def optimize_threshold_by_f1(y_true: pd.Series, scores: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(y_true, scores)

    if len(thresholds) == 0:
        return 0.5

    f1_scores = (
        2 * precision[:-1] * recall[:-1]
        / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    )

    best_idx = int(np.nanargmax(f1_scores))
    return float(thresholds[best_idx])


def evaluate_scores(
    model_name: str,
    y_true: pd.Series,
    scores: np.ndarray,
    threshold: float,
    train_rows: int,
    test_rows: int,
    train_time: float | None,
    predict_time: float,
    note: str,
) -> dict:
    y_pred = (scores >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    fpr = fp / max(fp + tn, 1)
    fnr = fn / max(fn + tp, 1)

    throughput = test_rows / predict_time if predict_time > 0 else None

    return {
        "model": model_name,
        "train_rows": int(train_rows),
        "test_rows": int(test_rows),
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "train_time_seconds": None if train_time is None else float(train_time),
        "predict_time_seconds": float(predict_time),
        "throughput_flows_per_second": None if throughput is None else float(throughput),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "note": note,
    }


def train_and_evaluate_model(
    model_name: str,
    estimator: Any,
    X_dev: pd.DataFrame,
    y_dev: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    schema: dict,
    train_sample: int | None,
    note: str,
) -> dict:
    print("\n" + "=" * 70)
    print(f"THUẬT TOÁN: {model_name}")
    print("=" * 70)

    X_work, y_work = stratified_sample(X_dev, y_dev, train_sample, model_name)

    # Chia validation nhỏ để tối ưu threshold.
    X_train, X_val, y_train, y_val = train_test_split(
        X_work,
        y_work,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y_work,
    )

    # Train lần 1 để chọn threshold.
    pipe_threshold = build_pipeline(estimator, schema)

    start = time.perf_counter()
    pipe_threshold.fit(X_train, y_train)
    threshold_train_time = time.perf_counter() - start

    if hasattr(pipe_threshold, "predict_proba"):
        val_scores = pipe_threshold.predict_proba(X_val)[:, 1]
    else:
        val_scores = pipe_threshold.decision_function(X_val)

    threshold = optimize_threshold_by_f1(y_val, val_scores)

    print(f"[+] Threshold tối ưu theo F1 trên validation = {threshold:.6f}")
    print(f"[+] Train chọn threshold: {threshold_train_time:.2f}s")

    # Train lại trên X_work.
    pipe_final = build_pipeline(estimator, schema)

    start = time.perf_counter()
    pipe_final.fit(X_work, y_work)
    train_time = time.perf_counter() - start

    # Đánh giá trên toàn bộ Hold-out Test Set.
    start = time.perf_counter()

    if hasattr(pipe_final, "predict_proba"):
        test_scores = pipe_final.predict_proba(X_test)[:, 1]
    else:
        test_scores = pipe_final.decision_function(X_test)

    predict_time = time.perf_counter() - start

    result = evaluate_scores(
        model_name=model_name,
        y_true=y_test,
        scores=test_scores,
        threshold=threshold,
        train_rows=len(X_work),
        test_rows=len(X_test),
        train_time=train_time,
        predict_time=predict_time,
        note=note,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return result


def load_random_forest_final_result(X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    print("\n" + "=" * 70)
    print("THUẬT TOÁN: Random Forest - Đề xuất")
    print("=" * 70)

    if not RF_MODEL_PATH.exists():
        raise FileNotFoundError(f"Không tìm thấy model: {RF_MODEL_PATH}")

    if not RF_METRICS_PATH.exists():
        raise FileNotFoundError(f"Không tìm thấy metrics: {RF_METRICS_PATH}")

    with open(RF_METRICS_PATH, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    threshold = float(metrics["threshold"])

    rf_pipe = load_trusted_model(RF_MODEL_PATH, RF_METADATA_PATH)

    start = time.perf_counter()
    scores = rf_pipe.predict_proba(X_test)[:, 1]
    predict_time = time.perf_counter() - start

    result = evaluate_scores(
        model_name="Random Forest (Đề xuất)",
        y_true=y_test,
        scores=scores,
        threshold=threshold,
        train_rows=2030129,
        test_rows=len(X_test),
        train_time=None,
        predict_time=predict_time,
        note="Mô hình đề xuất; threshold là median từ 5-Fold CV",
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))

    return result


def try_build_xgboost():
    try:
        from xgboost import XGBClassifier
    except ImportError:
        print("[!] Chưa cài xgboost. Bỏ qua thuật toán XGBoost.")
        return None

    return XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        tree_method="hist",
    )


def save_markdown(df: pd.DataFrame) -> None:
    md_lines = []
    md_lines.append(
        "| Thuật toán | Accuracy | Precision | Recall | F1-score | FPR | ROC-AUC | Threshold | Train rows | Train time | Throughput | Ghi chú |"
    )
    md_lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"
    )

    for _, row in df.iterrows():
        train_time = (
            ""
            if pd.isna(row["train_time_seconds"])
            else f"{row['train_time_seconds']:.2f}s"
        )

        throughput = (
            ""
            if pd.isna(row["throughput_flows_per_second"])
            else f"{row['throughput_flows_per_second']:.2f}"
        )

        md_lines.append(
            f"| {row['model']} "
            f"| {row['accuracy']:.6f} "
            f"| {row['precision']:.6f} "
            f"| {row['recall']:.6f} "
            f"| {row['f1']:.6f} "
            f"| {row['fpr']:.6f} "
            f"| {row['roc_auc']:.6f} "
            f"| {row['threshold']:.6f} "
            f"| {int(row['train_rows'])} "
            f"| {train_time} "
            f"| {throughput} "
            f"| {row['note']} |"
        )

    OUTPUT_MD.write_text("\n".join(md_lines), encoding="utf-8")


def main() -> None:
    print("=" * 70)
    print("SO SÁNH HIỆU NĂNG CÁC THUẬT TOÁN HỌC MÁY")
    print("=" * 70)

    schema = load_schema()

    X_dev, y_dev = load_labeled_csv(TRAIN_PATH, schema)
    X_test, y_test = load_labeled_csv(TEST_PATH, schema)

    if GLOBAL_BASELINE_SAMPLE is not None:
        X_dev_base, y_dev_base = stratified_sample(
            X_dev,
            y_dev,
            GLOBAL_BASELINE_SAMPLE,
            "GLOBAL_BASELINE_SAMPLE",
        )
    else:
        X_dev_base, y_dev_base = X_dev, y_dev

    results = []

    # 0. Dummy baseline để có mốc thấp nhất.
    results.append(
        train_and_evaluate_model(
            model_name="Dummy Majority Baseline",
            estimator=DummyClassifier(strategy="most_frequent"),
            X_dev=X_dev_base,
            y_dev=y_dev_base,
            X_test=X_test,
            y_test=y_test,
            schema=schema,
            train_sample=None,
            note="Baseline tối thiểu, dùng làm mốc tham chiếu",
        )
    )

    # 1. Decision Tree
    results.append(
        train_and_evaluate_model(
            model_name="Decision Tree",
            estimator=DecisionTreeClassifier(
                max_depth=12,
                min_samples_leaf=5,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
            X_dev=X_dev_base,
            y_dev=y_dev_base,
            X_test=X_test,
            y_test=y_test,
            schema=schema,
            train_sample=None,
            note="Chạy full Development Set",
        )
    )

    # 2. Naive Bayes
    results.append(
        train_and_evaluate_model(
            model_name="Naive Bayes",
            estimator=GaussianNB(),
            X_dev=X_dev_base,
            y_dev=y_dev_base,
            X_test=X_test,
            y_test=y_test,
            schema=schema,
            train_sample=None,
            note="Chạy full Development Set",
        )
    )

    # 3. Logistic Regression
    results.append(
        train_and_evaluate_model(
            model_name="Logistic Regression",
            estimator=LogisticRegression(
                max_iter=300,
                class_weight="balanced",
                solver="saga",
                n_jobs=-1,
                random_state=RANDOM_STATE,
            ),
            X_dev=X_dev_base,
            y_dev=y_dev_base,
            X_test=X_test,
            y_test=y_test,
            schema=schema,
            train_sample=None,
            note="Chạy full Development Set",
        )
    )

    # 4. SVM RBF Kernel
    """ results.append(
        train_and_evaluate_model(
           model_name="SVM (RBF Kernel)",
            estimator=SVC(
                kernel="rbf",
                C=1.0,
                gamma="scale",
                class_weight="balanced",
               probability=True,
                random_state=RANDOM_STATE,
            ),
            X_dev=X_dev,
            y_dev=y_dev,
            X_test=X_test,
           y_test=y_test,
            schema=schema,
            train_sample=SVM_TRAIN_SAMPLE,
            note=f"Train trên mẫu stratified {SVM_TRAIN_SAMPLE:,} dòng do RBF SVM rất tốn tài nguyên",
        )
    )
    """

    # 5. XGBoost
    xgb_model = try_build_xgboost()
    if xgb_model is not None:
        results.append(
            train_and_evaluate_model(
                model_name="XGBoost",
                estimator=xgb_model,
                X_dev=X_dev,
                y_dev=y_dev,
                X_test=X_test,
                y_test=y_test,
                schema=schema,
                train_sample=XGB_TRAIN_SAMPLE,
                note="Chạy full Development Set nếu XGB_TRAIN_SAMPLE=None",
            )
        )

    # 6. Deep Learning baseline: MLP Neural Network
    results.append(
        train_and_evaluate_model(
            model_name="MLP Neural Network",
            estimator=MLPClassifier(
                hidden_layer_sizes=(128, 64),
                activation="relu",
                solver="adam",
                batch_size=2048,
                learning_rate_init=0.001,
                max_iter=30,
                early_stopping=True,
                validation_fraction=0.1,
                random_state=RANDOM_STATE,
            ),
            X_dev=X_dev,
            y_dev=y_dev,
            X_test=X_test,
            y_test=y_test,
            schema=schema,
            train_sample=MLP_TRAIN_SAMPLE,
            note="Deep Learning baseline; chạy full Development Set",
        )
    )

    # 7. Random Forest - model đề xuất
    results.append(load_random_forest_final_result(X_test, y_test))

    df = pd.DataFrame(results)
    df = df.sort_values(["f1", "fpr"], ascending=[False, True]).reset_index(drop=True)

    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    save_markdown(df)

    print("\n" + "=" * 70)
    print("BẢNG SO SÁNH TỔNG HỢP")
    print("=" * 70)
    print(df.to_string(index=False))

    print("\n[+] Đã lưu:")
    print(f"    {OUTPUT_CSV}")
    print(f"    {OUTPUT_MD}")


if __name__ == "__main__":
    main()

