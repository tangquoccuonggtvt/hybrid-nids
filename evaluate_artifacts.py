"""Đánh giá nhanh full pipeline chính thức trên một CSV có label."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from artifact_security import load_trusted_model
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from nids_detector import load_feature_schema, load_threshold, prepare_features
from schema_check import build_official_schema_report, validate_schema_contract


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate official NIDS pipeline trên CSV có label.")
    parser.add_argument("--csv", default="./UNSW_NB15_Splitted_CLEAN/unsw_nb15_test_holdout.csv")
    parser.add_argument("--model", default="./models/nids_rf_pipeline.pkl")
    parser.add_argument("--schema", default="./models/feature_schema_model.json")
    parser.add_argument("--metadata", default="./models/metadata.json")
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--output-json", default=None)
    return parser.parse_args()


def load_artifacts(model_path: str, schema_path: str, metadata_path: str | None, cli_threshold: float | None) -> tuple[Any, dict, float]:
    pipeline = load_trusted_model(model_path, metadata_path)
    schema = load_feature_schema(Path(schema_path))
    validate_schema_contract(schema)

    feature_columns = list(schema["feature_columns"])
    model_features = getattr(pipeline, "n_features_in_", len(feature_columns))
    if int(model_features) != len(feature_columns):
        raise ValueError(f"Pipeline cần {model_features} feature nhưng schema có {len(feature_columns)} cột.")

    threshold = load_threshold(Path(metadata_path) if metadata_path else None, cli_threshold)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"Threshold phải nằm trong [0, 1], nhận được: {threshold}")
    return pipeline, schema, threshold


def positive_scores(pipeline: Any, X: pd.DataFrame) -> tuple[pd.Series | Any, Any]:
    if hasattr(pipeline, "predict_proba"):
        scores = pipeline.predict_proba(X)[:, 1]
        return scores, scores

    y_pred = pipeline.predict(X)
    return y_pred, y_pred


def main() -> None:
    args = parse_args()
    df = pd.read_csv(args.csv, low_memory=False)
    if "label" not in df.columns:
        raise ValueError("CSV cần có cột label để evaluate.")

    pipeline, schema, threshold = load_artifacts(args.model, args.schema, args.metadata, args.threshold)
    schema_report = build_official_schema_report(df, schema)
    if schema_report.missing:
        raise ValueError(f"CSV thiếu feature bắt buộc so với schema chính thức: {schema_report.missing}")
    if schema_report.non_numeric:
        raise ValueError(f"Feature numeric chứa giá trị không ép kiểu số được: {schema_report.non_numeric}")

    X = prepare_features(df, schema)
    y = pd.to_numeric(df["label"], errors="raise").astype(int)

    scores, raw_prediction = positive_scores(pipeline, X)
    if hasattr(pipeline, "predict_proba"):
        y_pred = (scores >= threshold).astype(int)
    else:
        y_pred = raw_prediction

    cm = confusion_matrix(y, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    has_binary_labels = len(set(y)) == 2

    results = {
        "rows": int(len(df)),
        "model": args.model,
        "schema": args.schema,
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y, y_pred)),
        "precision": float(precision_score(y, y_pred, zero_division=0)),
        "recall": float(recall_score(y, y_pred, zero_division=0)),
        "f1": float(f1_score(y, y_pred, zero_division=0)),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "roc_auc": float(roc_auc_score(y, scores)) if has_binary_labels else None,
        "average_precision": float(average_precision_score(y, scores)) if has_binary_labels else None,
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
        "schema_report": {
            "extra_columns_ignored": schema_report.extra,
            "nan_count_before_cleaning": schema_report.nan_count_before_cleaning,
            "inf_count_before_cleaning": schema_report.inf_count_before_cleaning,
        },
    }
    print(json.dumps(results, ensure_ascii=False, indent=2))

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
