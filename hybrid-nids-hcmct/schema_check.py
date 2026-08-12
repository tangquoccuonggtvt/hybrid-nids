"""Kiểm tra nhanh schema chính thức của model và CSV flow records."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from nids_detector import load_feature_schema, normalize_columns, prepare_features


@dataclass(frozen=True)
class OfficialSchemaReport:
    """Báo cáo kiểm tra CSV so với schema 41 feature chính thức."""

    expected_feature_count: int
    numeric_feature_count: int
    categorical_feature_count: int
    missing: list[str]
    extra: list[str]
    non_numeric: list[str]
    nan_count_before_cleaning: int
    inf_count_before_cleaning: int

    @property
    def ok(self) -> bool:
        return not self.missing and not self.non_numeric


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check schema chính thức của model/dataset NIDS.")
    parser.add_argument("--schema", default="./models/feature_schema_model.json")
    parser.add_argument("--csv", default=None, help="CSV flow records cần kiểm tra.")
    parser.add_argument("--non-strict", action="store_true", help="Không raise khi CSV thiếu/sai cột; chỉ in report.")
    return parser.parse_args()


def validate_schema_contract(schema: dict) -> None:
    required_keys = {"numeric_features", "categorical_features", "feature_columns"}
    missing_keys = required_keys - set(schema)
    if missing_keys:
        raise ValueError(f"Schema thiếu khóa bắt buộc: {sorted(missing_keys)}")

    numeric_features = list(schema["numeric_features"])
    categorical_features = list(schema["categorical_features"])
    feature_columns = list(schema["feature_columns"])
    if feature_columns != numeric_features + categorical_features:
        raise ValueError("feature_columns phải bằng numeric_features + categorical_features theo đúng thứ tự.")
    if len(feature_columns) != len(set(feature_columns)):
        raise ValueError("Schema có feature bị trùng tên.")


def build_official_schema_report(df: pd.DataFrame, schema: dict) -> OfficialSchemaReport:
    work = normalize_columns(df)
    feature_columns = list(schema["feature_columns"])
    numeric_features = list(schema["numeric_features"])
    categorical_features = list(schema["categorical_features"])

    missing = sorted(set(feature_columns) - set(work.columns))
    extra = sorted(set(work.columns) - set(feature_columns))

    non_numeric: list[str] = []
    for col in numeric_features:
        if col not in work.columns:
            continue
        converted = pd.to_numeric(work[col], errors="coerce")
        invalid_mask = work[col].notna() & converted.isna()
        if bool(invalid_mask.any()):
            non_numeric.append(col)

    present_numeric = [col for col in numeric_features if col in work.columns]
    numeric_part = work[present_numeric].apply(pd.to_numeric, errors="coerce") if present_numeric else pd.DataFrame()
    nan_count = int(numeric_part.isna().sum().sum()) if not numeric_part.empty else 0
    inf_count = int(np.isinf(numeric_part.to_numpy(dtype=float, na_value=np.nan)).sum()) if not numeric_part.empty else 0

    return OfficialSchemaReport(
        expected_feature_count=len(feature_columns),
        numeric_feature_count=len(numeric_features),
        categorical_feature_count=len(categorical_features),
        missing=missing,
        extra=extra,
        non_numeric=non_numeric,
        nan_count_before_cleaning=nan_count,
        inf_count_before_cleaning=inf_count,
    )


def main() -> None:
    args = parse_args()
    schema = load_feature_schema(Path(args.schema))
    validate_schema_contract(schema)

    print("[+] Official feature schema artifact hợp lệ.")
    print(json.dumps({"schema": args.schema, "feature_count": len(schema["feature_columns"])}, ensure_ascii=False, indent=2))

    if args.csv:
        df = pd.read_csv(args.csv, low_memory=False)
        report = build_official_schema_report(df, schema)
        print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
        if not args.non_strict:
            prepare_features(df, schema)
            if report.non_numeric:
                raise ValueError(f"Feature numeric chứa giá trị không ép kiểu số được: {report.non_numeric}")
            print("[+] CSV khớp schema 41 feature chính thức.")


if __name__ == "__main__":
    main()
