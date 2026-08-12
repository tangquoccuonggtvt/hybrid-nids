"""
===========================================================
KIỂM TRA DATA LEAKAGE / DUPLICATE GIỮA DEVELOPMENT VÀ TEST
===========================================================

Mục tiêu:
- Kiểm tra xem có dòng dữ liệu nào bị trùng giữa Development Set và Hold-out Test Set hay không.
- Nếu trùng nhiều, kết quả ROC-AUC/F1 có thể bị nghi ngờ.
- Kết quả xuất ra: models/leakage_check.json
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd


DATA_DIR = Path("./UNSW_NB15_Splitted_CLEAN")
MODELS_DIR = Path("./models")
METADATA_PATH = MODELS_DIR / "training_metadata.json"
OUTPUT_PATH = MODELS_DIR / "leakage_check.json"


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Chuẩn hóa tên cột giống pipeline huấn luyện.
    """
    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    rename_map = {
        "smeansz": "smean",
        "dmeansz": "dmean",
        "sintpkt": "sinpkt",
        "dintpkt": "dinpkt",
        "res_bdy_len": "response_body_len",

        # Sửa lỗi khoảng trắng nếu có trong dữ liệu
        "ct_src_ ltm": "ct_src_ltm",
    }

    df = df.rename(columns=rename_map)
    df = df.loc[:, ~df.columns.duplicated()]
    return df


def load_metadata() -> dict:
    if not METADATA_PATH.exists():
        raise FileNotFoundError(f"Không tìm thấy metadata: {METADATA_PATH}")

    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_feature_columns(metadata: dict) -> list[str]:
    """
    Lấy danh sách feature từ metadata.
    Đồng thời sửa lỗi tên cột nếu có khoảng trắng.
    """
    feature_columns = metadata["schema"]["feature_columns"]

    fixed_columns = []
    for col in feature_columns:
        col = col.lower().strip()
        if col == "ct_src_ ltm":
            col = "ct_src_ltm"
        fixed_columns.append(col)

    return fixed_columns


def load_csv_selected(path: Path, feature_columns: list[str]) -> pd.DataFrame:
    """
    Đọc CSV và chỉ lấy các feature dùng cho mô hình.
    """
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {path}")

    df = pd.read_csv(path, low_memory=False)
    df = normalize_columns(df)

    missing = set(feature_columns) - set(df.columns)
    if missing:
        raise ValueError(
            f"File {path} thiếu các cột feature: {sorted(missing)}"
        )

    X = df[feature_columns].copy()

    # Chuẩn hóa giá trị để hash ổn định hơn
    for col in X.columns:
        if X[col].dtype == "object":
            X[col] = X[col].fillna("unknown").astype(str).str.lower().str.strip()
        else:
            X[col] = pd.to_numeric(X[col], errors="coerce")
            X[col] = X[col].replace([np.inf, -np.inf], np.nan)
            X[col] = X[col].fillna(0)

    return X


def load_development_set(feature_columns: list[str]) -> pd.DataFrame:
    """
    Ưu tiên dùng train_full.
    Nếu chưa có thì ghép 5 validation fold, giống cách pipeline final đã dùng.
    """
    candidates = [
        DATA_DIR / "unsw_nb15_train_full.csv",
        DATA_DIR / "train_full.csv",
    ]

    for path in candidates:
        if path.exists():
            print(f"[+] Dùng Development Set: {path}")
            return load_csv_selected(path, feature_columns)

    print("[!] Không có train_full. Đang ghép 5 validation fold để kiểm tra...")

    parts = []
    for fold in range(1, 6):
        path = DATA_DIR / f"unsw_nb15_fold{fold}_val.csv"
        parts.append(load_csv_selected(path, feature_columns))

    return pd.concat(parts, ignore_index=True)


def load_test_set(feature_columns: list[str]) -> pd.DataFrame:
    candidates = [
        DATA_DIR / "unsw_nb15_test_holdout.csv",
        DATA_DIR / "test_holdout.csv",
        DATA_DIR / "unsw_test_16467.csv",
    ]

    for path in candidates:
        if path.exists():
            print(f"[+] Dùng Hold-out Test Set: {path}")
            return load_csv_selected(path, feature_columns)

    raise FileNotFoundError("Không tìm thấy file test hold-out.")


def dataframe_hash(df: pd.DataFrame) -> pd.Series:
    """
    Tạo hash cho từng dòng dựa trên toàn bộ feature.
    """
    return pd.util.hash_pandas_object(df, index=False)


def main() -> None:
    print("=" * 70)
    print("KIỂM TRA DATA LEAKAGE / DUPLICATE")
    print("=" * 70)

    metadata = load_metadata()
    feature_columns = get_feature_columns(metadata)

    print(f"[+] Số feature dùng để hash: {len(feature_columns)}")

    X_dev = load_development_set(feature_columns)
    X_test = load_test_set(feature_columns)

    print(f"[+] Development rows: {len(X_dev):,}")
    print(f"[+] Test rows:        {len(X_test):,}")

    dev_hash = dataframe_hash(X_dev)
    test_hash = dataframe_hash(X_test)

    dev_hash_set = set(dev_hash.astype("uint64").tolist())
    test_hash_set = set(test_hash.astype("uint64").tolist())

    intersection = dev_hash_set.intersection(test_hash_set)

    duplicate_count = len(intersection)
    duplicate_ratio_test = duplicate_count / max(len(X_test), 1)

    result = {
        "development_rows": int(len(X_dev)),
        "test_rows": int(len(X_test)),
        "duplicate_hash_count": int(duplicate_count),
        "duplicate_ratio_over_test": float(duplicate_ratio_test),
        "is_pass": bool(duplicate_count == 0),
        "note": (
            "PASS: Không phát hiện duplicate giữa Development và Test."
            if duplicate_count == 0
            else "WARNING: Có duplicate giữa Development và Test, cần xem lại cách chia dữ liệu."
        ),
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[+] Đã lưu kết quả tại: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
