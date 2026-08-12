"""
===========================================================
TẠO DATA SPLIT SẠCH KHÔNG LEAKAGE
===========================================================

Mục tiêu:
- Tạo lại bộ dữ liệu sạch cho Hybrid-NIDS.
- Loại bỏ duplicate/data leakage giữa Development Set và Hold-out Test Set.
- Loại bỏ các nhóm có cùng feature hash nhưng label mâu thuẫn.
Nguyên tắc:
- Các dòng có cùng vector đặc trưng sẽ có cùng feature hash.
- Các dòng có cùng feature hash không được xuất hiện đồng thời ở Development và Test.
- Nếu một feature hash có cả label 0 và label 1, nhóm đó được xem là label conflict và bị loại bỏ.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold


# =========================================================
# 1. CẤU HÌNH
# =========================================================

# Thư mục dữ liệu cũ
OLD_DATA_DIR = Path("./UNSW_NB15_Splitted")

# Thư mục dữ liệu sạch sẽ được tạo mới
NEW_DATA_DIR = Path("./UNSW_NB15_Splitted_CLEAN")

# Thư mục chứa metadata của mô hình final đã chạy trước đó
MODELS_DIR = Path("./models")
METADATA_PATH = MODELS_DIR / "training_metadata.json"

# Cấu hình chia dữ liệu
RANDOM_STATE = 42
TEST_SIZE = 0.20
N_SPLITS = 5

# =========================================================
# 2. HÀM CHUẨN HÓA DỮ LIỆU
# =========================================================

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Chuẩn hóa tên cột:
    - Chuyển tên cột về chữ thường.
    - Bỏ khoảng trắng đầu/cuối.
    - Đổi một số tên cột cũ sang tên chuẩn.
    - Sửa lỗi tên cột có khoảng trắng bất thường.
    """
    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    rename_map = {
        "smeansz": "smean",
        "dmeansz": "dmean",
        "sintpkt": "sinpkt",
        "dintpkt": "dinpkt",
        "res_bdy_len": "response_body_len",

        # Sửa lỗi tên cột nếu metadata hoặc CSV có khoảng trắng
        "ct_src_ ltm": "ct_src_ltm",
    }

    df = df.rename(columns=rename_map)

    # Nếu sau khi đổi tên bị trùng cột thì giữ cột đầu tiên
    df = df.loc[:, ~df.columns.duplicated()]

    return df

def fix_col_name(col: str) -> str:
    """
    Chuẩn hóa tên cột lấy từ metadata.
    """
    col = str(col).lower().strip()

    if col == "ct_src_ ltm":
        return "ct_src_ltm"

    return col

# =========================================================
# 3. ĐỌC METADATA VÀ SCHEMA
# =========================================================

def load_metadata() -> dict:
    """
    Đọc training_metadata.json để lấy schema feature.
    """
    if not METADATA_PATH.exists():
        raise FileNotFoundError(
            f"Không tìm thấy metadata: {METADATA_PATH}\n"
            "Bạn cần chạy script huấn luyện chính thức ít nhất một lần để tạo metadata."
        )

    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def get_schema_from_metadata(metadata: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Lấy danh sách numeric_features, categorical_features và feature_columns từ metadata.
    """
    numeric_features = [
        fix_col_name(c) for c in metadata["schema"]["numeric_features"]
    ]

    categorical_features = [
        fix_col_name(c) for c in metadata["schema"]["categorical_features"]
    ]

    feature_columns = [
        fix_col_name(c) for c in metadata["schema"]["feature_columns"]
    ]

    return numeric_features, categorical_features, feature_columns

# =========================================================
# 4. ĐỌC DỮ LIỆU CŨ
# =========================================================

def load_csv(path: Path) -> pd.DataFrame:
    """
    Đọc một file CSV và chuẩn hóa tên cột.
    """
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {path}")

    print(f"[*] Đang đọc: {path}")
    df = pd.read_csv(path, low_memory=False)
    df = normalize_columns(df)

    return df

def load_all_rows() -> pd.DataFrame:
    """
    Gom dữ liệu gốc để chia lại.

    Ưu tiên:
    - Nếu có unsw_nb15_train_full.csv hoặc train_full.csv thì dùng file đó + test_holdout.
    - Nếu chưa có train_full thì dùng 5 validation fold + test_holdout.

    Lưu ý:
    - Không dùng fold_train cũ vì các fold_train trong cross-validation thường chồng lặp nhau.
    """
    full_candidates = [
        OLD_DATA_DIR / "unsw_nb15_train_full.csv",
        OLD_DATA_DIR / "train_full.csv",
    ]

    test_candidates = [
        OLD_DATA_DIR / "unsw_nb15_test_holdout.csv",
        OLD_DATA_DIR / "test_holdout.csv",
        OLD_DATA_DIR / "unsw_test_16467.csv",
    ]

    data_parts: list[pd.DataFrame] = []

    # Tìm test cũ
    test_path = None
    for path in test_candidates:
        if path.exists():
            test_path = path
            break

    if test_path is None:
        raise FileNotFoundError("Không tìm thấy file test hold-out trong thư mục dữ liệu cũ.")

    # Tìm train_full cũ
    full_path = None
    for path in full_candidates:
        if path.exists():
            full_path = path
            break

    if full_path is not None:
        print(f"[+] Có train_full cũ: {full_path}")
        data_parts.append(load_csv(full_path))
    else:
        print("[!] Không có train_full. Dùng 5 validation fold làm Development cũ.")

        for fold in range(1, 6):
            val_path = OLD_DATA_DIR / f"unsw_nb15_fold{fold}_val.csv"
            data_parts.append(load_csv(val_path))

    print(f"[+] Dùng test cũ: {test_path}")
    data_parts.append(load_csv(test_path))

    df_all = pd.concat(data_parts, ignore_index=True)
    df_all = df_all.loc[:, ~df_all.columns.duplicated()]

    print(f"[+] Tổng số dòng trước khi xử lý conflict: {len(df_all):,}")

    return df_all


# =========================================================
# 5. KIỂM TRA VÀ CHUẨN HÓA LABEL/SCHEMA
# =========================================================

def validate_schema(df: pd.DataFrame, feature_columns: list[str]) -> None:
    """
    Kiểm tra dữ liệu có đủ feature và label hay không.
    """
    required_columns = set(feature_columns + ["label"])
    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(f"Dữ liệu thiếu cột bắt buộc: {sorted(missing)}")


def prepare_label(df: pd.DataFrame) -> pd.DataFrame:
    """
    Chuẩn hóa label về int 0/1.
    """
    df = df.copy()

    if "label" not in df.columns:
        raise ValueError("Không tìm thấy cột label.")

    df["label"] = pd.to_numeric(df["label"], errors="coerce")

    if df["label"].isna().any():
        raise ValueError("Có giá trị label không hợp lệ.")

    df["label"] = df["label"].astype(int)

    unique_labels = set(df["label"].unique())

    if not unique_labels.issubset({0, 1}):
        raise ValueError(f"Label phải là 0/1. Hiện có: {sorted(unique_labels)}")

    return df


# =========================================================
# 6. TẠO FEATURE HASH
# =========================================================

def normalize_for_hash(
    df: pd.DataFrame,
    numeric_features: list[str],
    categorical_features: list[str],
    feature_columns: list[str],
) -> pd.DataFrame:
    """
    Chuẩn hóa dữ liệu trước khi hash.

    Mục tiêu:
    - Đảm bảo cùng một flow có cùng hash.
    - Numeric được ép kiểu số.
    - Categorical được chuẩn hóa chữ thường.
    """
    X = df[feature_columns].copy()

    for col in numeric_features:
        X[col] = pd.to_numeric(X[col], errors="coerce")
        X[col] = X[col].replace([np.inf, -np.inf], np.nan)
        X[col] = X[col].fillna(0)

        # Đa số đặc trưng flow không nên âm
        X[col] = X[col].clip(lower=0)

    for col in categorical_features:
        X[col] = (
            X[col]
            .fillna("unknown")
            .astype(str)
            .str.lower()
            .str.strip()
        )

    return X


def add_feature_hash(
    df: pd.DataFrame,
    numeric_features: list[str],
    categorical_features: list[str],
    feature_columns: list[str],
) -> pd.DataFrame:
    """
    Thêm cột _feature_hash cho từng dòng dữ liệu.
    """
    X_hash = normalize_for_hash(
        df=df,
        numeric_features=numeric_features,
        categorical_features=categorical_features,
        feature_columns=feature_columns,
    )

    df = df.copy()
    df["_feature_hash"] = pd.util.hash_pandas_object(
        X_hash,
        index=False,
    ).astype("uint64")

    return df


# =========================================================
# 7. PHÁT HIỆN VÀ LOẠI LABEL CONFLICT
# =========================================================

def detect_label_conflicts(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, set]:
    """
    Phát hiện các nhóm có cùng feature hash nhưng label mâu thuẫn.

    Một group bị xem là conflict nếu:
    - Cùng _feature_hash
    - Nhưng xuất hiện cả label 0 và label 1

    Trả về:
    - group_table: toàn bộ group
    - conflict_table: các group có label mâu thuẫn
    - conflict_hashes: tập hash cần loại bỏ
    """
    group_table = (
        df.groupby("_feature_hash")
        .agg(
            row_count=("label", "size"),
            label_nunique=("label", "nunique"),
            group_label=("label", "max"),
            normal_count=("label", lambda x: int((x == 0).sum())),
            attack_count=("label", lambda x: int((x == 1).sum())),
        )
        .reset_index()
    )

    conflict_table = group_table[group_table["label_nunique"] > 1].copy()
    conflict_hashes = set(conflict_table["_feature_hash"].astype("uint64").tolist())

    total_groups = int(len(group_table))
    conflict_group_count = int(len(conflict_table))
    conflict_row_count = int(conflict_table["row_count"].sum()) if conflict_group_count > 0 else 0

    print(f"[+] Số group/hash duy nhất ban đầu: {total_groups:,}")
    print(f"[!] Số group có label mâu thuẫn: {conflict_group_count:,}")
    print(f"[!] Số dòng thuộc group mâu thuẫn: {conflict_row_count:,}")

    if total_groups > 0:
        print(
            f"[!] Tỷ lệ group mâu thuẫn: "
            f"{conflict_group_count / total_groups:.8f}"
        )

    return group_table, conflict_table, conflict_hashes


def remove_conflict_groups(
    df: pd.DataFrame,
    conflict_hashes: set,
) -> pd.DataFrame:
    """
    Loại bỏ toàn bộ dòng thuộc các group có label mâu thuẫn.
    """
    if not conflict_hashes:
        print("[+] Không có group label mâu thuẫn. Không cần loại bỏ.")
        return df

    before_rows = int(len(df))

    df_clean = df[~df["_feature_hash"].isin(conflict_hashes)].copy()

    after_rows = int(len(df_clean))
    removed_rows = before_rows - after_rows

    print(
        f"[+] Đã loại bỏ {removed_rows:,} dòng "
        f"thuộc {len(conflict_hashes):,} group có label mâu thuẫn."
    )

    print(f"[+] Số dòng còn lại sau khi loại conflict: {after_rows:,}")

    return df_clean


# =========================================================
# 8. CHIA DATASET SẠCH
# =========================================================

def make_group_table_after_clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Tạo group table sau khi đã loại label conflict.

    Do conflict đã bị loại, group_label sẽ là label đại diện của group.
    """
    group_table = (
        df.groupby("_feature_hash")
        .agg(
            row_count=("label", "size"),
            label_nunique=("label", "nunique"),
            group_label=("label", "max"),
        )
        .reset_index()
    )

    remaining_conflicts = int((group_table["label_nunique"] > 1).sum())

    if remaining_conflicts != 0:
        raise RuntimeError(
            f"Vẫn còn {remaining_conflicts} group label mâu thuẫn sau khi xử lý."
        )

    print(f"[+] Số group sạch còn lại: {len(group_table):,}")

    return group_table


def check_overlap(dev_df: pd.DataFrame, test_df: pd.DataFrame) -> int:
    """
    Kiểm tra số hash trùng giữa hai tập.
    """
    dev_hash = set(dev_df["_feature_hash"].astype("uint64").tolist())
    test_hash = set(test_df["_feature_hash"].astype("uint64").tolist())

    return len(dev_hash.intersection(test_hash))


def class_distribution(df: pd.DataFrame) -> dict:
    """
    Thống kê phân bố lớp.
    """
    counts = df["label"].value_counts().to_dict()
    total = len(df)

    normal = int(counts.get(0, 0))
    attack = int(counts.get(1, 0))

    return {
        "total": int(total),
        "normal_count": normal,
        "attack_count": attack,
        "normal_ratio": float(normal / max(total, 1)),
        "attack_ratio": float(attack / max(total, 1)),
    }


def save_csv(df: pd.DataFrame, path: Path) -> None:
    """
    Lưu CSV, bỏ cột kỹ thuật _feature_hash.
    """
    df_out = df.drop(columns=["_feature_hash"], errors="ignore")
    df_out.to_csv(path, index=False, encoding="utf-8-sig")


# =========================================================
# 9. MAIN
# =========================================================

def main() -> None:
    print("=" * 70)
    print("TẠO DATA SPLIT SẠCH KHÔNG LEAKAGE + LOẠI LABEL CONFLICT")
    print("=" * 70)

    if OLD_DATA_DIR.resolve() == NEW_DATA_DIR.resolve():
        raise RuntimeError("OLD_DATA_DIR và NEW_DATA_DIR không được trùng nhau.")

    metadata = load_metadata()
    numeric_features, categorical_features, feature_columns = get_schema_from_metadata(metadata)

    print(f"[+] Numeric features: {len(numeric_features)}")
    print(f"[+] Categorical features: {len(categorical_features)}")
    print(f"[+] Total features: {len(feature_columns)}")

    # Xóa thư mục output cũ nếu tồn tại
    if NEW_DATA_DIR.exists():
        print(f"[!] Xóa thư mục output cũ: {NEW_DATA_DIR}")
        shutil.rmtree(NEW_DATA_DIR)

    NEW_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Đọc và chuẩn hóa dữ liệu
    df_all = load_all_rows()
    validate_schema(df_all, feature_columns)
    df_all = prepare_label(df_all)

    total_rows_before_conflict_removal = int(len(df_all))

    # Tạo feature hash
    df_all = add_feature_hash(
        df=df_all,
        numeric_features=numeric_features,
        categorical_features=categorical_features,
        feature_columns=feature_columns,
    )

    # Phát hiện conflict
    group_table_raw, conflict_table, conflict_hashes = detect_label_conflicts(df_all)

    # Lưu danh sách group conflict
    conflict_report_path = NEW_DATA_DIR / "label_conflict_groups.csv"
    conflict_table.to_csv(conflict_report_path, index=False, encoding="utf-8-sig")
    print(f"[+] Đã lưu danh sách label conflict: {conflict_report_path}")

    label_conflict_group_count = int(len(conflict_table))
    label_conflict_row_count = int(conflict_table["row_count"].sum()) if label_conflict_group_count > 0 else 0

    # Loại bỏ conflict
    df_all = remove_conflict_groups(df_all, conflict_hashes)

    total_rows_after_conflict_removal = int(len(df_all))

    # Tạo group table sạch
    group_table = make_group_table_after_clean(df_all)

    groups = group_table["_feature_hash"].to_numpy()
    group_labels = group_table["group_label"].to_numpy()

    # Chia Development/Test theo group-aware split
    train_groups, test_groups = train_test_split(
        groups,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=group_labels,
    )

    train_group_set = set(train_groups.tolist())
    test_group_set = set(test_groups.tolist())

    df_dev = df_all[df_all["_feature_hash"].isin(train_group_set)].copy()
    df_test = df_all[df_all["_feature_hash"].isin(test_group_set)].copy()

    overlap = check_overlap(df_dev, df_test)

    if overlap != 0:
        raise RuntimeError(f"Vẫn còn overlap giữa Development và Test: {overlap}")

    train_full_path = NEW_DATA_DIR / "unsw_nb15_train_full.csv"
    test_path = NEW_DATA_DIR / "unsw_nb15_test_holdout.csv"

    save_csv(df_dev, train_full_path)
    save_csv(df_test, test_path)

    print(f"[+] Đã lưu train_full: {train_full_path}")
    print(f"[+] Đã lưu test_holdout: {test_path}")

    dev_distribution = class_distribution(df_dev)
    test_distribution = class_distribution(df_test)

    print("[+] Development distribution:")
    print(json.dumps(dev_distribution, indent=2, ensure_ascii=False))

    print("[+] Test distribution:")
    print(json.dumps(test_distribution, indent=2, ensure_ascii=False))

    # Tạo 5-fold CV sạch trong Development Set
    print("[+] Đang tạo 5-fold CV sạch trong Development Set...")

    dev_group_table = (
        df_dev.groupby("_feature_hash")
        .agg(group_label=("label", "max"))
        .reset_index()
    )

    dev_groups = dev_group_table["_feature_hash"].to_numpy()
    dev_group_labels = dev_group_table["group_label"].to_numpy()

    skf = StratifiedKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    fold_summaries = []

    for fold, (train_idx, val_idx) in enumerate(
        skf.split(dev_groups, dev_group_labels),
        start=1,
    ):
        fold_train_groups = set(dev_groups[train_idx].tolist())
        fold_val_groups = set(dev_groups[val_idx].tolist())

        df_fold_train = df_dev[df_dev["_feature_hash"].isin(fold_train_groups)].copy()
        df_fold_val = df_dev[df_dev["_feature_hash"].isin(fold_val_groups)].copy()

        fold_overlap = check_overlap(df_fold_train, df_fold_val)

        if fold_overlap != 0:
            raise RuntimeError(f"Fold {fold} vẫn còn overlap train/val: {fold_overlap}")

        train_path = NEW_DATA_DIR / f"unsw_nb15_fold{fold}_train.csv"
        val_path = NEW_DATA_DIR / f"unsw_nb15_fold{fold}_val.csv"

        save_csv(df_fold_train, train_path)
        save_csv(df_fold_val, val_path)

        fold_summary = {
            "fold": fold,
            "train_rows": int(len(df_fold_train)),
            "val_rows": int(len(df_fold_val)),
            "train_val_overlap_hash_count": int(fold_overlap),
            "train_distribution": class_distribution(df_fold_train),
            "val_distribution": class_distribution(df_fold_val),
        }

        fold_summaries.append(fold_summary)

        print(
            f"[+] Fold {fold}: "
            f"train={len(df_fold_train):,}, "
            f"val={len(df_fold_val):,}, "
            f"overlap={fold_overlap}"
        )

    # Lưu summary
    summary = {
        "source_dir": str(OLD_DATA_DIR),
        "output_dir": str(NEW_DATA_DIR),
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "n_splits": N_SPLITS,

        "total_rows_before_conflict_removal": total_rows_before_conflict_removal,
        "total_rows_after_conflict_removal": total_rows_after_conflict_removal,
        "removed_rows_due_to_label_conflict": int(
            total_rows_before_conflict_removal - total_rows_after_conflict_removal
        ),

        "raw_unique_feature_hash_groups": int(len(group_table_raw)),
        "clean_unique_feature_hash_groups": int(len(group_table)),
        "label_conflict_group_count": label_conflict_group_count,
        "label_conflict_row_count": label_conflict_row_count,
        "label_conflict_handling": (
            "Removed all feature-hash groups with conflicting labels before split."
        ),

        "development_rows": int(len(df_dev)),
        "test_rows": int(len(df_test)),
        "dev_test_overlap_hash_count": int(overlap),

        "development_distribution": dev_distribution,
        "test_distribution": test_distribution,

        "fold_summaries": fold_summaries,

        "output_files": {
            "train_full": str(train_full_path),
            "test_holdout": str(test_path),
            "label_conflict_groups": str(conflict_report_path),
        },

        "note": (
            "Clean group-aware split. Conflicting-label groups are removed. "
            "Duplicate feature hashes are not allowed across Development/Test "
            "or between train/validation inside each fold."
        ),
    }

    summary_path = NEW_DATA_DIR / "clean_split_summary.json"

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("=" * 70)
    print("HOÀN TẤT TẠO DATA SPLIT SẠCH")
    print("=" * 70)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[+] Summary: {summary_path}")


if __name__ == "__main__":
    main()
