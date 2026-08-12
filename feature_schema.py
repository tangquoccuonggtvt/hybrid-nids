"""Feature schema cho nhánh tích hợp PCAP/NFStreamer của NIDS.

Mục tiêu của file này:
1. Khóa danh sách feature mà extractor PCAP hiện sinh được.
2. Kiểm tra nghiêm ngặt dữ liệu PCAP/flow thử nghiệm trước khi đưa vào model.
3. Phát hiện thiếu cột rõ ràng thay vì tự điền 0 âm thầm.

Schema chính thức của mô hình đã huấn luyện là `models/feature_schema_model.json`
với 41 feature. Danh sách bên dưới là schema 22 feature của nhánh PCAP/NFStreamer
và không được báo cáo như tương đương schema hold-out chính thức.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np
import pandas as pd


FEATURE_COLUMNS: list[str] = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sload",
    "dload",
    "sjit",
    "djit",
    "smean",
    "dmean",
    "sinpkt",
    "dinpkt",
    "tcprtt",
    "is_sm_ips_ports",
    "ct_state_ttl",
    "ct_srv_src",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
]

# Các alias từng xuất hiện trong detector cũ. Chuẩn hoá alias giúp kiểm tra/di trú
# dữ liệu dễ hơn, nhưng detector mới vẫn phải sinh đúng tên lower-case ngay từ đầu.
COLUMN_ALIASES: dict[str, str] = {
    "Sload": "sload",
    "Dload": "dload",
    "Sjit": "sjit",
    "Djit": "djit",
    "Sintpkt": "sinpkt",
    "Dintpkt": "dinpkt",
}

INTEGER_LIKE_FEATURES: set[str] = {
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "smean",
    "dmean",
    "is_sm_ips_ports",
    "ct_state_ttl",
    "ct_srv_src",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
}


@dataclass(frozen=True)
class SchemaReport:
    """Báo cáo kiểm tra schema trước khi đưa dữ liệu vào model."""

    missing: list[str]
    extra: list[str]
    aliased: dict[str, str]
    non_numeric: list[str]
    nan_count: int
    inf_count: int

    @property
    def ok(self) -> bool:
        return not self.missing and not self.non_numeric


def expected_feature_columns(feature_columns: Sequence[str] | None = None) -> list[str]:
    """Trả về danh sách feature theo đúng thứ tự model cần."""
    columns = list(feature_columns or FEATURE_COLUMNS)
    return [col for col in columns if col != "label"]


def normalize_feature_names(
    df: pd.DataFrame,
    aliases: Mapping[str, str] | None = None,
) -> tuple[pd.DataFrame, dict[str, str]]:
    """Đổi các tên cột alias về tên chuẩn.

    Nếu cả alias và cột chuẩn cùng tồn tại, cột chuẩn được giữ nguyên để tránh ghi đè
    dữ liệu đã đúng. Cột alias dư sẽ bị loại sau bước `validate_and_prepare_features`.
    """
    alias_map = dict(aliases or COLUMN_ALIASES)
    rename_map: dict[str, str] = {}
    for old_name, new_name in alias_map.items():
        if old_name in df.columns and new_name not in df.columns:
            rename_map[old_name] = new_name
    if rename_map:
        df = df.rename(columns=rename_map)
    return df, rename_map


def build_schema_report(
    df: pd.DataFrame,
    feature_columns: Sequence[str] | None = None,
    aliased: Mapping[str, str] | None = None,
) -> SchemaReport:
    """Tạo báo cáo thiếu/thừa/sai kiểu dữ liệu cho DataFrame feature."""
    expected = expected_feature_columns(feature_columns)
    missing = sorted(set(expected) - set(df.columns))
    extra = sorted(set(df.columns) - set(expected))

    non_numeric: list[str] = []
    for col in expected:
        if col not in df.columns:
            continue
        converted = pd.to_numeric(df[col], errors="coerce")
        # Nếu cột gốc có giá trị không-null nhưng convert thành NaN thì cột đó không sạch số.
        invalid_mask = df[col].notna() & converted.isna()
        if bool(invalid_mask.any()):
            non_numeric.append(col)

    numeric_part = df[[c for c in expected if c in df.columns]].apply(pd.to_numeric, errors="coerce")
    nan_count = int(numeric_part.isna().sum().sum())
    inf_count = int(np.isinf(numeric_part.to_numpy(dtype=float, na_value=np.nan)).sum())

    return SchemaReport(
        missing=missing,
        extra=extra,
        aliased=dict(aliased or {}),
        non_numeric=non_numeric,
        nan_count=nan_count,
        inf_count=inf_count,
    )


def validate_and_prepare_features(
    df: pd.DataFrame,
    feature_columns: Sequence[str] | None = None,
    *,
    allow_aliases: bool = True,
    strict: bool = True,
    fill_nan_value: float = 0.0,
) -> tuple[pd.DataFrame, SchemaReport]:
    """Chuẩn hoá DataFrame feature để đưa vào scaler/model.

    Khác với code cũ, hàm này KHÔNG tự tạo cột thiếu bằng 0 trong chế độ strict.
    Nếu thiếu cột, caller sẽ nhận `ValueError` để sửa feature extraction thay vì
    model âm thầm nhận dữ liệu sai schema.
    """
    work = df.copy()
    aliased: dict[str, str] = {}
    if allow_aliases:
        work, aliased = normalize_feature_names(work)

    expected = expected_feature_columns(feature_columns)
    report = build_schema_report(work, expected, aliased)

    if strict and report.missing:
        raise ValueError(
            "Thiếu feature bắt buộc trước khi inference/train: "
            f"{report.missing}. Không tự fill 0 để tránh dự đoán sai âm thầm."
        )
    if strict and report.non_numeric:
        raise ValueError(f"Feature không thể ép kiểu số: {report.non_numeric}")

    # Chỉ ở chế độ không strict mới cho phép tạo cột thiếu bằng NaN rồi fill.
    # Chế độ này phù hợp để khám phá dữ liệu, không nên dùng production.
    for col in expected:
        if col not in work.columns:
            work[col] = np.nan

    prepared = work.reindex(columns=expected).apply(pd.to_numeric, errors="coerce")
    prepared = prepared.replace([np.inf, -np.inf], np.nan).fillna(fill_nan_value)

    # Giữ các count ở dạng số nguyên không âm để ổn định hơn.
    for col in INTEGER_LIKE_FEATURES.intersection(prepared.columns):
        prepared[col] = prepared[col].clip(lower=0).round().astype("int64")

    return prepared, report


def validate_saved_feature_list(saved_columns: Iterable[str]) -> None:
    """Kiểm tra artifact danh sách feature PCAP có khớp schema nguồn không."""
    saved = expected_feature_columns(list(saved_columns))
    expected = expected_feature_columns(FEATURE_COLUMNS)
    if saved != expected:
        raise ValueError(
            "feature_columns artifact không khớp FEATURE_COLUMNS trong source.\n"
            f"Artifact: {saved}\n"
            f"Source:   {expected}"
        )
