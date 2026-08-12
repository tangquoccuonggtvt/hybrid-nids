"""Benchmark inference speed for the official Hybrid-NIDS model.

This script does not train a model. It loads the official full pipeline and
hold-out test CSV, then writes `models/inference_benchmark.json`.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from artifact_security import load_trusted_model
import numpy as np
import pandas as pd
import sklearn

from nids_detector import load_feature_schema, prepare_features


DEFAULT_BATCH_SIZES = [1, 32, 128, 512, 1024]


for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark tốc độ suy luận Hybrid-NIDS.")
    parser.add_argument("--model", default="./models/nids_rf_pipeline.pkl")
    parser.add_argument("--schema", default="./models/feature_schema_model.json")
    parser.add_argument("--metadata", default="./models/metadata.json")
    parser.add_argument("--test-csv", default="./UNSW_NB15_Splitted_CLEAN/unsw_nb15_test_holdout.csv")
    parser.add_argument("--output", default="./models/inference_benchmark.json")
    parser.add_argument("--sample-size", type=int, default=100_000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--batch-sizes", default=",".join(str(x) for x in DEFAULT_BATCH_SIZES))
    return parser.parse_args()


def parse_batch_sizes(value: str) -> list[int]:
    batch_sizes = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        batch_size = int(part)
        if batch_size <= 0:
            raise ValueError(f"Batch size phải > 0, nhận được: {batch_size}")
        batch_sizes.append(batch_size)
    if not batch_sizes:
        raise ValueError("Danh sách batch size không được rỗng.")
    return batch_sizes


def load_test_features(csv_path: Path, schema: dict[str, Any], sample_size: int) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"Không tìm thấy test CSV: {csv_path}")
    if sample_size <= 0:
        raise ValueError("sample_size phải > 0.")

    df = pd.read_csv(csv_path, low_memory=False, nrows=sample_size)
    if df.empty:
        raise ValueError(f"Test CSV rỗng: {csv_path}")
    return prepare_features(df, schema)


def benchmark_pipeline(
    pipeline: Any,
    X_test: pd.DataFrame,
    batch_sizes: list[int],
    repeats: int,
) -> dict:
    if repeats <= 0:
        raise ValueError("repeats phải > 0.")

    results: dict[str, dict] = {}

    for batch_size in batch_sizes:
        sample = X_test.head(min(batch_size, len(X_test)))
        if sample.empty:
            raise ValueError("Không có dữ liệu để benchmark.")

        _ = pipeline.predict_proba(sample)

        elapsed_times = []
        for _ in range(repeats):
            start = time.perf_counter()
            _ = pipeline.predict_proba(sample)
            elapsed_times.append(time.perf_counter() - start)

        average_time = float(np.mean(elapsed_times))
        std_time = float(np.std(elapsed_times))
        flows = int(len(sample))
        latency_ms_per_flow = float((average_time / flows) * 1000)
        throughput = float(flows / average_time) if average_time > 0 else 0.0

        results[f"batch_{batch_size}"] = {
            "flows": flows,
            "repeats": int(repeats),
            "average_time_seconds": average_time,
            "std_time_seconds": std_time,
            "latency_ms_per_flow": latency_ms_per_flow,
            "throughput_flows_per_second": throughput,
        }

    return results


def main() -> None:
    args = parse_args()
    model_path = Path(args.model)
    schema_path = Path(args.schema)
    metadata_path = Path(args.metadata) if args.metadata else None
    test_csv_path = Path(args.test_csv)
    output_path = Path(args.output)
    batch_sizes = parse_batch_sizes(args.batch_sizes)

    if not model_path.exists():
        raise FileNotFoundError(f"Không tìm thấy model: {model_path}")

    schema = load_feature_schema(schema_path)
    pipeline = load_trusted_model(model_path, metadata_path if metadata_path and metadata_path.exists() else None)
    X_test = load_test_features(test_csv_path, schema, args.sample_size)

    batch_results = benchmark_pipeline(
        pipeline=pipeline,
        X_test=X_test,
        batch_sizes=batch_sizes,
        repeats=args.repeats,
    )

    report = {
        "benchmark_created_at": datetime.now().isoformat(timespec="seconds"),
        "model_file": str(model_path),
        "schema_file": str(schema_path),
        "metadata_file": str(metadata_path) if metadata_path else None,
        "test_csv": str(test_csv_path),
        "sample_size": int(len(X_test)),
        "requested_sample_size": int(args.sample_size),
        "batch_sizes": batch_sizes,
        "repeats": int(args.repeats),
        "results": batch_results,
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "numpy_version": np.__version__,
            "pandas_version": pd.__version__,
            "sklearn_version": sklearn.__version__,
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print(f"[+] Đã lưu benchmark: {output_path}")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
