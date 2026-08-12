# Hybrid-NIDS: Suricata + Random Forest Network Intrusion Detection

> A hybrid Network Intrusion Detection System (Hybrid-NIDS) combining signature-based detection (Suricata) with flow-based machine learning detection (Random Forest).

[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13-blue)]()
[![scikit--learn](https://img.shields.io/badge/scikit--learn-1.6.1-orange)]()
[![License](https://img.shields.io/badge/license-TBD-lightgrey)]()

---

## Introduction

**Hybrid-NIDS** is the source code supporting an applied master's thesis project on a hybrid network intrusion detection system, combining two **independent** detection branches:

- **Suricata** — signature/rule-based detection.
- **Random Forest** — detection based on network flow features (flow-based machine learning).

Alerts from the two branches are **fused (correlated)** within a time window and forwarded to the **ELK Stack/Kibana** for monitoring, analysis, and demonstration in a lab environment.

> **Note:** This repository has been cleaned for public release on GitHub. The virtual environment, the large UNSW-NB15 dataset, real PCAP captures, operational logs, and any files containing deployment secrets are **not** included in the repo.

---

## Table of Contents

- [Overall Architecture](#overall-architecture)
- [Key Features of the Codebase](#key-features-of-the-codebase)
- [Official Model Results](#official-model-results)
- [Repository Structure](#repository-structure)
- [Environment Requirements](#environment-requirements)
- [Quick Installation](#quick-installation)
- [Post-Installation Checks](#post-installation-checks)
- [Running AI Inference on Sample Data](#running-ai-inference-on-sample-data)
- [Running the Real-Time Dashboard](#running-the-real-time-dashboard)
- [Suricata + AI Alert Fusion](#suricata--ai-alert-fusion)
- [Dataset and Reproducing Results](#dataset-and-reproducing-results)
- [PCAP / Live Traffic](#pcap--live-traffic)
- [Ubuntu + ELK Deployment](#ubuntu--elk-deployment)
- [Secrets Security](#secrets-security)
- [Key Documentation](#key-documentation)
- [Intended Use](#intended-use)
- [License Note](#license-note)

---

## Overall Architecture

```mermaid
flowchart LR
    A[SPAN / Mirror Port] --> B[Traffic Capture]
    B --> C[Suricata]
    B --> D[Flow Extractor / NFStream]
    C --> E[EVE JSON Alerts]
    D --> F[41-feature Schema]
    F --> G[Random Forest]
    G --> H[AI Alerts JSONL]
    E --> I[Hybrid Alert Fusion]
    H --> I
    I --> J[ELK / Kibana]
    H --> K[Realtime Dashboard]
```

At the collection layer, the same traffic source is observed via a SPAN/mirror port. At the detection layer, Suricata and Random Forest operate as two independent mechanisms. The `hybrid_alert_fusion.py` module performs **alert correlation**, rather than merging the two branches into a single classifier.

---

## Key Features of the Codebase

- Random Forest with a preprocessing pipeline for both numerical and categorical data.
- Official schema of **41 features**, comprising 35 numerical features and 6 categorical features.
- **Development/Hold-out** split by feature hash to limit overlap between sets.
- **Group-aware Stratified 5-Fold Cross Validation** for classification threshold selection.
- Leakage checks, inference benchmarking, feature importance analysis, and confusion matrix reporting.
- Fusion of Suricata + AI alerts into `HYBRID_CORRELATED_ALERT`, `AI_ONLY_ALERT`, and `SURICATA_ONLY_ALERT`.
- Real-time replay dashboard for demonstrations, plus a web control panel (`hybrid_nids_webpanel.py`) and multichannel alert forwarding.
- Ubuntu deployment assets covering systemd services, Suricata rules, and an ELK Docker Compose stack.
- A CI smoke test workflow (`.github/workflows/smoke-test.yml`) for basic pipeline validation on every push.

---

## Official Model Results

> The values below are taken from `models/metrics.json` in this repository.

| Metric | Result |
|---|---|
| Accuracy | 0.992768 |
| Balanced Accuracy | 0.984698 |
| Precision | 0.968823 |
| Recall | 0.973911 |
| F1-score | 0.971360 |
| False Positive Rate | 0.004515 |
| False Negative Rate | 0.026089 |
| ROC-AUC | 0.999671 |
| Threshold | 0.870846 |
| Hold-out test size | 508,039 flows |

**Confusion matrix (hold-out test set):**

| | Predicted Negative | Predicted Positive |
|---|---|---|
| **Actual Negative** | TN = 442,060 | FP = 2,005 |
| **Actual Positive** | FN = 1,669 | TP = 62,305 |

Leakage check results are stored in `models/leakage_check.json`: `duplicate_hash_count = 0` and `is_pass = true`.

---

## Repository Structure

```text
hybrid-nids-hcmct/
│
├── README.md                          # REQUIRED
├── .gitignore                         # REQUIRED
├── requirements.txt                   # REQUIRED
├── requirements-optional.txt
│
├── nids_detector.py                   # ML detector
├── nids_streaming_detector.py
├── nids_features.py
├── feature_schema.py
├── hybrid_alert_fusion.py             # Suricata + ML fusion
├── realtime_dashboard.py
├── hybrid_nids_webpanel.py
├── alert_multichannel_forwarder.py
│
├── train_model.py                     # Training
├── clean_data.py
├── check_leakage.py
├── compare_baselines.py
├── benchmark_inference.py
├── evaluate_artifacts.py
├── evaluate_hybrid_labeled.py
├── evaluate_local_traffic.py
├── schema_check.py
│
├── sample_flows.csv                   # Small sample dataset
│
├── data/
│   ├── README.md
│   ├── NUSW-NB15_features.csv
│   └── unsw_test_16467.csv            # Kept — only ~2.6 MB
│
├── models/
│   ├── nids_rf_pipeline.pkl           # Official model
│   ├── metrics.json
│   ├── metadata.json
│   ├── training_metadata.json
│   ├── feature_schema_model.json
│   ├── leakage_check.json
│   ├── inference_benchmark.json
│   ├── feature_importance.csv
│   ├── feature_importance_top20.csv
│   ├── confusion_matrix.png
│   ├── feature_importance_top20.png
│   ├── benchmark_latency.png
│   └── benchmark_throughput.png
│
├── deployment/
│   ├── hybrid-nids.env.example        # Template file ONLY
│   │
│   ├── suricata/
│   │   └── local.rules
│   │
│   ├── elk/
│   │   ├── docker-compose.yml
│   │   └── BAO_MAT_ELK.md
│   │
│   └── systemd/
│       ├── hybrid-nids-ai-detector.service
│       ├── hybrid-nids-capture.service
│       ├── hybrid-nids-fusion.service
│       └── hybrid-nids-webpanel.service
│
├── scripts/
│   ├── capture_pcap_rotate.sh
│   ├── check_elk_pipeline.sh
│   ├── generate_normal_traffic.sh
│   ├── nids_demo_start.sh
│   ├── nids_demo_stop.sh
│   └── nids_demo_status.sh
│
├── docs/
│   ├── RESULTS_SUMMARY.md
│   ├── REPRODUCIBILITY_GUIDE.md
│   ├── HYBRID_FUSION_GUIDE.md
│   ├── UBUNTU_DEPLOYMENT_GUIDE.md
│   ├── LOCAL_TRAFFIC_EVALUATION_GUIDE.md
│   └── figures/
│       └── ...
│
├── logs/
│   ├── README.md
│   └── sample_suricata_eve.jsonl      # SAMPLE log only
│
└── .github/
    └── workflows/
        └── smoke-test.yml
```

---

## Environment Requirements

### Python

**Python 3.12 or 3.13** is recommended. The current model artifact was built with:

| Component | Version |
|---|---|
| Python | 3.13.9 |
| scikit-learn | 1.6.1 |
| pandas | 2.3.3 |
| NumPy | 2.3.5 |

> `scikit-learn` is **pinned** to version `1.6.1` in `requirements.txt` to reduce the risk of incompatibility when deserializing the model.

### Operating System

| OS | Suitable for |
|---|---|
| **Windows** | Training, evaluation, CSV replay, and dashboard |
| **Ubuntu/Linux** | PCAP capture, NFStream, Suricata, systemd, and ELK deployment |

---

## Quick Installation

### Windows PowerShell

```powershell
git clone https://github.com/tangquoccuonggtvt/hybrid-nids.git
cd hybrid-nids-hcmct

py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Ubuntu/Linux

```bash
git clone https://github.com/<YOUR-USERNAME>/hybrid-nids-hcmct.git
cd hybrid-nids-hcmct

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Utilities outside the main pipeline (e.g. XGBoost comparison or DOCX editing tools) can be installed additionally with:

```bash
pip install -r requirements-optional.txt
```

---

## Post-Installation Checks

**1. Feature schema check**

```bash
python schema_check.py
```

This verifies that the flow feature extractor output matches the schema the official model was trained on (`models/feature_schema_model.json`).

**2. Artifact evaluation**

```bash
python evaluate_artifacts.py
```

This script validates the official model artifacts in `models/` (pipeline, metadata, metrics) before they are used for inference.

> ⚠️ **Do not load** `.pkl`/`.joblib` files from untrusted sources. Pickle/joblib can execute arbitrary code during deserialization.

---

## Running AI Inference on Sample Data

The repo ships with `sample_flows.csv` for a quick test:

```bash
python nids_detector.py \
  --input-csv sample_flows.csv \
  --once \
  --output-log logs/ai_alerts.jsonl \
  --disable-discord \
  --disable-telegram
```

On PowerShell:

```powershell
python nids_detector.py `
  --input-csv sample_flows.csv `
  --once `
  --output-log logs\ai_alerts.jsonl `
  --disable-discord `
  --disable-telegram
```

The official model uses the following by default:

- `models/nids_rf_pipeline.pkl`
- `models/metadata.json`
- `models/feature_schema_model.json`

---

## Running the Real-Time Dashboard

```bash
python realtime_dashboard.py \
  --input-csv sample_flows.csv \
  --host 127.0.0.1 \
  --port 8050
```

On PowerShell, use the backtick line-continuation character instead of the backslash shown above.

Then open: `http://127.0.0.1:8050`

The dashboard can display the number of flows processed, alert count, alert rate, latency, throughput, and additional live metrics when the input is labeled.

---

## Suricata + AI Alert Fusion

The repo includes sample logs to test the fusion module:

```bash
python hybrid_alert_fusion.py \
  --suricata-eve logs/sample_suricata_eve.jsonl \
  --ai-alerts logs/ai_alerts.jsonl \
  --output logs/hybrid_alerts.jsonl \
  --window-seconds 300 \
  --include-unmatched \
  --max-records 20
```

> If `logs/ai_alerts.jsonl` has not been created yet, run the AI inference step first.

📖 Detailed documentation: [`docs/HYBRID_FUSION_GUIDE.md`](docs/HYBRID_FUSION_GUIDE.md)

---

## Dataset and Reproducing Results

The large UNSW-NB15 files are **not** committed to GitHub. To fully reproduce training/evaluation, prepare a local dataset following the structure required by the codebase, specifically:

```text
UNSW_NB15_Splitted_CLEAN/
├── unsw_nb15_train_full.csv
├── unsw_nb15_test_holdout.csv
├── clean_split_summary.json
└── label_conflict_groups.csv
```

Once the data is in place, you can run:

```bash
python clean_data.py
python check_leakage.py
python train_model.py
python compare_baselines.py
python benchmark_inference.py
python evaluate_artifacts.py
```

> Several of these scripts (`train_model.py`, `benchmark_inference.py`, `evaluate_artifacts.py`) expect the full local dataset and will report missing files if you clone the GitHub version without placing the large UNSW-NB15 dataset on your machine.

📖 Detailed reproduction guide: [`docs/REPRODUCIBILITY_GUIDE.md`](docs/REPRODUCIBILITY_GUIDE.md)

---

## PCAP / Live Traffic

The `nids_streaming_detector.py` script and the `scripts/capture_pcap_rotate.sh` capture utility are used for integration and live testing against real traffic.

The following distinctions must be observed:

- Official metrics in `models/metrics.json` are evaluated on the hold-out dataset using the 41-feature schema.
- Results on **unlabeled** real-world traffic (via `evaluate_local_traffic.py`) are operational checks only and **must not be interpreted** as Accuracy/Precision/Recall/F1.
- When the live schema extractor is not equivalent to the training schema (verify with `schema_check.py`), PCAP results **must not be treated** as equivalent to hold-out results.

See also: [`docs/LOCAL_TRAFFIC_EVALUATION_GUIDE.md`](docs/LOCAL_TRAFFIC_EVALUATION_GUIDE.md)

---

## Ubuntu + ELK Deployment

Main files:

```text
deployment/
├── hybrid-nids.env.example    # Template file ONLY
├── suricata/
│   └── local.rules
├── elk/
│   ├── docker-compose.yml
│   └── BAO_MAT_ELK.md         # ELK security notes
└── systemd/
    ├── hybrid-nids-ai-detector.service
    ├── hybrid-nids-capture.service
    ├── hybrid-nids-fusion.service
    └── hybrid-nids-webpanel.service
```

> ⚠️ Do **not** edit `hybrid-nids.env.example` directly to hold real secrets. Instead, create a local copy:

```bash
cp deployment/hybrid-nids.env.example deployment/hybrid-nids.env
```

Then fill in passwords/tokens on the deployment machine. `deployment/hybrid-nids.env` is already excluded from Git via `.gitignore`.

The four `systemd/` unit files (`hybrid-nids-capture`, `hybrid-nids-ai-detector`, `hybrid-nids-fusion`, `hybrid-nids-webpanel`) run the capture, detection, fusion, and web panel components as independent services in production.

📖 Guide: [`docs/UBUNTU_DEPLOYMENT_GUIDE.md`](docs/UBUNTU_DEPLOYMENT_GUIDE.md)

---

## Secrets Security

**Never commit** the following:

- Elasticsearch password
- Kibana system password
- Discord webhook
- Telegram bot token/chat ID
- Web panel password
- PCAP or logs collected from real networks containing sensitive data

The repo only retains `deployment/hybrid-nids.env.example` with placeholder values.

> ⚠️ If a real secret was ever committed to Git in the past, simply adding it to `.gitignore` is **not sufficient**. The secret must be **revoked/rotated** and **removed from Git history** before making the repository public.

---

## Key Documentation

| Document | Purpose |
|---|---|
| [`docs/REPRODUCIBILITY_GUIDE.md`](docs/REPRODUCIBILITY_GUIDE.md) | Reproducing experiments |
| [`docs/RESULTS_SUMMARY.md`](docs/RESULTS_SUMMARY.md) | Results summary |
| [`docs/HYBRID_FUSION_GUIDE.md`](docs/HYBRID_FUSION_GUIDE.md) | Alert fusion |
| [`docs/LOCAL_TRAFFIC_EVALUATION_GUIDE.md`](docs/LOCAL_TRAFFIC_EVALUATION_GUIDE.md) | Local traffic evaluation |
| [`docs/UBUNTU_DEPLOYMENT_GUIDE.md`](docs/UBUNTU_DEPLOYMENT_GUIDE.md) | Ubuntu deployment |
| [`deployment/elk/BAO_MAT_ELK.md`](deployment/elk/BAO_MAT_ELK.md) | ELK Stack security notes |
| [`data/README.md`](data/README.md) | Dataset sample notes |
| [`logs/README.md`](logs/README.md) | Sample log notes |

---

## Intended Use

This codebase is intended for **research, education, and lab testing purposes**. 
---

## License Note



---

<p align="center"><sub>Hybrid-NIDS — Master's Thesis on a Hybrid Network Intrusion Detection System</sub></p>
