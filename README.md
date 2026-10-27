# GrayZone: neuro-fuzzy alert triage for network intrusion detection

Instead of a yes/no "attack" verdict, every network flow gets a **risk level** that a security analyst can act on:

| Level | Meaning |
|---|---|
| **Monitor** | looks normal, no action |
| **Investigate** | suspicious or uncertain, worth a look |
| **High** | confident, severe attack |

Two Transformer models produce the evidence. A fuzzy rule system combines that evidence into a 0-100 risk score, which is then mapped to the three levels. The rules are first written by hand, then tuned on validation data (neuro-fuzzy). A Streamlit dashboard replays the test traffic and shows the risk level for every flow.

Dataset: **CIC-IDS2017** (the labelled `TrafficLabelling` CSVs, about 2.8M flows over 5 days, 15 labels).

## Pipeline

| Notebook | What it does |
|---|---|
| [01_eda.ipynb](01_eda.ipynb) | Cleaning, duplicates and label conflicts, timestamp fix (the CSVs use a 12-hour clock with no AM/PM), feature distributions, IP analysis |
| [02_preprocessing.ipynb](02_preprocessing.ipynb) | Chronological split inside each attack block (no leakage from near-identical flows), `log1p` + StandardScaler fitted on train only, per-Source-IP sequence arrays |
| [03_baseline_rf.ipynb](03_baseline_rf.ipynb) | Random Forest baseline on single flows |
| [04_transformer.ipynb](04_transformer.ipynb) | **Model A:** Transformer classifier over a "story" (the last 32 flows from the same Source IP). **Model B:** Transformer autoencoder trained only on benign stories, used as an anomaly score |
| [05_fuzzy.ipynb](05_fuzzy.ipynb) | Fuzzy layer: membership functions, hand-made rules, crisp baselines, neuro-fuzzy tuning, final test comparison |
| [app/dashboard.py](app/dashboard.py) | Streamlit dashboard |

### Fuzzy inputs

- `p_attack`: classifier confidence that the flow is an attack (`1 - p_BENIGN`)
- `anomaly_pct`: autoencoder reconstruction error, as a percentile of benign validation traffic
- `severity`: how dangerous the most likely attack type is (0 = harmless, 1 = worst, our own design choice)
- `scan_evidence`: share of the IP's recent flows that went to a new destination port (port scans are close to 1)

Example rules:
- *IF* `p_attack` is high *AND* `severity` is high *AND* `anomaly_pct` is not low *THEN* risk is high
- *IF* `anomaly_pct` is high *AND* `p_attack` is low *THEN* risk is medium (possible new attack)

## Results

**Classifier (validation, same 565k rows, macro F1):** Transformer 0.781 vs Random Forest 0.773. The Transformer is much better on web attacks (for example XSS 0.87 vs 0.30) because it sees what the same IP did just before. The RF is better on the rarest classes (Heartbleed, Infiltration).

**Anomaly detector:** strong on SSH-Patator, Heartbleed, Infiltration and slow DoS (ROC-AUC 0.93-0.98). It also catches the rare classes the classifier misses. Port scans look *more* normal than benign traffic, so `scan_evidence` covers those instead.

**Final triage on the test split** ([results/fuzzy/final_test_comparison.csv](results/fuzzy/final_test_comparison.csv)):

| Method | Match | Kappa | Benign → High | Benign → Investigate | Attacks missed | Severe not High |
|---|---|---|---|---|---|---|
| Crisp A: classifier only | 0.9944 | 0.9779 | 976 | 72 | 2048 | 2097 |
| Crisp B: classifier + anomaly | 0.9850 | 0.9685 | 976 | 5359 | 2045 | 2097 |
| Fuzzy: hand-made rules | 0.9247 | 0.9050 | 126 | 14487 | 1392 | 27940 |
| Fuzzy: tuned (neuro-fuzzy) | 0.9852 | 0.9700 | 379 | 4806 | 2342 | 3156 |

*Match* = share of flows given the expected level. *Benign → High* counts false high-priority alerts, the most expensive kind of mistake for an analyst. Tuning brought the fuzzy system from 0.92 to 0.99 match and cut its false High alerts to less than half of the crisp baselines', at the cost of more "Investigate" alerts and slightly more missed attacks.

Plots are in [results/](results/) (EDA distributions, confusion matrix, anomaly scores, membership functions).

## Running it

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows; use source .venv/bin/activate on Linux/macOS
pip install numpy pandas pyarrow scikit-learn torch matplotlib joblib streamlit jupyter
```

1. Download CIC-IDS2017 (`TrafficLabelling` CSVs) from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) and put the 8 CSV files in `TrafficLabelling/`.
2. Run the notebooks in order, `01` to `05`. Each one saves its outputs under `data/` and `models/` for the next.
3. Start the dashboard from the project folder:

```bash
streamlit run app/dashboard.py
```

The raw data, processed data and the Random Forest model are not in the repo because of their size (see [.gitignore](.gitignore)). The small trained models (`transformer_clf.pt`, `transformer_ae.pt`, `neuro_fuzzy.pt`, `scaler.joblib`) are in [models/](models/).
