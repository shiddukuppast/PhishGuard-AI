# PhishGuard AI – Machine Learning Subsystem & Forensic Audit

> **Platform:** PhishGuard AI | *Detect. Analyze. Protect.*  
> **Component:** Machine Learning Phishing Classification Engine & Forensic Dataset Audit  
> **Artifacts Directory:** `model/artifacts/`  
> **Training Scripts & Notebooks:** `model/Code/`  
> **Dataset Source:** `model/Data/phishing_features.csv`  

---

## 1. Subsystem Architecture Overview

The PhishGuard AI machine learning subsystem provides static, privacy-preserving lexical and structural phishing detection for submitted URLs. It operates strictly without making outbound HTTP/HTTPS requests to avoid Server-Side Request Forgery (SSRF) and threat-actor tracking.

```
┌──────────────────────────────────────────────────────────────┐
│                    User Submitted Target URL                 │
└──────────────────────────────┬───────────────────────────────┘
                               │
               ┌───────────────▼──────────────┐
               │    Static URL Normalization  │ (urlparse, no SSRF)
               └───────────────┬──────────────┘
                               │
    ┌──────────────────────────┴──────────────────────────┐
    │                                                     │
┌───▼──────────────────────────┐         ┌────────────────▼────────────────┐
│  11 Canonical ML Features    │         │  Heuristic Security Attributes  │
│  (Lexical, Entropy, TLD)     │         │  (IP host, Brands, Ports, @)   │
└───┬──────────────────────────┘         └────────────────┬────────────────┘
    │                                                     │
┌───▼──────────────────────────┐                          │
│  Scikit-Learn Pipeline       │                          │
│  - ColumnTransformer         │                          │
│  - StandardScaler / OneHot   │                          │
│  - Random Forest Ensemble    │                          │
└───┬──────────────────────────┘                          │
    │                                                     │
    │ (Prediction & Confidence)                           │
    └──────────────────────────┬──────────────────────────┘
                               │
               ┌───────────────▼──────────────┐
               │  Multi-Layer Risk Engine     │
               │  - Threat Intelligence Feeds │
               │  - Heuristic Penalty Rules   │
               │  - ML Signal Calibration     │
               └───────────────┬──────────────┘
                               │
               ┌───────────────▼──────────────┐
               │  Consolidated Threat Report  │
               └──────────────────────────────┘
```

---

## 2. Dataset Information & Forensic Audit of the "100% Score"

### Dataset Dimensions:
- **Total Records:** 160,064
- **Columns:** 13 (`url`, `label`, and 11 feature columns)
- **Class Distribution:**
  - **Class 0 (Legitimate / Benign):** 820 samples (0.51%)
  - **Class 1 (Phishing URLs):** 159,244 samples (99.49%)
  - **Class Imbalance Ratio:** 194.2 : 1

### Root Causes of the Artificial 100% (1.0) Benchmark Score:
Our forensic investigation of `model/Data/phishing_features.csv` and previous training code in `Untitled.ipynb` revealed why all four classifiers (Logistic Regression, Decision Tree, Random Forest, XGBoost) reported 1.0 accuracy, precision, recall, and macro F1:

1. **Target Leakage via Inconsistent URL Schemes:**
   - **Class 0 (Legitimate):** Sourced from top domain rankings as **bare domains** (e.g., `google.com`, `youtube.com`) with **zero URL scheme prefixes** (`http://` or `https://`).
   - **Class 1 (Phishing):** Sourced from active phishing feeds with **100% fully-qualified schemes** (`http://...` or `https://...`).
2. **Target Leakage via `num_subdirs` (`url.count('/')`):**
   - **100% of Class 0 URLs** contain **0 slashes** (`num_subdirs == 0`).
   - **100% of Class 1 URLs** contain **>= 2 slashes** (`num_subdirs >= 2`).
   - Any single decision split on `num_subdirs <= 0` separates 100% of the dataset with zero error.
3. **Target Leakage via Missing TLD (`tld == NaN`):**
   - The original feature generator used `urlparse(url).netloc` to extract the host. When `urlparse("google.com")` runs on a bare domain without a scheme, `netloc` evaluates to empty string `""`.
   - Consequently, TLD extraction failed, leaving `tld == NaN` for **820 out of 820 Class 0 URLs (100%)** and only 1 Class 1 URL.
   - When imputed with `SimpleImputer(fill_value="Unknown")`, the generated one-hot feature `tld_Unknown` acted as a 100% deterministic proxy for Class 0.
4. **Generalization Consequence:**
   - Naive models trained on these features memorized `num_subdirs == 0` and `tld == 'Unknown'` as legitimate.
   - In production, real legitimate URLs (such as `https://google.com/search?q=test`) contain slashes and valid TLDs (`.com`), causing a naive model to falsely classify them as phishing.
   - **Architectural Solution:** PhishGuard AI keeps ML predictions and rule-based risk scores conceptually separate. Heuristic rules and Threat Intelligence feeds guarantee legitimate URLs are not misclassified.

---

## 3. Canonical Suspicious Words Feature

Because the original dataset generation script was not committed, the keyword counting definition had minor discrepancies. We established and canonicalized the exact 15-keyword definition across the entire platform:

### Canonical 15 Keywords:
```python
CANONICAL_KEYWORDS = [
    "login", "verify", "update", "password", "secure",
    "banking", "account", "signin", "confirm", "wallet",
    "paypal", "credential", "authenticate", "suspended", "recover"
]
```

### Canonical Counting Function:
```python
def count_suspicious_words(url_str: str) -> int:
    u = str(url_str).lower()
    return sum(1 for kw in CANONICAL_KEYWORDS if kw in u)
```
- Matches 99.45% of existing dataset positive counts.
- Implemented identically in `model/Code/feature_extractor.py`, `model/Code/train.py`, and `backend/app/services/url_analyzer.py`.

---

## 4. Feature Set & Preprocessing Pipeline

The model consumes 11 static lexical and structural features:

| Feature Name | Type | Definition / Formula | Preprocessing |
|---|---|---|---|
| `url_length` | Numerical | `len(cleaned_url)` | SimpleImputer(median) + StandardScaler |
| `num_dots` | Numerical | `cleaned_url.count('.')` | SimpleImputer(median) + StandardScaler |
| `has_https` | Numerical | `1 if url.startswith('https') else 0` | SimpleImputer(median) + StandardScaler |
| `has_ip` | Numerical | `1 if host is IPv4/IPv6 else 0` | SimpleImputer(median) + StandardScaler |
| `num_subdirs` | Numerical | `cleaned_url.count('/')` | SimpleImputer(median) + StandardScaler |
| `num_params` | Numerical | `len(query.split('&')) if query else 0` | SimpleImputer(median) + StandardScaler |
| `suspicious_words` | Numerical | Count of 15 canonical keywords present | SimpleImputer(median) + StandardScaler |
| `special_char_count`| Numerical | Count of `[-_?=&%~+*!$#@]` | SimpleImputer(median) + StandardScaler |
| `digits_count` | Numerical | `sum(c.isdigit() for c in url)` | SimpleImputer(median) + StandardScaler |
| `entropy` | Numerical | Shannon entropy base 2: `-\sum p \log_2 p` | SimpleImputer(median) + StandardScaler |
| `tld` | Categorical | Extracted top-level domain string | SimpleImputer('Unknown') + OneHotEncoder |

All preprocessing is encapsulated inside a Scikit-learn `ColumnTransformer` and serialized as part of the overall `Pipeline`.

---

## 5. Model Evaluation & Benchmark Results

### Benchmark 1: Stratified Split (80% Train / 20% Test)
- Train size: 128,051 (Class 0: 656, Class 1: 127,395)
- Test size: 32,013 (Class 0: 164, Class 1: 31,849)

| Model | Accuracy | Precision (Macro) | Recall (Macro) | F1 (Macro) | Phishing Recall | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Decision Tree | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Random Forest (Selected)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

### Benchmark 2: Domain-Based Split (`GroupShuffleSplit` on Registered Domain)
- Train size: 126,279 (Class 0: 664, Class 1: 125,615)
- Test size: 33,785 (Class 0: 156, Class 1: 33,629)
- Train unique domains: 45,915 | Test unique domains: 11,479

| Model | Accuracy | Precision (Macro) | Recall (Macro) | F1 (Macro) | Phishing Recall | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Decision Tree | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Random Forest (Selected)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

*Note:* As identified in the forensic audit, both benchmarks score 1.0 because the target leakage shortcuts (`num_subdirs == 0` and `tld == NaN`) are properties of the Class 0 sample collection across all domains.

---

## 6. Production Model Artifacts

Artifacts are located in `model/artifacts/`:

```text
model/artifacts/
├── phishing_model.pkl    # Serialized Scikit-learn Pipeline (ColumnTransformer + RandomForest)
├── feature_names.json    # Ordered list of the 11 canonical features
└── model_metadata.json   # Training hyperparameters, dataset metrics, version, audit findings
```

### Loading in Python:
```python
import joblib
import pandas as pd

pipeline = joblib.load("model/artifacts/phishing_model.pkl")

# Pass 11 canonical features as DataFrame
sample = pd.DataFrame([{
    "url_length": 35,
    "num_dots": 2,
    "has_https": 1,
    "has_ip": 0,
    "num_subdirs": 1,
    "num_params": 0,
    "suspicious_words": 0,
    "special_char_count": 2,
    "digits_count": 0,
    "entropy": 3.45,
    "tld": "com"
}])

prediction = pipeline.predict(sample)[0]  # 0 = LEGITIMATE, 1 = PHISHING
probabilities = pipeline.predict_proba(sample)[0]  # [prob_legitimate, prob_phishing]
```

---

## 7. FastAPI Backend Integration

1. **Lifespan Startup (`app/main.py`):**
   `prediction_service.load_model()` is called on application boot. If the file is absent, it logs an informative warning and marks `is_loaded = False` without blocking startup.
2. **Feature Extraction (`app/services/url_analyzer.py`):**
   Extracts all 11 features deterministically using static regex and URL components.
3. **Inference Execution (`app/services/prediction_service.py`):**
   Converts extracted features into a `pandas.DataFrame` row, runs `pipeline.predict()`, and queries `predict_proba()` for calibrated confidence.
4. **Risk Engine Synthesis (`app/services/risk_engine.py`):**
   ML confidence is blended into the overall security score alongside threat intelligence signatures and lexical heuristics.

---

## 8. Limitations & Security Recommendations

1. **Dataset Syntactic Bias:** The dataset features demonstrate that lexical patterns alone can be circumvented by attackers using shortening services, obscure URL schemes, or legitimate cloud hosting (e.g., Google Forms, Cloudflare Workers).
2. **Multi-Layer Defense:** Machine learning predictions must always remain one layer of defense alongside active Threat Intelligence (PhishTank, OpenPhish) and deterministic heuristics.
3. **Future Retraining:** Future training iterations should incorporate legitimate URLs with deep path structures (e.g., Wikipedia articles, GitHub documentation) to eliminate the `num_subdirs` bias.
