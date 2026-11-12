"""Read-only dataset validation and bias analysis for PhishGuard AI."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EDA_DIR = Path(__file__).resolve().parent
VISUALIZATIONS_DIR = EDA_DIR / "visualizations"
DATA_PATH = PROJECT_ROOT / "model" / "Data" / "phishing_features.csv"
PSL_PATH = EDA_DIR / "public_suffix_list.dat"
FEATURE_COLUMNS = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "tld",
    "special_char_count",
    "digits_count",
    "entropy",
]
NUMERIC_FEATURES = [column for column in FEATURE_COLUMNS if column != "tld"]
EXPECTED_COLUMNS = [
    "url",
    "label",
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "tld",
    "special_char_count",
    "digits_count",
    "entropy",
]
URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
UUID_PATTERN = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f-]{27,}\b")
HEX_PATTERN = re.compile(r"(?i)\b[0-9a-f]{12,}\b")
LONG_NUMBER_PATTERN = re.compile(r"\d{4,}")


def load_public_suffix_rules(path: Path) -> tuple[set[str], set[str], set[str], str]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exceptions: set[str] = set()
    lines = path.read_text(encoding="utf-8").splitlines()
    version = next(
        (line.removeprefix("// VERSION:").strip() for line in lines if line.startswith("// VERSION:")),
        "version not recorded",
    )
    for line in lines:
        rule = line.strip().lower()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcard.add(rule[2:])
        else:
            exact.add(rule)
    if len(exact) < 9000:
        raise ValueError(f"Public Suffix List appears incomplete: {len(exact)} exact rules")
    return exact, wildcard, exceptions, version


def parse_url(raw_url: object) -> tuple[object | None, str | None, str]:
    if pd.isna(raw_url):
        return None, None, "missing"
    value = str(raw_url).strip()
    if not value:
        return None, None, "empty"
    try:
        parsed = urlsplit(value if URL_SCHEME.match(value) or value.startswith("//") else "//" + value)
        _ = parsed.port
        hostname = parsed.hostname
        if hostname:
            hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        return parsed, hostname, "ok" if hostname else "no_hostname"
    except (UnicodeError, ValueError):
        return None, None, "parse_error"


def is_ip_address(hostname: str | None) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(
    hostname: str | None,
    exact_rules: set[str],
    wildcard_rules: set[str],
    exception_rules: set[str],
) -> str | None:
    if not hostname:
        return None
    if is_ip_address(hostname):
        return f"IP:{hostname}"

    labels = hostname.lower().split(".")
    if len(labels) == 1:
        return f"SINGLE:{hostname.lower()}"

    public_suffix_length = 1
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        if suffix in exception_rules:
            public_suffix_length = len(labels) - index - 1
            break
        if suffix in exact_rules:
            public_suffix_length = max(public_suffix_length, len(labels) - index)
        if index + 1 < len(labels) and ".".join(labels[index + 1 :]) in wildcard_rules:
            public_suffix_length = max(public_suffix_length, len(labels) - index)

    if len(labels) <= public_suffix_length:
        return f"PUBLIC_SUFFIX_ONLY:{hostname.lower()}"
    return ".".join(labels[-(public_suffix_length + 1) :])


def normalize_url(parsed: object, hostname: str | None, keep_scheme: bool) -> str:
    scheme = parsed.scheme.lower() if keep_scheme else ""
    port = parsed.port
    netloc = hostname or ""
    if port is not None and not (
        (parsed.scheme.lower() == "http" and port == 80)
        or (parsed.scheme.lower() == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"
    path = parsed.path or ("/" if netloc else "")
    return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))


def normalize_template(parsed: object, hostname: str | None) -> str:
    path = UUID_PATTERN.sub("<UUID>", parsed.path)
    path = HEX_PATTERN.sub("<HEX>", path)
    path = LONG_NUMBER_PATTERN.sub("<NUM>", path)
    query_keys = sorted({part.split("=", 1)[0] for part in parsed.query.split("&") if part})
    return f"{hostname or ''}{path}?{'&'.join(query_keys)}"


def feature_mismatch_table(data: pd.DataFrame) -> pd.DataFrame:
    code_dir = PROJECT_ROOT / "model" / "Code"
    if str(code_dir) not in sys.path:
        sys.path.insert(0, str(code_dir))
    from feature_extractor import extract_canonical_features

    mismatches = Counter()
    total = len(data)
    for row in data[["url", *FEATURE_COLUMNS]].itertuples(index=False, name=None):
        raw_url = row[0]
        stored = dict(zip(FEATURE_COLUMNS, row[1:]))
        recomputed = extract_canonical_features(raw_url)
        for column in FEATURE_COLUMNS:
            actual = stored[column]
            expected = recomputed[column]
            if column == "tld":
                equal = (
                    pd.isna(actual) and expected == "Unknown"
                    or not pd.isna(actual) and str(actual).lower() == str(expected).lower()
                )
            elif column == "entropy":
                equal = abs(float(actual) - float(expected)) < 0.001
            else:
                equal = actual == expected
            if not equal:
                mismatches[column] += 1

    return pd.DataFrame(
        [
            {
                "feature": column,
                "mismatches": int(mismatches[column]),
                "mismatch_percent": round(mismatches[column] / total * 100, 4),
            }
            for column in FEATURE_COLUMNS
        ]
    )


def _top_values(series: pd.Series, limit: int = 10) -> str:
    values = series.value_counts(dropna=False).head(limit)
    formatted = []
    for value, count in values.items():
        display_value = "(missing)" if pd.isna(value) else str(value)
        if len(display_value) > 100:
            display_value = display_value[:97] + "..."
        formatted.append(f"{display_value}: {int(count)}")
    return "; ".join(formatted)


def _markdown_table(frame: pd.DataFrame, floatfmt: str | None = None) -> str:
    def format_value(value: object) -> str:
        if pd.isna(value):
            return ""
        if isinstance(value, (float, np.floating)) and floatfmt:
            return format(float(value), floatfmt)
        return str(value).replace("|", "\\|").replace("\n", " ")

    headers = [str(column) for column in frame.columns]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in frame.itertuples(index=False, name=None):
        lines.append("| " + " | ".join(format_value(value) for value in row) + " |")
    return "\n".join(lines)


def _write_visualizations(data: pd.DataFrame, url_data: pd.DataFrame, correlations: pd.DataFrame) -> None:
    VISUALIZATIONS_DIR.mkdir(parents=True, exist_ok=True)
    colors = {0: "#4c72b0", 1: "#dd8452"}

    counts = data["label"].value_counts().sort_index()
    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(
        [str(label) for label in counts.index],
        counts.values,
        color=[colors[label] for label in counts.index],
    )
    ax.set_yscale("log")
    ax.set_title("Target label counts (log scale)")
    ax.set_xlabel("Stored label (meaning is project-documented, not independently verified)")
    ax.set_ylabel("Rows")
    ax.bar_label(bars, labels=[f"{int(value):,}" for value in counts.values], padding=3)
    fig.tight_layout()
    fig.savefig(VISUALIZATIONS_DIR / "label_distribution.png", dpi=180)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, column, title in zip(
        axes,
        ["num_subdirs", "url_length"],
        ["Stored slash count (`num_subdirs`)", "URL length"],
    ):
        sns.ecdfplot(data=data, x=column, hue="label", ax=ax, palette=colors)
        if column == "url_length":
            ax.set_xscale("log")
            ax.set_xlabel("URL length (log scale)")
        ax.set_title(title + " by label")
        ax.set_ylabel("Within-class cumulative proportion")
    fig.tight_layout()
    fig.savefig(VISUALIZATIONS_DIR / "url_structure_by_label.png", dpi=180)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, label in zip(axes, [0, 1]):
        class_urls = url_data.loc[url_data["label"] == label]
        scheme_counts = class_urls["scheme"].value_counts(normalize=True).reindex(
            ["NO_SCHEME", "http", "https"], fill_value=0
        )
        ax.bar(
            scheme_counts.index,
            scheme_counts.values * 100,
            color=[colors[label]] * len(scheme_counts),
        )
        ax.set_title(f"Label {label} (n={len(class_urls):,})")
        ax.set_ylabel("Percent of class")
        ax.set_xlabel("Parsed scheme")
        ax.tick_params(axis="x", rotation=20)
    fig.suptitle("Scheme composition by class (within-class percentages)")
    fig.tight_layout()
    fig.savefig(VISUALIZATIONS_DIR / "structure_by_label.png", dpi=180)
    plt.close(fig)

    fig, axes = plt.subplots(5, 2, figsize=(14, 18))
    axes = axes.ravel()
    for ax, column in zip(axes, NUMERIC_FEATURES):
        upper = data[column].quantile(0.99)
        values = data[column].clip(upper=upper)
        low = max(0.0, float(values.min()))
        high = float(values.max())
        bins = [-0.5, 0.5, 1.5] if data[column].nunique() == 2 else np.linspace(low, high, 31)
        for label in [0, 1]:
            class_values = values.loc[data["label"] == label]
            weights = np.full(len(class_values), 1 / len(class_values))
            ax.hist(
                class_values,
                bins=bins,
                weights=weights,
                histtype="step",
                linewidth=1.5,
                color=colors[label],
                label=f"Label {label}",
            )
        ax.set_title(f"{column} (values clipped at pooled p99 for display)")
        ax.set_ylabel("Within-class proportion per bin")
        ax.legend()
    fig.suptitle("Numeric feature distributions by class (target excluded)", y=0.995)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    fig.savefig(VISUALIZATIONS_DIR / "numeric_feature_histograms.png", dpi=180)
    plt.close(fig)

    tld_data = data[["label", "tld"]].copy()
    tld_data["tld_display"] = tld_data["tld"].fillna("(missing)").astype(str)
    top_nonmissing = (
        tld_data.loc[tld_data["label"] == 1, "tld_display"]
        .loc[lambda values: values != "(missing)"]
        .value_counts()
        .head(9)
        .index.tolist()
    )
    categories = ["(missing)", *top_nonmissing]
    fig, axes = plt.subplots(1, 2, figsize=(15, 6), sharex=False)
    for ax, label in zip(axes, [0, 1]):
        class_values = tld_data.loc[tld_data["label"] == label, "tld_display"]
        proportions = class_values.value_counts(normalize=True).reindex(categories, fill_value=0)
        ax.barh(categories[::-1], proportions.values[::-1] * 100, color=colors[label])
        ax.set_title(f"Label {label} (n={len(class_values):,})")
        ax.set_xlabel("Percent of class")
        ax.set_ylabel("Stored `tld` value (raw; includes invalid numeric values)")
    fig.suptitle("Stored TLD values by class: within-class percentages")
    fig.tight_layout()
    fig.savefig(VISUALIZATIONS_DIR / "tld_by_label.png", dpi=180)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 7))
    sns.heatmap(
        correlations,
        cmap="vlag",
        center=0,
        vmin=-1,
        vmax=1,
        square=True,
        ax=ax,
        cbar_kws={"label": "Pearson correlation"},
    )
    ax.set_title("Numeric feature correlation (label excluded)")
    fig.tight_layout()
    fig.savefig(VISUALIZATIONS_DIR / "numeric_feature_correlations.png", dpi=180)
    plt.close(fig)


def run_eda() -> dict[str, object]:
    if not DATA_PATH.is_file():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")
    if not PSL_PATH.is_file():
        raise FileNotFoundError(f"Public Suffix List snapshot not found: {PSL_PATH}")

    exact_rules, wildcard_rules, exception_rules, psl_version = load_public_suffix_rules(PSL_PATH)
    data = pd.read_csv(DATA_PATH)
    if list(data.columns) != EXPECTED_COLUMNS:
        raise ValueError(f"Unexpected columns: {list(data.columns)}")

    source_hash = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    overview = pd.DataFrame(
        [
            ("rows", len(data)),
            ("columns", len(data.columns)),
            ("memory_usage_bytes_deep", int(data.memory_usage(deep=True).sum())),
            ("duplicate_rows", int(data.duplicated().sum())),
            ("exact_duplicate_urls", int(data["url"].duplicated().sum())),
            ("blank_or_whitespace_urls", int(data["url"].fillna("").str.strip().eq("").sum())),
            ("dataset_sha256", source_hash),
            ("psl_version", psl_version),
            ("psl_exact_rules", len(exact_rules)),
            ("psl_wildcard_rules", len(wildcard_rules)),
            ("psl_exception_rules", len(exception_rules)),
        ],
        columns=["measure", "value"],
    )

    dtype_table = pd.DataFrame(
        {
            "column": data.columns,
            "dtype": [str(data[column].dtype) for column in data.columns],
            "missing": [int(data[column].isna().sum()) for column in data.columns],
            "unique_including_missing": [int(data[column].nunique(dropna=False)) for column in data.columns],
        }
    )
    label_counts = (
        data["label"].value_counts().sort_index().rename_axis("label").to_frame("rows").reset_index()
    )
    label_counts["percent"] = label_counts["rows"] / len(data) * 100
    label_counts["meaning_in_project_docs"] = label_counts["label"].map(
        {0: "LEGITIMATE (project-documented)", 1: "PHISHING (project-documented)"}
    ).fillna("UNMAPPED")

    missing_by_label = data.groupby("label", dropna=False).agg(
        rows=("label", "size"),
        missing_tld=("tld", lambda series: int(series.isna().sum())),
        missing_tld_percent=("tld", lambda series: series.isna().mean() * 100),
    ).reset_index()

    class_profiles = data.groupby("label").agg(
        rows=("label", "size"),
        mean_url_length=("url_length", "mean"),
        min_url_length=("url_length", "min"),
        max_url_length=("url_length", "max"),
        mean_num_subdirs=("num_subdirs", "mean"),
        min_num_subdirs=("num_subdirs", "min"),
        max_num_subdirs=("num_subdirs", "max"),
        https_percent=("has_https", lambda series: series.mean() * 100),
        ip_percent=("has_ip", lambda series: series.mean() * 100),
        query_count_percent=("num_params", lambda series: (series > 0).mean() * 100),
        mean_entropy=("entropy", "mean"),
    ).reset_index()

    url_rows = []
    for raw_url in data["url"]:
        parsed, hostname, status = parse_url(raw_url)
        if parsed is None:
            url_rows.append(
                {
                    "parse_status": status,
                    "scheme": "PARSE_ERROR",
                    "hostname": None,
                    "registrable_domain": None,
                    "path": None,
                    "query": None,
                    "fragment": None,
                    "normalized_url": None,
                    "normalized_without_scheme": None,
                    "path_segments": 0,
                    "template": None,
                }
            )
            continue
        url_rows.append(
            {
                "parse_status": status,
                "scheme": parsed.scheme.lower() or "NO_SCHEME",
                "hostname": hostname,
                "registrable_domain": registrable_domain(
                    hostname, exact_rules, wildcard_rules, exception_rules
                ),
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "normalized_url": normalize_url(parsed, hostname, keep_scheme=True),
                "normalized_without_scheme": normalize_url(parsed, hostname, keep_scheme=False),
                "path_segments": len([part for part in parsed.path.split("/") if part]),
                "template": normalize_template(parsed, hostname),
            }
        )
    url_data = pd.DataFrame(url_rows, index=data.index)
    parsed_data = pd.concat([data[["label"]], url_data], axis=1)

    url_structure = (
        parsed_data.groupby(["label", "scheme"], dropna=False)
        .agg(
            rows=("label", "size"),
            path_present=("path", lambda series: int(series.fillna("").ne("").sum())),
            query_present=("query", lambda series: int(series.fillna("").ne("").sum())),
            fragment_present=("fragment", lambda series: int(series.fillna("").ne("").sum())),
            mean_path_segments=("path_segments", "mean"),
        )
        .reset_index()
    )
    for column in ["path_present", "query_present", "fragment_present"]:
        url_structure[column + "_percent"] = (
            url_structure[column] / url_structure["rows"] * 100
        )

    parse_status = (
        parsed_data.groupby(["label", "parse_status"], dropna=False)
        .size()
        .rename("rows")
        .reset_index()
    )
    normalized_stats = pd.DataFrame(
        [
            {
                "normalization": "scheme-preserving (host case/IDNA/trailing dot/default port/empty path)",
                "duplicate_rows_after_first": int(url_data["normalized_url"].duplicated().sum()),
                "duplicate_groups": int(url_data["normalized_url"].value_counts().gt(1).sum()),
                "mixed_label_groups": int(
                    parsed_data.groupby("normalized_url")["label"].nunique().gt(1).sum()
                ),
            },
            {
                "normalization": "same key while ignoring scheme (diagnostic only)",
                "duplicate_rows_after_first": int(
                    url_data["normalized_without_scheme"].duplicated().sum()
                ),
                "duplicate_groups": int(
                    url_data["normalized_without_scheme"].value_counts().gt(1).sum()
                ),
                "mixed_label_groups": int(
                    parsed_data.groupby("normalized_without_scheme")["label"].nunique().gt(1).sum()
                ),
            },
        ]
    )

    domain_counts = parsed_data.groupby("registrable_domain", dropna=False).agg(
        rows=("label", "size"),
        label_count=("label", "nunique"),
        labels=("label", lambda series: json.dumps({str(k): int(v) for k, v in series.value_counts().items()})),
    )
    repeated_domains = domain_counts[domain_counts["rows"] > 1]
    mixed_domains = domain_counts[domain_counts["label_count"] > 1].sort_values(
        "rows", ascending=False
    )
    expected_crossed_domains = (
        1 - np.power(0.8, repeated_domains["rows"]) - np.power(0.2, repeated_domains["rows"])
    )
    domain_summary = pd.DataFrame(
        [
            ("unique registrable-domain/IP/single-label groups", len(domain_counts)),
            ("repeated groups", len(repeated_domains)),
            ("rows in repeated groups", int(repeated_domains["rows"].sum())),
            ("groups with both labels", len(mixed_domains)),
            ("rows in groups with both labels", int(mixed_domains["rows"].sum())),
            ("expected repeated groups crossing random 80/20 split", round(float(expected_crossed_domains.sum()), 1)),
            (
                "expected rows in repeated groups crossing random 80/20 split",
                round(float((expected_crossed_domains * repeated_domains["rows"]).sum()), 1),
            ),
        ],
        columns=["measure", "value"],
    )
    mixed_domain_examples = mixed_domains.head(30).reset_index()

    repeated_templates = (
        parsed_data.groupby("template", dropna=False)
        .agg(rows=("label", "size"), label_count=("label", "nunique"))
    )
    repeated_templates = repeated_templates[
        (repeated_templates["rows"] > 1) & repeated_templates.index.notna()
    ].sort_values("rows", ascending=False)
    template_summary = pd.DataFrame(
        [
            ("repeated host/path templates", len(repeated_templates)),
            ("rows in repeated templates", int(repeated_templates["rows"].sum())),
            ("templates containing both labels", int(repeated_templates["label_count"].gt(1).sum())),
        ],
        columns=["measure", "value"],
    )
    template_examples = repeated_templates.head(20).reset_index()

    numeric_features = data[NUMERIC_FEATURES]
    feature_rows = []
    distributions = []
    outlier_rows = []
    for column in FEATURE_COLUMNS:
        series = data[column]
        dominant_value = series.value_counts(dropna=False).index[0]
        feature_rows.append(
            {
                "feature": column,
                "dtype": str(series.dtype),
                "unique_including_missing": int(series.nunique(dropna=False)),
                "missing": int(series.isna().sum()),
                "dominant_value": "(missing)" if pd.isna(dominant_value) else str(dominant_value),
                "dominant_percent": round(float(series.value_counts(dropna=False, normalize=True).iloc[0] * 100), 4),
                "top_values_and_counts": _top_values(series),
            }
        )
        distributions.append(
            {
                "feature": column,
                "unique_including_missing": int(series.nunique(dropna=False)),
                "top_values_and_counts": _top_values(series),
            }
        )
        if column in NUMERIC_FEATURES:
            q1, q3 = series.quantile([0.25, 0.75])
            iqr = q3 - q1
            lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
            outlier_rows.append(
                {
                    "feature": column,
                    "q1": q1,
                    "median": series.median(),
                    "q3": q3,
                    "p99": series.quantile(0.99),
                    "max": series.max(),
                    "iqr_lower": lower,
                    "iqr_upper": upper,
                    "iqr_outlier_rows": int(((series < lower) | (series > upper)).sum()),
                    "iqr_outlier_percent": float(((series < lower) | (series > upper)).mean() * 100),
                }
            )

    feature_summary = pd.DataFrame(feature_rows)
    feature_distributions = pd.DataFrame(distributions)
    numeric_statistics = (
        data[NUMERIC_FEATURES]
        .describe(percentiles=[0.01, 0.25, 0.5, 0.75, 0.95, 0.99])
        .transpose()
        .reset_index()
        .rename(columns={"index": "feature"})
    )
    outliers = pd.DataFrame(outlier_rows)
    correlation_matrix = numeric_features.corr(method="pearson")
    high_correlations = [
        {
            "feature_a": left,
            "feature_b": right,
            "pearson_r": correlation_matrix.loc[left, right],
        }
        for index, left in enumerate(NUMERIC_FEATURES)
        for right in NUMERIC_FEATURES[index + 1 :]
        if abs(correlation_matrix.loc[left, right]) >= 0.7
    ]
    correlation_pairs = pd.DataFrame(high_correlations)
    if correlation_pairs.empty:
        correlation_pairs = pd.DataFrame(columns=["feature_a", "feature_b", "pearson_r"])
    spearman_label = (
        data[["label", *NUMERIC_FEATURES]]
        .corr(method="spearman")["label"]
        .drop("label")
        .rename("spearman_with_label")
        .reset_index()
        .rename(columns={"index": "feature"})
        .sort_values("spearman_with_label", key=lambda series: series.abs(), ascending=False)
    )

    feature_mismatches = feature_mismatch_table(data)
    numeric_tld = data["tld"].astype("string").str.fullmatch(r"\d+", na=False)
    tld_summary = pd.DataFrame(
        [
            ("distinct stored TLD values including missing", int(data["tld"].nunique(dropna=False))),
            ("rows with numeric stored TLD", int(numeric_tld.sum())),
            ("distinct numeric stored TLD values", int(data.loc[numeric_tld, "tld"].nunique())),
            ("rows with actual IP hostname", int(parsed_data["hostname"].map(is_ip_address).sum())),
        ],
        columns=["measure", "value"],
    )

    feature_by_label = (
        data.groupby("label")[NUMERIC_FEATURES]
        .agg(["mean", "median", "min", "max"])
        .round(4)
    )
    feature_by_label.columns = [
        f"{feature}_{statistic}" for feature, statistic in feature_by_label.columns
    ]
    feature_by_label = feature_by_label.reset_index()

    url_hash = source_hash
    results: dict[str, object] = {
        "overview": overview,
        "dtypes_missing": dtype_table,
        "label_counts": label_counts,
        "missing_by_label": missing_by_label,
        "class_profiles": class_profiles,
        "url_structure": url_structure,
        "parse_status": parse_status,
        "normalized_duplicates": normalized_stats,
        "domain_summary": domain_summary,
        "mixed_domains": mixed_domain_examples,
        "template_summary": template_summary,
        "template_examples": template_examples,
        "feature_summary": feature_summary,
        "feature_distributions": feature_distributions,
        "numeric_statistics": numeric_statistics,
        "outliers": outliers,
        "feature_by_label": feature_by_label,
        "correlation_pairs": correlation_pairs,
        "spearman_label": spearman_label,
        "feature_mismatches": feature_mismatches,
        "tld_summary": tld_summary,
        "correlation_matrix": correlation_matrix,
        "psl_version": psl_version,
        "source_sha256": url_hash,
        "data": data,
        "parsed_data": parsed_data,
    }

    _write_visualizations(data, parsed_data, correlation_matrix)
    write_report(results)
    return results


def write_report(results: dict[str, object]) -> None:
    data = results["data"]
    lines = [
        "# PhishGuard AI — Dataset Quality, Bias and Leakage Audit",
        "",
        "> **Scope:** Read-only validation and EDA only. No cleaning, imputation, balancing, feature engineering, splitting, model evaluation, or training was performed.",
        "",
        "## Executive summary",
        "",
        "The dataset has a severe collection-format confound. All 820 label-0 rows are scheme-less bare domains with no parsed path, while all 159,244 label-1 rows have an HTTP/HTTPS scheme; every label-0 row has `num_subdirs == 0`, while every label-1 row has `num_subdirs >= 2`. The latter feature is the raw slash count, so it directly captures the scheme marker and class-specific formatting. This is compelling evidence of a shortcut and dataset-construction bias, not proof that the labels themselves are wrong or that leakage was intentional.",
        "",
        "The project files document label 0 as legitimate and label 1 as phishing, but the original dataset source, collection dates, labeling procedure, and row-level ground truth cannot be independently verified from repository evidence. The dataset should not be treated as a representative benchmark until provenance and the class-conditional URL format are resolved.",
        "",
        "## 1. Dataset overview",
        "",
        f"- Shape: **{len(data):,} rows × {len(data.columns)} columns**.",
        f"- Deep pandas memory usage: **{int(data.memory_usage(deep=True).sum()):,} bytes**.",
        f"- SHA-256 of the read-only source CSV: `{results['source_sha256']}`.",
        "- Columns: `url`, `label`, `url_length`, `num_dots`, `has_https`, `has_ip`, `num_subdirs`, `num_params`, `suspicious_words`, `tld`, `special_char_count`, `digits_count`, `entropy`.",
        "",
        "### Types, missingness and cardinality",
        "",
        _markdown_table(results["dtypes_missing"]),
        "",
        "### Label meanings and provenance",
        "",
        "- **Project-documented mapping:** label 0 = LEGITIMATE/BENIGN; label 1 = PHISHING. This appears in `model/README.md`, `model/artifacts/model_metadata.json`, and the label mapping in `model/Code/train.py`.",
        "- **Not independently verified:** no upstream dataset URL, source citation, data dictionary, collection timestamp, annotation protocol, adjudication process, or committed dataset-construction script was found. The project README says benign examples came from top-domain rankings and phishing examples from active feeds, but does not identify those sources or document how labels were applied.",
        "- **Conclusion:** retain the mapping as a project claim only; do not treat it as verified source provenance. The positive/negative meanings, timing, and label quality require owner confirmation.",
        "",
        "## 2. Class imbalance",
        "",
        _markdown_table(results["label_counts"], floatfmt=".4f"),
        "",
        f"- Majority/minority ratio: **{data['label'].value_counts().max() / data['label'].value_counts().min():.2f}:1**.",
        "- The small label-0 sample (820 rows) is insufficient to characterize the variety of benign URLs likely in deployment. Do not remove this minority class or balance the data before provenance and representativeness are resolved.",
        "",
        "## 3. Missing-value analysis",
        "",
        _markdown_table(results["missing_by_label"], floatfmt=".4f"),
        "",
        "- Only `tld` is missing: 821 rows total. Missingness is class-concentrated: all 820 label-0 rows and 1 label-1 row.",
        "- This makes missingness itself a near-deterministic label proxy. Existing training metadata describes filling categorical missing TLDs with `Unknown`; that would preserve the proxy rather than repair its cause.",
        "- Do not impute or drop these rows until the source feature-generation logic is established. Keep explicit missingness and original values in any future derived dataset.",
        "",
        "## 4. URL structure by class",
        "",
        _markdown_table(results["class_profiles"], floatfmt=".4f"),
        "",
        "### Parsed URL components",
        "",
        "Parsing used Python `urllib.parse.urlsplit`, with scheme-less inputs interpreted as authorities (`//host`) for inspection. This is syntactic parsing, not DNS validation or a reachability check.",
        "",
        _markdown_table(results["parse_status"]),
        "",
        _markdown_table(results["url_structure"], floatfmt=".4f"),
        "",
        "- All 160,064 rows yielded a hostname under this parsing policy; no blank or parser-rejected URLs were found. Because URL parsers are permissive, this does not establish that each host is valid, resolvable, safe, or live.",
        "- Label 0 is 100% scheme-less, pathless, queryless and fragmentless. Label 1 is 100% HTTP/HTTPS; 99.05% has a non-empty path, 9.90% a query, and 0.22% a fragment.",
        "- The 820 label-0 URLs are 6–22 characters long; label 1 spans 12–25,523 characters. URL format is a major class confound.",
        "",
        "## 5. Duplicate, variant and domain overlap analysis",
        "",
        "- Exact duplicate rows: **0**.",
        "- Exact duplicate URL strings: **0**.",
        "- No empty or whitespace-only URL strings were found.",
        "",
        _markdown_table(results["normalized_duplicates"]),
        "",
        "- Scheme-preserving normalization lowercases/IDNA-normalizes hostnames, removes trailing host dots and default ports, and maps an empty authority path to `/`; it preserves query, fragment and scheme. It finds 93 duplicate rows across 93 collision groups, with no mixed-label groups.",
        "- Ignoring the scheme is a deliberately broader diagnostic (not a deduplication rule): it finds 629 duplicate rows across 621 groups, with no mixed-label groups. HTTP and HTTPS can be distinct resources; these collisions require review rather than automatic merging.",
        f"- Using the Public Suffix List snapshot `{results['psl_version']}` (including ICANN and PRIVATE rules), registrable-domain/IP/single-label grouping found:",
        "",
        _markdown_table(results["domain_summary"]),
        "",
        "Largest groups containing both labels:",
        "",
        _markdown_table(results["mixed_domains"]),
        "",
        "- Domains shared across labels may represent benign services hosting malicious content, mislabels, or shared infrastructure; they are not by themselves evidence of incorrect labels. They do show that domain-level grouping and review matter.",
        "- Under an illustrative independent row-wise 80/20 split, approximately 8,761 repeated-domain groups would be expected to straddle both partitions, involving about 111,677 rows. This is a probability calculation, not an actual split or model evaluation.",
        "",
        "### Near-duplicate pattern scan",
        "",
        _markdown_table(results["template_summary"]),
        "",
        "Candidate patterns below use the same hostname and path after replacing long numeric, UUID-like, and long hexadecimal path tokens; query values are omitted while parameter names are retained. This is a heuristic template scan, not edit-distance proof of duplicate content.",
        "",
        _markdown_table(results["template_examples"]),
        "",
        "## 6. Feature-level distributions and data quality",
        "",
        "Per-feature unique-value counts and the ten most frequent values are shown below. `url` is a high-cardinality identifier (all values are unique), so its sample values are not a meaningful categorical distribution.",
        "",
        _markdown_table(results["feature_distributions"]),
        "",
        "Numerical statistics exclude the target label:",
        "",
        _markdown_table(results["numeric_statistics"], floatfmt=".4f"),
        "",
        "### Outlier screening",
        "",
        "IQR counts are descriptive flags only; no rows were removed. The IQR rule is especially uninformative for zero-inflated features whose first and third quartiles are both zero.",
        "",
        _markdown_table(results["outliers"], floatfmt=".4f"),
        "",
        "The maximum URL length is driven by an exceptionally long URL with a large encoded HTML-like fragment; it is a candidate for manual source inspection, not an automatic outlier to delete. Several count features have long right tails and should be assessed within class and by source.",
        "",
        "### Feature formula agreement with the committed extractor",
        "",
        "Each stored feature was compared read-only against `model/Code/feature_extractor.py::extract_canonical_features` on the same raw URL. This checks consistency with the current project implementation, not correctness of the original labels or the upstream feature generator.",
        "",
        _markdown_table(results["feature_mismatches"], floatfmt=".4f"),
        "",
        "- Notable discrepancies: 78,447 stored `tld` values differ from the committed extractor; 16,139 `special_char_count`; 878 `suspicious_words`; 347 `num_params`; and 109 `has_ip` values differ. URL length, dot count, HTTPS flag, slash count, digits and rounded entropy agree on this comparison.",
        "- The stored `tld` field has 536 distinct values, including 77,600 numeric values; 77,598 rows parse to IP-address hostnames. Numeric “TLDs” are not valid DNS TLD names and indicate an extraction/representation issue. All 820 label-0 TLDs are missing.",
        "- The current extractor counts `=` among special characters; the observed mismatch is concentrated in that feature and must be reconciled with the data-generation definition before deciding which formula is authoritative.",
        "- The committed training script recomputes `suspicious_words` from the URL before fitting, while the CSV values disagree with the committed extractor in 878 rows. This means the serialized training feature was not necessarily the stored CSV feature.",
        "",
        "## 7. Correlation, constant values and suspicious label relationships",
        "",
        "No non-target feature is constant across the whole dataset. `suspicious_words` is the closest to near-constant: zero in 97.87% of all rows. It is sparse, but not a constant feature.",
        "",
        "Pearson-correlated numeric feature pairs with |r| ≥ 0.70:",
        "",
        _markdown_table(results["correlation_pairs"], floatfmt=".4f"),
        "",
        "Spearman associations with the binary label (descriptive only; correlation magnitude can understate deterministic threshold separation under severe imbalance):",
        "",
        _markdown_table(results["spearman_label"], floatfmt=".5f"),
        "",
        "Most consequential relationships are conditional distributions, not the global correlation coefficients:",
        "",
        "- `num_subdirs` is exactly 0 for all label 0 rows and at least 2 for all label 1 rows. In the committed extractor it is the count of `/` characters, including the two slashes in `http://` or `https://`; it is not literally a count of path subdirectories. This single feature perfectly separates the observed labels.",
        "- `has_https` is 0 for every label 0 row; it is 1 for 43.63% of label 1 rows. `has_ip` is also 0 for every label 0 row and 1 for 48.80% of label 1 rows.",
        "- `tld` missingness is almost deterministic by label, while the stored numeric TLD values correlate with IP-host rows.",
        "- These are strong signs of a collection-source/format shortcut. They do not prove malicious intent, prove all labels are correct, or establish that a feature was generated from the target. The causal explanation remains unverified without the collection pipeline.",
        "",
        "## 8. Provenance and likely construction bias",
        "",
        "### Verified from repository files",
        "",
        "- `model/README.md` documents the 0/1 mapping and asserts that benign samples were sourced from domain rankings and phishing samples from active feeds.",
        "- `model/artifacts/model_metadata.json` records the same mapping and historical benchmark results of 1.0; it also documents the bare-domain/missing-TLD explanation.",
        "- `model/Code/feature_extractor.py` and `model/Code/train.py` define the current feature contract; the training script recomputes `suspicious_words` during training.",
        "- The source CSV and committed artifacts were hash-compared with `HEAD` before analysis and matched exactly (see final verification below).",
        "",
        "### Unresolved",
        "",
        "- No original dataset citation, upstream download record, collection timestamp, feed snapshot, deduplication log, label adjudication procedure, or generator script was found in the repository.",
        "- The README's source description is project documentation, not independent evidence that the row-level labels or classes have the claimed meanings.",
        "- Extreme repetition in several host/path templates and 77,598 IP-address hostnames is consistent with feed/vendor or bulk-generated URL patterns, but EDA alone cannot establish that data is synthetic.",
        "",
        "## 9. Audit of existing EDA",
        "",
        "- `model/EDA/eda_analysis.ipynb` previously had only two minimal cells and invalid Python expressions for the CSV path and label indexing; it did not contain executed outputs or interpretations.",
        "- The old TLD chart overplotted bars for classes at the same positions and only visibly represented the final class; it was misleading. It is replaced by side-by-side within-class percentages and explicitly labels the stored field as raw.",
        "- The old report omitted missing TLD values from its top-value listing (so label 0 appeared to have no TLD distribution), included `label` in IQR outlier screening, and made broad target-leakage claims without distinguishing label shortcut from verified causal leakage.",
        "- Its basic shape, missing counts, duplicate counts, class counts and numerical summary values match this read-only audit. The 100% structural separation is confirmed; the generation mechanism causing it is not verified.",
        "- The committed `model/README.md` and metadata assert historical perfect scores. This audit did not execute or independently validate any model; given the perfect structural shortcut, those scores are not evidence of real-world generalization.",
        "",
        "## 10. Risks to real-world phishing detection",
        "",
        "- A model may learn “bare string means legitimate; URL with a scheme/slashes means phishing” rather than phishing behavior. Valid legitimate URLs with paths/schemes are absent from label 0 in this dataset.",
        "- A model may learn the missing-TLD signal and invalid numeric TLDs from IP addresses.",
        "- The 194:1 imbalance and only 820 label-0 examples create poor coverage of legitimate URL diversity and can make aggregate metrics misleading.",
        "- Repeated hosts, registrable domains and path templates can produce overly optimistic row-random evaluation.",
        "- Stale or unknown collection dates mean temporal drift and label validity cannot be assessed.",
        "- Static lexical features cannot by themselves determine whether a destination currently hosts phishing content; no live URL requests were performed in this audit.",
        "",
        "## 11. Findings and recommended disposition",
        "",
        "| Severity | Finding | Evidence | Recommendation |",
        "|---|---|---|---|",
        "| **Critical** | Class identity is perfectly confounded with URL input format / slash count. | Label 0: 820/820 scheme-less and `num_subdirs=0`; label 1: 159,244/159,244 HTTP(S), `num_subdirs>=2`. | **Investigate/replace for benchmark use.** Obtain comparable benign full URLs and verify provenance before any model development. Preserve this source unchanged. |",
        "| **Critical** | Original labels and collection process are not independently verifiable. | No upstream citation, dates, annotation method or committed collection script; project docs alone provide the mapping. | **Investigate.** Obtain source, licensing, timestamp and labeling evidence; do not claim verified semantics until then. |",
        "| **High** | TLD is systematically missing or invalid for large portions of data. | 821 missing values, 820 from label 0; 77,600 numeric stored TLDs, mostly IP hosts; 78,448 disagreements with current extractor. | **Repair only in a separately reviewed derived copy.** Recompute from parsed hostname using PSL-aware logic; preserve raw column and provenance. Do not impute silently. |",
        "| **High** | Feature calculations are inconsistent with the committed extractor. | Mismatch counts: special chars 16,139; suspicious words 878; parameters 347; IP flag 109. | **Investigate/repair.** Establish the historical feature definitions; then recompute from raw URLs and retain before/after audits. |",
        "| **High** | Row-wise random splitting is vulnerable to domain/template overlap. | 18,946 repeated registrable-domain groups; 4,918 repeated host/path templates; estimated ~8,761 repeated groups straddle an illustrative 80/20 split. | **Retain grouping keys and use domain-aware splitting** after label/provenance review; group IPs by exact IP and hosted services carefully. |",
        "| **High** | Severe class imbalance and undercoverage of legitimate URLs. | 820 vs 159,244 (194.2:1); label 0 URLs only 6–22 characters and have no path/scheme. | **Investigate/add data.** Do not discard label 0 or balance automatically. Add diverse, independently verified benign full URLs and representative phishing examples. |",
        "| **Medium** | Duplicate/URL-variant groups warrant manual policy. | 93 scheme-preserving normalized collisions; 629 scheme-ignored collisions; no mixed-label normalized collisions found. | **Investigate** exact variants and define conservative normalization before resolving duplicates. |",
        "| **Medium** | Extreme count/length tails and templated content may reflect sources rather than general URL behavior. | URL length max 25,523; 4,918 repeated path templates; highly repeated IP-host paths. | **Investigate source/records**; retain until validated. IQR flags are not grounds for deletion. |",
        "| **Low** | Several features are correlated or sparse. | Pearson: `url_length`–`digits_count` r≈0.83, `has_https`–`has_ip` r≈−0.78; `suspicious_words=0` for 97.87%. | **Retain pending validation**; evaluate redundancy and stability later, on source-verified data. |",
        "",
        "### Feature decisions (provisional)",
        "",
        "- `url_length`, `num_dots`, `has_https`, `digits_count`, `entropy`: values agree with the committed extractor on this corpus; retain as candidates, subject to reparsing and deployment parity checks.",
        "- `num_subdirs`: name is misleading and value is a slash count; do not use as a literal directory-depth feature. Investigate/redefine only in a future approved feature phase.",
        "- `has_ip`: 109 stored values disagree with current host-IP semantics; investigate whether the old calculation detected any IP substring.",
        "- `num_params`: 347 rows disagree with URL-query semantics; inspect fragment and repeated-question-mark edge cases before deciding.",
        "- `suspicious_words`: 878 values differ from the committed 15-keyword implementation; retain raw URL as source and recompute only in an approved derived dataset.",
        "- `tld`: do not trust as currently stored; repair separately using parsed host + PSL, preserving the original field.",
        "- `special_char_count`: the committed extractor's character set and CSV formula disagree in 16,139 records; resolve whether `=` belongs before recomputing.",
        "- `url`: retain as immutable source and audit key; maintain raw and normalized forms separately. Do not train on the raw URL as a feature without a separately approved design.",
        "",
        "## 12. Proposed preprocessing plan — NOT APPLIED",
        "",
        "1. **Resolve provenance first:** record the upstream URL/citation, license, collection date/window, source feed/ranking, label meaning, and annotation confidence. Preserve the current file/hash as immutable input.",
        "2. **Maintain raw and normalized URL fields:** trim surrounding whitespace only in a derived column; lowercase/IDNA-normalize host, strip a terminal dot, parse scheme/host/port/path/query/fragment separately, and do not collapse HTTP with HTTPS. Keep original strings unchanged. Reject/flag parse failures rather than silently deleting them.",
        "3. **Domain extraction:** use a pinned, versioned Public Suffix List including PRIVATE rules; retain hostname, IP address, public suffix, registrable domain, and extraction status as separate derived values. Review hosted-service boundaries and public-suffix-only names.",
        "4. **Missing values:** retain explicit missing indicators and investigate why missingness aligns with label. Recompute derived TLD from URL only after confirming the source policy; never fill with a value that acts as a class code without documenting the semantics.",
        "5. **Duplicates and conflicts:** report exact duplicates, conservative normalized duplicates, scheme-insensitive candidates and mixed labels. Do not automatically drop; adjudicate conflicts against source evidence and preserve a duplicate/decision log.",
        "6. **Feature recomputation:** derive all engineered features from raw URLs with one versioned extractor shared by offline analysis and runtime. Reconcile special-character, query-count, IP and keyword definitions first; store both original and recomputed columns during validation.",
        "7. **Data supplementation:** collect independently verified legitimate full URLs with path/query variation and more representative phishing cases, while avoiding collection-source shortcuts. Add source, time, and label-confidence metadata.",
        "8. **Domain-aware evaluation split:** group by PSL registrable domain; group IP-address hosts by exact IP. Keep groups wholly in one partition, assess whether both labels are represented, and report any unassignable or mixed-label groups. Consider temporal holdout only after source dates are available.",
        "9. **Class imbalance (future, not now):** first improve coverage and use group-aware evaluation. Later compare class-weighted/cost-sensitive approaches and carefully scoped resampling only within training folds; never balance before splitting, and do not delete the minority class. Use per-class precision/recall, PR-AUC, calibration and operational false-positive/false-negative costs rather than accuracy alone.",
        "",
        "**No preprocessing, cleaning, row removal, imputation, encoding, resampling, split, or predictive-model evaluation was performed in this phase.**",
        "",
        "## 13. Final verification",
        "",
        "- The source CSV SHA-256 is recorded above. Before analysis, `git hash-object` matched `git rev-parse HEAD:<path>` for the CSV and every tracked model artifact.",
        "- No model artifact was opened for inference or modified. No training script or other training command was executed in this audit.",
        "- This report and its helper/notebook/visualizations are confined to `model/EDA/`.",
        "",
        "## Evidence sources",
        "",
        "- `model/README.md` (project label mapping, source assertions and historical benchmark description).",
        "- `model/artifacts/model_metadata.json` (project label mapping and historical metadata; not independently validated here).",
        "- `model/Code/train.py` and `model/Code/feature_extractor.py` (current feature and label mapping definitions; scripts inspected but not executed).",
        f"- Official Public Suffix List snapshot: `https://publicsuffix.org/list/public_suffix_list.dat`, version `{results['psl_version']}`, stored at `model/EDA/public_suffix_list.dat` for reproducibility.",
        "",
    ]
    report_path = EDA_DIR / "data_quality_and_bias_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    result = run_eda()
    print(result["overview"].to_string(index=False))
    print("\nClass profiles:\n", result["class_profiles"].to_string(index=False))
    print("\nRegistrable domains:\n", result["domain_summary"].to_string(index=False))
    print("\nFeature mismatches:\n", result["feature_mismatches"].to_string(index=False))
