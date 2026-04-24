"""
config.py
---------
Central configuration for the ASmap Diff Analyzer.
All magic numbers live here — never scattered across files.
"""

# ── Severity score weights ────────────────────────────────────────────────────
# Three signals combined into one score. Weights must sum to 1.0.
SEVERITY_WEIGHTS = {
    "coverage": 0.50,  # IPv4 address space affected (most important)
    "churn": 0.30,  # fraction of prefixes that changed
    "concentration": 0.20,  # how concentrated changes are in one ASN
}

# Normalisation caps — signal value at or above cap = score of 1.0
SEVERITY_CAPS = {
    "coverage": 10.0,  # 10% of IPv4 space changed → max signal
    "churn": 20.0,  # 20% of prefixes changed   → max signal
}

# Score thresholds → label
SEVERITY_THRESHOLDS = [
    (0.20, "Low"),
    (0.45, "Moderate"),
    (0.70, "High"),
    (1.01, "Critical"),
]

# ── Historical reference (from asmap-data collaborative runs) ─────────────────
HISTORICAL_RUNS = [
    {"date": "2024-04-05", "total_prefixes": 53232, "diff_pct": 0.0, "coverage_v4": 0.000},
    {"date": "2024-06-21", "total_prefixes": 58144, "diff_pct": 3.1, "coverage_v4": 0.031},
    {"date": "2024-09-03", "total_prefixes": 64891, "diff_pct": 3.8, "coverage_v4": 0.038},
    {"date": "2024-11-14", "total_prefixes": 70817, "diff_pct": 4.2, "coverage_v4": 0.042},
    {"date": "2025-01-08", "total_prefixes": 76602, "diff_pct": 5.1, "coverage_v4": 0.051},
    {"date": "2025-03-12", "total_prefixes": 84219, "diff_pct": 4.2, "coverage_v4": 0.042},
]

# ── IP address space totals ───────────────────────────────────────────────────
TOTAL_IPV4_ADDRESSES = 2**32  # 4,294,967,296
TOTAL_IPV6_ADDRESSES = 2**128

# ── Output defaults ───────────────────────────────────────────────────────────
DEFAULT_TOP_ASNS = 5
DEFAULT_JSON_PATH = "output.json"
DEFAULT_CSV_PATH = "output.csv"
DEFAULT_MD_PATH = "report.md"
SAMPLE_CHANGE_LIMIT = 20  # how many sample entries to include in JSON/MD

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
LOG_DATE = "%H:%M:%S"
