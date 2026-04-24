"""
utils.py
--------
Core diff logic for comparing two ASmap prefix→ASN mappings.

ASmap text format (one line per prefix):
    1.0.0.0/24 AS13335
    2606:4700::/32 AS13335

Use asmap_decoder.py to load binary .asmap files,
or load text files directly with load_asmap().
"""

import ipaddress
import logging
from collections import Counter
from dataclasses import dataclass, field

from config import (
    SEVERITY_CAPS,
    SEVERITY_THRESHOLDS,
    SEVERITY_WEIGHTS,
    TOTAL_IPV4_ADDRESSES,
    TOTAL_IPV6_ADDRESSES,
)

log = logging.getLogger(__name__)


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class DiffResult:
    """Holds the complete output of compare_maps()."""

    added:           list[dict] = field(default_factory=list)
    removed:         list[dict] = field(default_factory=list)
    changed:         list[dict] = field(default_factory=list)
    unchanged:       int        = 0
    total_baseline:  int        = 0
    total_candidate: int        = 0

    # Prefix-count metrics
    total_changes:   int   = 0
    diff_percentage: float = 0.0

    # IP coverage metrics
    coverage_added_v4:      int   = 0
    coverage_removed_v4:    int   = 0
    coverage_changed_v4:    int   = 0
    coverage_added_v6:      int   = 0
    coverage_removed_v6:    int   = 0
    coverage_changed_v6:    int   = 0
    coverage_change_pct_v4: float = 0.0
    coverage_change_pct_v6: float = 0.0

    # Severity
    severity_score: float = 0.0
    severity_label: str   = "Low"

    # Top ASNs
    top_changed_asns: list[dict] = field(default_factory=list)


# ── File loading ──────────────────────────────────────────────────────────────

def load_asmap(file_path: str) -> dict[str, str]:
    """
    Load an ASmap text file into {prefix: asn}.

    Each line must be:  <prefix> <ASN>
    e.g.  1.0.0.0/24 AS13335

    Blank lines and lines starting with # are skipped.
    Lines with unexpected format are logged as warnings and skipped.

    Returns:
        dict mapping prefix strings to ASN strings.

    Raises:
        FileNotFoundError: if file_path does not exist.
        ValueError:        if no valid entries were loaded.
    """
    mapping: dict[str, str] = {}
    skipped = 0

    with open(file_path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                log.warning("line %d skipped (expected 'prefix ASN', got %r)", line_num, line)
                skipped += 1
                continue
            prefix, asn = parts
            mapping[prefix] = asn

    log.info("loaded %d prefixes from %s (%d lines skipped)", len(mapping), file_path, skipped)
    if not mapping:
        raise ValueError(f"No valid prefix entries found in {file_path!r}")
    return mapping


# ── IP coverage helpers ───────────────────────────────────────────────────────

def prefix_size(prefix: str) -> tuple[int, int]:
    """
    Return (ipv4_address_count, ipv6_address_count) for a prefix string.

    Uses the ipaddress module — handles CIDR correctly without estimation.
    One of the two values is always 0 depending on IP version.

    Example:
        prefix_size("1.0.0.0/24") -> (256, 0)
        prefix_size("2606::/32")  -> (0, 79228162514264337593543950336)
    """
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        size = net.num_addresses
        if net.version == 4:
            return size, 0
        return 0, size
    except ValueError:
        log.debug("could not parse prefix %r — skipping coverage count", prefix)
        return 0, 0


# ── Core comparison ───────────────────────────────────────────────────────────

def compare_maps(
    baseline:  dict[str, str],
    candidate: dict[str, str],
) -> DiffResult:
    """
    Compare two ASmap dicts and return a full DiffResult.

    Uses O(n) dict lookups — no nested loops.
    Computes:
      - Added / removed / changed / unchanged prefix counts
      - Real IP address coverage metrics (using ipaddress module)
      - Weighted severity score
      - Top changed ASNs ranked by IP space moved

    Args:
        baseline:  {prefix: asn} for the older collaborative run.
        candidate: {prefix: asn} for the new Kartograf run.

    Returns:
        DiffResult with all metrics populated.
    """
    result = DiffResult(
        total_baseline=len(baseline),
        total_candidate=len(candidate),
    )

    all_prefixes: set[str] = set(baseline.keys()) | set(candidate.keys())
    log.info("comparing %d baseline vs %d candidate prefixes (%d unique)",
             len(baseline), len(candidate), len(all_prefixes))

    for prefix in all_prefixes:
        b_asn: str | None = baseline.get(prefix)
        c_asn: str | None = candidate.get(prefix)
        v4, v6 = prefix_size(prefix)

        if b_asn is None:
            # New prefix in candidate
            result.added.append({"prefix": prefix, "asn": c_asn})
            result.coverage_added_v4 += v4
            result.coverage_added_v6 += v6

        elif c_asn is None:
            # Prefix removed in candidate
            result.removed.append({"prefix": prefix, "asn": b_asn})
            result.coverage_removed_v4 += v4
            result.coverage_removed_v6 += v6

        elif b_asn != c_asn:
            # Same prefix, different ASN assignment
            result.changed.append({
                "prefix":   prefix,
                "old_asn":  b_asn,
                "new_asn":  c_asn,
                "ip_count": v4 + v6,
            })
            result.coverage_changed_v4 += v4
            result.coverage_changed_v6 += v6

        else:
            result.unchanged += 1

    # Prefix-count diff %
    result.total_changes   = len(result.added) + len(result.removed) + len(result.changed)
    result.diff_percentage = round(
        result.total_changes / max(result.total_baseline, 1) * 100, 2
    )

    # IP coverage change % vs total routable space
    total_v4 = (result.coverage_added_v4
                + result.coverage_removed_v4
                + result.coverage_changed_v4)
    total_v6 = (result.coverage_added_v6
                + result.coverage_removed_v6
                + result.coverage_changed_v6)
    result.coverage_change_pct_v4 = round(total_v4 / TOTAL_IPV4_ADDRESSES * 100, 6)
    result.coverage_change_pct_v6 = round(total_v6 / TOTAL_IPV6_ADDRESSES * 100, 6)

    result.top_changed_asns = _top_changed_asns(result)
    result.severity_score, result.severity_label = _compute_severity(result)

    log.info("diff complete: +%d added, -%d removed, ~%d changed, score=%.4f (%s)",
             len(result.added), len(result.removed), len(result.changed),
             result.severity_score, result.severity_label)
    return result


# ── Top ASNs ──────────────────────────────────────────────────────────────────

def _top_changed_asns(result: DiffResult, top_n: int = 10) -> list[dict]:
    """
    Rank ASNs by net IP address space gained or lost.

    Ranking by IP space is more meaningful than by prefix count:
    one /8 = 16,777,216 addresses vs one /24 = 256 addresses.

    Returns:
        List of dicts sorted by abs(net_ips), length = min(top_n, unique_asns).
    """
    gained_ips: Counter = Counter()
    lost_ips:   Counter = Counter()
    gained_pfx: Counter = Counter()
    lost_pfx:   Counter = Counter()

    for e in result.added:
        v4, v6 = prefix_size(e["prefix"])
        gained_ips[e["asn"]] += v4 + v6
        gained_pfx[e["asn"]] += 1

    for e in result.removed:
        v4, v6 = prefix_size(e["prefix"])
        lost_ips[e["asn"]] += v4 + v6
        lost_pfx[e["asn"]] += 1

    for e in result.changed:
        v4, v6 = prefix_size(e["prefix"])
        gained_ips[e["new_asn"]] += v4 + v6
        gained_pfx[e["new_asn"]] += 1
        lost_ips[e["old_asn"]]   += v4 + v6
        lost_pfx[e["old_asn"]]   += 1

    all_asns: set[str] = set(gained_ips) | set(lost_ips)
    rows: list[dict] = [
        {
            "asn":        asn,
            "gained_pfx": gained_pfx[asn],
            "lost_pfx":   lost_pfx[asn],
            "net_pfx":    gained_pfx[asn] - lost_pfx[asn],
            "gained_ips": gained_ips[asn],
            "lost_ips":   lost_ips[asn],
            "net_ips":    gained_ips[asn] - lost_ips[asn],
        }
        for asn in all_asns
    ]
    rows.sort(key=lambda x: abs(x["net_ips"]), reverse=True)
    return rows[:top_n]


# ── Severity Score ────────────────────────────────────────────────────────────

def _compute_severity(result: DiffResult) -> tuple[float, str]:
    """
    Compute a weighted Diff Severity Score in [0, 1].

    Three signals — weights and caps come from config.py:

      Signal 1 — IPv4 coverage change  (weight: SEVERITY_WEIGHTS["coverage"])
        How much of the routable IPv4 space changed ASN assignment.
        Normalised: 0% → 0.0, ≥ SEVERITY_CAPS["coverage"]% → 1.0

      Signal 2 — Prefix churn ratio    (weight: SEVERITY_WEIGHTS["churn"])
        What fraction of prefixes changed.
        Normalised: 0% → 0.0, ≥ SEVERITY_CAPS["churn"]% → 1.0

      Signal 3 — ASN concentration     (weight: SEVERITY_WEIGHTS["concentration"])
        Share of all changes belonging to the single most-changed ASN.
        High concentration may indicate a data source issue.
        Already normalised to [0, 1].

    Thresholds from SEVERITY_THRESHOLDS in config.py:
      < 0.20 → Low
      < 0.45 → Moderate
      < 0.70 → High
      else   → Critical
    """
    sig_coverage = min(
        result.coverage_change_pct_v4 / SEVERITY_CAPS["coverage"], 1.0
    )
    sig_churn = min(
        result.diff_percentage / SEVERITY_CAPS["churn"], 1.0
    )
    if result.top_changed_asns and result.total_changes > 0:
        top      = result.top_changed_asns[0]
        top_pfx  = top["gained_pfx"] + top["lost_pfx"]
        sig_conc = min(top_pfx / result.total_changes, 1.0)
    else:
        sig_conc = 0.0

    score = round(
        sig_coverage * SEVERITY_WEIGHTS["coverage"]      +
        sig_churn    * SEVERITY_WEIGHTS["churn"]          +
        sig_conc     * SEVERITY_WEIGHTS["concentration"],
        4,
    )

    label = "Critical"
    for threshold, lbl in SEVERITY_THRESHOLDS:
        if score < threshold:
            label = lbl
            break

    log.debug("severity signals: coverage=%.4f churn=%.4f conc=%.4f → score=%.4f (%s)",
              sig_coverage, sig_churn, sig_conc, score, label)
    return score, label
