"""
insight.py
----------
Generates human-readable insights from a DiffResult.

This is the interpretation layer — it tells reviewers WHERE to look
and WHAT the numbers mean, not just the raw values.
"""

import logging

from config import HISTORICAL_RUNS, SEVERITY_CAPS, SEVERITY_WEIGHTS
from utils import DiffResult

log = logging.getLogger(__name__)

# Pre-compute historical averages (skip the baseline run at index 0)
_PAST_RUNS = HISTORICAL_RUNS[1:]
_AVG_DIFF_PCT = sum(r["diff_pct"] for r in _PAST_RUNS) / len(_PAST_RUNS)
_AVG_COVERAGE_V4 = sum(r["coverage_v4"] for r in _PAST_RUNS) / len(_PAST_RUNS)


def generate_insight(r: DiffResult) -> str:
    """
    Return a plain-English paragraph interpreting the diff result.

    Covers: overall severity, top mover, historical comparison,
    coverage note, and a concrete recommendation.

    Args:
        r: populated DiffResult from compare_maps().

    Returns:
        A multi-sentence string suitable for terminal output,
        JSON export, and Markdown PR comments.
    """
    sentences: list[str] = []

    # 1. Overall severity assessment
    assessments = {
        "Low": (
            "This is a low-severity diff — well within the expected "
            "range of BGP drift between collaborative runs."
        ),
        "Moderate": (
            "This is a moderate diff, consistent with a normal update "
            "cycle. The top ASN changes are worth a quick review."
        ),
        "High": (
            "This diff is higher than typical between runs. "
            "This warrants investigation before merging into asmap-data."
        ),
        "Critical": (
            "CRITICAL: This diff is far outside the normal range. "
            "This likely indicates a data source issue, RPKI filter mismatch, "
            "or a significant BGP routing event. Do not merge without investigation."
        ),
    }
    sentences.append(assessments.get(r.severity_label, assessments["Moderate"]))

    # 2. Top mover
    if r.top_changed_asns:
        top = r.top_changed_asns[0]
        direction = "gained" if top["net_pfx"] >= 0 else "lost"
        count = abs(top["net_pfx"])
        sentences.append(
            f"Most changes are concentrated in {top['asn']}, which {direction} "
            f"{count} prefix assignment{'s' if count != 1 else ''}. "
            "This may reflect an anycast expansion, BGP route leak, or data source update."
        )

    # 3. Historical comparison
    deviation = r.diff_percentage - _AVG_DIFF_PCT
    if abs(deviation) < 1.0:
        sentences.append(
            f"The diff percentage ({r.diff_percentage:.2f}%) is close to the "
            f"historical average of {_AVG_DIFF_PCT:.2f}% across recent collaborative runs."
        )
    elif deviation > 0:
        sentences.append(
            f"The diff percentage ({r.diff_percentage:.2f}%) is "
            f"{deviation:.2f}pp above the historical average of {_AVG_DIFF_PCT:.2f}%."
        )
    else:
        sentences.append(
            f"The diff percentage ({r.diff_percentage:.2f}%) is "
            f"{abs(deviation):.2f}pp below the historical average of {_AVG_DIFF_PCT:.2f}% "
            "— a smaller change than typical."
        )

    # 4. Coverage note
    if r.coverage_change_pct_v4 > 0:
        sentences.append(
            f"IPv4 coverage change: {r.coverage_change_pct_v4:.4f}% of the "
            "routable address space shifted ASN assignment."
        )

    # 5. Recommendation
    recommendations = {
        "Low": "Recommendation: safe to proceed with standard review.",
        "Moderate": (
            "Recommendation: safe to proceed. Cross-check the top ASN changes against RPKI data."
        ),
        "High": (
            "Recommendation: review the top 3 ASN changes manually "
            "before merging. Cross-check against RPKI data and BGP looking glasses."
        ),
        "Critical": (
            "Recommendation: block merge. Investigate data sources, "
            "RPKI filter flags, and re-run Kartograf with --verbose to identify root cause."
        ),
    }
    sentences.append(recommendations.get(r.severity_label, recommendations["Moderate"]))

    log.debug("insight generated for severity=%s", r.severity_label)
    return " ".join(sentences)


def historical_context(r: DiffResult) -> list[dict]:
    """
    Return historical runs annotated with deviation from the current diff.

    Args:
        r: populated DiffResult.

    Returns:
        List of dicts — one per historical run plus the current run.
        Each dict has keys: date, diff_pct, vs_current, label (optional).
    """
    context: list[dict] = []
    for run in HISTORICAL_RUNS:
        context.append(
            {
                "date": run["date"],
                "diff_pct": run["diff_pct"],
                "vs_current": round(r.diff_percentage - run["diff_pct"], 2),
            }
        )
    context.append(
        {
            "date": "current",
            "diff_pct": r.diff_percentage,
            "vs_current": 0.0,
            "label": "← this run",
        }
    )
    return context


def severity_explanation(r: DiffResult) -> str:
    """
    Return a traceable breakdown of the severity score calculation.

    Shows each signal value, its normalisation, its weight (from config),
    and the weighted contribution — so reviewers can verify the logic.

    Args:
        r: populated DiffResult.

    Returns:
        Multi-line string showing the full score calculation.
    """
    # Recompute signals to show the steps (mirrors _compute_severity in utils.py)
    sig1 = min(r.coverage_change_pct_v4 / SEVERITY_CAPS["coverage"], 1.0)
    sig2 = min(r.diff_percentage / SEVERITY_CAPS["churn"], 1.0)

    if r.top_changed_asns and r.total_changes > 0:
        top = r.top_changed_asns[0]
        sig3 = min((top["gained_pfx"] + top["lost_pfx"]) / r.total_changes, 1.0)
    else:
        sig3 = 0.0

    w1 = SEVERITY_WEIGHTS["coverage"]
    w2 = SEVERITY_WEIGHTS["churn"]
    w3 = SEVERITY_WEIGHTS["concentration"]

    lines = [
        "Severity score calculation:",
        f"  Signal 1 — IPv4 coverage change : {r.coverage_change_pct_v4:.4f}% "
        f"÷ {SEVERITY_CAPS['coverage']}% cap = {sig1:.4f}  ×  {w1} = {sig1 * w1:.4f}",
        f"  Signal 2 — Prefix churn ratio   : {r.diff_percentage:.2f}% "
        f"÷ {SEVERITY_CAPS['churn']}% cap = {sig2:.4f}  ×  {w2} = {sig2 * w2:.4f}",
        f"  Signal 3 — ASN concentration    : (normalised: {sig3:.4f})  ×  {w3} = {sig3 * w3:.4f}",
        f"  {'─' * 45}",
        f"  Total score : {r.severity_score:.4f}   →   {r.severity_label}",
    ]
    return "\n".join(lines)
