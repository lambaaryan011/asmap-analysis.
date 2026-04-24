"""
tests/test_insight.py
---------------------
Tests for insight.py: generate_insight(), historical_context(),
severity_explanation(), and the historical-average constants.

Run:
    pytest tests/test_insight.py -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import HISTORICAL_RUNS
from insight import (
    _AVG_COVERAGE_V4,
    _AVG_DIFF_PCT,
    _PAST_RUNS,
    generate_insight,
    historical_context,
    severity_explanation,
)
from utils import DiffResult, compare_maps

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_result(
    diff_pct: float = 0.0,
    severity_label: str = "Low",
    severity_score: float = 0.0,
    coverage_pct_v4: float = 0.0,
    top_asns: list | None = None,
    total_changes: int = 0,
) -> DiffResult:
    """Construct a minimal DiffResult for insight tests."""
    r = DiffResult()
    r.diff_percentage = diff_pct
    r.severity_label = severity_label
    r.severity_score = severity_score
    r.coverage_change_pct_v4 = coverage_pct_v4
    r.top_changed_asns = top_asns or []
    r.total_changes = total_changes
    return r


def _realistic_result(severity: str) -> DiffResult:
    """
    Build a result through compare_maps() so all fields are populated
    consistently — used for tests that need a fully coherent DiffResult.
    """
    if severity == "Low":
        base = {"1.0.0.0/24": "AS1"}
        cand = {"1.0.0.0/24": "AS1"}
    elif severity == "Moderate":
        base = {f"{i}.0.0.0/24": "AS1" for i in range(1, 101)}
        cand = dict(base)
        for i in range(10):
            cand[f"{i}.0.0.0/24"] = "AS2"  # 10% churn → Moderate
    elif severity == "Critical":
        base = {f"{i}.0.0.0/24": "AS1" for i in range(50)}
        cand = {f"{i}.0.0.0/24": "AS2" for i in range(50, 100)}
    else:
        base = {f"{i}.0.0.0/24": "AS1" for i in range(50)}
        cand = dict(base)
        for i in range(20):
            cand[f"{i}.0.0.0/24"] = "AS2"
    return compare_maps(base, cand)


# ══════════════════════════════════════════════════════════════════════════════
# Internal constants derived from config.HISTORICAL_RUNS
# ══════════════════════════════════════════════════════════════════════════════


class TestHistoricalAverages:
    def test_past_runs_excludes_first_run(self):
        assert len(_PAST_RUNS) == len(HISTORICAL_RUNS) - 1

    def test_avg_diff_pct_is_positive(self):
        assert _AVG_DIFF_PCT > 0.0

    def test_avg_diff_pct_matches_manual_calculation(self):
        expected = sum(r["diff_pct"] for r in HISTORICAL_RUNS[1:]) / len(HISTORICAL_RUNS[1:])
        assert abs(_AVG_DIFF_PCT - expected) < 1e-9

    def test_avg_coverage_v4_is_non_negative(self):
        assert _AVG_COVERAGE_V4 >= 0.0


# ══════════════════════════════════════════════════════════════════════════════
# generate_insight()
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateInsight:
    def test_returns_string(self):
        r = _realistic_result("Low")
        assert isinstance(generate_insight(r), str)

    def test_non_empty(self):
        r = _realistic_result("Low")
        assert len(generate_insight(r).strip()) > 0

    def test_low_severity_text_present(self):
        r = _make_result(severity_label="Low")
        text = generate_insight(r)
        assert "low" in text.lower() or "low-severity" in text.lower()

    def test_moderate_severity_text_present(self):
        r = _make_result(severity_label="Moderate", diff_pct=4.0)
        text = generate_insight(r)
        assert "moderate" in text.lower()

    def test_high_severity_text_present(self):
        r = _make_result(severity_label="High", diff_pct=6.0)
        text = generate_insight(r)
        assert "high" in text.lower() or "warrants" in text.lower()

    def test_critical_severity_escalation(self):
        r = _make_result(severity_label="Critical", diff_pct=30.0)
        text = generate_insight(r)
        assert "CRITICAL" in text or "block" in text.lower()

    def test_top_asn_mentioned_when_present(self):
        r = _make_result(
            severity_label="Moderate",
            diff_pct=4.0,
            total_changes=10,
            top_asns=[
                {
                    "asn": "AS13335",
                    "gained_pfx": 6,
                    "lost_pfx": 2,
                    "net_pfx": 4,
                    "gained_ips": 1000,
                    "lost_ips": 100,
                    "net_ips": 900,
                }
            ],
        )
        text = generate_insight(r)
        assert "AS13335" in text

    def test_top_asn_direction_gained(self):
        r = _make_result(
            severity_label="Low",
            diff_pct=1.0,
            total_changes=3,
            top_asns=[
                {
                    "asn": "AS999",
                    "gained_pfx": 3,
                    "lost_pfx": 0,
                    "net_pfx": 3,
                    "gained_ips": 768,
                    "lost_ips": 0,
                    "net_ips": 768,
                }
            ],
        )
        text = generate_insight(r)
        assert "gained" in text.lower()

    def test_top_asn_direction_lost(self):
        r = _make_result(
            severity_label="Low",
            diff_pct=1.0,
            total_changes=3,
            top_asns=[
                {
                    "asn": "AS999",
                    "gained_pfx": 0,
                    "lost_pfx": 3,
                    "net_pfx": -3,
                    "gained_ips": 0,
                    "lost_ips": 768,
                    "net_ips": -768,
                }
            ],
        )
        text = generate_insight(r)
        assert "lost" in text.lower()

    def test_recommendation_present_for_all_severities(self):
        for sev in ("Low", "Moderate", "High", "Critical"):
            r = _make_result(severity_label=sev)
            text = generate_insight(r)
            assert "recommendation" in text.lower(), (
                f"No recommendation sentence for severity={sev!r}"
            )

    def test_critical_recommendation_says_block(self):
        r = _make_result(severity_label="Critical", diff_pct=30.0)
        text = generate_insight(r)
        assert "block" in text.lower()

    def test_coverage_note_included_when_nonzero(self):
        r = _make_result(severity_label="Low", coverage_pct_v4=0.05)
        text = generate_insight(r)
        assert "0.0500" in text or "IPv4 coverage" in text

    def test_coverage_note_omitted_when_zero(self):
        r = _make_result(severity_label="Low", coverage_pct_v4=0.0)
        text = generate_insight(r)
        assert "0.0000%" not in text

    def test_historical_comparison_above_average(self):
        # diff_pct well above historical average (~4.08%) → "above" language
        r = _make_result(severity_label="High", diff_pct=15.0)
        text = generate_insight(r)
        assert "above" in text.lower()

    def test_historical_comparison_below_average(self):
        # diff_pct below historical average
        r = _make_result(severity_label="Low", diff_pct=0.5)
        text = generate_insight(r)
        assert "below" in text.lower() or "smaller" in text.lower()

    def test_no_crash_on_empty_top_asns(self):
        r = _make_result(severity_label="Low")
        # Must not raise
        text = generate_insight(r)
        assert isinstance(text, str)


# ══════════════════════════════════════════════════════════════════════════════
# historical_context()
# ══════════════════════════════════════════════════════════════════════════════


class TestHistoricalContext:
    def test_returns_list(self):
        r = _make_result()
        ctx = historical_context(r)
        assert isinstance(ctx, list)

    def test_length_is_historical_runs_plus_one(self):
        r = _make_result(diff_pct=4.0)
        ctx = historical_context(r)
        # One entry per HISTORICAL_RUNS row, plus the "current" run
        assert len(ctx) == len(HISTORICAL_RUNS) + 1

    def test_last_entry_is_current(self):
        r = _make_result(diff_pct=4.0)
        ctx = historical_context(r)
        assert ctx[-1]["date"] == "current"

    def test_current_entry_has_label(self):
        r = _make_result(diff_pct=4.0)
        ctx = historical_context(r)
        assert "← this run" in ctx[-1].get("label", "")

    def test_current_vs_current_is_zero(self):
        r = _make_result(diff_pct=4.0)
        ctx = historical_context(r)
        assert ctx[-1]["vs_current"] == 0.0

    def test_vs_current_arithmetic(self):
        r = _make_result(diff_pct=5.0)
        ctx = historical_context(r)
        for entry in ctx[:-1]:
            expected = round(5.0 - entry["diff_pct"], 2)
            assert abs(entry["vs_current"] - expected) < 1e-9

    def test_each_entry_has_required_keys(self):
        r = _make_result(diff_pct=3.0)
        ctx = historical_context(r)
        for entry in ctx:
            assert "date" in entry
            assert "diff_pct" in entry
            assert "vs_current" in entry

    def test_diff_pct_matches_config(self):
        r = _make_result(diff_pct=3.0)
        ctx = historical_context(r)
        for i, run in enumerate(HISTORICAL_RUNS):
            assert ctx[i]["diff_pct"] == run["diff_pct"]


# ══════════════════════════════════════════════════════════════════════════════
# severity_explanation()
# ══════════════════════════════════════════════════════════════════════════════


class TestSeverityExplanation:
    def test_returns_string(self):
        r = _realistic_result("Low")
        assert isinstance(severity_explanation(r), str)

    def test_contains_signal_1(self):
        r = _realistic_result("Low")
        text = severity_explanation(r)
        assert "Signal 1" in text

    def test_contains_signal_2(self):
        r = _realistic_result("Low")
        text = severity_explanation(r)
        assert "Signal 2" in text

    def test_contains_signal_3(self):
        r = _realistic_result("Low")
        text = severity_explanation(r)
        assert "Signal 3" in text

    def test_contains_total_score(self):
        r = _realistic_result("Low")
        text = severity_explanation(r)
        assert "Total score" in text

    def test_contains_severity_label(self):
        r = _realistic_result("Low")
        text = severity_explanation(r)
        assert r.severity_label in text

    def test_multiline_output(self):
        r = _realistic_result("Low")
        text = severity_explanation(r)
        assert "\n" in text

    def test_no_crash_on_zero_changes(self):
        r = _make_result()
        text = severity_explanation(r)
        assert isinstance(text, str)

    def test_score_value_appears_in_text(self):
        r = _realistic_result("Moderate")
        text = severity_explanation(r)
        # The numeric score should appear somewhere
        assert f"{r.severity_score:.4f}" in text
