"""
tests/test_utils.py
-------------------
Tests for utils.py: load_asmap(), compare_maps(), prefix_size(),
coverage arithmetic, severity scoring, and top-ASN ranking.

Run:
    pytest tests/test_utils.py -v
"""

import os
import sys

import pytest

# Allow imports from the project root (where utils.py lives)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils import DiffResult, compare_maps, load_asmap, prefix_size

# ══════════════════════════════════════════════════════════════════════════════
# load_asmap()
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadAsmap:
    def test_loads_valid_file(self, single_prefix):
        m = load_asmap(single_prefix)
        assert m == {"1.0.0.0/24": "AS13335"}

    def test_loads_two_prefixes(self, two_prefixes):
        m = load_asmap(two_prefixes)
        assert len(m) == 2
        assert m["1.0.0.0/24"] == "AS13335"
        assert m["2.0.0.0/24"] == "AS15169"

    def test_skips_comments_and_blanks(self, map_with_comments_and_blanks):
        m = load_asmap(map_with_comments_and_blanks)
        # Only "1.0.0.0/24 AS13335" and "2.0.0.0/24 AS15169" are valid
        assert len(m) == 2
        assert "1.0.0.0/24" in m
        assert "2.0.0.0/24" in m

    def test_malformed_lines_are_skipped(self, map_with_comments_and_blanks):
        m = load_asmap(map_with_comments_and_blanks)
        # "bad line here" must NOT appear as a key
        assert "bad line here" not in m

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_asmap("/tmp/does_not_exist_asmap_12345.txt")

    def test_raises_on_empty_file(self, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="No valid prefix"):
            load_asmap(str(empty))

    def test_ipv6_prefixes_loaded(self, ipv6_map):
        m = load_asmap(ipv6_map)
        assert "2606:4700::/32" in m
        assert "2001:db8::/48" in m

    def test_returns_dict(self, single_prefix):
        m = load_asmap(single_prefix)
        assert isinstance(m, dict)

    def test_asn_values_are_strings(self, two_prefixes):
        m = load_asmap(two_prefixes)
        for v in m.values():
            assert isinstance(v, str)


# ══════════════════════════════════════════════════════════════════════════════
# prefix_size()
# ══════════════════════════════════════════════════════════════════════════════


class TestPrefixSize:
    def test_slash_24_is_256_v4(self):
        v4, v6 = prefix_size("1.0.0.0/24")
        assert v4 == 256
        assert v6 == 0

    def test_slash_16_is_65536_v4(self):
        v4, v6 = prefix_size("10.0.0.0/16")
        assert v4 == 65536
        assert v6 == 0

    def test_slash_8_is_16M_v4(self):
        v4, v6 = prefix_size("1.0.0.0/8")
        assert v4 == 16_777_216
        assert v6 == 0

    def test_ipv6_prefix_returns_zero_v4(self):
        v4, v6 = prefix_size("2606:4700::/32")
        assert v4 == 0
        assert v6 > 0

    def test_ipv6_slash_32(self):
        v4, v6 = prefix_size("2001:db8::/32")
        # 2^(128-32) = 2^96
        assert v6 == 2**96

    def test_invalid_prefix_returns_zeros(self):
        v4, v6 = prefix_size("not-a-prefix")
        assert v4 == 0
        assert v6 == 0

    def test_slash_32_is_one_address(self):
        v4, v6 = prefix_size("192.168.1.1/32")
        assert v4 == 1

    def test_host_bit_set_is_tolerated(self):
        # strict=False: 192.168.1.1/24 → 192.168.1.0/24 → 256 addresses
        v4, v6 = prefix_size("192.168.1.1/24")
        assert v4 == 256


# ══════════════════════════════════════════════════════════════════════════════
# compare_maps() — prefix-count metrics
# ══════════════════════════════════════════════════════════════════════════════


class TestCompareMapsBasic:
    def test_added_prefix(self, tmp_path):
        base = {"1.0.0.0/24": "AS13335"}
        cand = {"1.0.0.0/24": "AS13335", "2.0.0.0/24": "AS15169"}
        r = compare_maps(base, cand)
        assert len(r.added) == 1
        assert len(r.removed) == 0
        assert len(r.changed) == 0
        assert r.unchanged == 1

    def test_removed_prefix(self, tmp_path):
        base = {"1.0.0.0/24": "AS13335", "2.0.0.0/24": "AS15169"}
        cand = {"1.0.0.0/24": "AS13335"}
        r = compare_maps(base, cand)
        assert len(r.removed) == 1
        assert len(r.added) == 0
        assert len(r.changed) == 0
        assert r.unchanged == 1

    def test_changed_asn(self):
        base = {"1.0.0.0/24": "AS13335"}
        cand = {"1.0.0.0/24": "AS15169"}
        r = compare_maps(base, cand)
        assert len(r.changed) == 1
        assert r.changed[0]["old_asn"] == "AS13335"
        assert r.changed[0]["new_asn"] == "AS15169"
        assert r.changed[0]["prefix"] == "1.0.0.0/24"

    def test_unchanged_prefix(self):
        base = {"1.0.0.0/24": "AS13335"}
        cand = {"1.0.0.0/24": "AS13335"}
        r = compare_maps(base, cand)
        assert r.unchanged == 1
        assert r.total_changes == 0

    def test_identical_maps(self, identical_maps):
        base_path, cand_path = identical_maps
        r = compare_maps(load_asmap(base_path), load_asmap(cand_path))
        assert r.total_changes == 0
        assert r.diff_percentage == 0.0

    def test_returns_diff_result(self):
        r = compare_maps({"1.0.0.0/24": "AS1"}, {"2.0.0.0/24": "AS2"})
        assert isinstance(r, DiffResult)

    def test_total_baseline_and_candidate_counts(self):
        base = {f"{i}.0.0.0/24": "AS1" for i in range(10)}
        cand = {f"{i}.0.0.0/24": "AS1" for i in range(12)}
        r = compare_maps(base, cand)
        assert r.total_baseline == 10
        assert r.total_candidate == 12

    def test_added_dict_has_prefix_and_asn_keys(self):
        r = compare_maps({}, {"1.0.0.0/24": "AS13335"})
        assert len(r.added) == 1
        assert "prefix" in r.added[0]
        assert "asn" in r.added[0]

    def test_changed_dict_has_required_keys(self):
        r = compare_maps({"1.0.0.0/24": "AS1"}, {"1.0.0.0/24": "AS2"})
        e = r.changed[0]
        assert "prefix" in e
        assert "old_asn" in e
        assert "new_asn" in e
        assert "ip_count" in e

    def test_multiple_changes_counted_correctly(self):
        base = {"1.0.0.0/24": "AS1", "2.0.0.0/24": "AS2", "3.0.0.0/24": "AS3"}
        cand = {"1.0.0.0/24": "AS1", "2.0.0.0/24": "AS9", "4.0.0.0/24": "AS4"}
        r = compare_maps(base, cand)
        assert len(r.added) == 1  # 4.0.0.0/24
        assert len(r.removed) == 1  # 3.0.0.0/24
        assert len(r.changed) == 1  # 2.0.0.0/24
        assert r.unchanged == 1  # 1.0.0.0/24


# ══════════════════════════════════════════════════════════════════════════════
# compare_maps() — diff_percentage
# ══════════════════════════════════════════════════════════════════════════════


class TestDiffPercentage:
    def test_twenty_percent_churn(self, hundred_prefix_pair):
        base_path, cand_path = hundred_prefix_pair
        base = load_asmap(base_path)
        cand = load_asmap(cand_path)
        r = compare_maps(base, cand)
        assert r.diff_percentage == 20.0

    def test_zero_percent_on_identical(self, identical_maps):
        b, c = identical_maps
        r = compare_maps(load_asmap(b), load_asmap(c))
        assert r.diff_percentage == 0.0

    def test_total_changes_matches_sum(self):
        base = {"1.0.0.0/24": "AS1", "2.0.0.0/24": "AS2"}
        cand = {"1.0.0.0/24": "AS9", "3.0.0.0/24": "AS3"}
        r = compare_maps(base, cand)
        expected = len(r.added) + len(r.removed) + len(r.changed)
        assert r.total_changes == expected

    def test_diff_percentage_is_float(self):
        base = {"1.0.0.0/24": "AS1"}
        cand = {"2.0.0.0/24": "AS2"}
        r = compare_maps(base, cand)
        assert isinstance(r.diff_percentage, float)


# ══════════════════════════════════════════════════════════════════════════════
# compare_maps() — IP coverage metrics
# ══════════════════════════════════════════════════════════════════════════════


class TestCoverageMetrics:
    def test_added_coverage_v4_nonzero(self):
        r = compare_maps({}, {"1.0.0.0/24": "AS13335"})
        assert r.coverage_added_v4 == 256

    def test_removed_coverage_v4_nonzero(self):
        r = compare_maps({"1.0.0.0/24": "AS13335"}, {})
        assert r.coverage_removed_v4 == 256

    def test_changed_coverage_v4(self):
        r = compare_maps({"1.0.0.0/24": "AS1"}, {"1.0.0.0/24": "AS2"})
        assert r.coverage_changed_v4 == 256

    def test_large_prefix_dominates(self):
        # /16 (65 536) vs /24 (256): /16 should dominate total
        base = {"10.0.0.0/16": "AS1"}
        cand = {"10.0.0.0/24": "AS1", "11.0.0.0/24": "AS2"}
        r = compare_maps(base, cand)
        # /16 was removed (65 536 addresses), two /24s involved (512 total)
        assert r.coverage_removed_v4 == 65536

    def test_coverage_pct_v4_is_float(self):
        r = compare_maps({"1.0.0.0/24": "AS1"}, {})
        assert isinstance(r.coverage_change_pct_v4, float)

    def test_coverage_pct_v4_range(self):
        r = compare_maps({"1.0.0.0/24": "AS1"}, {})
        # 256 / 2^32 * 100 ≈ 0.000006% — tiny but > 0
        assert 0.0 < r.coverage_change_pct_v4 < 1.0

    def test_ipv6_coverage_separate_from_v4(self):
        # Use a /1 so the percentage survives rounding to 6 decimal places.
        # A /32 only covers 2^-32 of the IPv6 space (~2.3e-10%) which rounds to 0.0.
        base = {"2000::/1": "AS13335"}
        cand = {}
        r = compare_maps(base, cand)
        assert r.coverage_removed_v6 > 0
        assert r.coverage_removed_v4 == 0
        assert r.coverage_change_pct_v6 > 0.0

    def test_identical_maps_zero_coverage(self, identical_maps):
        b, c = identical_maps
        r = compare_maps(load_asmap(b), load_asmap(c))
        assert r.coverage_change_pct_v4 == 0.0
        assert r.coverage_change_pct_v6 == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# compare_maps() — severity score
# ══════════════════════════════════════════════════════════════════════════════


class TestSeverityScore:
    def test_identical_maps_score_low(self, identical_maps):
        b, c = identical_maps
        r = compare_maps(load_asmap(b), load_asmap(c))
        assert r.severity_label == "Low"
        assert r.severity_score == 0.0

    def test_score_in_unit_interval(self):
        base = {f"{i}.0.0.0/24": "AS1" for i in range(1, 51)}
        cand = {f"{i}.0.0.0/24": "AS2" for i in range(1, 51)}
        r = compare_maps(base, cand)
        assert 0.0 <= r.severity_score <= 1.0

    def test_score_is_float(self):
        r = compare_maps({"1.0.0.0/24": "AS1"}, {"1.0.0.0/24": "AS2"})
        assert isinstance(r.severity_score, float)

    def test_label_is_one_of_four_tiers(self):
        valid = {"Low", "Moderate", "High", "Critical"}
        for base, cand in [
            ({"1.0.0.0/24": "AS1"}, {"1.0.0.0/24": "AS1"}),
            ({"1.0.0.0/24": "AS1"}, {"1.0.0.0/24": "AS2"}),
        ]:
            r = compare_maps(base, cand)
            assert r.severity_label in valid

    def test_high_churn_produces_nontrivial_score(self, high_churn_maps):
        b, c = high_churn_maps
        r = compare_maps(load_asmap(b), load_asmap(c))
        # 50 removed + 50 added out of 50-prefix baseline → 200% churn, capped
        assert r.severity_score > 0.2

    def test_single_asn_concentration_increases_score(self):
        # All changes in one ASN → max concentration signal
        base = {f"{i}.0.0.0/24": "AS1" for i in range(1, 11)}
        cand = {f"{i}.0.0.0/24": "AS2" for i in range(1, 11)}
        r = compare_maps(base, cand)
        # concentration signal = 1.0, contributing 0.2 to total
        assert r.severity_score >= 0.2

    def test_severity_monotonically_worse_with_churn(self):
        """More churn → higher score."""
        scores = []
        for n_changed in [0, 5, 20, 50]:
            base = {f"{i}.0.0.0/24": "AS1" for i in range(100)}
            cand = dict(base)
            for i in range(n_changed):
                cand[f"{i}.0.0.0/24"] = "AS2"
            r = compare_maps(base, cand)
            scores.append(r.severity_score)
        assert scores == sorted(scores), f"scores not monotone: {scores}"


# ══════════════════════════════════════════════════════════════════════════════
# compare_maps() — top_changed_asns ranking
# ══════════════════════════════════════════════════════════════════════════════


class TestTopChangedAsns:
    def test_top_asns_returned(self):
        base = {"1.0.0.0/16": "AS1", "2.0.0.0/24": "AS2"}
        cand = {"3.0.0.0/16": "AS1", "2.0.0.0/24": "AS2"}
        r = compare_maps(base, cand)
        assert len(r.top_changed_asns) >= 1

    def test_top_asns_sorted_by_net_ips_desc(self):
        # AS1 gains a /16 (65536), AS2 gains a /24 (256) — AS1 must rank first
        base = {}
        cand = {"10.0.0.0/16": "AS1", "20.0.0.0/24": "AS2"}
        r = compare_maps(base, cand)
        asns = [a["asn"] for a in r.top_changed_asns]
        assert asns[0] == "AS1", f"AS1 (/16) should rank first, got {asns}"

    def test_top_asn_dict_has_required_keys(self):
        r = compare_maps({}, {"1.0.0.0/24": "AS13335"})
        required = {"asn", "gained_pfx", "lost_pfx", "net_pfx", "gained_ips", "lost_ips", "net_ips"}
        assert required.issubset(set(r.top_changed_asns[0].keys()))

    def test_net_pfx_is_gained_minus_lost(self):
        # AS1 gains 2 prefixes, loses 1 → net_pfx = 1
        base = {"1.0.0.0/24": "AS1"}
        cand = {"2.0.0.0/24": "AS1", "3.0.0.0/24": "AS1"}
        r = compare_maps(base, cand)
        row = next(a for a in r.top_changed_asns if a["asn"] == "AS1")
        assert row["net_pfx"] == row["gained_pfx"] - row["lost_pfx"]

    def test_no_top_asns_on_identical_maps(self, identical_maps):
        b, c = identical_maps
        r = compare_maps(load_asmap(b), load_asmap(c))
        # Either empty or all entries have net_ips == 0
        for a in r.top_changed_asns:
            assert a["net_ips"] == 0

    def test_ip_ranking_beats_prefix_count_ranking(self):
        """
        One AS gets 1 /8 (16M addresses), another gets 100 /24s (25.6K).
        IP-space ranking must put the /8 AS first.
        """
        base = {}
        cand = {
            "100.0.0.0/8": "AS_BIG",  # 1 prefix, 16 777 216 addresses
            **{
                f"200.{i}.0.0/24": "AS_MANY"  # 100 prefixes, 25 600 addresses
                for i in range(100)
            },
        }
        r = compare_maps(base, cand)
        assert r.top_changed_asns[0]["asn"] == "AS_BIG"
