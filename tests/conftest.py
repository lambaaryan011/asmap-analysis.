"""
conftest.py
-----------
Shared pytest fixtures for the ASmap Data Analysis Dashboard test suite.

All fixtures use tmp_path (pytest built-in) so files are cleaned up
automatically.  Fixtures are intentionally minimal — they encode the
simplest possible ASmap that exercises the feature under test.
"""

import pytest

# ── ASmap file factory ────────────────────────────────────────────────────────


def _write_asmap(path, lines: list[str]) -> str:
    """Write a list of lines to a temp .txt file and return its path string."""
    p = path / "asmap.txt"
    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)


# ── Tiny maps (prefix-count focused) ─────────────────────────────────────────


@pytest.fixture
def single_prefix(tmp_path):
    """One prefix, one ASN."""
    return _write_asmap(tmp_path, ["1.0.0.0/24 AS13335"])


@pytest.fixture
def two_prefixes(tmp_path):
    """Two distinct prefixes, two distinct ASNs."""
    subdir = tmp_path / "base"
    subdir.mkdir(parents=True, exist_ok=True)
    return _write_asmap(
        subdir,
        [
            "1.0.0.0/24 AS13335",
            "2.0.0.0/24 AS15169",
        ],
    )


@pytest.fixture
def identical_maps(tmp_path):
    """Baseline and candidate are byte-for-byte identical."""
    lines = ["1.0.0.0/24 AS13335", "2.0.0.0/24 AS15169"]
    base = tmp_path / "base.txt"
    cand = tmp_path / "cand.txt"
    base.write_text("\n".join(lines), encoding="utf-8")
    cand.write_text("\n".join(lines), encoding="utf-8")
    return str(base), str(cand)


# ── Coverage-focused maps ─────────────────────────────────────────────────────


@pytest.fixture
def large_prefix_map(tmp_path):
    """Baseline with a /16 (65 536 addresses) and a /24 (256 addresses)."""
    return _write_asmap(
        tmp_path,
        [
            "10.0.0.0/16 AS13335",
            "11.0.0.0/24 AS15169",
        ],
    )


@pytest.fixture
def ipv6_map(tmp_path):
    """A map containing both IPv4 and IPv6 prefixes."""
    return _write_asmap(
        tmp_path,
        [
            "1.0.0.0/24 AS13335",
            "2606:4700::/32 AS13335",
            "2001:db8::/48 AS15169",
        ],
    )


# ── Dirty-input maps (parser robustness) ─────────────────────────────────────


@pytest.fixture
def map_with_comments_and_blanks(tmp_path):
    """Mix of valid entries, comments, blank lines, and malformed lines."""
    lines = [
        "# ASmap text format — generated sample",
        "",
        "1.0.0.0/24 AS13335",
        "bad line here",
        "   ",
        "2.0.0.0/24 AS15169",
        "# trailing comment",
    ]
    return _write_asmap(tmp_path, lines)


# ── Hundred-prefix map for percentage tests ───────────────────────────────────


@pytest.fixture
def hundred_prefix_baseline(tmp_path):
    """100 prefixes so that diff percentages are whole numbers."""
    lines = [f"{i}.0.0.0/24 AS13335" for i in range(1, 101)]
    return _write_asmap(tmp_path, lines)


@pytest.fixture
def hundred_prefix_candidate(tmp_path):
    """
    Candidate derived from the 100-prefix baseline:
      - keeps prefixes 1-90 (90 unchanged)
      - removes prefixes 91-100 (10 removed)
      - adds  200.0-9.0.0/24   (10 added)
    Net: 20 changes out of 100 baseline → diff_percentage == 20.0
    NOTE: tmp_path here is a different directory from hundred_prefix_baseline.
    Use the hundred_prefix_pair fixture when you need both files for compare_maps.
    """
    lines = [f"{i}.0.0.0/24 AS13335" for i in range(1, 91)] + [
        f"200.{i}.0.0/24 AS15169" for i in range(10)
    ]
    return _write_asmap(tmp_path, lines)


@pytest.fixture
def hundred_prefix_pair(tmp_path):
    """
    Both baseline and candidate written to the SAME tmp_path so that
    compare_maps() sees real diffs.

    baseline: 100 prefixes (1.x–100.x), all AS13335
    candidate: keeps 1.x–90.x, drops 91.x–100.x, adds 200.0–9.x
    → 10 removed + 10 added = 20 total changes out of 100 → diff_percentage == 20.0
    """
    base_lines = [f"{i}.0.0.0/24 AS13335" for i in range(1, 101)]
    cand_lines = [f"{i}.0.0.0/24 AS13335" for i in range(1, 91)] + [
        f"200.{i}.0.0/24 AS15169" for i in range(10)
    ]
    base_path = tmp_path / "baseline.txt"
    cand_path = tmp_path / "candidate.txt"
    base_path.write_text("\n".join(base_lines), encoding="utf-8")
    cand_path.write_text("\n".join(cand_lines), encoding="utf-8")
    return str(base_path), str(cand_path)


# ── High-churn map (severity: Critical threshold) ────────────────────────────


@pytest.fixture
def high_churn_maps(tmp_path):
    """
    50 prefixes baseline; candidate has a completely different set.
    Produces diff_percentage = 200% (capped) → severity Critical.
    """
    base_lines = [f"{i}.0.0.0/24 AS13335" for i in range(1, 51)]
    cand_lines = [f"{i}.0.0.0/24 AS15169" for i in range(100, 151)]
    base = tmp_path / "base.txt"
    cand = tmp_path / "cand.txt"
    base.write_text("\n".join(base_lines), encoding="utf-8")
    cand.write_text("\n".join(cand_lines), encoding="utf-8")
    return str(base), str(cand)
