"""
main.py
-------
ASmap Diff Analyzer — compare two ASmap files.

Supports:
  - Binary .asmap files from https://github.com/bitcoin-core/asmap-data
  - Text files produced by: asmap-tool decode file.asmap > out.txt
  - Demo files from: python generate_sample_data.py

Usage:
  python main.py --baseline baseline.asmap --candidate candidate.asmap
  python main.py --baseline baseline.txt   --candidate candidate.txt --top 10
  python main.py --baseline baseline.asmap --candidate candidate.asmap --json --csv --md --explain
"""

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timezone

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

from asmap_decoder import decode_asmap_file
from config import (
    DEFAULT_CSV_PATH,
    DEFAULT_JSON_PATH,
    DEFAULT_MD_PATH,
    DEFAULT_TOP_ASNS,
    LOG_DATE,
    LOG_FORMAT,
    SAMPLE_CHANGE_LIMIT,
)
from insight import generate_insight, historical_context, severity_explanation
from utils import DiffResult, compare_maps, load_asmap

# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE, level=level)

log = logging.getLogger(__name__)


# ── Smart loader ──────────────────────────────────────────────────────────────

def smart_load(label: str, path: str) -> dict[str, str]:
    """
    Load an ASmap file regardless of format (.asmap binary or .txt text).
    Validates existence and non-empty before loading.

    Raises SystemExit on unrecoverable errors so the CLI gives clean messages.
    """
    if not os.path.isfile(path):
        log.error("%s file not found: %r", label, path)
        print(f"error: {label} file not found: {path!r}", file=sys.stderr)
        sys.exit(1)
    if os.path.getsize(path) == 0:
        log.error("%s file is empty: %r", label, path)
        print(f"error: {label} file is empty: {path!r}", file=sys.stderr)
        sys.exit(1)

    ext = os.path.splitext(path)[1].lower()
    if ext in (".asmap", ".dat", ".bin", ""):
        try:
            return decode_asmap_file(path)
        except RuntimeError as exc:
            log.warning("binary/auto decode failed: %s — falling back to text loader", exc)
    try:
        return load_asmap(path)
    except (ValueError, OSError) as exc:
        print(f"error: could not load {label} file {path!r}: {exc}", file=sys.stderr)
        sys.exit(1)


# ── Formatters ────────────────────────────────────────────────────────────────

def fmt_ips(n: int) -> str:
    """Format a large IP count into a compact human-readable string."""
    if n >= 10 ** 18:
        return f"{n / 10 ** 18:.1f}E"
    if n >= 10 ** 12:
        return f"{n / 10 ** 12:.1f}T"
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


# ── ANSI colors ───────────────────────────────────────────────────────────────

def _tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.name != "nt"

G    = "\033[92m" if _tty() else ""
R    = "\033[91m" if _tty() else ""
Y    = "\033[93m" if _tty() else ""
B    = "\033[94m" if _tty() else ""
CY   = "\033[96m" if _tty() else ""
BOLD = "\033[1m"  if _tty() else ""
DIM  = "\033[2m"  if _tty() else ""
RST  = "\033[0m"  if _tty() else ""

SEV_COLOR: dict[str, str] = {
    "Low":      G,
    "Moderate": Y,
    "High":     R,
    "Critical": R + BOLD,
}


# ── Terminal output ───────────────────────────────────────────────────────────

def print_summary(r: DiffResult, show_top: int, explain: bool) -> None:
    sc = SEV_COLOR.get(r.severity_label, "")

    print(f"\n{BOLD}ASmap Diff Summary{RST}")
    print("─" * 50)
    print(f"  {'Baseline prefixes':<30}: {r.total_baseline:>10,}")
    print(f"  {'Candidate prefixes':<30}: {r.total_candidate:>10,}")
    print("─" * 50)
    print(f"  {'Added':<30}: {G}{len(r.added):>+10,}{RST}")
    print(f"  {'Removed':<30}: {R}{-len(r.removed):>+10,}{RST}")
    print(f"  {'Changed ASN':<30}: {Y}{len(r.changed):>10,}{RST}")
    print(f"  {'Unchanged':<30}: {DIM}{r.unchanged:>10,}{RST}")
    print(f"  {'Total changes':<30}: {r.total_changes:>10,}")
    print(f"  {'Diff percentage':<30}: {r.diff_percentage:>9.2f}%")
    print("─" * 50)
    total_v4 = r.coverage_added_v4 + r.coverage_removed_v4 + r.coverage_changed_v4
    print(f"  {'IPv4 coverage changed':<30}: {r.coverage_change_pct_v4:>9.4f}%")
    print(f"    {'(addresses affected)':<28}: {fmt_ips(total_v4):>10}")
    print(f"  {'IPv6 coverage changed':<30}: {r.coverage_change_pct_v6:>9.6f}%")
    print("─" * 50)
    print(f"  {'Severity score':<30}: {r.severity_score:>10.4f}")
    print(f"  {'Diff severity':<30}: {sc}{r.severity_label:>10}{RST}")
    print("─" * 50)

    # Top ASNs table
    if r.top_changed_asns:
        print(f"\n{BOLD}Top {show_top} ASNs by IP space moved:{RST}")
        rows = []
        for a in r.top_changed_asns[:show_top]:
            net_pfx = f"{a['net_pfx']:+}"
            net_ips = (f"{G}+{fmt_ips(a['net_ips'])}{RST}"
                       if a["net_ips"] >= 0
                       else f"{R}-{fmt_ips(abs(a['net_ips']))}{RST}")
            rows.append([a["asn"],
                         f"{G}+{a['gained_pfx']}{RST}",
                         f"{R}-{a['lost_pfx']}{RST}",
                         net_pfx, net_ips])
        if HAS_TABULATE:
            print(tabulate(rows,
                           headers=["ASN", "Gained", "Lost", "Net pfx", "Net IPs"],
                           tablefmt="simple"))
        else:
            print(f"  {'ASN':<12} {'Gained':>8} {'Lost':>8} {'Net pfx':>10} {'Net IPs':>12}")
            print("  " + "─" * 54)
            for a in r.top_changed_asns[:show_top]:
                nips = f"{'+' if a['net_ips'] >= 0 else '-'}{fmt_ips(abs(a['net_ips']))}"
                print(f"  {a['asn']:<12} {a['gained_pfx']:>8} {a['lost_pfx']:>8}"
                      f" {a['net_pfx']:>+10} {nips:>12}")

    # Insight paragraph
    print(f"\n{BOLD}{CY}Insight:{RST}")
    for sentence in generate_insight(r).split(". "):
        if sentence.strip():
            print(f"  {sentence.strip()}.")

    # Historical table
    print(f"\n{BOLD}Historical context:{RST}")
    hist = historical_context(r)
    if HAS_TABULATE:
        rows_h = [[h["date"],
                   f"{h['diff_pct']:.2f}%",
                   f"{h['vs_current']:+.2f}pp",
                   h.get("label", "")]
                  for h in hist]
        print(tabulate(rows_h,
                       headers=["Run date", "Diff %", "vs current", ""],
                       tablefmt="simple"))
    else:
        print(f"  {'Run date':<14} {'Diff %':>8}  {'vs current':>12}")
        print("  " + "─" * 40)
        for h in hist:
            lbl = h.get("label", "")
            print(f"  {h['date']:<14} {h['diff_pct']:>7.2f}%  {h['vs_current']:>+10.2f}pp  {lbl}")

    # Severity breakdown (only with --explain)
    if explain:
        print(f"\n{BOLD}Severity score breakdown:{RST}")
        for line in severity_explanation(r).splitlines():
            print(f"  {line}")


# ── JSON output ───────────────────────────────────────────────────────────────

def write_json(r: DiffResult, path: str) -> None:
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "baseline_total":          r.total_baseline,
            "candidate_total":         r.total_candidate,
            "added":                   len(r.added),
            "removed":                 len(r.removed),
            "changed":                 len(r.changed),
            "unchanged":               r.unchanged,
            "total_changes":           r.total_changes,
            "diff_percentage":         r.diff_percentage,
            "coverage_change_pct_v4":  r.coverage_change_pct_v4,
            "coverage_change_pct_v6":  r.coverage_change_pct_v6,
            "severity_score":          r.severity_score,
            "severity_label":          r.severity_label,
        },
        "insights": {
            "summary":            generate_insight(r),
            "severity_formula":   severity_explanation(r),
            "historical_context": historical_context(r),
        },
        "top_changed_asns": r.top_changed_asns,
        "changes": {
            "added":   r.added[:SAMPLE_CHANGE_LIMIT],
            "removed": r.removed[:SAMPLE_CHANGE_LIMIT],
            "changed": r.changed[:SAMPLE_CHANGE_LIMIT],
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    log.info("JSON written to %s", path)
    print(f"\nJSON written  → {path}")


# ── CSV output ────────────────────────────────────────────────────────────────

def write_csv(r: DiffResult, path: str) -> None:
    import ipaddress

    def ip_count(prefix: str) -> int:
        try:
            return ipaddress.ip_network(prefix, strict=False).num_addresses
        except ValueError:
            return 0

    rows: list[dict] = []
    for e in r.added:
        rows.append({"type": "added",   "prefix": e["prefix"],
                     "old_asn": "",          "new_asn": e["asn"],
                     "ip_count": ip_count(e["prefix"])})
    for e in r.removed:
        rows.append({"type": "removed", "prefix": e["prefix"],
                     "old_asn": e["asn"],    "new_asn": "",
                     "ip_count": ip_count(e["prefix"])})
    for e in r.changed:
        rows.append({"type": "changed", "prefix": e["prefix"],
                     "old_asn": e["old_asn"], "new_asn": e["new_asn"],
                     "ip_count": e["ip_count"]})

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["type", "prefix", "old_asn", "new_asn", "ip_count"]
        )
        writer.writeheader()
        writer.writerows(rows)
    log.info("CSV written to %s (%d rows)", path, len(rows))
    print(f"CSV written   → {path}")


# ── Markdown PR summary ───────────────────────────────────────────────────────

def write_markdown(r: DiffResult, path: str) -> None:
    badge  = {"Low": "🟢", "Moderate": "🟡", "High": "🟠", "Critical": "🔴"}
    b      = badge.get(r.severity_label, "⚪")
    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lim    = SAMPLE_CHANGE_LIMIT

    lines = [
        "## ASmap Diff Report",
        f"\n_Generated: {ts}_\n",
        "### Summary\n",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Baseline prefixes | {r.total_baseline:,} |",
        f"| Candidate prefixes | {r.total_candidate:,} |",
        f"| Added | `+{len(r.added):,}` |",
        f"| Removed | `-{len(r.removed):,}` |",
        f"| Changed ASN | `~{len(r.changed):,}` |",
        f"| Diff percentage | `{r.diff_percentage}%` |",
        f"| IPv4 coverage changed | `{r.coverage_change_pct_v4:.4f}%` |",
        f"| Severity score | `{r.severity_score}` |",
        f"| **Diff severity** | {b} **{r.severity_label}** |",
        "\n### Insight\n",
        f"> {generate_insight(r)}",
        "\n### Top Changed ASNs\n",
        "| ASN | Gained pfx | Lost pfx | Net pfx | Net IPs |",
        "|-----|-----------|----------|---------|---------|",
    ]
    for a in r.top_changed_asns:
        net_pfx = f"+{a['net_pfx']}" if a["net_pfx"] >= 0 else str(a["net_pfx"])
        net_ips = (f"+{fmt_ips(a['net_ips'])}"
                   if a["net_ips"] >= 0
                   else f"-{fmt_ips(abs(a['net_ips']))}")
        lines.append(f"| {a['asn']} | +{a['gained_pfx']} | -{a['lost_pfx']} | {net_pfx} | {net_ips} |")

    lines += [
        "\n### Historical Context\n",
        "| Run date | Diff % | vs current |",
        "|----------|--------|------------|",
    ]
    for h in historical_context(r):
        vs  = f"+{h['vs_current']:.2f}pp" if h["vs_current"] >= 0 else f"{h['vs_current']:.2f}pp"
        lbl = "  ← this run" if h.get("label") else ""
        lines.append(f"| {h['date']} | {h['diff_pct']:.2f}% | {vs}{lbl} |")

    lines += [
        "\n<details><summary>Sample changes</summary>\n",
        f"\n**Added (first {lim})**\n```",
    ]
    for e in r.added[:lim]:
        lines.append(f"{e['prefix']}  {e['asn']}")
    lines += [f"```\n**Removed (first {lim})**\n```"]
    for e in r.removed[:lim]:
        lines.append(f"{e['prefix']}  {e['asn']}")
    lines += [f"```\n**Changed ASN (first {lim})**\n```"]
    for e in r.changed[:lim]:
        lines.append(f"{e['prefix']}  {e['old_asn']} → {e['new_asn']}")
    lines += [
        "```\n</details>",
        "\n---",
        "_Generated by [asmap-diff-analyzer](https://github.com/YOUR_USERNAME/asmap-prototype)_",
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info("Markdown written to %s", path)
    print(f"Markdown      → {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASmap Diff Analyzer — compare two ASmap files (.asmap binary or text)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py --baseline baseline.asmap --candidate candidate.asmap
  python main.py --baseline baseline.txt   --candidate candidate.txt --top 10
  python main.py --baseline baseline.asmap --candidate candidate.asmap --json --csv --md --explain

generate demo files (no real .asmap needed):
  python generate_sample_data.py

convert binary .asmap to text manually:
  asmap-tool decode file.asmap > output.txt
        """,
    )
    parser.add_argument("--baseline",  required=True,  help="Baseline ASmap file (.asmap or .txt)")
    parser.add_argument("--candidate", required=True,  help="Candidate ASmap file (.asmap or .txt)")
    parser.add_argument("--top",     type=int, default=DEFAULT_TOP_ASNS,
                        help=f"Top N ASNs to show (default: {DEFAULT_TOP_ASNS})")
    parser.add_argument("--json",    action="store_true", help=f"Write {DEFAULT_JSON_PATH}")
    parser.add_argument("--csv",     action="store_true", help=f"Write {DEFAULT_CSV_PATH}")
    parser.add_argument("--md",      action="store_true", help=f"Write {DEFAULT_MD_PATH} (PR-ready)")
    parser.add_argument("--explain", action="store_true", help="Show severity score breakdown")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    print(f"Loading baseline  : {args.baseline}")
    baseline  = smart_load("baseline",  args.baseline)

    print(f"Loading candidate : {args.candidate}")
    candidate = smart_load("candidate", args.candidate)

    print(f"Comparing {len(baseline):,} baseline vs {len(candidate):,} candidate prefixes...")
    result = compare_maps(baseline, candidate)

    print_summary(result, show_top=args.top, explain=args.explain)

    if args.json:
        write_json(result,    DEFAULT_JSON_PATH)
    if args.csv:
        write_csv(result,     DEFAULT_CSV_PATH)
    if args.md:
        write_markdown(result, DEFAULT_MD_PATH)


if __name__ == "__main__":
    main()
