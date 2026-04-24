"""
fetch_history.py
----------------
Downloads two real, historical, binary .asmap files from the
bitcoin-core/asmap-data GitHub repository and saves them locally for use
with the ASmap Diff Analyzer.

Usage:
    python fetch_history.py

Output:
    data/baseline.asmap  — snapshot dated 2024-04-05
    data/candidate.asmap — snapshot dated 2024-06-21

These paths match the defaults expected by:
    python main.py --baseline data/baseline.asmap \\
                   --candidate data/candidate.asmap --json --csv --md
"""

from __future__ import annotations

import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

DATA_DIR = Path("data")

DOWNLOADS: list[dict[str, str]] = [
    {
        "label": "Baseline  (2024-04-05)",
        "url": (
            "https://raw.githubusercontent.com/bitcoin-core/asmap-data"
            "/master/2024-04-05/asmap.dat"
        ),
        "dest": str(DATA_DIR / "baseline.asmap"),
    },
    {
        "label": "Candidate (2024-06-21)",
        "url": (
            "https://raw.githubusercontent.com/bitcoin-core/asmap-data"
            "/master/2024-06-21/asmap.dat"
        ),
        "dest": str(DATA_DIR / "candidate.asmap"),
    },
]

TIMEOUT_SECONDS = 15
USER_AGENT = (
    "asmap-diff-analyzer/1.0 "
    "(Summer-of-Bitcoin-2026; "
    "+https://github.com/bitcoin-core/asmap-data)"
)

# ANSI helpers (disabled on Windows without ANSI support)
def _ansi(code: str) -> str:
    if sys.stdout.isatty() and os.name != "nt":
        return f"\033[{code}m"
    return ""

RESET  = _ansi("0")
BOLD   = _ansi("1")
DIM    = _ansi("2")
GREEN  = _ansi("92")
RED    = _ansi("91")
YELLOW = _ansi("93")
CYAN   = _ansi("96")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    """Return a compact human-readable byte count."""
    if n >= 1_048_576:
        return f"{n / 1_048_576:.2f} MiB"
    if n >= 1_024:
        return f"{n / 1_024:.1f} KiB"
    return f"{n} B"


def _build_request(url: str) -> urllib.request.Request:
    """Construct a Request with a proper User-Agent header."""
    return urllib.request.Request(url, headers={"User-Agent": USER_AGENT})


def _download(label: str, url: str, dest: str) -> bool:
    """
    Download *url* to *dest* with a progress indicator.

    Returns True on success, False on any failure (error already printed).
    Skips the download if the destination file already exists and is non-empty.
    """
    dest_path = Path(dest)

    # ── Skip if already present ───────────────────────────────────────────────
    if dest_path.exists() and dest_path.stat().st_size > 0:
        size = _fmt_bytes(dest_path.stat().st_size)
        print(
            f"  {YELLOW}↩  Skipping{RESET}  {label}\n"
            f"     {DIM}{dest}{RESET} already exists ({size})"
        )
        return True

    print(f"  {CYAN}↓  Fetching{RESET}  {label}")
    print(f"     {DIM}{url}{RESET}")

    t_start = time.monotonic()
    try:
        req = _build_request(url)
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            # Honour Content-Length for a progress hint, but it may be absent.
            content_length = resp.headers.get("Content-Length")
            total = int(content_length) if content_length else None

            data = bytearray()
            chunk_size = 65_536  # 64 KiB

            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                data += chunk
                if total:
                    pct = len(data) / total * 100
                    bar_filled = int(pct / 5)
                    bar = "█" * bar_filled + "░" * (20 - bar_filled)
                    print(
                        f"\r     [{bar}] {pct:5.1f}%  "
                        f"{_fmt_bytes(len(data))} / {_fmt_bytes(total)}  ",
                        end="",
                        flush=True,
                    )

            if total:
                print()  # newline after progress bar

    except urllib.error.HTTPError as exc:
        print(
            f"\n  {RED}✗  HTTP {exc.code}{RESET}  {label}\n"
            f"     {exc.reason} — check that the URL still exists:\n"
            f"     {url}"
        )
        return False

    except urllib.error.URLError as exc:
        reason = exc.reason
        print(
            f"\n  {RED}✗  Network error{RESET}  {label}\n"
            f"     {reason}\n"
            f"     Verify your internet connection and try again."
        )
        return False

    except TimeoutError:
        print(
            f"\n  {RED}✗  Timeout{RESET}  {label}\n"
            f"     No response after {TIMEOUT_SECONDS}s. "
            "Try again or check your connection."
        )
        return False

    # ── Sanity-check: ASmap binaries start with 0x00 (version byte) ──────────
    if not data:
        print(f"  {RED}✗  Empty response{RESET}  {label}")
        return False

    # ── Write to disk ─────────────────────────────────────────────────────────
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest_path.write_bytes(bytes(data))
    except OSError as exc:
        print(f"  {RED}✗  Write error{RESET}  {dest}: {exc}")
        return False

    elapsed = time.monotonic() - t_start
    size    = _fmt_bytes(len(data))
    print(
        f"  {GREEN}✓  Saved{RESET}      {dest}\n"
        f"     {DIM}{size} in {elapsed:.1f}s{RESET}"
    )
    return True


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}ASmap Historical Data Fetcher{RESET}")
    print("─" * 48)
    print(f"  Target directory : {DATA_DIR.resolve()}")
    print(f"  Timeout          : {TIMEOUT_SECONDS}s per file")
    print(f"  Files to fetch   : {len(DOWNLOADS)}")
    print("─" * 48 + "\n")

    # Ensure data/ exists before starting
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    successes = 0
    for item in DOWNLOADS:
        ok = _download(item["label"], item["url"], item["dest"])
        if ok:
            successes += 1
        print()

    print("─" * 48)
    if successes == len(DOWNLOADS):
        print(f"{GREEN}{BOLD}All files ready.{RESET}\n")
        print("Next step — run the diff analyzer:")
        print(
            f"  {DIM}python main.py \\\n"
            f"    --baseline  data/baseline.asmap \\\n"
            f"    --candidate data/candidate.asmap \\\n"
            f"    --json --csv --md --explain{RESET}\n"
        )
    else:
        failed = len(DOWNLOADS) - successes
        print(
            f"{RED}{BOLD}{failed} download(s) failed.{RESET} "
            "Check your internet connection and retry.\n"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
