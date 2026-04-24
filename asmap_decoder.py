"""
asmap_decoder.py
----------------
Decodes real Bitcoin Core binary .asmap files.

The .asmap format is a compressed bit-trie stored MSB-first:
  - Internal node: bit 1, then left subtree (bit=0), then right (bit=1)
  - Leaf node:     bit 0, then ASN encoded as a variable-length int

The path from root to leaf encodes the IP prefix.

Reference:
  https://github.com/bitcoin/bitcoin/blob/master/src/util/asmap.cpp
  https://github.com/bitcoin/bitcoin/blob/master/contrib/asmap/asmap.py

Falls back to text format if binary decode yields fewer than MIN_ENTRIES entries.
"""

import logging
from pathlib import Path

log = logging.getLogger(__name__)

MIN_ENTRIES = 10  # fewer results than this → assume binary parse failed


# ── Bit-stream reader ─────────────────────────────────────────────────────────


class BitReader:
    """Read a byte buffer one bit at a time, MSB first."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._byte = 0
        self._bit = 8  # triggers byte load on first read_bit()

    def read_bit(self) -> int:
        if self._bit >= 8:
            if self._byte >= len(self._data):
                raise EOFError("unexpected end of .asmap bitstream")
            self._cur = self._data[self._byte]
            self._byte += 1
            self._bit = 0
        bit = (self._cur >> (7 - self._bit)) & 1
        self._bit += 1
        return bit

    def read_bits(self, n: int) -> int:
        val = 0
        for _ in range(n):
            val = (val << 1) | self.read_bit()
        return val


# ── ASN varint decoder ────────────────────────────────────────────────────────


def _read_asn(reader: BitReader) -> int:
    """
    Read a variable-length ASN from the bitstream.

    Bitcoin Core prefix coding:
      00 → 8-bit  value  (ASN < 256)
      01 → 16-bit value
      10 → 24-bit value
      11 → 32-bit value  (all valid ASNs)
    """
    prefix = reader.read_bits(2)
    widths = {0: 8, 1: 16, 2: 24, 3: 32}
    return reader.read_bits(widths[prefix])


# ── Trie traversal ────────────────────────────────────────────────────────────


def _decode_trie(
    reader: BitReader,
    path_bits: list[int],
    results: list[tuple[str, str]],
) -> None:
    """
    DFS traversal of the bit-trie.
    path_bits accumulates the current prefix (0 = left, 1 = right).
    Appends (prefix_str, ASN_str) tuples to results.
    """
    try:
        node_type = reader.read_bit()
    except EOFError:
        return

    if node_type == 0:
        # Leaf node
        try:
            asn = _read_asn(reader)
        except EOFError:
            return
        if asn == 0:
            return  # unrouted / not mapped
        prefix_str = _bits_to_prefix(path_bits)
        if prefix_str:
            results.append((prefix_str, f"AS{asn}"))
    else:
        # Internal node — recurse left then right
        try:
            _decode_trie(reader, path_bits + [0], results)
            _decode_trie(reader, path_bits + [1], results)
        except (EOFError, RecursionError):
            pass


# ── Bit-path → prefix string ──────────────────────────────────────────────────


def _bits_to_prefix(bits: list[int]) -> str | None:
    """
    Convert a trie path (list of 0/1 bits) to an IP prefix string.

    Short paths (≤ 32 bits) → IPv4.
    Longer paths             → IPv6.
    """
    if not bits:
        return None
    n = len(bits)
    try:
        if n <= 32:
            padded = bits + [0] * (32 - n)
            octets = [sum(padded[i * 8 + j] << (7 - j) for j in range(8)) for i in range(4)]
            return f"{'.'.join(map(str, octets))}/{n}"
        else:
            padded = (bits + [0] * 128)[:128]
            groups = [
                format(sum(padded[i * 16 + j] << (15 - j) for j in range(16)), "x")
                for i in range(8)
            ]
            return f"{':'.join(groups)}/{n}"
    except Exception as exc:
        log.debug("_bits_to_prefix failed for %d-bit path: %s", n, exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────


def decode_asmap_file(filepath: str) -> dict[str, str]:
    """
    Decode a .asmap file and return {prefix: ASN} dict.

    Strategy:
      1. Try binary trie decode.
      2. If that yields < MIN_ENTRIES results, fall back to text format.
      3. If both fail, raise RuntimeError with a clear message.

    Args:
        filepath: path to a .asmap binary or text file.

    Returns:
        dict[str, str] mapping prefix strings (e.g. "1.0.0.0/24") to
        ASN strings (e.g. "AS13335").

    Raises:
        FileNotFoundError: if filepath does not exist.
        RuntimeError:      if neither binary nor text decode succeeds.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"asmap file not found: {filepath!r}")

    raw = path.read_bytes()
    log.info("decoding %s (%d bytes)", path.name, len(raw))

    # ── Attempt 1: binary trie decode ────────────────────────────────────────
    results: list[tuple[str, str]] = []
    try:
        reader = BitReader(raw)
        _decode_trie(reader, [], results)
        log.debug("binary trie decode: %d entries", len(results))
    except Exception as exc:
        log.warning(
            "binary trie decode raised %s: %s — trying text fallback", type(exc).__name__, exc
        )
        results = []

    if len(results) >= MIN_ENTRIES:
        log.info("binary decode succeeded: %d prefixes", len(results))
        return dict(results)

    # ── Attempt 2: text format fallback ──────────────────────────────────────
    log.info("binary decode yielded %d entries — trying text format", len(results))
    try:
        text = raw.decode("utf-8", errors="ignore")
        mapping: dict[str, str] = {}
        skipped = 0
        for line_num, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 2:
                mapping[parts[0]] = parts[1]
            else:
                log.warning("line %d skipped in text fallback: %r", line_num, line)
                skipped += 1
        if mapping:
            log.info("text decode succeeded: %d prefixes (%d skipped)", len(mapping), skipped)
            return mapping
    except Exception as exc:
        log.warning("text decode failed: %s", exc)

    raise RuntimeError(
        f"Could not decode {filepath!r} as binary .asmap or text format.\n"
        "Ensure the file is a valid Bitcoin Core .asmap or a text file "
        "where each line is:  <prefix> <ASN>  (e.g. '1.0.0.0/24 AS13335').\n"
        "To convert a binary .asmap to text: asmap-tool decode file.asmap > out.txt"
    )


def asmap_info(filepath: str) -> dict:
    """
    Return basic metadata about an asmap file without full decode.
    Useful for quick sanity checks before running a full diff.
    """
    path = Path(filepath)
    if not path.exists():
        return {"error": f"file not found: {filepath!r}"}
    size = path.stat().st_size
    raw = path.read_bytes()
    sample: list[tuple[str, str]] = []
    try:
        reader = BitReader(raw[: min(len(raw), 65_536)])  # first 64 KB only
        _decode_trie(reader, [], sample)
    except Exception:
        pass
    return {
        "filepath": filepath,
        "size_bytes": size,
        "size_kb": round(size / 1024, 1),
        "format": "binary" if len(sample) >= MIN_ENTRIES else "text/unknown",
        "sample_entries": sample[:5],
    }
