"""
tests/test_decoder.py
---------------------
Tests for asmap_decoder.py: BitReader, text fallback, decode_asmap_file(),
asmap_info(), and the format-detection heuristic.

Run:
    pytest tests/test_decoder.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from asmap_decoder import (
    MIN_ENTRIES,
    BitReader,
    asmap_info,
    decode_asmap_file,
)

# ══════════════════════════════════════════════════════════════════════════════
# BitReader
# ══════════════════════════════════════════════════════════════════════════════


class TestBitReader:
    def test_read_single_bit_high(self):
        r = BitReader(b"\x80")  # 0b10000000
        assert r.read_bit() == 1

    def test_read_single_bit_low(self):
        r = BitReader(b"\x00")
        assert r.read_bit() == 0

    def test_msb_first_ordering(self):
        # 0xAC = 0b10101100
        r = BitReader(b"\xac")
        bits = [r.read_bit() for _ in range(8)]
        assert bits == [1, 0, 1, 0, 1, 1, 0, 0]

    def test_read_bits_multi(self):
        # 0xFF = 0b11111111 → read 4 bits → 0b1111 = 15
        r = BitReader(b"\xff")
        assert r.read_bits(4) == 15

    def test_read_bits_zero(self):
        r = BitReader(b"\x00")
        assert r.read_bits(8) == 0

    def test_eof_raises(self):
        r = BitReader(b"\xff")
        r.read_bits(8)  # consume all 8 bits
        with pytest.raises(EOFError):
            r.read_bit()

    def test_multi_byte_sequential(self):
        # 0x00 0xFF → first 8 bits are 0, next 8 are 1
        r = BitReader(b"\x00\xff")
        first = r.read_bits(8)
        second = r.read_bits(8)
        assert first == 0
        assert second == 255

    def test_read_bits_returns_int(self):
        r = BitReader(b"\xab\xcd")
        assert isinstance(r.read_bits(4), int)


# ══════════════════════════════════════════════════════════════════════════════
# decode_asmap_file() — text fallback path
# ══════════════════════════════════════════════════════════════════════════════


class TestDecodeAsmapFileTextFallback:
    """
    Valid text files are loaded via the text fallback path because they
    contain no valid bit-trie header and yield < MIN_ENTRIES from binary decode.
    """

    def _make_txt(self, tmp_path, lines):
        p = tmp_path / "test.txt"
        p.write_text("\n".join(lines), encoding="utf-8")
        return str(p)

    def test_loads_text_file(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS13335"])
        m = decode_asmap_file(path)
        assert "1.0.0.0/24" in m
        assert m["1.0.0.0/24"] == "AS13335"

    def test_skips_comment_lines(self, tmp_path):
        path = self._make_txt(
            tmp_path,
            [
                "# header comment",
                "1.0.0.0/24 AS13335",
            ],
        )
        m = decode_asmap_file(path)
        assert len(m) == 1

    def test_skips_blank_lines(self, tmp_path):
        path = self._make_txt(tmp_path, ["", "1.0.0.0/24 AS13335", ""])
        m = decode_asmap_file(path)
        assert len(m) == 1

    def test_text_fallback_does_not_validate_prefix_format(self, tmp_path):
        """
        KNOWN BEHAVIOUR (not a bug we fix here, but document it):

        The text fallback in asmap_decoder.py splits on whitespace and accepts
        any two-token line — it does NOT validate that token[0] is a valid CIDR
        prefix.  So "bad line" is stored as {"bad": "line"}.

        Contrast this with load_asmap() in utils.py which has the same two-token
        check but logs a warning on non-prefix-looking strings.

        This test pins the current behaviour so a future fix is visible as a
        deliberate change.  If you tighten the fallback parser, update this test.

        See: asmap_decoder.py lines 190-199 (text format fallback section).
        """
        path = self._make_txt(
            tmp_path,
            [
                "# comment",
                "",
                "1.0.0.0/24 AS13335",
                "bad line",  # two tokens — accepted by current fallback
                "2.0.0.0/24 AS15169",
            ],
        )
        m = decode_asmap_file(path)
        # Current behaviour: 3 entries (including "bad" -> "line")
        assert len(m) == 3
        assert "1.0.0.0/24" in m
        assert "2.0.0.0/24" in m
        assert "bad" in m  # pin current behaviour

    def test_loads_ipv6_prefixes(self, tmp_path):
        path = self._make_txt(
            tmp_path,
            [
                "2606:4700::/32 AS13335",
                "2001:db8::/48 AS15169",
            ],
        )
        m = decode_asmap_file(path)
        assert "2606:4700::/32" in m
        assert "2001:db8::/48" in m

    def test_returns_dict(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        assert isinstance(decode_asmap_file(path), dict)

    def test_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            decode_asmap_file("/tmp/no_such_asmap_file_xyz.asmap")

    def test_raises_runtime_error_on_empty(self, tmp_path):
        p = tmp_path / "empty.asmap"
        p.write_bytes(b"")
        with pytest.raises(RuntimeError, match="Could not decode"):
            decode_asmap_file(str(p))

    def test_runtime_error_message_is_helpful(self, tmp_path):
        p = tmp_path / "garbage.asmap"
        p.write_bytes(b"\x00" * 3)  # 3 zero-bytes → binary yields 0 entries; text yields nothing
        with pytest.raises(RuntimeError) as exc_info:
            decode_asmap_file(str(p))
        assert "asmap-tool" in str(exc_info.value)

    def test_large_text_file(self, tmp_path):
        lines = [f"{i}.0.0.0/24 AS{10000 + i}" for i in range(1, 201)]
        path = self._make_txt(tmp_path, lines)
        m = decode_asmap_file(path)
        assert len(m) == 200

    def test_min_entries_constant_is_positive(self):
        assert MIN_ENTRIES > 0


# ══════════════════════════════════════════════════════════════════════════════
# asmap_info()
# ══════════════════════════════════════════════════════════════════════════════


class TestAsmapInfo:
    def _make_txt(self, tmp_path, lines):
        p = tmp_path / "info_test.txt"
        p.write_text("\n".join(lines), encoding="utf-8")
        return str(p)

    def test_returns_dict(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        info = asmap_info(path)
        assert isinstance(info, dict)

    def test_has_required_keys(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        info = asmap_info(path)
        for key in ("filepath", "size_bytes", "size_kb", "format", "sample_entries"):
            assert key in info, f"missing key: {key!r}"

    def test_filepath_matches(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        info = asmap_info(path)
        assert info["filepath"] == path

    def test_size_bytes_positive(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS13335"])
        info = asmap_info(path)
        assert info["size_bytes"] > 0

    def test_size_kb_is_float(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        info = asmap_info(path)
        assert isinstance(info["size_kb"], float)

    def test_sample_entries_is_list(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        info = asmap_info(path)
        assert isinstance(info["sample_entries"], list)

    def test_missing_file_returns_error_key(self):
        info = asmap_info("/tmp/does_not_exist_asmap_info_test.asmap")
        assert "error" in info

    def test_format_is_string(self, tmp_path):
        path = self._make_txt(tmp_path, ["1.0.0.0/24 AS1"])
        info = asmap_info(path)
        assert isinstance(info["format"], str)
