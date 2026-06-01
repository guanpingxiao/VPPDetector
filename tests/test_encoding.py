import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vppdetector import getEncoding


def _make_temp_file(content, encoding="utf-8"):
    """Create a temp file with given content and encoding, return path."""
    tmp = tempfile.NamedTemporaryFile(mode="wb", suffix=".py", delete=False)
    tmp.write(content.encode(encoding))
    tmp.close()
    return tmp.name


class TestGetEncoding:
    """Tests for getEncoding() — encoding detection with chardet."""

    def test_utf8_with_unicode_char_lower_one_eighth_block(self):
        """Reproduce bug: chardet misdetects UTF-8 file containing '▁'
        (U+2581) as Windows-1254 with ~51% confidence, but the detected
        encoding fails to decode the file → file silently skipped."""
        content = '''UNDERLINE = "▁"

class SomeTokenizer:
    def __init__(self, **kwargs):
        pass
'''
        path = _make_temp_file(content, "utf-8")
        try:
            encoding = getEncoding(path)

            # The detected encoding must ACTUALLY decode the file
            with open(path, "r", encoding=encoding) as f:
                decoded = f.read()

            assert "UNDERLINE" in decoded
            assert "SomeTokenizer" in decoded
        finally:
            os.unlink(path)

    def test_pure_ascii(self):
        """ASCII-only file should be detected and decode correctly."""
        content = "def foo(*args):\n    pass\n"
        path = _make_temp_file(content, "ascii")
        try:
            encoding = getEncoding(path)
            with open(path, "r", encoding=encoding) as f:
                decoded = f.read()
            assert decoded == content
        finally:
            os.unlink(path)

    def test_utf8_with_chinese(self):
        """UTF-8 file with CJK characters should be correctly handled."""
        content = '# 中文注释\ndef bar(**kwargs):\n    pass\n'
        path = _make_temp_file(content, "utf-8")
        try:
            encoding = getEncoding(path)
            with open(path, "r", encoding=encoding) as f:
                decoded = f.read()
            assert "中文注释" in decoded
        finally:
            os.unlink(path)

    def test_detected_encoding_must_work(self):
        """Property: getEncoding must return an encoding that can
        actually decode the file. This is the core invariant the bug
        violated."""
        # Multiple files with different Unicode chars that chardet
        # tends to misclassify
        test_cases = [
            ("▁", "lower one eighth block"),
            ("é", "e-acute (common in French names)"),
            ("“”", "smart quotes"),
            ("αβ", "Greek letters"),
        ]

        for char, desc in test_cases:
            content = f"x = '{char}'  # {desc}\ndef f(**kw):\n    pass\n"
            path = _make_temp_file(content, "utf-8")
            try:
                encoding = getEncoding(path)
                with open(path, "r", encoding=encoding) as fh:
                    decoded = fh.read()
                assert char in decoded, (
                    f"char {desc!r} lost with encoding {encoding!r}"
                )
            finally:
                os.unlink(path)
