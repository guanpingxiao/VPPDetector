"""Robust Python source-encoding selection."""

from __future__ import annotations

import io
import tokenize
from pathlib import Path
from typing import Union

import chardet

PathLike = Union[str, Path]


def get_encoding(file_path: PathLike) -> str:
    """Return an encoding that is verified to decode the complete file."""

    raw_data = Path(file_path).read_bytes()
    candidates = []

    try:
        declared, _ = tokenize.detect_encoding(io.BytesIO(raw_data).readline)
        candidates.append(declared)
    except SyntaxError:
        pass

    candidates.append("utf-8-sig")
    detected = chardet.detect(raw_data).get("encoding")
    if detected:
        candidates.append(detected)
    candidates.append("latin-1")

    tried = set()
    for encoding in candidates:
        normalized = encoding.lower()
        if normalized in tried:
            continue
        tried.add(normalized)
        try:
            raw_data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
        return encoding

    raise UnicodeError("No usable encoding found for {}".format(file_path))


def getEncoding(filePath: PathLike) -> str:
    """Compatibility alias for the VPPDetector 1.0 public helper."""

    return get_encoding(filePath)
