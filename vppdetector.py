"""Standalone entry point for whole-package VPP risk scanning."""

from __future__ import annotations

import argparse
import json
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Sequence

from vppdetector import scan_package


def _to_data(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _to_data(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_to_data(item) for item in value]
    if isinstance(value, list):
        return [_to_data(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_data(item) for key, item in value.items()}
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="scan one package version for VPP risks")
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--import-root", action="append", type=Path, default=[])
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = build_parser().parse_args(argv)
    report = scan_package(arguments.package_root, import_roots=arguments.import_root)
    text = json.dumps(_to_data(report), ensure_ascii=False, indent=2)
    if arguments.output:
        arguments.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
