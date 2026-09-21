"""Command-line boundary for standalone scans and targeted assessments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from .assessment import assess_change
from .models import (
    ChangeKind,
    FunctionIdentity,
    ParameterChange,
    SourceContext,
    VariadicKind,
    VPPRequest,
)
from .scanner import scan_package
from .serialization import to_data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vppdetector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan one package version")
    scan.add_argument("package_root", type=Path)
    scan.add_argument("--import-root", action="append", type=Path, default=[])
    scan.add_argument("--output", type=Path)

    assess = subparsers.add_parser("assess", help="assess one known parameter change")
    assess.add_argument("package_root", type=Path)
    assess.add_argument("--import-root", action="append", type=Path, default=[])
    assess.add_argument("--module", required=True)
    assess.add_argument("--qualname", required=True)
    assess.add_argument("--file", type=Path)
    assess.add_argument("--line", type=int)
    assess.add_argument("--change", choices=[item.value for item in ChangeKind], required=True)
    assess.add_argument("--old-name", required=True)
    assess.add_argument("--new-name")
    assess.add_argument("--captured-by", required=True)
    assess.add_argument(
        "--capture-kind",
        choices=[item.value for item in VariadicKind],
        required=True,
    )
    assess.add_argument("--max-depth", type=int, default=5)
    assess.add_argument("--output", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        result = scan_package(args.package_root, import_roots=args.import_root)
    else:
        source = SourceContext(args.package_root, tuple(args.import_root))
        request = VPPRequest(
            source=source,
            target_api=FunctionIdentity(
                module=args.module,
                qualname=args.qualname,
                file_path=args.file,
                lineno=args.line,
            ),
            change=ParameterChange(
                kind=ChangeKind(args.change),
                old_name=args.old_name,
                new_name=args.new_name,
                captured_by=args.captured_by,
                capture_kind=VariadicKind(args.capture_kind),
            ),
            max_depth=args.max_depth,
        )
        result = assess_change(request)
    text = json.dumps(to_data(result), ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
