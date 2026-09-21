"""Narrow adapter around PCResolve's experimental exact-target flow API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import FunctionIdentity
from .source import SourceIndex


class ResolutionError(RuntimeError):
    """Raised when PCResolve cannot start an analysis for an explicit entry."""


class PCResolveAdapter:
    def __init__(self, index: SourceIndex) -> None:
        try:
            from pcresolve import FlowAnalyzer
        except ImportError as exc:  # pragma: no cover - packaging failure
            raise ResolutionError("PCResolve is required; install pcresolve>=1.0.6,<2") from exc
        self._index = index
        self._analyzer = FlowAnalyzer(
            source_files=index.files,
            import_roots=index.source.import_roots,
        )

    def analyze(self, function: FunctionIdentity, max_depth: int = 1) -> Any:
        from pcresolve import FunctionRef

        entry = FunctionRef(
            module=function.module,
            qualname=function.qualname,
            file_path=str(function.file_path or ""),
            lineno=function.lineno or 0,
        )
        try:
            return self._analyzer.analyze(entry, max_depth=max_depth)
        except (KeyError, RuntimeError, ValueError) as exc:
            raise ResolutionError(str(exc)) from exc


def identity_from_target(target: Any) -> FunctionIdentity:
    path = getattr(target, "file_path", "")
    return FunctionIdentity(
        module=getattr(target, "module", ""),
        qualname=getattr(target, "qualname", ""),
        file_path=Path(path) if path else None,
        lineno=getattr(target, "lineno", 0) or None,
    )
