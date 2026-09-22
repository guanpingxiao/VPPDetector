"""Shared PCResolve-backed facts for VPP scan and refinement modes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import FunctionIdentity, SourceContext, SourceSpan, VariadicKind
from .source import SourceIndex, build_source_index


class ResolutionError(RuntimeError):
    """Raised when PCResolve cannot start an analysis for an explicit entry."""


class PCResolveAdapter:
    """Narrow adapter around PCResolve's experimental value-flow API."""

    def __init__(self, index: SourceIndex) -> None:
        try:
            from pcresolve import FlowAnalyzer
        except ImportError as exc:  # pragma: no cover - packaging failure
            raise ResolutionError("PCResolve is required; install pcresolve>=1.0.6,<2") from exc
        self._analyzer = FlowAnalyzer(
            source_files=index.files,
            import_roots=index.source.import_roots,
        )
        self._analysis_cache = {}

    def analyze(self, function: FunctionIdentity, max_depth: int = 1) -> Any:
        from pcresolve import FunctionRef

        cache_key = (function, max_depth)
        cached = self._analysis_cache.get(cache_key)
        if cached is not None:
            return cached
        entry = FunctionRef(
            module=function.module,
            qualname=function.qualname,
            file_path=str(function.file_path or ""),
            lineno=function.lineno or 0,
        )
        try:
            analysis = self._analyzer.analyze(entry, max_depth=max_depth)
        except (KeyError, RuntimeError, ValueError) as exc:
            raise ResolutionError(str(exc)) from exc
        self._analysis_cache[cache_key] = analysis
        return analysis


@dataclass
class AnalysisContext:
    """Reusable source and PCResolve state for one library source version."""

    index: SourceIndex
    adapter: PCResolveAdapter

    @classmethod
    def from_source(cls, source: SourceContext) -> "AnalysisContext":
        return cls.from_index(build_source_index(source))

    @classmethod
    def from_index(cls, index: SourceIndex) -> "AnalysisContext":
        return cls(index=index, adapter=PCResolveAdapter(index))


def identity_from_target(target: Any) -> FunctionIdentity:
    path = getattr(target, "file_path", "")
    return FunctionIdentity(
        module=getattr(target, "module", ""),
        qualname=getattr(target, "qualname", ""),
        file_path=Path(path) if path else None,
        lineno=getattr(target, "lineno", 0) or None,
    )


def direct_calls(analysis: Any, caller: FunctionIdentity) -> Iterable[Any]:
    for call in analysis.calls:
        if call.caller.module == caller.module and call.caller.qualname == caller.qualname:
            yield call


def forwards_parameter(call: Any, parameter: str, kind: VariadicKind) -> bool:
    return any(
        flow.get("source_parameter") == parameter
        and _is_variadic_expansion(flow.get("argument", {}), kind)
        for flow in call.parameter_flows
    )


def parameter_reaches_call(call: Any, parameter: str) -> bool:
    return any(flow.get("source_parameter") == parameter for flow in call.parameter_flows)


def forwarding_is_conditional(call: Any, parameter: str) -> bool:
    return any(
        bool(flow.get("conditions"))
        for flow in call.parameter_flows
        if flow.get("source_parameter") == parameter
    )


def call_span(call: Any) -> SourceSpan:
    path = call.caller.file_path or ""
    return SourceSpan(
        file_path=Path(path),
        lineno=call.lineno,
        col_offset=call.col_offset,
        end_lineno=call.end_lineno or call.lineno,
        end_col_offset=call.end_col_offset or call.col_offset,
    )


def _is_variadic_expansion(argument: dict, kind: VariadicKind) -> bool:
    if kind is VariadicKind.POSITIONAL:
        return bool(argument.get("starred"))
    return "keyword" in argument and argument.get("keyword") is None
