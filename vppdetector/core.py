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
    if isinstance(target, dict):
        path = target.get("file_path", "")
        module = target.get("module", "")
        qualname = target.get("qualname", "")
        lineno = target.get("lineno", 0)
    else:
        path = getattr(target, "file_path", "")
        module = getattr(target, "module", "")
        qualname = getattr(target, "qualname", "")
        lineno = getattr(target, "lineno", 0)
    return FunctionIdentity(
        module=module,
        qualname=qualname,
        file_path=Path(path) if path else None,
        lineno=lineno or None,
    )


def candidate_identities(call: Any) -> tuple[FunctionIdentity, ...]:
    """Read source candidates without treating them as certain runtime targets."""

    result = []
    for candidate in getattr(call, "target_candidates", ()):
        identity = identity_from_target(candidate)
        if identity not in result:
            result.append(identity)
    return tuple(result)


def direct_calls(analysis: Any, caller: FunctionIdentity) -> Iterable[Any]:
    for call in analysis.calls:
        if call.caller.module == caller.module and call.caller.qualname == caller.qualname:
            yield call


def mapping_effects(analysis: Any, function: FunctionIdentity) -> Iterable[dict]:
    """Return element effects for one exact analyzed function, when available."""

    for summary in analysis.functions:
        owner = summary.get("function", {})
        if (
            owner.get("module") == function.module
            and owner.get("qualname") == function.qualname
            and (not function.lineno or owner.get("lineno") == function.lineno)
        ):
            yield from summary.get("mapping_effects", ())


def forwards_parameter(call: Any, parameter: str, kind: VariadicKind) -> bool:
    return any(
        flow.get("source_parameter") == parameter
        and _is_variadic_expansion(flow.get("argument", {}), kind)
        for flow in call.parameter_flows
    )


def parameter_reaches_call(call: Any, parameter: str) -> bool:
    return any(flow.get("source_parameter") == parameter for flow in call.parameter_flows)


def mapping_reaches_callable_candidate(call: Any, parameter: str) -> bool:
    """Recognize an element-bearing mapping passed to a source-only callable."""

    if call.target_status != "callable_instance_candidate" or call.target is None:
        return False
    if not getattr(call, "callable_instance_evidence", None):
        return False
    return any(
        source.get("kind") == "parameter"
        and source.get("source") == parameter
        and "*" in source.get("output_path", ())
        for argument in getattr(call, "argument_sources", ())
        if not argument.get("argument", {}).get("starred")
        and argument.get("argument", {}).get("keyword", "ordinary") is not None
        for source in argument.get("sources", ())
    )


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
