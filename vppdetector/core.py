"""Shared PCResolve facts and structural rules for both VPP scan scopes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple

from .models import (
    AnalysisBoundary,
    ForwardingFinding,
    ForwardingStep,
    FunctionIdentity,
    SourceContext,
    SourceSpan,
    VariadicKind,
)
from .source import IndexedFunction, SourceIndex, build_source_index


class ResolutionError(RuntimeError):
    """Raised when PCResolve cannot analyze an explicit source entry."""


class PCResolveAdapter:
    """Narrow adapter around PCResolve's value-flow API."""

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
    _scan_cache: dict = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def from_source(cls, source: SourceContext) -> "AnalysisContext":
        return cls.from_index(build_source_index(source))

    @classmethod
    def from_index(cls, index: SourceIndex) -> "AnalysisContext":
        return cls(index=index, adapter=PCResolveAdapter(index))

    def resolve_api(self, identity: FunctionIdentity) -> Optional[IndexedFunction]:
        entry = self.index.find(identity) or self.index.resolve_imported(identity)
        if entry is not None:
            return entry
        if identity.file_path or identity.lineno:
            return None
        # Inherited methods are resolved by PCResolve, not by name heuristics.
        analysis = self.adapter.analyze(identity)
        return self.index.find(identity_from_target(analysis.entry))


def identity_from_target(target: Any) -> FunctionIdentity:
    def value(name: str, default: Any) -> Any:
        if isinstance(target, dict):
            return target.get(name, default)
        return getattr(target, name, default)

    path = value("file_path", "")
    return FunctionIdentity(
        module=value("module", ""),
        qualname=value("qualname", ""),
        file_path=Path(path) if path else None,
        lineno=value("lineno", 0) or None,
    )


def candidate_identities(call: Any) -> tuple[FunctionIdentity, ...]:
    result = []
    for candidate in getattr(call, "target_candidates", ()):
        identity = identity_from_target(candidate)
        if identity not in result:
            result.append(identity)
    return tuple(result)


def direct_calls(analysis: Any, caller: FunctionIdentity) -> Iterable[Any]:
    for call in analysis.calls:
        owner = identity_from_target(call.caller)
        if (
            owner.module == caller.module
            and owner.qualname == caller.qualname
            and (not caller.lineno or owner.lineno == caller.lineno)
            and (not caller.file_path or owner.file_path == caller.file_path)
        ):
            yield call


def call_span(call: Any) -> SourceSpan:
    return SourceSpan(
        file_path=Path(call.caller.file_path or ""),
        lineno=call.lineno,
        col_offset=call.col_offset,
        end_lineno=call.end_lineno or call.lineno,
        end_col_offset=call.end_col_offset or call.col_offset,
    )


def _expansion_kind(argument: dict) -> Optional[VariadicKind]:
    if argument.get("starred"):
        return VariadicKind.POSITIONAL
    if "keyword" in argument and argument["keyword"] is None:
        return VariadicKind.KEYWORD
    return None


def _whole_container(flow: dict) -> bool:
    """Require an open container, not a selected element or dict key."""

    if flow.get("projection") or flow.get("container_role") == "key":
        return False
    path = flow.get("output_path", [])
    if flow.get("relation") == "direct" and not path:
        return True
    return flow.get("relation") in {"contained", "derived"} and path == ["*"]


@dataclass(frozen=True)
class _State:
    function: IndexedFunction
    parameter: str
    origin_parameter: str
    kind: VariadicKind
    path: Tuple[ForwardingStep, ...] = ()
    ancestry: tuple = ()


def scan_function(
    context: AnalysisContext, entry: IndexedFunction, max_depth: int = 5
) -> tuple[tuple[ForwardingFinding, ...], tuple[AnalysisBoundary, ...], Optional[str]]:
    """Follow open variadic containers to fixed expansion signatures.

    Ordinary arguments carry containers across helpers but never constitute
    sinks themselves. The result is a structural pattern, not a client-call
    compatibility decision or a claim of guaranteed runtime failure.
    """

    cache_key = (entry.identity, max_depth)
    if cache_key in context._scan_cache:
        return context._scan_cache[cache_key]
    pending = [_State(entry, name, name, kind) for name, kind in entry.variadic_parameters]
    findings = []
    boundaries = []
    schema = None
    while pending:
        state = pending.pop(0)
        identity = state.function.identity
        state_key = (identity, state.parameter, state.kind)
        if state_key in state.ancestry:
            boundaries.append(
                AnalysisBoundary("recursive_forwarding", "Recursive forwarding path.", identity)
            )
            continue
        try:
            analysis = context.adapter.analyze(identity)
        except ResolutionError as exc:
            boundaries.append(AnalysisBoundary("flow_analysis_failed", str(exc), identity))
            continue
        schema = getattr(analysis, "schema_version", schema)
        relevant_calls = set()
        for call in direct_calls(analysis, identity):
            flows = [
                flow
                for flow in call.parameter_flows
                if flow.get("source_parameter") == state.parameter
            ]
            if not flows:
                continue
            relevant_calls.add(call.id)
            carried = [flow for flow in flows if _whole_container(flow)]
            span = call_span(call)
            uncertain_operation = _carrier_operation_boundary(
                analysis, identity, state.parameter, call
            )
            if carried and uncertain_operation is not None:
                boundaries.append(
                    AnalysisBoundary(
                        "unsupported_carrier_operation",
                        "Unknown receiver effect obscures later container contents.",
                        identity,
                        uncertain_operation,
                    )
                )
                continue
            if not carried:
                boundaries.append(
                    AnalysisBoundary(
                        "unsupported_variadic_transformation",
                        "Flow facts do not establish an open variadic container at this call.",
                        identity,
                        span,
                    )
                )
                continue
            candidates = candidate_identities(call)
            selected = identity_from_target(call.target) if call.target else None
            targets = (
                (selected,)
                if selected and call.target_status == "resolved"
                else tuple(dict.fromkeys(((selected,) if selected else ()) + candidates))
            )
            if not targets:
                boundaries.append(
                    AnalysisBoundary(
                        "downstream_target_unresolved",
                        "No source target for forwarding call.",
                        identity,
                        span,
                    )
                )
                continue
            for target in targets:
                definition = (
                    context.index.find_by_location(target.file_path, target.lineno)
                    if target.file_path and target.lineno
                    else context.index.find(target)
                )
                if definition is None:
                    boundaries.append(
                        AnalysisBoundary(
                            "target_definition_unavailable",
                            "Forwarding target source is unavailable.",
                            identity,
                            span,
                        )
                    )
                    continue
                status = _target_status(analysis, call)
                step = ForwardingStep(
                    identity,
                    state.parameter,
                    call.callee_name,
                    span,
                    definition.identity,
                    status,
                )
                path = (*state.path, step)
                for flow in carried:
                    expansion = _expansion_kind(flow.get("argument", {}))
                    if expansion is not None:
                        if expansion != state.kind:
                            boundaries.append(
                                AnalysisBoundary(
                                    "variadic_channel_transformation",
                                    "Cross-channel variadic expansion is not supported.",
                                    identity,
                                    span,
                                )
                            )
                            continue
                        if not definition.signature.accepts_variadic(expansion):
                            finding = ForwardingFinding(
                                function=entry.identity,
                                parameter_name=state.origin_parameter,
                                parameter_kind=state.kind,
                                callee_expression=call.callee_name,
                                callsite=span,
                                target=definition.identity,
                                reason_code="target_lacks_corresponding_variadic_parameter",
                                path=path,
                                target_status=status,
                                target_candidates=candidates,
                                receiver_type_evidence=tuple(
                                    getattr(call, "receiver_type_evidence", ())
                                ),
                            )
                            if finding not in findings:
                                findings.append(finding)
                            continue
                        next_parameter = (
                            definition.signature.kwarg
                            if expansion is VariadicKind.KEYWORD
                            else definition.signature.vararg
                        )
                    else:
                        next_parameter = flow.get("target_parameter")
                        if flow.get("target_path"):
                            next_parameter = None
                    if next_parameter not in _parameters(definition):
                        boundaries.append(
                            AnalysisBoundary(
                                "propagation_binding_unavailable",
                                "No whole-container binding to a downstream formal parameter.",
                                identity,
                                span,
                            )
                        )
                        continue
                    if len(path) >= max_depth:
                        boundaries.append(
                            AnalysisBoundary(
                                "max_forwarding_depth_reached",
                                "Forwarding depth limit reached.",
                                identity,
                                span,
                            )
                        )
                        continue
                    next_state = _State(
                        definition,
                        next_parameter,
                        state.origin_parameter,
                        state.kind,
                        path,
                        (*state.ancestry, state_key),
                    )
                    if next_state not in pending:
                        pending.append(next_state)
        boundaries.extend(_analysis_boundaries(analysis, identity, relevant_calls))
    result = (tuple(findings), tuple(dict.fromkeys(boundaries)), schema)
    context._scan_cache[cache_key] = result
    return result


def _parameters(function: IndexedFunction) -> tuple:
    signature = function.signature
    return tuple(
        name
        for name in (
            *signature.positional_only,
            *signature.positional_or_keyword,
            *signature.keyword_only,
            signature.vararg,
            signature.kwarg,
        )
        if name is not None
    )


def _carrier_operation_boundary(
    analysis: Any, identity: FunctionIdentity, parameter: str, destination: Any
) -> Optional[SourceSpan]:
    """Do not assume a helper's generic formal survives unknown receiver effects."""

    destination_end = (
        destination.end_lineno or destination.lineno,
        destination.end_col_offset or destination.col_offset,
    )
    for call in direct_calls(analysis, identity):
        if call.target_status != "receiver_unresolved":
            continue
        if (call.lineno, call.col_offset) > destination_end:
            continue
        if any(
            value.get("kind") == "parameter"
            and value.get("source") == parameter
            and _whole_container(value)
            for value in call.receiver_sources
        ):
            return call_span(call)
    return None


def _target_status(analysis: Any, call: Any) -> str:
    if call.target_status != "resolved":
        return call.target_status
    if any(
        boundary.get("call_id") == call.id
        and boundary.get("reason", "").startswith("dynamic_")
        and boundary.get("reason") != "dynamic_argument_expansion"
        for boundary in analysis.boundaries
    ):
        return "source_candidate"
    return "resolved"


def _analysis_boundaries(
    analysis: Any, identity: FunctionIdentity, relevant_calls: set
) -> Iterable[AnalysisBoundary]:
    calls = {call.id: call for call in direct_calls(analysis, identity)}
    for boundary in analysis.boundaries:
        reason = boundary.get("reason", "unspecified")
        # The scanner composes its own depth-limited container paths. Unknown
        # expansion elements are its input, not concrete client-binding errors.
        if reason in {"depth_limit", "dynamic_argument_expansion"}:
            continue
        call_id = boundary.get("call_id")
        if call_id and call_id not in relevant_calls:
            if call_id not in calls or reason not in {
                "unsupported_expression",
                "receiver_unresolved",
                "definition_unavailable",
            }:
                continue
        yield AnalysisBoundary(
            "pcresolve_" + reason,
            "PCResolve boundary: {}.".format(reason),
            identity,
            call_span(calls[call_id]) if call_id in calls else None,
        )
