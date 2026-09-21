"""Change-conditioned VPP compatibility assessment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

from .flow import (
    call_span,
    direct_calls,
    forwarding_is_conditional,
    forwards_parameter,
    parameter_reaches_call,
)
from .models import (
    AnalysisBoundary,
    ArgumentEffect,
    ChangeKind,
    DownstreamSink,
    FunctionIdentity,
    RepairAction,
    VariadicKind,
    Verdict,
    VPPAssessment,
    VPPRequest,
)
from .resolution import PCResolveAdapter, ResolutionError, identity_from_target
from .source import IndexedFunction, SourceIndex, build_source_index, parameter_is_mutated


@dataclass(frozen=True)
class _FlowState:
    function: IndexedFunction
    parameter: str
    depth: int
    conditional: bool = False
    ancestry: Tuple[Tuple[str, str, int, str], ...] = ()


@dataclass
class _FlowOutcome:
    sinks: List[DownstreamSink] = field(default_factory=list)
    boundaries: List[AnalysisBoundary] = field(default_factory=list)
    rejected: int = 0
    conditional_rejections: int = 0
    accepted: int = 0
    dropped: int = 0


def assess_change(request: VPPRequest) -> VPPAssessment:
    """Assess one pre-detected delete/rename against the target implementation."""

    index = build_source_index(request.source)
    function = index.find(request.target_api)
    if function is None:
        return _assessment(
            request,
            Verdict.UNKNOWN,
            RepairAction.MANUAL_REVIEW,
            ArgumentEffect.UNKNOWN,
            "target_api_not_found",
            "The target API definition could not be selected uniquely.",
            boundaries=index.boundaries,
        )

    change = request.change
    expected_capture = (
        function.signature.kwarg
        if change.capture_kind is VariadicKind.KEYWORD
        else function.signature.vararg
    )
    if expected_capture != change.captured_by:
        return _assessment(
            request,
            Verdict.NOT_APPLICABLE,
            RepairAction.NONE,
            ArgumentEffect.UNKNOWN,
            "capture_parameter_not_present",
            "The target signature does not contain the declared variadic capture.",
            boundaries=index.boundaries,
        )

    if change.capture_kind is VariadicKind.POSITIONAL:
        boundary = AnalysisBoundary(
            code="positional_element_tracking_not_implemented",
            message="Element-level *args assessment requires a concrete positional binding model.",
            function=function.identity,
        )
        return _assessment(
            request,
            Verdict.UNKNOWN,
            RepairAction.MANUAL_REVIEW,
            ArgumentEffect.UNKNOWN,
            boundary.code,
            boundary.message,
            boundaries=(*index.boundaries, boundary),
        )

    adapter = PCResolveAdapter(index)
    outcome, schema_version = _trace_keyword(
        index=index,
        adapter=adapter,
        entry=function,
        parameter=change.captured_by,
        old_name=change.old_name,
        max_depth=request.max_depth,
    )
    boundaries = (*index.boundaries, *outcome.boundaries)

    if outcome.rejected:
        if (
            outcome.accepted
            or outcome.dropped
            or outcome.boundaries
            or outcome.conditional_rejections
        ):
            return _assessment(
                request,
                Verdict.MAY_FAIL,
                RepairAction.MANUAL_REVIEW,
                ArgumentEffect.FORWARDED,
                "path_dependent_downstream_rejection",
                "The old keyword is rejected on at least one feasible forwarding path.",
                sinks=tuple(outcome.sinks),
                boundaries=boundaries,
                schema_version=schema_version,
            )
        action = RepairAction.DELETE if change.kind is ChangeKind.DELETE else RepairAction.RENAME
        return _assessment(
            request,
            Verdict.MUST_FAIL,
            action,
            ArgumentEffect.REJECTED,
            "downstream_rejects_old_keyword",
            "The old keyword reaches a fixed signature that cannot bind it.",
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
        )

    if outcome.boundaries:
        primary = outcome.boundaries[0]
        return _assessment(
            request,
            Verdict.UNKNOWN,
            RepairAction.MANUAL_REVIEW,
            ArgumentEffect.FORWARDED if outcome.sinks else ArgumentEffect.UNKNOWN,
            primary.code,
            primary.message,
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
        )

    if outcome.accepted:
        return _assessment(
            request,
            Verdict.SAFE,
            RepairAction.PRESERVE,
            ArgumentEffect.ACCEPTED,
            "downstream_accepts_old_keyword",
            "Every terminal forwarding target explicitly accepts the old keyword.",
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
        )

    return _assessment(
        request,
        Verdict.SAFE,
        RepairAction.PRESERVE,
        ArgumentEffect.DROPPED,
        "old_argument_not_forwarded",
        "The captured old keyword is not expanded into a rejecting downstream call.",
        sinks=tuple(outcome.sinks),
        boundaries=boundaries,
        schema_version=schema_version,
    )


def assess_changes(requests: Iterable[VPPRequest]) -> Tuple[VPPAssessment, ...]:
    """Convenience batch wrapper; it does not compare library versions."""

    return tuple(assess_change(request) for request in requests)


def _trace_keyword(
    *,
    index: SourceIndex,
    adapter: PCResolveAdapter,
    entry: IndexedFunction,
    parameter: str,
    old_name: str,
    max_depth: int,
) -> Tuple[_FlowOutcome, Optional[str]]:
    outcome = _FlowOutcome()
    pending = [_FlowState(entry, parameter, 0)]
    schema_version: Optional[str] = None

    while pending:
        state = pending.pop()
        identity = state.function.identity
        key = (
            identity.module,
            identity.qualname,
            identity.lineno or 0,
            state.parameter,
        )
        if key in state.ancestry:
            outcome.boundaries.append(
                AnalysisBoundary(
                    code="recursive_variadic_forwarding",
                    message="A recursive variadic forwarding cycle was encountered.",
                    function=identity,
                )
            )
            continue

        if parameter_is_mutated(state.function, state.parameter):
            outcome.boundaries.append(
                AnalysisBoundary(
                    code="variadic_capture_mutated",
                    message="A propagated **kwargs mapping is mutated before or during forwarding.",
                    function=identity,
                )
            )
            continue

        try:
            analysis = adapter.analyze(identity, max_depth=1)
        except ResolutionError as exc:
            outcome.boundaries.append(
                AnalysisBoundary(
                    code="entry_resolution_failed",
                    message=str(exc),
                    function=identity,
                )
            )
            continue
        schema_version = analysis.schema_version
        expanded = False
        indirect = False
        relevant_call_ids = set()

        for call in direct_calls(analysis, identity):
            if not parameter_reaches_call(call, state.parameter):
                continue
            relevant_call_ids.add(call.id)
            if not forwards_parameter(call, state.parameter, VariadicKind.KEYWORD):
                indirect = True
                continue
            expanded = True
            conditional = state.conditional or forwarding_is_conditional(call, state.parameter)
            target_identity = identity_from_target(call.target) if call.target else None
            target_definition = _target_definition(index, target_identity)

            if target_definition is None:
                outcome.sinks.append(
                    DownstreamSink(
                        callee_expression=call.callee_name,
                        callsite=call_span(call),
                        target=target_identity,
                        accepts_changed_argument=None,
                        reason_code="target_definition_unavailable",
                        conditional=conditional,
                    )
                )
                outcome.boundaries.append(
                    AnalysisBoundary(
                        code="downstream_target_unresolved",
                        message="A forwarding target could not be resolved exactly.",
                        function=identity,
                        callsite=call_span(call),
                    )
                )
                continue

            if target_definition.signature.explicitly_accepts_keyword(old_name):
                outcome.sinks.append(
                    DownstreamSink(
                        callee_expression=call.callee_name,
                        callsite=call_span(call),
                        target=target_identity,
                        accepts_changed_argument=True,
                        reason_code="target_explicitly_accepts_old_keyword",
                        conditional=conditional,
                    )
                )
                outcome.accepted += 1
                continue

            if target_definition.signature.kwarg:
                outcome.sinks.append(
                    DownstreamSink(
                        callee_expression=call.callee_name,
                        callsite=call_span(call),
                        target=target_identity,
                        accepts_changed_argument=True,
                        reason_code="forwarded_to_variadic_target",
                        conditional=conditional,
                    )
                )
                if state.depth + 1 >= max_depth:
                    outcome.boundaries.append(
                        AnalysisBoundary(
                            code="max_forwarding_depth_reached",
                            message="Variadic forwarding exceeded the configured depth limit.",
                            function=target_definition.identity,
                        )
                    )
                    continue
                pending.append(
                    _FlowState(
                        function=target_definition,
                        parameter=target_definition.signature.kwarg,
                        depth=state.depth + 1,
                        conditional=conditional,
                        ancestry=(*state.ancestry, key),
                    )
                )
                continue

            outcome.sinks.append(
                DownstreamSink(
                    callee_expression=call.callee_name,
                    callsite=call_span(call),
                    target=target_identity,
                    accepts_changed_argument=False,
                    reason_code="target_rejects_old_keyword",
                    conditional=conditional,
                )
            )
            outcome.rejected += 1
            if conditional:
                outcome.conditional_rejections += 1

        outcome.boundaries.extend(
            _unhandled_analyzer_boundaries(
                analysis=analysis,
                relevant_call_ids=relevant_call_ids,
                function=identity,
            )
        )

        if indirect:
            outcome.boundaries.append(
                AnalysisBoundary(
                    code="indirect_parameter_transformation",
                    message="The variadic capture reaches a call without a supported ** expansion.",
                    function=identity,
                )
            )
        if not expanded and not indirect:
            outcome.dropped += 1

    return outcome, schema_version


def _unhandled_analyzer_boundaries(
    *,
    analysis: object,
    relevant_call_ids: set,
    function: FunctionIdentity,
) -> List[AnalysisBoundary]:
    handled_reasons = {
        "definition_unavailable",
        "depth_limit",
        "dynamic_argument_expansion",
        "invalid_argument_binding",
        "receiver_unresolved",
    }
    boundaries = []
    for item in analysis.boundaries:
        reason = item.get("reason", "analyzer_boundary")
        call_id = item.get("call_id")
        if call_id and call_id not in relevant_call_ids:
            continue
        if reason in handled_reasons:
            continue
        boundaries.append(
            AnalysisBoundary(
                code="pcresolve_{}".format(reason),
                message="PCResolve reported an unhandled analysis boundary: {}.".format(reason),
                function=function,
            )
        )
    return boundaries


def _target_definition(
    index: SourceIndex,
    target: Optional[FunctionIdentity],
) -> Optional[IndexedFunction]:
    if target is None or target.file_path is None or target.lineno is None:
        return None
    return index.find_by_location(target.file_path, target.lineno)


def _assessment(
    request: VPPRequest,
    verdict: Verdict,
    action: RepairAction,
    effect: ArgumentEffect,
    reason_code: str,
    message: str,
    *,
    sinks: Tuple[DownstreamSink, ...] = (),
    boundaries: Sequence[AnalysisBoundary] = (),
    schema_version: Optional[str] = None,
) -> VPPAssessment:
    return VPPAssessment(
        request=request,
        verdict=verdict,
        recommended_action=action,
        argument_effect=effect,
        reason_code=reason_code,
        message=message,
        sinks=sinks,
        boundaries=tuple(boundaries),
        analyzer_schema_version=schema_version,
    )
