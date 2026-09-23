"""Change-conditioned VPP compatibility assessment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .binding import bind_callsite
from .core import (
    AnalysisContext,
    PCResolveAdapter,
    ResolutionError,
    call_span,
    direct_calls,
    forwarding_is_conditional,
    forwards_parameter,
    identity_from_target,
    parameter_reaches_call,
)
from .keyflow import KeyEffect, KeyPresence, analyze_mapping_key
from .models import (
    AnalysisBoundary,
    ArgumentEffect,
    BindingStatus,
    DownstreamSink,
    EntryBinding,
    FunctionIdentity,
    SourceContext,
    VariadicKind,
    Verdict,
    VPPAssessment,
    VPPRequest,
)
from .source import IndexedFunction, SourceIndex


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
    consumed: int = 0
    renamed: int = 0


def assess_change(
    request: VPPRequest,
    *,
    _context: Optional[AnalysisContext] = None,
) -> VPPAssessment:
    """Assess one pre-detected delete/rename against the target implementation."""

    context = _context or AnalysisContext.from_source(request.source)
    index = context.index
    function = index.find(request.target_api)
    if function is None:
        return _assessment(
            request,
            Verdict.UNKNOWN,
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
            ArgumentEffect.UNKNOWN,
            "capture_parameter_not_present",
            "The target signature does not contain the declared variadic capture.",
            boundaries=index.boundaries,
        )

    entry_binding = None
    if request.callsite is not None:
        entry_binding = bind_callsite(request.callsite, function, change)
        early = _assessment_from_entry_binding(
            request=request,
            binding=entry_binding,
            boundaries=index.boundaries,
        )
        if early is not None:
            return early

    if change.capture_kind is VariadicKind.POSITIONAL:
        boundary = AnalysisBoundary(
            code="positional_element_tracking_not_implemented",
            message="Element-level *args assessment requires a concrete positional binding model.",
            function=function.identity,
        )
        return _assessment(
            request,
            Verdict.UNKNOWN,
            ArgumentEffect.UNKNOWN,
            boundary.code,
            boundary.message,
            boundaries=(*index.boundaries, boundary),
            entry_binding=entry_binding,
        )

    outcome, schema_version = _trace_keyword(
        index=index,
        adapter=context.adapter,
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
                ArgumentEffect.FORWARDED,
                "path_dependent_downstream_rejection",
                "The old keyword is rejected on at least one feasible forwarding path.",
                sinks=tuple(outcome.sinks),
                boundaries=boundaries,
                schema_version=schema_version,
                entry_binding=entry_binding,
            )
        return _assessment(
            request,
            Verdict.MUST_FAIL,
            ArgumentEffect.REJECTED,
            "downstream_rejects_old_keyword",
            "The old keyword reaches a fixed signature that cannot bind it.",
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
            entry_binding=entry_binding,
        )

    if outcome.boundaries:
        primary = outcome.boundaries[0]
        return _assessment(
            request,
            Verdict.UNKNOWN,
            ArgumentEffect.FORWARDED if outcome.sinks else ArgumentEffect.UNKNOWN,
            primary.code,
            primary.message,
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
            entry_binding=entry_binding,
        )

    if outcome.accepted:
        return _assessment(
            request,
            Verdict.SAFE,
            ArgumentEffect.ACCEPTED,
            "downstream_accepts_old_keyword",
            "Every terminal forwarding target explicitly accepts the old keyword.",
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
            entry_binding=entry_binding,
        )

    if outcome.renamed:
        return _assessment(
            request,
            Verdict.SAFE,
            ArgumentEffect.RENAMED,
            "old_argument_renamed_locally",
            "The captured old keyword is consumed and retained under another local key.",
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
            entry_binding=entry_binding,
        )

    if outcome.consumed:
        return _assessment(
            request,
            Verdict.SAFE,
            ArgumentEffect.CONSUMED,
            "old_argument_consumed_locally",
            "The captured old keyword is consumed before downstream variadic forwarding.",
            sinks=tuple(outcome.sinks),
            boundaries=boundaries,
            schema_version=schema_version,
            entry_binding=entry_binding,
        )

    return _assessment(
        request,
        Verdict.SAFE,
        ArgumentEffect.DROPPED,
        "old_argument_not_forwarded",
        "The captured old keyword is not expanded into a rejecting downstream call.",
        sinks=tuple(outcome.sinks),
        boundaries=boundaries,
        schema_version=schema_version,
        entry_binding=entry_binding,
    )


def _assessment_from_entry_binding(
    *,
    request: VPPRequest,
    binding: EntryBinding,
    boundaries: Sequence[AnalysisBoundary],
) -> Optional[VPPAssessment]:
    if binding.status is BindingStatus.NOT_EXERCISED:
        return _assessment(
            request,
            Verdict.NOT_APPLICABLE,
            ArgumentEffect.UNKNOWN,
            binding.reason_code,
            "The concrete call does not pass the changed argument.",
            boundaries=boundaries,
            entry_binding=binding,
        )
    if binding.status is BindingStatus.UNKNOWN:
        boundary = AnalysisBoundary(
            code=binding.reason_code,
            message="The concrete call could not be bound conclusively to the new signature.",
            function=request.target_api,
        )
        return _assessment(
            request,
            Verdict.UNKNOWN,
            ArgumentEffect.UNKNOWN,
            boundary.code,
            boundary.message,
            boundaries=(*boundaries, boundary),
            entry_binding=binding,
        )
    if binding.status is BindingStatus.INVALID:
        replacement = request.change.new_name
        missing_replacement = bool(replacement and replacement in binding.missing_required)
        captured_old_name = binding.changed_argument_target == request.change.captured_by
        if missing_replacement and captured_old_name:
            return _assessment(
                request,
                Verdict.MUST_FAIL,
                ArgumentEffect.REJECTED,
                "renamed_parameter_unbound",
                (
                    "The old keyword is captured variadically while its required "
                    "replacement remains unbound."
                ),
                boundaries=boundaries,
                entry_binding=binding,
            )
        boundary = AnalysisBoundary(
            code=binding.reason_code,
            message=(
                "The concrete call is invalid for a reason not proven to be caused by this change."
            ),
            function=request.target_api,
        )
        return _assessment(
            request,
            Verdict.UNKNOWN,
            ArgumentEffect.UNKNOWN,
            boundary.code,
            boundary.message,
            boundaries=(*boundaries, boundary),
            entry_binding=binding,
        )
    if binding.changed_argument_target != request.change.captured_by:
        return _assessment(
            request,
            Verdict.NOT_APPLICABLE,
            ArgumentEffect.UNKNOWN,
            "changed_argument_not_variadically_captured",
            (
                "The concrete call binds the changed argument without using the "
                "declared variadic capture."
            ),
            boundaries=boundaries,
            entry_binding=binding,
        )
    return None


def assess_changes(requests: Iterable[VPPRequest]) -> Tuple[VPPAssessment, ...]:
    """Assess requests while reusing analysis state for each source version."""

    contexts: Dict[SourceContext, AnalysisContext] = {}
    results = []
    for request in requests:
        context = contexts.get(request.source)
        if context is None:
            context = AnalysisContext.from_source(request.source)
            contexts[request.source] = context
        results.append(assess_change(request, _context=context))
    return tuple(results)


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
        key_flow = analyze_mapping_key(state.function, state.parameter, old_name)
        if key_flow.raised_paths:
            outcome.boundaries.append(
                AnalysisBoundary(
                    code="mapping_control_flow_may_raise",
                    message="The analyzed function has a reachable raise or assertion path.",
                    function=identity,
                )
            )
        expanded = False
        indirect = False
        relevant_call_ids = set()

        for call in direct_calls(analysis, identity):
            if not parameter_reaches_call(call, state.parameter):
                continue
            relevant_call_ids.add(call.id)
            span = call_span(call)
            if key_flow.is_recognized_mutation(span):
                continue
            if not forwards_parameter(call, state.parameter, VariadicKind.KEYWORD):
                indirect = True
                continue
            expanded = True
            presences = key_flow.presence_at(span)
            if not presences:
                if key_flow.recognized_mutations or key_flow.terminal_effects:
                    presences = frozenset({KeyPresence.UNKNOWN})
                else:
                    presences = frozenset({KeyPresence.PRESENT})
            if presences == frozenset({KeyPresence.ABSENT}):
                outcome.dropped += 1
                continue
            conditional_presence = KeyPresence.ABSENT in presences
            if conditional_presence:
                outcome.dropped += 1
            if KeyPresence.UNKNOWN in presences:
                outcome.boundaries.append(
                    AnalysisBoundary(
                        code="mapping_key_state_unknown",
                        message="The old keyword's presence at a forwarding call is uncertain.",
                        function=identity,
                        callsite=span,
                    )
                )
            conditional = (
                state.conditional
                or conditional_presence
                or KeyPresence.UNKNOWN in presences
                or key_flow.is_exception_guarded(span)
                or forwarding_is_conditional(call, state.parameter)
            )
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
        if any(terminal.presence is KeyPresence.UNKNOWN for terminal in key_flow.terminal_states):
            outcome.boundaries.append(
                AnalysisBoundary(
                    code="mapping_key_state_unknown",
                    message="The old keyword's final mapping state is uncertain.",
                    function=identity,
                )
            )
        if key_flow.every_terminal_has(KeyEffect.RENAMED):
            outcome.renamed += 1
        elif key_flow.every_terminal_has(KeyEffect.CONSUMED):
            outcome.consumed += 1

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
    effect: ArgumentEffect,
    reason_code: str,
    message: str,
    *,
    sinks: Tuple[DownstreamSink, ...] = (),
    boundaries: Sequence[AnalysisBoundary] = (),
    schema_version: Optional[str] = None,
    entry_binding: Optional[EntryBinding] = None,
) -> VPPAssessment:
    return VPPAssessment(
        request=request,
        verdict=verdict,
        argument_effect=effect,
        reason_code=reason_code,
        message=message,
        sinks=sinks,
        boundaries=tuple(boundaries),
        analyzer_schema_version=schema_version,
        entry_binding=entry_binding,
    )
