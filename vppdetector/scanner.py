"""Standalone package scanner for latent variadic forwarding mismatches."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence, Union

from .core import (
    AnalysisContext,
    ResolutionError,
    call_span,
    candidate_identities,
    direct_calls,
    forwards_parameter,
    identity_from_target,
)
from .models import (
    AnalysisBoundary,
    FindingKind,
    ForwardingFinding,
    ScanReport,
    SourceContext,
    VariadicFunction,
)
from .source import SourceIndex, build_source_index

PathLike = Union[str, Path]


def scan_package(
    package_root: PathLike,
    *,
    import_roots: Optional[Sequence[PathLike]] = None,
) -> ScanReport:
    """Scan one source version for variadic forwarding structures.

    This is intentionally a single-version structural scan. It does not infer
    API evolution or compare two library releases.
    """

    source = SourceContext(
        package_root=Path(package_root),
        import_roots=tuple(Path(path) for path in (import_roots or ())),
    )
    index = build_source_index(source)
    if not index.files:
        boundary = AnalysisBoundary(
            code="no_python_sources",
            message="No Python source files were found under the package root.",
        )
        return ScanReport(
            source=index.source,
            functions_scanned=0,
            variadic_functions=(),
            findings=(),
            boundaries=(*index.boundaries, boundary),
        )
    context = AnalysisContext.from_index(index)
    variadic_functions: List[VariadicFunction] = []
    findings: List[ForwardingFinding] = []
    boundaries: List[AnalysisBoundary] = list(index.boundaries)
    schema_version: Optional[str] = None

    for function in index.functions:
        if function.is_overload or not function.variadic_parameters:
            continue
        variadic_functions.append(VariadicFunction(function.identity, function.variadic_parameters))
        try:
            analysis = context.adapter.analyze(function.identity, max_depth=1)
        except ResolutionError as exc:
            boundaries.append(
                AnalysisBoundary(
                    code="entry_resolution_failed",
                    message=str(exc),
                    function=function.identity,
                )
            )
            continue
        schema_version = analysis.schema_version
        for call in direct_calls(analysis, function.identity):
            for parameter_name, parameter_kind in function.variadic_parameters:
                if not forwards_parameter(call, parameter_name, parameter_kind):
                    continue
                target_identity = identity_from_target(call.target) if call.target else None
                target_candidates = candidate_identities(call)
                target_definition = _target_definition(index, target_identity)
                ambiguity = _target_ambiguity(analysis, call.id)
                if target_definition is None:
                    if target_candidates:
                        kind = FindingKind.AMBIGUOUS_TARGET
                        reason_code = "source_target_candidates_only"
                    else:
                        kind = FindingKind.UNRESOLVED_TARGET
                        reason_code = "target_definition_unavailable"
                elif ambiguity:
                    kind = FindingKind.AMBIGUOUS_TARGET
                    reason_code = "pcresolve_{}".format(ambiguity)
                elif target_definition.signature.accepts_variadic(parameter_kind):
                    kind = FindingKind.FORWARDING_ACCEPTED_BY_VARIADIC
                    reason_code = "target_accepts_corresponding_variadic_parameter"
                else:
                    kind = FindingKind.LATENT_ACCEPTANCE_MISMATCH
                    reason_code = "target_lacks_corresponding_variadic_parameter"
                findings.append(
                    ForwardingFinding(
                        function=function.identity,
                        parameter_name=parameter_name,
                        parameter_kind=parameter_kind,
                        callee_expression=call.callee_name,
                        callsite=call_span(call),
                        target=target_identity,
                        kind=kind,
                        reason_code=reason_code,
                        target_candidates=target_candidates,
                        receiver_type_evidence=tuple(getattr(call, "receiver_type_evidence", ())),
                    )
                )

    return ScanReport(
        source=index.source,
        functions_scanned=len(index.functions),
        variadic_functions=tuple(variadic_functions),
        findings=tuple(findings),
        boundaries=tuple(boundaries),
        analyzer_schema_version=schema_version,
    )


def _target_definition(index: SourceIndex, target: object):
    if target is None or target.file_path is None or target.lineno is None:
        return None
    return index.find_by_location(target.file_path, target.lineno)


def _target_ambiguity(analysis: object, call_id: str) -> Optional[str]:
    handled_reasons = {
        "depth_limit",
        "dynamic_argument_expansion",
        "invalid_argument_binding",
    }
    for boundary in analysis.boundaries:
        if boundary.get("call_id") != call_id:
            continue
        reason = boundary.get("reason", "analyzer_boundary")
        if reason not in handled_reasons:
            return reason
    return None
