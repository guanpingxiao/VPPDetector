"""Whole-package and on-demand scopes over the same VPP detection core."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import List, Optional, Sequence, Union

from .core import AnalysisContext, ResolutionError, scan_function
from .models import (
    AnalysisBoundary,
    ForwardingFinding,
    FunctionIdentity,
    ScanReport,
    SourceContext,
    VariadicFunction,
)
from .source import IndexedFunction, SourceIndex, build_source_index, normalized_import_roots

PathLike = Union[str, Path]
ScanSource = Union[PathLike, SourceContext]


def scan_package(
    package_root: ScanSource,
    *,
    import_roots: Optional[Sequence[PathLike]] = None,
    max_depth: int = 5,
    context: Optional[AnalysisContext] = None,
) -> ScanReport:
    """Find VPPs in one library version, optionally reusing analysis state."""

    _validate_depth(max_depth)
    index, context = _prepare_context(package_root, import_roots, context)
    if not index.files:
        return _empty_source_report(index)
    entries = tuple(function for function in index.functions if not function.is_overload)
    return _scan_entries(context, entries, max_depth=max_depth)


def scan_api(
    package_root: ScanSource,
    target_api: FunctionIdentity,
    *,
    import_roots: Optional[Sequence[PathLike]] = None,
    max_depth: int = 5,
    context: Optional[AnalysisContext] = None,
) -> ScanReport:
    """Find VPPs reachable from one API without assessing a client call.

    API identity resolution may follow imports, aliases and inherited methods.
    The requested API stays attached to findings while path steps identify the
    actual source implementations.
    """

    _validate_depth(max_depth)
    index, context = _prepare_context(package_root, import_roots, context)
    if not index.files:
        return replace(_empty_source_report(index), target_api=target_api)
    try:
        entry = context.resolve_api(target_api)
    except ResolutionError as exc:
        return _missing_api_report(index, target_api, "entry_resolution_failed", str(exc))
    if entry is None or entry.is_overload:
        return _missing_api_report(
            index,
            target_api,
            "target_api_unavailable",
            "The requested API could not be resolved to one source implementation.",
        )
    report = _scan_entries(context, (entry,), max_depth=max_depth)
    return replace(
        report,
        target_api=target_api,
        resolved_api=entry.identity,
        variadic_functions=tuple(
            replace(
                function,
                function=target_api,
                implementation=entry.identity if target_api != entry.identity else None,
            )
            for function in report.variadic_functions
        ),
        findings=tuple(replace(finding, function=target_api) for finding in report.findings),
    )


def _scan_entries(
    context: AnalysisContext,
    entries: Sequence[IndexedFunction],
    *,
    max_depth: int,
) -> ScanReport:
    variadic_functions: List[VariadicFunction] = []
    findings: List[ForwardingFinding] = []
    boundaries: List[AnalysisBoundary] = list(context.index.boundaries)
    schema_version: Optional[str] = None
    for entry in entries:
        if not entry.variadic_parameters:
            continue
        variadic_functions.append(VariadicFunction(entry.identity, entry.variadic_parameters))
        entry_findings, entry_boundaries, entry_schema = scan_function(context, entry, max_depth)
        findings.extend(entry_findings)
        boundaries.extend(entry_boundaries)
        if entry_schema is not None:
            schema_version = entry_schema
    return ScanReport(
        source=context.index.source,
        functions_scanned=len(entries),
        variadic_functions=tuple(variadic_functions),
        findings=tuple(findings),
        boundaries=tuple(boundaries),
        analyzer_schema_version=schema_version,
    )


def _prepare_context(
    package_root: ScanSource,
    import_roots: Optional[Sequence[PathLike]],
    context: Optional[AnalysisContext],
) -> tuple[SourceIndex, Optional[AnalysisContext]]:
    if isinstance(package_root, SourceContext):
        source = package_root
        if import_roots is not None:
            source = replace(source, import_roots=tuple(Path(path) for path in import_roots))
    else:
        source = SourceContext(
            package_root=Path(package_root),
            import_roots=tuple(Path(path) for path in (import_roots or ())),
        )
    if context is not None:
        expected = SourceContext(source.package_root.resolve(), normalized_import_roots(source))
        actual = context.index.source
        if (
            actual.package_root.resolve() != expected.package_root
            or normalized_import_roots(actual) != expected.import_roots
        ):
            raise ValueError("Analysis context must use the requested source root and import roots")
        return context.index, context
    index = build_source_index(source)
    return index, AnalysisContext.from_index(index) if index.files else None


def _validate_depth(max_depth: int) -> None:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")


def _empty_source_report(index: SourceIndex) -> ScanReport:
    return ScanReport(
        source=index.source,
        functions_scanned=0,
        variadic_functions=(),
        findings=(),
        boundaries=(
            *index.boundaries,
            AnalysisBoundary(
                code="no_python_sources",
                message="No Python source files were found under the package root.",
            ),
        ),
    )


def _missing_api_report(
    index: SourceIndex, target_api: FunctionIdentity, code: str, message: str
) -> ScanReport:
    return ScanReport(
        source=index.source,
        functions_scanned=0,
        variadic_functions=(),
        findings=(),
        boundaries=(
            *index.boundaries,
            AnalysisBoundary(code=code, message=message, function=target_api),
        ),
        target_api=target_api,
    )
