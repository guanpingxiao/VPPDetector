"""Stable domain objects shared by standalone and PCART integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple


class StringEnum(str, Enum):
    """Enum whose values remain convenient at CLI and report boundaries."""

    def __str__(self) -> str:
        return self.value


class VariadicKind(StringEnum):
    POSITIONAL = "var_positional"
    KEYWORD = "var_keyword"


class ChangeKind(StringEnum):
    DELETE = "delete"
    RENAME = "rename"


class Verdict(StringEnum):
    SAFE = "safe"
    MUST_FAIL = "must_fail"
    MAY_FAIL = "may_fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class RepairAction(StringEnum):
    PRESERVE = "preserve"
    DELETE = "delete"
    RENAME = "rename"
    MANUAL_REVIEW = "manual_review"
    NONE = "none"


class ArgumentEffect(StringEnum):
    ACCEPTED = "accepted"
    DROPPED = "dropped"
    FORWARDED = "forwarded"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class FindingKind(StringEnum):
    LATENT_ACCEPTANCE_MISMATCH = "latent_acceptance_mismatch"
    FORWARDING_ACCEPTED_BY_VARIADIC = "forwarding_accepted_by_variadic"
    AMBIGUOUS_TARGET = "ambiguous_target"
    UNRESOLVED_TARGET = "unresolved_target"


@dataclass(frozen=True)
class SourceContext:
    """Source files and module roots available to the analysis."""

    package_root: Path
    import_roots: Tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class FunctionIdentity:
    """Source-level identity of one function or method."""

    module: str
    qualname: str
    file_path: Optional[Path] = None
    lineno: Optional[int] = None


@dataclass(frozen=True)
class CallSite:
    """Optional concrete client call associated with a compatibility query."""

    file_path: Path
    lineno: int
    col_offset: int = 0
    end_lineno: Optional[int] = None
    end_col_offset: Optional[int] = None
    call_text: Optional[str] = None


@dataclass(frozen=True)
class ParameterChange:
    """One already-detected parameter change; VPPDetector does not infer it."""

    kind: ChangeKind
    old_name: str
    captured_by: str
    capture_kind: VariadicKind
    new_name: Optional[str] = None
    old_position: Optional[int] = None

    def __post_init__(self) -> None:
        if not self.old_name:
            raise ValueError("old_name must not be empty")
        if not self.captured_by:
            raise ValueError("captured_by must not be empty")
        if self.kind is ChangeKind.RENAME and not self.new_name:
            raise ValueError("rename changes require new_name")


@dataclass(frozen=True)
class VPPRequest:
    """In-process request accepted by :func:`assess_change`."""

    source: SourceContext
    target_api: FunctionIdentity
    change: ParameterChange
    callsite: Optional[CallSite] = None
    max_depth: int = 5

    def __post_init__(self) -> None:
        if self.max_depth < 1:
            raise ValueError("max_depth must be positive")


@dataclass(frozen=True)
class SourceSpan:
    file_path: Path
    lineno: int
    col_offset: int
    end_lineno: int
    end_col_offset: int


@dataclass(frozen=True)
class AnalysisBoundary:
    code: str
    message: str
    function: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None


@dataclass(frozen=True)
class DownstreamSink:
    callee_expression: str
    callsite: SourceSpan
    target: Optional[FunctionIdentity]
    accepts_changed_argument: Optional[bool]
    reason_code: str
    conditional: bool = False


@dataclass(frozen=True)
class VPPAssessment:
    request: VPPRequest
    verdict: Verdict
    recommended_action: RepairAction
    argument_effect: ArgumentEffect
    reason_code: str
    message: str
    sinks: Tuple[DownstreamSink, ...] = field(default_factory=tuple)
    boundaries: Tuple[AnalysisBoundary, ...] = field(default_factory=tuple)
    analyzer_schema_version: Optional[str] = None


@dataclass(frozen=True)
class VariadicFunction:
    function: FunctionIdentity
    parameters: Tuple[Tuple[str, VariadicKind], ...]


@dataclass(frozen=True)
class ForwardingFinding:
    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    callee_expression: str
    callsite: SourceSpan
    target: Optional[FunctionIdentity]
    kind: FindingKind
    reason_code: str


@dataclass(frozen=True)
class ScanReport:
    source: SourceContext
    functions_scanned: int
    variadic_functions: Tuple[VariadicFunction, ...]
    findings: Tuple[ForwardingFinding, ...]
    boundaries: Tuple[AnalysisBoundary, ...] = field(default_factory=tuple)
    analyzer_schema_version: Optional[str] = None

    @property
    def potential_pitfalls(self) -> Tuple[ForwardingFinding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.kind is FindingKind.LATENT_ACCEPTANCE_MISMATCH
        )
