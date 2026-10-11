"""Source identities, structural findings and parameter-level evidence."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Union


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


class ParameterState(StringEnum):
    """Disposition of one changed argument, not a repair or compatibility verdict."""

    HANDLED = "handled"
    REJECTED = "rejected"
    IGNORED = "ignored"
    UNKNOWN = "unknown"


class ScanCoverageStatus(StringEnum):
    """Observed analysis limits, never a proof of complete coverage."""

    NO_KNOWN_BOUNDARY = "no_known_boundary"
    LIMITED = "limited"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ParameterChange:
    """One parameter deletion or rename supplied by the caller."""

    kind: ChangeKind
    old_name: str
    new_name: Optional[str] = None
    old_position: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ChangeKind(self.kind))
        if not self.old_name.isidentifier():
            raise ValueError("old_name must be a parameter name")
        if self.kind is ChangeKind.RENAME and (
            not self.new_name or not self.new_name.isidentifier()
        ):
            raise ValueError("A rename requires new_name")
        if self.old_position is not None and (
            type(self.old_position) is not int or self.old_position < 0
        ):
            raise ValueError("old_position must be a nonnegative integer")


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
class SourceSpan:
    file_path: Path
    lineno: int
    col_offset: int
    end_lineno: int
    end_col_offset: int


@dataclass(frozen=True)
class CallContext:
    """Original call and optional trusted, finite facts for that call only.

    known_values supplies primitive constants under source parameter names or
    receiver attribute paths, e.g. (("self.closed", False),). These are caller
    evidence, not expressions to execute. None is distinct from an unknown value.
    bound_receiver overrides the indexed method convention for unbound calls.
    known_targets confirms implementations at exact library call locations;
    copying a nominal PCResolve candidate is not an independent confirmation.
    """

    expression: Union[str, ast.Call]
    bound_receiver: Optional[bool] = None
    known_values: Tuple[Tuple[str, object], ...] = ()
    callsite: Optional[SourceSpan] = None
    known_targets: Tuple[Tuple[SourceSpan, FunctionIdentity], ...] = ()

    def __post_init__(self) -> None:
        if self.bound_receiver is not None and type(self.bound_receiver) is not bool:
            raise ValueError("bound_receiver must be bool or None")
        names = [name for name, _ in self.known_values]
        if len(set(names)) != len(names) or any(
            not all(part.isidentifier() for part in name.split(".")) for name in names
        ):
            raise ValueError("known_values requires unique parameter or attribute paths")
        if any(
            type(value) not in (str, bytes, int, float, bool, type(None))
            for _, value in self.known_values
        ):
            raise ValueError("known_values accepts only primitive constants")
        spans = [span for span, _ in self.known_targets]
        if len(set(spans)) != len(spans):
            raise ValueError("known_targets requires unique library call locations")


@dataclass(frozen=True)
class AnalysisBoundary:
    """A diagnostic explaining an analysis limit, rather than a VPP finding."""

    code: str
    message: str
    function: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None
    root_function: Optional[FunctionIdentity] = None
    parameter_name: Optional[str] = None
    parameter_kind: Optional[VariadicKind] = None


@dataclass(frozen=True)
class ParameterEvidence:
    """A binding, use, drop or selected condition supporting an assessment."""

    function: FunctionIdentity
    reason: str
    detail: str
    callsite: Optional[SourceSpan] = None
    target: Optional[FunctionIdentity] = None


@dataclass(frozen=True)
class ParameterAssessment:
    """Handling state and supporting evidence for one changed argument in a call."""

    target_api: FunctionIdentity
    change: ParameterChange
    call_text: str
    state: ParameterState
    reason: str
    evidence: Tuple[ParameterEvidence, ...] = ()
    boundaries: Tuple[AnalysisBoundary, ...] = ()
    resolved_api: Optional[FunctionIdentity] = None
    callsite: Optional[SourceSpan] = None


@dataclass(frozen=True)
class VariadicFunction:
    function: FunctionIdentity
    parameters: Tuple[Tuple[str, VariadicKind], ...]
    implementation: Optional[FunctionIdentity] = None


@dataclass(frozen=True)
class ForwardingStep:
    """One source-resolved hop in a root API's forwarding path."""

    function: FunctionIdentity
    parameter_name: str
    callee_expression: str
    callsite: SourceSpan
    target: FunctionIdentity
    target_status: str = "resolved"


@dataclass(frozen=True)
class ForwardingFinding:
    """A root variadic parameter reaches an incompatible expansion signature."""

    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    callee_expression: str
    callsite: SourceSpan
    target: FunctionIdentity
    reason_code: str
    path: Tuple[ForwardingStep, ...] = field(default_factory=tuple)
    target_status: str = "resolved"
    target_candidates: Tuple[FunctionIdentity, ...] = field(default_factory=tuple)
    receiver_type_evidence: Tuple[dict, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class VariadicCoverage:
    """One root channel's findings and recorded limits in a scan snapshot."""

    function: FunctionIdentity
    parameter_name: str
    parameter_kind: VariadicKind
    status: ScanCoverageStatus
    finding_count: int = 0
    boundary_codes: Tuple[str, ...] = ()
    implementation: Optional[FunctionIdentity] = None


@dataclass(frozen=True)
class ScanReport:
    """Positive VPP findings and diagnostics for one scan scope."""

    source: SourceContext
    functions_scanned: int
    variadic_functions: Tuple[VariadicFunction, ...]
    findings: Tuple[ForwardingFinding, ...]
    boundaries: Tuple[AnalysisBoundary, ...] = field(default_factory=tuple)
    analyzer_schema_version: Optional[str] = None
    target_api: Optional[FunctionIdentity] = None
    resolved_api: Optional[FunctionIdentity] = None
    coverage: Tuple[VariadicCoverage, ...] = ()

    @property
    def has_vpp(self) -> bool:
        """Whether this scan found a VPP; false does not prove full coverage."""

        return bool(self.findings)

    @property
    def potential_pitfalls(self) -> Tuple[ForwardingFinding, ...]:
        """Compatibility alias for the positive findings collection."""

        return self.findings
