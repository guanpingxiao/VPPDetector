"""Source identities and positive findings shared by both VPP scan modes."""

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
class AnalysisBoundary:
    """A diagnostic explaining an analysis limit, rather than a VPP finding."""

    code: str
    message: str
    function: Optional[FunctionIdentity] = None
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

    @property
    def has_vpp(self) -> bool:
        """Whether this scan found a VPP; false does not prove full coverage."""

        return bool(self.findings)

    @property
    def potential_pitfalls(self) -> Tuple[ForwardingFinding, ...]:
        """Compatibility alias for the positive findings collection."""

        return self.findings
