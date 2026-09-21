"""Public Python API for VPPDetector."""

from .assessment import assess_change, assess_changes
from .encoding import get_encoding, getEncoding
from .models import (
    AnalysisBoundary,
    ArgumentEffect,
    CallSite,
    ChangeKind,
    FindingKind,
    ForwardingFinding,
    FunctionIdentity,
    ParameterChange,
    RepairAction,
    ScanReport,
    SourceContext,
    VariadicKind,
    Verdict,
    VPPAssessment,
    VPPRequest,
)
from .scanner import scan_package

__all__ = [
    "AnalysisBoundary",
    "ArgumentEffect",
    "CallSite",
    "ChangeKind",
    "FindingKind",
    "ForwardingFinding",
    "FunctionIdentity",
    "ParameterChange",
    "RepairAction",
    "ScanReport",
    "SourceContext",
    "VPPAssessment",
    "VPPRequest",
    "VariadicKind",
    "Verdict",
    "assess_change",
    "assess_changes",
    "getEncoding",
    "get_encoding",
    "scan_package",
]

__version__ = "1.1.0"
