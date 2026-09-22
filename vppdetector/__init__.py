"""Incubation API shared by the VPP scanner and compatibility refinement."""

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
