"""Whole-library and on-demand VPP detection backed by PCResolve facts."""

from .core import AnalysisContext, ResolutionError
from .encoding import get_encoding, getEncoding
from .models import (
    AnalysisBoundary,
    ForwardingFinding,
    ForwardingStep,
    FunctionIdentity,
    ScanReport,
    SourceContext,
    SourceSpan,
    VariadicFunction,
    VariadicKind,
)
from .scanner import scan_api, scan_package

__all__ = [
    "AnalysisBoundary",
    "AnalysisContext",
    "ForwardingFinding",
    "ForwardingStep",
    "FunctionIdentity",
    "ResolutionError",
    "ScanReport",
    "SourceContext",
    "SourceSpan",
    "VariadicFunction",
    "VariadicKind",
    "getEncoding",
    "get_encoding",
    "scan_api",
    "scan_package",
]

__version__ = "1.1.0"
