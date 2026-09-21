"""VPP-specific interpretation of PCResolve call-flow records."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .models import FunctionIdentity, SourceSpan, VariadicKind


def direct_calls(analysis: Any, caller: FunctionIdentity) -> Iterable[Any]:
    for call in analysis.calls:
        if call.caller.module == caller.module and call.caller.qualname == caller.qualname:
            yield call


def forwards_parameter(call: Any, parameter: str, kind: VariadicKind) -> bool:
    return any(
        flow.get("source_parameter") == parameter
        and _is_variadic_expansion(flow.get("argument", {}), kind)
        for flow in call.parameter_flows
    )


def parameter_reaches_call(call: Any, parameter: str) -> bool:
    return any(flow.get("source_parameter") == parameter for flow in call.parameter_flows)


def forwarding_is_conditional(call: Any, parameter: str) -> bool:
    return any(
        bool(flow.get("conditions"))
        for flow in call.parameter_flows
        if flow.get("source_parameter") == parameter
    )


def call_span(call: Any) -> SourceSpan:
    path = call.caller.file_path or ""
    return SourceSpan(
        file_path=Path(path),
        lineno=call.lineno,
        col_offset=call.col_offset,
        end_lineno=call.end_lineno or call.lineno,
        end_col_offset=call.end_col_offset or call.col_offset,
    )


def _is_variadic_expansion(argument: dict, kind: VariadicKind) -> bool:
    if kind is VariadicKind.POSITIONAL:
        return bool(argument.get("starred"))
    return "keyword" in argument and argument.get("keyword") is None
