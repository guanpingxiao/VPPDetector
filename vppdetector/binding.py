"""Concrete callsite binding facts used before variadic propagation."""

from __future__ import annotations

import ast
import tokenize
from pathlib import Path
from typing import Optional, Tuple

from .models import BindingStatus, CallSite, EntryBinding, ParameterChange
from .source import IndexedFunction, SignatureFacts


def bind_callsite(
    callsite: CallSite,
    function: IndexedFunction,
    change: ParameterChange,
) -> EntryBinding:
    """Bind one syntactically known client call to the selected new signature."""

    return bind_signature(
        callsite,
        function.signature,
        is_bound_method=function.is_bound_method,
        change=change,
    )


def bind_signature(
    callsite: CallSite,
    signature: SignatureFacts,
    *,
    is_bound_method: bool,
    change: ParameterChange,
) -> EntryBinding:
    """Bind without retaining the source index or PCResolve analysis context."""

    call = _load_call(callsite)
    if call is None:
        return EntryBinding(
            status=BindingStatus.UNKNOWN,
            reason_code="callsite_not_resolved",
        )

    positional_only = list(signature.positional_only)
    positional_or_keyword = list(signature.positional_or_keyword)
    required_positional = set(signature.required_positional)
    if is_bound_method:
        if positional_only:
            implicit = positional_only.pop(0)
            required_positional.discard(implicit)
        elif positional_or_keyword:
            implicit = positional_or_keyword.pop(0)
            required_positional.discard(implicit)

    positional_parameters = [*positional_only, *positional_or_keyword]
    bound = set()
    duplicates = set()
    unexpected_keywords = set()
    dynamic_positional = False
    dynamic_keywords = False
    positional_index = 0
    changed_argument_target: Optional[str] = None
    changed_argument_seen = False

    for argument in call.args:
        if isinstance(argument, ast.Starred):
            dynamic_positional = True
            continue
        if positional_index < len(positional_parameters):
            parameter = positional_parameters[positional_index]
            bound.add(parameter)
            if change.old_position == positional_index:
                changed_argument_seen = True
                changed_argument_target = parameter
        elif signature.vararg:
            if change.old_position == positional_index:
                changed_argument_seen = True
                changed_argument_target = signature.vararg
        else:
            return EntryBinding(
                status=BindingStatus.INVALID,
                reason_code="too_many_positional_arguments",
                changed_argument_target=changed_argument_target,
            )
        positional_index += 1

    for keyword in call.keywords:
        if keyword.arg is None:
            dynamic_keywords = True
            continue
        name = keyword.arg
        if name == change.old_name:
            changed_argument_seen = True
        if name in positional_only:
            if signature.kwarg:
                if name == change.old_name:
                    changed_argument_target = signature.kwarg
            else:
                unexpected_keywords.add(name)
            continue
        if name in positional_or_keyword or name in signature.keyword_only:
            if name in bound:
                duplicates.add(name)
            bound.add(name)
            if name == change.old_name:
                changed_argument_target = name
            continue
        if signature.kwarg:
            if name == change.old_name:
                changed_argument_target = signature.kwarg
            continue
        unexpected_keywords.add(name)

    missing_required = {
        name
        for name in (*required_positional, *signature.required_keyword_only)
        if name not in bound
    }
    definite_missing = set(missing_required)
    if dynamic_positional:
        definite_missing.difference_update(required_positional)
        definite_missing.difference_update(positional_or_keyword)
    if dynamic_keywords:
        definite_missing.difference_update(positional_or_keyword)
        definite_missing.difference_update(signature.required_keyword_only)

    if duplicates or unexpected_keywords or definite_missing:
        if duplicates:
            reason_code = "duplicate_argument_binding"
        elif unexpected_keywords:
            reason_code = "unexpected_keyword_argument"
        else:
            reason_code = "required_parameter_unbound"
        return EntryBinding(
            status=BindingStatus.INVALID,
            reason_code=reason_code,
            changed_argument_target=changed_argument_target,
            missing_required=tuple(sorted(definite_missing)),
            duplicate_parameters=tuple(sorted(duplicates)),
            unexpected_keywords=tuple(sorted(unexpected_keywords)),
            dynamic_positional=dynamic_positional,
            dynamic_keywords=dynamic_keywords,
        )

    if not changed_argument_seen:
        if dynamic_positional or dynamic_keywords:
            return EntryBinding(
                status=BindingStatus.UNKNOWN,
                reason_code="changed_argument_may_be_dynamically_supplied",
                missing_required=tuple(sorted(missing_required)),
                dynamic_positional=dynamic_positional,
                dynamic_keywords=dynamic_keywords,
            )
        return EntryBinding(
            status=BindingStatus.NOT_EXERCISED,
            reason_code="changed_argument_not_passed",
        )

    if dynamic_positional or dynamic_keywords or missing_required:
        return EntryBinding(
            status=BindingStatus.UNKNOWN,
            reason_code="dynamic_call_binding",
            changed_argument_target=changed_argument_target,
            missing_required=tuple(sorted(missing_required)),
            dynamic_positional=dynamic_positional,
            dynamic_keywords=dynamic_keywords,
        )

    return EntryBinding(
        status=BindingStatus.VALID,
        reason_code="call_binding_valid",
        changed_argument_target=changed_argument_target,
    )


def _load_call(callsite: CallSite) -> Optional[ast.Call]:
    if callsite.call_text:
        return _parse_call_text(callsite.call_text)

    path = Path(callsite.file_path)
    try:
        with tokenize.open(path) as stream:
            calls = _parse_calls(stream.read(), str(path))
    except (OSError, SyntaxError, UnicodeError):
        return None

    exact = [
        call
        for call in calls
        if call.lineno == callsite.lineno and call.col_offset == callsite.col_offset
    ]
    if len(exact) == 1:
        return exact[0]
    containing = [call for call in calls if _contains_position(call, callsite)]
    if len(containing) == 1:
        return containing[0]
    same_line = [call for call in calls if call.lineno == callsite.lineno]
    return same_line[0] if len(same_line) == 1 else None


def _parse_call_text(source: str) -> Optional[ast.Call]:
    try:
        tree = ast.parse(source, filename="<callsite>")
    except SyntaxError:
        return None
    if len(tree.body) == 1:
        node = tree.body[0]
        value = node.value if isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign)) else None
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call):
            return value
    calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    return calls[0] if len(calls) == 1 else None


def _parse_calls(source: str, filename: str) -> Tuple[ast.Call, ...]:
    tree = ast.parse(source, filename=filename)
    return tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))


def _contains_position(call: ast.Call, callsite: CallSite) -> bool:
    end_lineno = getattr(call, "end_lineno", call.lineno)
    end_col_offset = getattr(call, "end_col_offset", call.col_offset)
    position = (callsite.lineno, callsite.col_offset)
    return (call.lineno, call.col_offset) <= position <= (end_lineno, end_col_offset)
