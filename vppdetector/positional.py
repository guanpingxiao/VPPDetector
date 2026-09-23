"""A deliberately narrow proof for concrete, direct ``*args`` forwarding."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from .binding import _load_call
from .core import PCResolveAdapter, ResolutionError, call_span, direct_calls, identity_from_target
from .models import SourceSpan, VPPRequest
from .source import IndexedFunction, SourceIndex


@dataclass(frozen=True)
class PositionalProof:
    rejects: bool
    target: IndexedFunction
    callsite: SourceSpan


def prove_direct_positional_forwarding(
    request: VPPRequest,
    entry: IndexedFunction,
    index: SourceIndex,
    adapter: PCResolveAdapter,
) -> Optional[PositionalProof]:
    """Prove only a whole, unmodified positional tuple reaches one fixed callee."""

    if request.callsite is None or request.change.old_position is None:
        return None
    callsite = _load_call(request.callsite)
    if callsite is None or any(isinstance(arg, ast.Starred) for arg in callsite.args):
        return None
    if any(keyword.arg is None for keyword in callsite.keywords):
        return None
    if len(entry.node.body) != 1:
        return None
    if entry.is_overload or entry.node.decorator_list:
        return None
    statement = entry.node.body[0]
    call = statement.value if isinstance(statement, (ast.Return, ast.Expr)) else None
    if not isinstance(call, ast.Call) or call.keywords or not isinstance(call.func, ast.Name):
        return None
    if len(call.args) != 1 or not isinstance(call.args[0], ast.Starred):
        return None
    if not isinstance(call.args[0].value, ast.Name):
        return None
    if call.args[0].value.id != entry.signature.vararg:
        return None

    fixed_entry = len(entry.signature.positional_only) + len(entry.signature.positional_or_keyword)
    if entry.is_bound_method:
        fixed_entry -= 1
    if request.change.old_position < fixed_entry:
        return None
    old_element_index = request.change.old_position - fixed_entry
    captured_count = len(callsite.args) - fixed_entry
    if old_element_index >= captured_count:
        return None

    try:
        analysis = adapter.analyze(entry.identity, max_depth=1)
    except ResolutionError:
        return None
    candidates = [
        item
        for item in direct_calls(analysis, entry.identity)
        if (item.lineno, item.col_offset) == (call.lineno, call.col_offset)
    ]
    if len(candidates) != 1 or candidates[0].target is None:
        return None
    selected_call = candidates[0]
    if selected_call.target_status != "resolved":
        return None
    if len(getattr(selected_call, "target_candidates", ())) != 1:
        return None
    if any(
        boundary.get("call_id") == selected_call.id
        and boundary.get("reason") not in {"dynamic_argument_expansion", "depth_limit"}
        for boundary in analysis.boundaries
    ):
        return None
    target_identity = identity_from_target(selected_call.target)
    if target_identity.file_path is None or target_identity.lineno is None:
        return None
    target = index.find_by_location(target_identity.file_path, target_identity.lineno)
    if (
        target is None
        or target.signature.vararg
        or target.is_bound_method
        or target.is_overload
        or target.node.decorator_list
    ):
        return None
    fixed_target = len(target.signature.positional_only) + len(
        target.signature.positional_or_keyword
    )
    if target.is_bound_method:
        fixed_target -= 1
    required_target = len(target.signature.required_positional)
    if target.is_bound_method:
        required_target -= 1
    if target.signature.required_keyword_only:
        return None
    if getattr(selected_call, "binding_status", "unavailable") == "invalid":
        # Another independently invalid binding must not be called a VPP proof.
        return None
    if old_element_index >= fixed_target:
        return PositionalProof(rejects=True, target=target, callsite=call_span(selected_call))
    if captured_count > fixed_target:
        return None
    if captured_count >= required_target:
        return PositionalProof(rejects=False, target=target, callsite=call_span(selected_call))
    return None
