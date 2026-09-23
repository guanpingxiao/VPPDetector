"""Narrow proof of a concrete keyword making an entry guard reject a call."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import FrozenSet, Optional

from .binding import _load_call
from .models import CallSite, SourceSpan
from .source import IndexedFunction


@dataclass(frozen=True)
class ConcreteCall:
    """Facts retained only while the changed keyword is the sole captured key."""

    none_parameters: FrozenSet[str]


def entry_call_facts(
    callsite: Optional[CallSite], function: IndexedFunction, old_name: str
) -> Optional[ConcreteCall]:
    if callsite is None:
        return None
    call = _load_call(callsite)
    if call is None:
        return None
    return _bind_concrete(call, function, old_name, frozenset(), None)


def forwarded_call_facts(
    caller: IndexedFunction,
    callee: IndexedFunction,
    call: ast.Call,
    parameter: str,
    old_name: str,
    facts: Optional[ConcreteCall],
) -> Optional[ConcreteCall]:
    if (
        facts is None
        or caller.node.decorator_list
        or isinstance(caller.node, ast.AsyncFunctionDef)
        or not _direct_return(caller.node, call)
        or not isinstance(call.func, ast.Name)
        or not all(isinstance(value, (ast.Name, ast.Constant)) for value in call.args)
        or not all(isinstance(keyword.value, (ast.Name, ast.Constant)) for keyword in call.keywords)
    ):
        return None
    return _bind_concrete(call, callee, old_name, facts.none_parameters, parameter)


def proven_guard_rejection(
    function: IndexedFunction, parameter: str, facts: Optional[ConcreteCall]
) -> Optional[SourceSpan]:
    if (
        facts is None
        or function.node.decorator_list
        or isinstance(function.node, ast.AsyncFunctionDef)
        or any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in ast.walk(function.node))
    ):
        return None
    statements = function.node.body
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        statements = statements[1:]
    if not statements or not isinstance(statements[0], ast.If):
        return None
    guard = statements[0]
    if guard.orelse or len(guard.body) != 1 or not isinstance(guard.body[0], ast.Raise):
        return None
    if not _none_and_mapping_guard(guard.test, facts.none_parameters, parameter):
        return None
    if function.identity.file_path is None:
        return None
    return SourceSpan(
        file_path=function.identity.file_path,
        lineno=guard.lineno,
        col_offset=guard.col_offset,
        end_lineno=guard.end_lineno,
        end_col_offset=guard.end_col_offset,
    )


def _bind_concrete(
    call: ast.Call,
    function: IndexedFunction,
    old_name: str,
    known_none: FrozenSet[str],
    forwarded_mapping: Optional[str],
) -> Optional[ConcreteCall]:
    signature = function.signature
    if signature.kwarg is None or any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    expansions = [keyword.value for keyword in call.keywords if keyword.arg is None]
    if forwarded_mapping is None:
        if expansions:
            return None
    elif (
        len(expansions) != 1
        or not isinstance(expansions[0], ast.Name)
        or expansions[0].id != forwarded_mapping
    ):
        return None

    positional = [*signature.positional_only, *signature.positional_or_keyword]
    if function.is_bound_method:
        positional = positional[1:]
    if len(call.args) > len(positional) and signature.vararg is None:
        return None
    explicit = {}
    for name, value in zip(positional, call.args):
        explicit[name] = value
    captured = []
    for keyword in call.keywords:
        if keyword.arg is None:
            continue
        name = keyword.arg
        if name in explicit:
            return None
        if name in signature.positional_or_keyword or name in signature.keyword_only:
            explicit[name] = keyword.value
        elif name in signature.positional_only or not signature.explicitly_accepts_keyword(name):
            captured.append(name)
    if forwarded_mapping is None:
        if captured != [old_name]:
            return None
    elif captured:
        return None

    none_parameters = {
        name for name, value in explicit.items() if _is_known_none(value, known_none)
    }
    arguments = function.node.args
    all_positional = [*arguments.posonlyargs, *arguments.args]
    for argument, default in zip(
        all_positional[len(all_positional) - len(arguments.defaults) :],
        arguments.defaults,
    ):
        if argument.arg not in explicit and _is_none(default):
            none_parameters.add(argument.arg)
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
        if argument.arg not in explicit and default is not None and _is_none(default):
            none_parameters.add(argument.arg)
    return ConcreteCall(frozenset(none_parameters))


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_known_none(node: ast.AST, known_none: FrozenSet[str]) -> bool:
    return _is_none(node) or isinstance(node, ast.Name) and node.id in known_none


def _none_and_mapping_guard(test: ast.AST, none_parameters: FrozenSet[str], mapping: str) -> bool:
    if not isinstance(test, ast.BoolOp) or not isinstance(test.op, ast.And):
        return False
    if len(test.values) != 2:
        return False
    return any(isinstance(term, ast.Name) and term.id == mapping for term in test.values) and any(
        isinstance(term, ast.Compare)
        and len(term.ops) == 1
        and isinstance(term.ops[0], ast.Is)
        and isinstance(term.left, ast.Name)
        and term.left.id in none_parameters
        and len(term.comparators) == 1
        and _is_none(term.comparators[0])
        for term in test.values
    )


def _direct_return(function: ast.AST, call: ast.Call) -> bool:
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return len(body) == 1 and isinstance(body[0], ast.Return) and body[0].value is call
