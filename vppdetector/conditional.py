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


def proven_concrete_key_consumption(
    function: IndexedFunction,
    parameter: str,
    key: str,
    facts: Optional[ConcreteCall],
) -> Optional[SourceSpan]:
    """Prove a sole captured key is popped on a concrete, unmodified None branch.

    This deliberately covers only a simple top-level deprecation shim. In
    particular, a later escape or possible mutation of the mapping defeats the
    proof even if the pop itself is certain.
    """

    if (
        facts is None
        or function.identity.file_path is None
        or function.node.decorator_list
        or isinstance(function.node, ast.AsyncFunctionDef)
        or any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in ast.walk(function.node))
    ):
        return None
    statements = function.node.body
    if statements and _is_docstring(statements[0]):
        statements = statements[1:]
    for position, statement in enumerate(statements):
        if not _key_membership(statement, parameter, key):
            if not _irrelevant_prior_statement(statement, parameter, key, facts.none_parameters):
                return None
            continue
        guard = statement
        if guard.orelse or not guard.body or not isinstance(guard.body[0], ast.If):
            return None
        inner = guard.body[0]
        if inner.orelse and not _mapping_free(inner.orelse, parameter):
            return None
        if not _known_none_test(inner.test, facts.none_parameters):
            return None
        if not inner.body or not _pop_assignment(inner.body[0], parameter, key):
            return None
        if not _safe_after_consumption(
            (*inner.body[1:], *guard.body[1:], *statements[position + 1 :]),
            parameter,
            key,
            function,
        ):
            return None
        return SourceSpan(
            file_path=function.identity.file_path,
            lineno=inner.body[0].lineno,
            col_offset=inner.body[0].col_offset,
            end_lineno=inner.body[0].end_lineno,
            end_col_offset=inner.body[0].end_col_offset,
        )
    return None


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _key_membership(statement: ast.stmt, mapping: str, key: str) -> bool:
    return (
        isinstance(statement, ast.If)
        and isinstance(statement.test, ast.Compare)
        and len(statement.test.ops) == 1
        and isinstance(statement.test.ops[0], ast.In)
        and len(statement.test.comparators) == 1
        and isinstance(statement.test.left, ast.Constant)
        and statement.test.left.value == key
        and isinstance(statement.test.comparators[0], ast.Name)
        and statement.test.comparators[0].id == mapping
    )


def _known_none_test(test: ast.AST, known_none: FrozenSet[str]) -> bool:
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Is)
        and isinstance(test.left, ast.Name)
        and test.left.id in known_none
        and len(test.comparators) == 1
        and _is_none(test.comparators[0])
    )


def _pop_assignment(statement: ast.stmt, mapping: str, key: str) -> bool:
    targets = (
        statement.targets
        if isinstance(statement, ast.Assign)
        else ((statement.target,) if isinstance(statement, ast.AnnAssign) else ())
    )
    value = statement.value if isinstance(statement, (ast.Assign, ast.AnnAssign)) else None
    return (
        len(targets) == 1
        and isinstance(targets[0], ast.Name)
        and targets[0].id != mapping
        and isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id == mapping
        and value.func.attr == "pop"
        and len(value.args) == 1
        and isinstance(value.args[0], ast.Constant)
        and value.args[0].value == key
        and not value.keywords
    )


def _irrelevant_prior_statement(
    statement: ast.stmt, mapping: str, key: str, known_none: FrozenSet[str]
) -> bool:
    # The concrete call has no other captured keys. A different-key guard is
    # therefore false; its body cannot affect the tracked mapping or guard.
    if isinstance(statement, ast.If):
        test = statement.test
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.In)
            and isinstance(test.left, ast.Constant)
            and isinstance(test.left.value, str)
            and test.left.value != key
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Name)
            and test.comparators[0].id == mapping
            and not statement.orelse
        ):
            return True
    return (
        not _references_name(statement, mapping)
        and not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"exec", "eval", "locals", "globals"}
            for node in ast.walk(statement)
        )
        and not any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in known_none
            for node in ast.walk(statement)
        )
        and not isinstance(statement, (ast.Return, ast.Raise, ast.Try))
    )


def _mapping_free(statements: list[ast.stmt], mapping: str) -> bool:
    return not any(_references_name(statement, mapping) for statement in statements)


def _references_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(child, ast.Name) and child.id == name for child in ast.walk(node))


def _safe_after_consumption(
    statements: tuple[ast.stmt, ...], mapping: str, key: str, function: IndexedFunction
) -> bool:
    bool_shadowed = _bool_shadowed(function)
    for statement in statements:
        parents = {
            child: node for node in ast.walk(statement) for child in ast.iter_child_nodes(node)
        }
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and node.id == mapping:
                parent = parents.get(node)
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    return False
                if isinstance(parent, ast.keyword) and parent.arg is None:
                    continue
                if isinstance(parent, ast.Dict) and any(
                    value is node and dict_key is None
                    for dict_key, value in zip(parent.keys, parent.values)
                ):
                    continue
                if (
                    isinstance(parent, ast.Compare)
                    and node in parent.comparators
                    and all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
                ):
                    continue
                if (
                    isinstance(parent, ast.Subscript)
                    and parent.value is node
                    and isinstance(parent.ctx, ast.Load)
                ):
                    if not (isinstance(parent.slice, ast.Constant) and parent.slice.value == key):
                        continue
                if isinstance(parent, ast.Call) and (
                    not bool_shadowed
                    and isinstance(parent.func, ast.Name)
                    and parent.func.id == "bool"
                    and parent.args == [node]
                    and not parent.keywords
                ):
                    continue
                if (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr in {"get", "keys", "values", "items", "copy"}
                ):
                    continue
                return False
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
                if any(_references_name(target, mapping) for target in targets):
                    return False
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "locals"}:
                    return False
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == mapping
                ):
                    # Read-only mapping methods only; unknown methods may reinsert a key.
                    if node.func.attr not in {"get", "keys", "values", "items", "copy"}:
                        return False
    return True


def _bool_shadowed(function: IndexedFunction) -> bool:
    if any(
        argument.arg == "bool"
        for argument in (
            *function.node.args.posonlyargs,
            *function.node.args.args,
            *function.node.args.kwonlyargs,
        )
    ):
        return True
    if any(
        isinstance(node, ast.Name)
        and node.id == "bool"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(function.node)
    ):
        return True
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval", "globals"}
        for node in ast.walk(function.node)
    ):
        return True
    # A module-level override would make bool(kwargs) an arbitrary call.
    try:
        module = ast.parse(function.identity.file_path.read_text(encoding="utf-8-sig"))
    except (OSError, SyntaxError, UnicodeError):
        return True
    for statement in module.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name == "bool":
                return True
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            if any((alias.asname or alias.name) in {"bool", "*"} for alias in statement.names):
                return True
        elif any(
            isinstance(node, ast.Name)
            and node.id == "bool"
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(statement)
        ):
            return True
    return False


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
