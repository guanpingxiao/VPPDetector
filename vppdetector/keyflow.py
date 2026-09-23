"""Lightweight, key-specific flow for a variadic keyword mapping."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from .models import SourceSpan
from .source import IndexedFunction


class KeyPresence(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class KeyEffect(str, Enum):
    CONSUMED = "consumed"
    RENAMED = "renamed"
    REASSIGNED = "reassigned"


@dataclass(frozen=True)
class _State:
    presence: KeyPresence
    effects: FrozenSet[KeyEffect] = frozenset()


@dataclass
class MappingKeyFlow:
    parameter: str = ""
    mutable_aliases: FrozenSet[str] = frozenset()
    pcresolve_operations: Dict[
        Tuple[int, int, int, int], Tuple[Optional[KeyPresence], Optional[KeyEffect]]
    ] = field(default_factory=dict)
    call_states: Dict[Tuple[int, int, int, int], Set[_State]] = field(default_factory=dict)
    recognized_mutations: Set[Tuple[int, int, int, int]] = field(default_factory=set)
    exception_guarded_calls: Set[Tuple[int, int, int, int]] = field(default_factory=set)
    terminal_states: Set[_State] = field(default_factory=set)
    raised_paths: bool = False
    independent_raised_paths: bool = False
    key_dependent_names: FrozenSet[str] = frozenset()

    def presence_at(self, span: SourceSpan) -> FrozenSet[KeyPresence]:
        states = self.call_states.get(_span_key(span), set())
        return frozenset(state.presence for state in states)

    def effects_at(self, span: SourceSpan) -> FrozenSet[KeyEffect]:
        states = self.call_states.get(_span_key(span), set())
        return frozenset(effect for state in states for effect in state.effects)

    def is_recognized_mutation(self, span: SourceSpan) -> bool:
        return _span_key(span) in self.recognized_mutations

    def is_exception_guarded(self, span: SourceSpan) -> bool:
        return _span_key(span) in self.exception_guarded_calls

    @property
    def terminal_effects(self) -> FrozenSet[KeyEffect]:
        return frozenset(effect for state in self.terminal_states for effect in state.effects)

    def every_terminal_has(self, effect: KeyEffect) -> bool:
        return bool(self.terminal_states) and all(
            effect in state.effects and state.presence is KeyPresence.ABSENT
            for state in self.terminal_states
        )


def analyze_mapping_key(
    function: IndexedFunction,
    parameter: str,
    key: str,
    *,
    mapping_effects: Sequence[dict] = (),
) -> MappingKeyFlow:
    """Track one known-present key through direct local mapping operations."""

    operations = _pcresolve_operations(mapping_effects, parameter, key)
    result = MappingKeyFlow(
        parameter=parameter,
        mutable_aliases=_mutable_alias_names(function.node, parameter, frozenset(operations)),
        pcresolve_operations=operations,
        key_dependent_names=_key_dependent_names(function.node, parameter, key),
    )
    initial = {_State(KeyPresence.PRESENT)}
    remaining = _walk_block(
        function.node.body,
        initial,
        parameter=parameter,
        key=key,
        result=result,
        exception_guard_relevant=None,
    )
    result.terminal_states.update(remaining)
    return result


def _walk_block(
    statements: Sequence[ast.stmt],
    states: Set[_State],
    *,
    parameter: str,
    key: str,
    result: MappingKeyFlow,
    exception_guard_relevant: Optional[bool],
) -> Set[_State]:
    current = set(states)
    for statement in statements:
        if not current:
            break
        if _may_raise_on_key_read(statement, current, parameter, key):
            result.raised_paths = True
        if isinstance(statement, ast.If):
            _record_calls(statement.test, current, result)
            current = _apply_expression(
                statement.test,
                current,
                parameter=parameter,
                key=key,
                result=result,
            )
            true_states, false_states = _refine_membership(current, statement.test, parameter, key)
            branch_guard_relevant = (
                exception_guard_relevant is True
            ) or _expression_references_key(
                statement.test, parameter, key, result.key_dependent_names
            )
            body_states = _walk_block(
                statement.body,
                true_states,
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=branch_guard_relevant,
            )
            else_states = _walk_block(
                statement.orelse,
                false_states,
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=branch_guard_relevant,
            )
            current = body_states | else_states
            continue
        if isinstance(statement, (ast.Return, ast.Raise)):
            value = getattr(statement, "value", None) or getattr(statement, "exc", None)
            if value is not None:
                _record_calls(value, current, result)
                current = _apply_expression(
                    value,
                    current,
                    parameter=parameter,
                    key=key,
                    result=result,
                )
            if isinstance(statement, ast.Raise):
                relevant_raise = (
                    exception_guard_relevant is not False
                    or _expression_references_key(
                        statement,
                        parameter,
                        key,
                        result.key_dependent_names,
                    )
                )
                if relevant_raise:
                    result.raised_paths = True
                    result.terminal_states.update(current)
                else:
                    result.independent_raised_paths = True
            else:
                result.terminal_states.update(current)
            current = set()
            continue
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            header = statement.test if isinstance(statement, ast.While) else statement.iter
            if _has_loop_exit(statement) and _references_parameter(statement, parameter):
                current = _set_presence(current, KeyPresence.UNKNOWN, None)
            _record_calls(header, current, result)
            loop_guard_relevant = (exception_guard_relevant is True) or _expression_references_key(
                header, parameter, key, result.key_dependent_names
            )
            body_states = _walk_block(
                statement.body,
                set(current),
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=loop_guard_relevant,
            )
            current |= body_states
            current = _walk_block(
                statement.orelse,
                current,
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=exception_guard_relevant,
            )
            continue
        if isinstance(statement, ast.Try):
            if statement.handlers:
                for body_statement in statement.body:
                    result.exception_guarded_calls.update(
                        _node_key(child)
                        for child in _descendants(body_statement)
                        if isinstance(child, ast.Call)
                    )
            body_states = _walk_block(
                statement.body,
                set(current),
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=exception_guard_relevant,
            )
            handler_states = set()
            for handler in statement.handlers:
                handler_states |= _walk_block(
                    handler.body,
                    set(current),
                    parameter=parameter,
                    key=key,
                    result=result,
                    exception_guard_relevant=(exception_guard_relevant is True)
                    or _expression_references_key(
                        statement.body[0] if statement.body else statement,
                        parameter,
                        key,
                        result.key_dependent_names,
                    ),
                )
            current = body_states | handler_states
            current = _walk_block(
                statement.orelse,
                current,
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=exception_guard_relevant,
            )
            current = _walk_block(
                statement.finalbody,
                current,
                parameter=parameter,
                key=key,
                result=result,
                exception_guard_relevant=exception_guard_relevant,
            )
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(statement, ast.Assert):
            _record_calls(statement, current, result)
            if _references_parameter(statement, parameter):
                current = _set_presence(current, KeyPresence.UNKNOWN, None)
            if exception_guard_relevant is True or _expression_references_key(
                statement.test, parameter, key, result.key_dependent_names
            ):
                result.raised_paths = True
            continue
        if isinstance(statement, (ast.With, ast.AsyncWith)) or (
            hasattr(ast, "Match") and isinstance(statement, ast.Match)
        ):
            if _references_parameter(statement, parameter):
                uncertain = _set_presence(current, KeyPresence.UNKNOWN, None)
                _record_calls(statement, uncertain, result)
                current = uncertain
            continue

        _record_calls(statement, current, result)
        current = _apply_statement(
            statement,
            current,
            parameter=parameter,
            key=key,
            result=result,
        )
    return current


def _record_calls(node: ast.AST, states: Set[_State], result: MappingKeyFlow) -> None:
    descendants = tuple(_descendants(node))
    calls = tuple(child for child in descendants if isinstance(child, ast.Call))
    concurrent_mutation = any(_is_tracked_mutation(call, result) for call in calls)
    visible_states = (
        _set_presence(states, KeyPresence.UNKNOWN, None)
        if concurrent_mutation and len(calls) > 1
        else states
    )
    for child in calls:
        if isinstance(child, ast.Call):
            result.call_states.setdefault(_node_key(child), set()).update(visible_states)


def _apply_statement(
    statement: ast.stmt,
    states: Set[_State],
    *,
    parameter: str,
    key: str,
    result: MappingKeyFlow,
) -> Set[_State]:
    current = set(states)
    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        value = getattr(statement, "value", None)
        renamed = value is not None and _pops_key(value, parameter, key)
        if value is not None:
            current = _apply_expression(
                value,
                current,
                parameter=parameter,
                key=key,
                result=result,
            )
        targets = statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
        for target in targets:
            current = _apply_assignment_target(target, current, parameter, key)
            if (
                isinstance(value, ast.Name)
                and value.id == parameter
                and isinstance(target, ast.Name)
                and target.id in result.mutable_aliases
            ):
                current = _set_presence(current, KeyPresence.UNKNOWN, None)
        if renamed and any(_assigns_other_key(target, parameter, key) for target in targets):
            current = _add_effect(current, KeyEffect.RENAMED)
        return current
    if isinstance(statement, ast.Delete):
        for target in statement.targets:
            if _is_key_subscript(target, parameter, key):
                if any(state.presence is not KeyPresence.PRESENT for state in current):
                    result.raised_paths = True
                current = _set_presence(current, KeyPresence.ABSENT, KeyEffect.CONSUMED)
        return current
    if isinstance(statement, ast.Expr):
        return _apply_expression(
            statement.value,
            current,
            parameter=parameter,
            key=key,
            result=result,
        )
    return current


def _apply_expression(
    expression: ast.AST,
    states: Set[_State],
    *,
    parameter: str,
    key: str,
    result: MappingKeyFlow,
) -> Set[_State]:
    current = set(states)
    if _has_conditional_mutation(expression, result):
        for call in _calls_in_evaluation_order(expression):
            if _is_tracked_mutation(call, result):
                result.recognized_mutations.add(_node_key(call))
        return _set_presence(current, KeyPresence.UNKNOWN, None)
    for call in _calls_in_evaluation_order(expression):
        if _passes_mapping_as_data(call, parameter):
            current = _set_presence(current, KeyPresence.UNKNOWN, None)
        if not _is_tracked_mutation(call, result):
            continue
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "pop"
            and call.args
            and _literal_string(call.args[0]) == key
            and len(call.args) == 1
            and not any(keyword.arg == "default" for keyword in call.keywords)
            and any(state.presence is not KeyPresence.PRESENT for state in current)
            and (
                _node_key(call) in result.pcresolve_operations
                or _is_mapping_mutation(call, parameter)
            )
        ):
            result.raised_paths = True
        result.recognized_mutations.add(_node_key(call))
        operation = result.pcresolve_operations.get(_node_key(call))
        if operation is None:
            operation = _mapping_operation(call, parameter, key)
        if operation is None:
            continue
        presence, effect = operation
        if presence is not None:
            current = _set_presence(current, presence, effect)
        elif effect is not None:
            current = _add_effect(current, effect)
    return current


def _has_conditional_mutation(node: ast.AST, result: MappingKeyFlow) -> bool:
    conditional_nodes = (
        ast.IfExp,
        ast.BoolOp,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    return any(
        isinstance(child, conditional_nodes)
        and any(
            isinstance(inner, ast.Call) and _is_tracked_mutation(inner, result)
            for inner in _descendants(child)
        )
        for child in _descendants(node)
    )


def _references_parameter(node: ast.AST, parameter: str) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id == parameter for child in _descendants(node)
    )


def _may_raise_on_key_read(
    node: ast.AST,
    states: Set[_State],
    parameter: str,
    key: str,
) -> bool:
    reads_key = any(
        isinstance(child, ast.Subscript)
        and isinstance(child.ctx, ast.Load)
        and _is_key_subscript(child, parameter, key)
        for child in _descendants(node)
    )
    return reads_key and (
        any(state.presence is not KeyPresence.PRESENT for state in states)
        or _pops_key(node, parameter, key)
    )


def _key_dependent_names(function: ast.AST, parameter: str, key: str) -> FrozenSet[str]:
    """Over-approximate locals derived from the tracked keyword."""

    assignments = []
    for node in _descendants(function):
        if isinstance(node, ast.Assign):
            assignments.append((node.targets, node.value))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            assignments.append(((node.target,), node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            assignments.append(((node.target,), node.iter))
    dependent = set()
    changed = True
    while changed:
        changed = False
        for targets, value in assignments:
            if not _expression_references_key(value, parameter, key, frozenset(dependent)):
                continue
            names = {
                child.id
                for target in targets
                for child in _descendants(target)
                if isinstance(child, ast.Name)
            }
            if not names.issubset(dependent):
                dependent.update(names)
                changed = True
    return frozenset(dependent)


def _expression_references_key(
    node: ast.AST,
    parameter: str,
    key: str,
    dependent_names: FrozenSet[str],
) -> bool:
    """Keep unrelated literal-key lookups out of exception guards."""

    if isinstance(node, ast.Name):
        return node.id == parameter or node.id in dependent_names
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id == parameter:
            literal = _literal_string(node.slice)
            return literal is None or literal == key
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        if (
            isinstance(receiver, ast.Name)
            and receiver.id == parameter
            and node.func.attr in {"get", "pop", "setdefault"}
            and node.args
        ):
            literal = _literal_string(node.args[0])
            if literal is not None and literal != key:
                return any(
                    _expression_references_key(argument, parameter, key, dependent_names)
                    for argument in (*node.args[1:], *(item.value for item in node.keywords))
                )
    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        if isinstance(node.ops[0], (ast.In, ast.NotIn)):
            comparator = node.comparators[0]
            if isinstance(comparator, ast.Name) and comparator.id == parameter:
                literal = _literal_string(node.left)
                if literal is not None and literal != key:
                    return False
    return any(
        _expression_references_key(child, parameter, key, dependent_names)
        for child in ast.iter_child_nodes(node)
    )


def _has_loop_exit(node: ast.AST) -> bool:
    return any(isinstance(child, (ast.Break, ast.Continue)) for child in _descendants(node))


def _mutable_alias_names(
    function: ast.AST,
    parameter: str,
    verified_operations: FrozenSet[Tuple[int, int, int, int]],
) -> FrozenSet[str]:
    aliases = {
        target.id
        for statement in _descendants(function)
        if isinstance(statement, ast.Assign)
        and isinstance(statement.value, ast.Name)
        and statement.value.id == parameter
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    mutable = set()
    for child in _descendants(function):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if (
                isinstance(child.func.value, ast.Name)
                and child.func.value.id in aliases
                and child.func.attr in {"clear", "pop", "popitem", "setdefault", "update"}
                and _node_key(child) not in verified_operations
            ):
                mutable.add(child.func.value.id)
        elif isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name):
            if child.value.id in aliases and isinstance(child.ctx, (ast.Store, ast.Del)):
                mutable.add(child.value.id)
    return frozenset(mutable)


def _pcresolve_operations(
    effects: Sequence[dict], parameter: str, key: str
) -> Dict[Tuple[int, int, int, int], Tuple[Optional[KeyPresence], Optional[KeyEffect]]]:
    """Use PCResolve provenance to identify mutations through local aliases."""

    operations = {}
    for effect in effects:
        if effect.get("operation") not in {"pop", "delete", "update"}:
            continue
        roots = effect.get("mapping", ())
        if len(roots) != 1 or not (
            roots[0].get("kind") == "parameter"
            and roots[0].get("name") == parameter
            and roots[0].get("element_path", []) in ([], ["*"])
        ):
            continue
        evidence = effect.get("evidence", {})
        if not all(
            isinstance(evidence.get(field), int)
            for field in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ):
            continue
        location = (
            evidence["lineno"],
            evidence["col_offset"],
            evidence["end_lineno"],
            evidence["end_col_offset"],
        )
        path = effect.get("element_path", ["*"])
        if effect.get("status") != "bounded" or path == ["*"]:
            operation = (KeyPresence.UNKNOWN, None)
        elif path != [key]:
            operation = (None, None)
        elif effect["operation"] in {"pop", "delete"}:
            operation = (KeyPresence.ABSENT, KeyEffect.CONSUMED)
        elif effect.get("state_after") in {"present", "conditional"}:
            operation = (KeyPresence.PRESENT, KeyEffect.REASSIGNED)
        else:
            operation = (KeyPresence.UNKNOWN, None)
        previous = operations.get(location)
        operations[location] = (
            (KeyPresence.UNKNOWN, None)
            if previous is not None and previous != operation
            else operation
        )
    return operations


def _is_tracked_mutation(call: ast.Call, result: MappingKeyFlow) -> bool:
    return _node_key(call) in result.pcresolve_operations or _is_mapping_mutation(
        call, result.parameter
    )


def _passes_mapping_as_data(call: ast.Call, parameter: str) -> bool:
    return any(isinstance(arg, ast.Name) and arg.id == parameter for arg in call.args) or any(
        isinstance(keyword.value, ast.Name)
        and keyword.value.id == parameter
        and keyword.arg is not None
        for keyword in call.keywords
    )


def _mapping_operation(
    call: ast.Call,
    parameter: str,
    key: str,
) -> Optional[Tuple[Optional[KeyPresence], Optional[KeyEffect]]]:
    if not isinstance(call.func, ast.Attribute):
        return None
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != parameter:
        return None
    method = call.func.attr
    literal_key = _literal_string(call.args[0]) if call.args else None
    if method == "pop" and literal_key == key:
        return KeyPresence.ABSENT, KeyEffect.CONSUMED
    if method == "pop":
        return (None, None) if literal_key is not None else (KeyPresence.UNKNOWN, None)
    if method == "clear":
        return KeyPresence.ABSENT, KeyEffect.CONSUMED
    if method == "setdefault" and literal_key == key:
        return KeyPresence.PRESENT, None
    if method == "setdefault":
        return (None, None) if literal_key is not None else (KeyPresence.UNKNOWN, None)
    if method == "update":
        updated = _updated_key_presence(call, key)
        if updated is KeyPresence.PRESENT:
            return updated, KeyEffect.REASSIGNED
        if updated is KeyPresence.ABSENT:
            return None, None
        return KeyPresence.UNKNOWN, None
    if method in {"popitem"}:
        return KeyPresence.UNKNOWN, None
    return None


def _apply_assignment_target(
    target: ast.AST,
    states: Set[_State],
    parameter: str,
    key: str,
) -> Set[_State]:
    if isinstance(target, ast.Name) and target.id == parameter:
        return _set_presence(states, KeyPresence.UNKNOWN, None)
    if _is_key_subscript(target, parameter, key):
        return _set_presence(states, KeyPresence.PRESENT, KeyEffect.REASSIGNED)
    if isinstance(target, (ast.Tuple, ast.List)):
        current = set(states)
        for item in target.elts:
            current = _apply_assignment_target(item, current, parameter, key)
        return current
    return states


def _refine_membership(
    states: Set[_State],
    test: ast.AST,
    parameter: str,
    key: str,
) -> Tuple[Set[_State], Set[_State]]:
    membership = _membership_test(test, parameter, key)
    if membership is None:
        return set(states), set(states)
    true_means_present = membership
    true_presence = KeyPresence.PRESENT if true_means_present else KeyPresence.ABSENT
    false_presence = KeyPresence.ABSENT if true_means_present else KeyPresence.PRESENT
    return (
        _restrict_presence(states, true_presence),
        _restrict_presence(states, false_presence),
    )


def _membership_test(test: ast.AST, parameter: str, key: str) -> Optional[bool]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        nested = _membership_test(test.operand, parameter, key)
        return None if nested is None else not nested
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    if _literal_string(test.left) != key:
        return None
    comparator = test.comparators[0]
    if not isinstance(comparator, ast.Name) or comparator.id != parameter:
        return None
    if isinstance(test.ops[0], ast.In):
        return True
    if isinstance(test.ops[0], ast.NotIn):
        return False
    return None


def _restrict_presence(states: Set[_State], required: KeyPresence) -> Set[_State]:
    restricted = set()
    for state in states:
        if state.presence is required:
            restricted.add(state)
        elif state.presence is KeyPresence.UNKNOWN:
            restricted.add(_State(required, state.effects))
    return restricted


def _set_presence(
    states: Iterable[_State],
    presence: KeyPresence,
    effect: Optional[KeyEffect],
) -> Set[_State]:
    return {
        _State(
            presence,
            state.effects | ({effect} if effect is not None else set()),
        )
        for state in states
    }


def _add_effect(states: Iterable[_State], effect: KeyEffect) -> Set[_State]:
    return {_State(state.presence, state.effects | {effect}) for state in states}


def _updated_key_presence(call: ast.Call, key: str) -> Optional[KeyPresence]:
    if any(keyword.arg == key for keyword in call.keywords):
        return KeyPresence.PRESENT
    if not call.args:
        return None
    mapping = call.args[0]
    if not isinstance(mapping, ast.Dict):
        return None
    if any(item is None for item in mapping.keys):
        return None
    literal_keys = {_literal_string(item) for item in mapping.keys}
    return KeyPresence.PRESENT if key in literal_keys else KeyPresence.ABSENT


def _is_mapping_mutation(call: ast.Call, parameter: str) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == parameter
        and call.func.attr in {"clear", "pop", "popitem", "setdefault", "update"}
    )


def _pops_key(node: ast.AST, parameter: str, key: str) -> bool:
    return any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Attribute)
        and isinstance(child.func.value, ast.Name)
        and child.func.value.id == parameter
        and child.func.attr == "pop"
        and child.args
        and _literal_string(child.args[0]) == key
        for child in _descendants(node)
    )


def _assigns_other_key(node: ast.AST, parameter: str, key: str) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == parameter
        and _literal_string(node.slice) not in {None, key}
    )


def _is_key_subscript(node: ast.AST, parameter: str, key: str) -> bool:
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == parameter
        and _literal_string(node.slice) == key
    )


def _literal_string(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _calls_in_evaluation_order(node: ast.AST) -> List[ast.Call]:
    calls = [child for child in _descendants(node) if isinstance(child, ast.Call)]
    return sorted(calls, key=lambda item: (item.lineno, item.col_offset))


def _descendants(node: ast.AST) -> Iterable[ast.AST]:
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        if isinstance(current, ast.Lambda) or (
            current is not node
            and isinstance(
                current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            )
        ):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(current))))


def _node_key(node: ast.AST) -> Tuple[int, int, int, int]:
    return (
        node.lineno,
        node.col_offset,
        getattr(node, "end_lineno", node.lineno),
        getattr(node, "end_col_offset", node.col_offset),
    )


def _span_key(span: SourceSpan) -> Tuple[int, int, int, int]:
    return (span.lineno, span.col_offset, span.end_lineno, span.end_col_offset)
