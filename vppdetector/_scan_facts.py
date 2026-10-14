"""Bounded syntax checks for consuming scan conditions and builtin copy facts."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional

from .models import FunctionIdentity


def capture_names(node, enclosing):
    """Use shared relay facts, retaining a diagnostic fallback for older dependencies."""

    try:
        from pcresolve.scope_facts import transitive_captured_names
    except ImportError:
        from pcresolve.scope_facts import captured_names, function_scope_facts

        return captured_names(function_scope_facts(node), enclosing)
    return transitive_captured_names(node, enclosing)


def immediate_body(node):
    """A synchronous named function call executes its body only if it is not a generator."""

    if not isinstance(node, ast.FunctionDef):
        return False
    pending = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.Yield, ast.YieldFrom)):
            return False
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pending.extend(ast.iter_child_nodes(child))
    return True


def _location(value):
    return tuple(value.get(name) for name in (
        'lineno', 'col_offset', 'end_lineno', 'end_col_offset',
    ))


def _node_location(node):
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


def _expression(text):
    if not isinstance(text, str) or len(text) > 4096:
        return None
    try:
        node = ast.parse(text, mode='eval').body
        return node if sum(1 for _ in ast.walk(node)) <= 128 else None
    except (SyntaxError, ValueError, RecursionError):
        return None


def copy_protocol_target(owner, analysis, call, value) -> Optional[FunctionIdentity]:
    """Check an exact copy edge, its output object and its indexed source witness."""

    obj = value.get('container_object', {})
    results = call.result_sources
    if not (
        call.target_status == 'local_container_protocol'
        and call.analysis_status == 'analyzed'
        and call.binding_status == 'complete'
        and not call.binding_issues
        and not call.target
        and not call.target_candidates
        and value.get('kind') == 'call_result'
        and value.get('source') == call.id
        and value.get('object_only')
        and value.get('relation') == 'direct'
        and not any(value.get(flag) for flag in ('value_incomplete', 'projection', 'output_path'))
        and len(results) == 1
        and results[0].get('kind') == 'call_result'
        and results[0].get('relation') == 'direct'
        and not any(results[0].get(flag) for flag in (
            'value_incomplete', 'projection', 'output_path',
        ))
        and results[0].get('object_only')
        and results[0].get('source') == call.id
        and results[0].get('container_object') == obj
        and obj.get('source') and obj.get('copied_from')
        and obj.get('container_shape') in {'dict', 'list', 'tuple'}
        and obj.get('identity') in {'shallow_copy', 'argument_alias'}
        and len(call.effects) == 1
    ):
        return None
    effect = call.effects[0]
    if not (
        effect.get('kind') == 'container_copy'
        and effect.get('operation') == 'copy'
        and effect.get('status') == 'bounded'
        and effect.get('completion') == 'normal_return'
        and effect.get('input_container') == obj['copied_from']
        and effect.get('output_container') == obj['source']
        and effect.get('container_shape') == obj['container_shape']
        and effect.get('identity') == obj['identity']
        and (obj['identity'] != 'shallow_copy' or obj['source'] != obj['copied_from'])
        and (obj['identity'] != 'argument_alias' or (
            obj['container_shape'] == 'tuple' and obj['source'] == obj['copied_from']))
        and not any(b.get('call_id') == call.id and b.get('reason') not in {'depth_limit'}
                    for b in analysis.boundaries)
    ):
        return None
    witness = effect.get('evidence', {})
    node = _expression(witness.get('source_text'))
    location = (call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)
    if (not isinstance(node, ast.Call) or _location(witness) != location
            or Path(witness.get('file_path', '')) != owner.identity.file_path
            or ast.unparse(node.func) != call.callee_name
            or not any(isinstance(source, ast.Call) and _node_location(source) == location
                       and ast.dump(source) == ast.dump(node) for source in ast.walk(owner.node))):
        return None
    if (isinstance(node.func, ast.Attribute) and node.func.attr == 'copy'
            and obj['container_shape'] == 'dict' and not node.args and not node.keywords):
        return FunctionIdentity('builtins', 'dict.copy')
    if (isinstance(node.func, ast.Name) and node.func.id == obj['container_shape']
            and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred)
            and not node.keywords):
        return FunctionIdentity('builtins', node.func.id)
    return None


def _constant_truth(node, depth=0):
    if depth > 16:
        return None
    if isinstance(node, ast.Constant) and type(node.value) in (
        str, bytes, int, float, bool, type(None),
    ):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        truth = _constant_truth(node.operand, depth + 1)
        return not truth if truth is not None else None
    if isinstance(node, ast.BoolOp):
        values = [_constant_truth(value, depth + 1) for value in node.values]
        decisive = isinstance(node.op, ast.Or)
        if decisive in values:
            return decisive
        if all(value is not None for value in values):
            return not decisive
    return None


def conditions_possible(context, value) -> bool:
    """Prune only a recorded branch contradicted by matching constant source syntax."""

    for condition in value.get('conditions', ()):
        branch = condition.get('branch')
        witness = condition.get('test', {})
        if type(branch) is not bool or not isinstance(witness, dict):
            continue
        path = Path(witness.get('file_path', ''))
        if path not in context._constant_tests:
            tests = {}
            for function in context.index.functions:
                if function.identity.file_path != path:
                    continue
                for node in ast.walk(function.node):
                    if not isinstance(node, (ast.Constant, ast.UnaryOp, ast.BoolOp)):
                        continue
                    truth = _constant_truth(node)
                    if truth is not None:
                        tests[_node_location(node)] = (truth, ast.dump(node))
            context._constant_tests[path] = tests
        test = context._constant_tests[path].get(_location(witness))
        if test is None or test[0] == branch:
            continue
        node = _expression(witness.get('source_text'))
        if node is not None and ast.dump(node) == test[1]:
            return False
    return True
