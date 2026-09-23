"""Recognize a narrow variadic-keyword path into a property validator.

This is a path proof, not a closed-world proof that a dynamic Python object
cannot acquire a property setter at runtime.  Callers should report MAY_FAIL.
"""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import FunctionIdentity, SourceSpan
from .source import IndexedFunction, SourceIndex


@dataclass(frozen=True)
class PropertyValidationPath:
    validator: IndexedFunction
    callsite: SourceSpan


def find_property_validation_path(
    entry: IndexedFunction,
    index: SourceIndex,
    old_name: str,
) -> Optional[PropertyValidationPath]:
    """Find a direct ``**kwargs -> super -> _internal_update`` path.

    The returned path is deliberately only possible: decorators, earlier
    exceptions, dynamic setters, and method overrides can still alter it.
    """

    identity = entry.identity
    if not identity.qualname.endswith(".__init__") or not entry.signature.kwarg:
        return None
    class_name = identity.qualname.removesuffix(".__init__")
    if "." in class_name or identity.file_path is None:
        return None
    tree = _load_tree(identity.file_path)
    if tree is None:
        return None
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    matches = [node for node in classes if node.name == class_name]
    if len(matches) != 1:
        return None
    current = matches[0]
    if len(current.bases) != 1 or not isinstance(current.bases[0], ast.Name):
        return None
    base_name = current.bases[0].id
    base_matches = [node for node in classes if node.name == base_name]
    if len(base_matches) != 1 or len(base_matches[0].bases) != 1:
        return None
    base_class = base_matches[0]
    base_constructor = index.find(FunctionIdentity(identity.module, f"{base_name}.__init__"))
    if base_constructor is None or not base_constructor.signature.kwarg:
        return None
    if not _direct_super_forward(entry.node, entry.signature.kwarg, old_name):
        return None
    base_kwarg = base_constructor.signature.kwarg
    update_call = _guarded_update_call(base_constructor.node, base_kwarg)
    if update_call is None:
        return None

    artist_base = base_class.bases[0]
    if not (
        isinstance(artist_base, ast.Attribute)
        and isinstance(artist_base.value, ast.Name)
        and artist_base.attr == "Artist"
    ):
        return None
    artist_import = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None
        for alias in node.names
        if alias.name == artist_base.value.id and alias.asname is None
    ]
    if len(artist_import) != 1:
        return None
    artist_module = f"{identity.module.rsplit('.', 1)[0]}.{artist_base.value.id}"
    internal = index.find(FunctionIdentity(artist_module, "Artist._internal_update"))
    validator = index.find(FunctionIdentity(artist_module, "Artist._update_props"))
    if internal is None or validator is None:
        return None
    if not _delegates_to_validator(internal.node, validator.node, old_name):
        return None
    if any(
        index.find(FunctionIdentity(identity.module, f"{name}._internal_update")) is not None
        for name in (class_name, base_name)
    ):
        return None
    relevant_classes = {
        class_name,
        base_name,
        "Artist",
    }
    if any(
        function.identity.module in {identity.module, artist_module}
        and function.identity.qualname in {f"{name}.set_{old_name}" for name in relevant_classes}
        for function in index.functions
    ):
        return None
    return PropertyValidationPath(
        validator=validator,
        callsite=SourceSpan(
            file_path=base_constructor.identity.file_path,
            lineno=update_call.lineno,
            col_offset=update_call.col_offset,
            end_lineno=update_call.end_lineno,
            end_col_offset=update_call.end_col_offset,
        ),
    )


def _load_tree(path: Path) -> Optional[ast.Module]:
    try:
        with tokenize.open(path) as stream:
            return ast.parse(stream.read(), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return None


def _direct_super_forward(node, kwarg: str, old_name: str) -> bool:
    for statement in node.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            return False
        call = statement.value
        if (
            ast.unparse(call.func) == f"{kwarg}.setdefault"
            and call.args
            and isinstance(call.args[0], ast.Constant)
            and call.args[0].value != old_name
            and not call.keywords
            and not any(
                isinstance(name, ast.Name) and name.id == kwarg
                for argument in call.args
                for name in ast.walk(argument)
            )
        ):
            continue
        if ast.unparse(call) == f"super().__init__(**{kwarg})":
            return True
        return False
    return False


def _guarded_update_call(node, kwarg: str) -> Optional[ast.Call]:
    for statement in node.body:
        if not isinstance(statement, ast.If) or ast.unparse(statement.test) != f"len({kwarg})":
            if any(isinstance(name, ast.Name) and name.id == kwarg for name in ast.walk(statement)):
                return None
            continue
        if len(statement.body) != 1 or statement.orelse:
            return None
        body = statement.body[0]
        if not isinstance(body, ast.Expr) or not isinstance(body.value, ast.Call):
            return None
        call = body.value
        if ast.unparse(call) == f"self._internal_update({kwarg})":
            return call
        return None
    return None


def _delegates_to_validator(internal, validator, old_name: str) -> bool:
    if internal.decorator_list or validator.decorator_list:
        return False
    internal_body = _without_docstring(internal.body)
    if len(internal_body) != 1 or not isinstance(internal_body[0], ast.Return):
        return False
    forwarded = internal_body[0].value
    if not isinstance(forwarded, ast.Call):
        return False
    if (
        ast.unparse(forwarded.func) != "self._update_props"
        or not forwarded.args
        or ast.unparse(forwarded.args[0]) != "kwargs"
        or forwarded.keywords
    ):
        return False
    if any(_is_key_special_case(node, old_name) for node in ast.walk(validator)):
        return False
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "props"
        and node.func.attr != "items"
        for node in ast.walk(validator)
    ):
        return False
    for loop in ast.walk(validator):
        if not isinstance(loop, ast.For):
            continue
        if not isinstance(loop.target, ast.Tuple) or len(loop.target.elts) != 2:
            continue
        if not isinstance(loop.target.elts[0], ast.Name):
            continue
        if ast.unparse(loop.iter) != "props.items()":
            continue
        key = loop.target.elts[0].id
        if any(
            _setter_lookup_then_raise(statements, key) for statements in _statement_lists(loop.body)
        ):
            return True
    return False


def _without_docstring(statements: list[ast.stmt]) -> list[ast.stmt]:
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        return statements[1:]
    return statements


def _is_key_special_case(node: ast.AST, old_name: str) -> bool:
    return (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and len(node.ops) == 1
        and isinstance(node.ops[0], (ast.Eq, ast.Is))
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == old_name
    )


def _statement_lists(statements: list[ast.stmt]):
    yield statements
    for statement in statements:
        if isinstance(statement, ast.If):
            yield from _statement_lists(statement.body)
            yield from _statement_lists(statement.orelse)
        elif isinstance(statement, (ast.With, ast.For, ast.While)):
            yield from _statement_lists(statement.body)


def _setter_lookup_then_raise(statements: list[ast.stmt], key: str) -> bool:
    for first, second in zip(statements, statements[1:]):
        if not (
            isinstance(first, ast.Assign)
            and len(first.targets) == 1
            and isinstance(first.targets[0], ast.Name)
            and isinstance(first.value, ast.Call)
            and ast.unparse(first.value) == f"getattr(self, f'set_{{{key}}}', None)"
        ):
            continue
        setter_var = first.targets[0].id
        if not (
            isinstance(second, ast.If)
            and ast.unparse(second.test) == f"not callable({setter_var})"
            and second.body
            and isinstance(second.body[0], ast.Raise)
            and isinstance(second.body[0].exc, ast.Call)
            and ast.unparse(second.body[0].exc.func) == "AttributeError"
        ):
            continue
        return True
    return False
