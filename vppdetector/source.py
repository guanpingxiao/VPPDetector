"""Source indexing and Python-signature facts used by VPP rules."""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from .models import AnalysisBoundary, FunctionIdentity, SourceContext, VariadicKind

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]


@dataclass(frozen=True)
class SignatureFacts:
    positional_only: Tuple[str, ...]
    positional_or_keyword: Tuple[str, ...]
    keyword_only: Tuple[str, ...]
    vararg: Optional[str]
    kwarg: Optional[str]
    required_positional: Tuple[str, ...]
    required_keyword_only: Tuple[str, ...]

    @classmethod
    def from_arguments(cls, arguments: ast.arguments) -> "SignatureFacts":
        positional = (*arguments.posonlyargs, *arguments.args)
        required_count = len(positional) - len(arguments.defaults)
        return cls(
            positional_only=tuple(arg.arg for arg in arguments.posonlyargs),
            positional_or_keyword=tuple(arg.arg for arg in arguments.args),
            keyword_only=tuple(arg.arg for arg in arguments.kwonlyargs),
            vararg=arguments.vararg.arg if arguments.vararg else None,
            kwarg=arguments.kwarg.arg if arguments.kwarg else None,
            required_positional=tuple(arg.arg for arg in positional[:required_count]),
            required_keyword_only=tuple(
                arg.arg
                for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults)
                if default is None
            ),
        )

    def accepts_keyword(self, name: str) -> bool:
        return bool(self.kwarg or self.explicitly_accepts_keyword(name))

    def explicitly_accepts_keyword(self, name: str) -> bool:
        return name in self.positional_or_keyword or name in self.keyword_only

    def accepts_variadic(self, kind: VariadicKind) -> bool:
        if kind is VariadicKind.KEYWORD:
            return self.kwarg is not None
        return self.vararg is not None


@dataclass
class IndexedFunction:
    identity: FunctionIdentity
    signature: SignatureFacts
    node: FunctionNode
    is_overload: bool
    is_bound_method: bool = False

    @property
    def variadic_parameters(self) -> Tuple[Tuple[str, VariadicKind], ...]:
        parameters: List[Tuple[str, VariadicKind]] = []
        if self.signature.vararg:
            parameters.append((self.signature.vararg, VariadicKind.POSITIONAL))
        if self.signature.kwarg:
            parameters.append((self.signature.kwarg, VariadicKind.KEYWORD))
        return tuple(parameters)


@dataclass(frozen=True)
class IndexedConstructor:
    class_identity: FunctionIdentity
    function: IndexedFunction


@dataclass
class SourceIndex:
    source: SourceContext
    files: Tuple[Path, ...]
    functions: Tuple[IndexedFunction, ...]
    constructors: Tuple[IndexedConstructor, ...]
    boundaries: Tuple[AnalysisBoundary, ...]

    def find(self, identity: FunctionIdentity) -> Optional[IndexedFunction]:
        requested_path = identity.file_path.resolve() if identity.file_path else None
        candidates = [
            function
            for function in self.functions
            if function.identity.module == identity.module
            and function.identity.qualname == identity.qualname
        ]
        if requested_path is not None:
            candidates = [
                function
                for function in candidates
                if function.identity.file_path
                and function.identity.file_path.resolve() == requested_path
            ]
        if identity.lineno:
            candidates = [
                function for function in candidates if function.identity.lineno == identity.lineno
            ]
        elif len(candidates) > 1:
            implementations = [function for function in candidates if not function.is_overload]
            if len(implementations) == 1:
                candidates = implementations
        return candidates[0] if len(candidates) == 1 else None

    def find_by_location(self, file_path: Path, lineno: int) -> Optional[IndexedFunction]:
        resolved = file_path.resolve()
        candidates = [
            function
            for function in self.functions
            if function.identity.file_path
            and function.identity.file_path.resolve() == resolved
            and function.identity.lineno == lineno
        ]
        if len(candidates) == 1:
            return candidates[0]
        constructors = [
            item.function
            for item in self.constructors
            if item.class_identity.file_path
            and item.class_identity.file_path.resolve() == resolved
            and item.class_identity.lineno == lineno
        ]
        return constructors[0] if len(constructors) == 1 else None


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, module: str, file_path: Path) -> None:
        self.module = module
        self.file_path = file_path
        self.scope: List[str] = []
        self.scope_kinds: List[str] = []
        self.functions: List[IndexedFunction] = []
        self.constructors: List[IndexedConstructor] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_qualname = ".".join((*self.scope, node.name))
        constructor = next(
            (
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == "__init__"
            ),
            None,
        )
        if constructor is not None:
            class_identity = FunctionIdentity(
                module=self.module,
                qualname=class_qualname,
                file_path=self.file_path,
                lineno=node.lineno,
            )
            constructor_identity = FunctionIdentity(
                module=self.module,
                qualname="{}.{}".format(class_qualname, constructor.name),
                file_path=self.file_path,
                lineno=constructor.lineno,
            )
            self.constructors.append(
                IndexedConstructor(
                    class_identity=class_identity,
                    function=IndexedFunction(
                        identity=constructor_identity,
                        signature=SignatureFacts.from_arguments(constructor.args),
                        node=constructor,
                        is_overload=False,
                        is_bound_method=True,
                    ),
                )
            )
        self.scope.append(node.name)
        self.scope_kinds.append("class")
        self.generic_visit(node)
        self.scope_kinds.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: FunctionNode) -> None:
        qualname = ".".join((*self.scope, node.name))
        identity = FunctionIdentity(
            module=self.module,
            qualname=qualname,
            file_path=self.file_path,
            lineno=node.lineno,
        )
        is_direct_class_member = bool(self.scope_kinds and self.scope_kinds[-1] == "class")
        is_static_method = any(
            _decorator_name(item).split(".")[-1] == "staticmethod" for item in node.decorator_list
        )
        self.functions.append(
            IndexedFunction(
                identity=identity,
                signature=SignatureFacts.from_arguments(node.args),
                node=node,
                is_overload=any(_is_overload_decorator(item) for item in node.decorator_list),
                is_bound_method=is_direct_class_member and not is_static_method,
            )
        )
        self.scope.append(node.name)
        self.scope_kinds.append("function")
        self.generic_visit(node)
        self.scope_kinds.pop()
        self.scope.pop()


def build_source_index(source: SourceContext) -> SourceIndex:
    root = source.package_root.resolve()
    if not root.exists():
        raise FileNotFoundError("Package root does not exist: {}".format(root))
    import_roots = normalized_import_roots(source)
    normalized_source = SourceContext(package_root=root, import_roots=import_roots)
    files = tuple(_python_files(root))
    functions: List[IndexedFunction] = []
    constructors: List[IndexedConstructor] = []
    boundaries: List[AnalysisBoundary] = []

    for file_path in files:
        try:
            with tokenize.open(file_path) as stream:
                tree = ast.parse(stream.read(), filename=str(file_path))
        except (OSError, SyntaxError, UnicodeError) as exc:
            boundaries.append(
                AnalysisBoundary(
                    code="source_parse_failed",
                    message="{}: {}".format(file_path, exc),
                )
            )
            continue
        module = module_name_for_path(file_path, import_roots)
        collector = _FunctionCollector(module, file_path)
        collector.visit(tree)
        functions.extend(collector.functions)
        constructors.extend(collector.constructors)

    return SourceIndex(
        source=normalized_source,
        files=files,
        functions=tuple(functions),
        constructors=tuple(constructors),
        boundaries=tuple(boundaries),
    )


def normalized_import_roots(source: SourceContext) -> Tuple[Path, ...]:
    if source.import_roots:
        return tuple(path.resolve() for path in source.import_roots)
    root = source.package_root.resolve()
    if (root / "__init__.py").is_file():
        return (root.parent,)
    source_root = root / "src"
    if source_root.is_dir():
        return (source_root,)
    return (root,)


def module_name_for_path(file_path: Path, import_roots: Sequence[Path]) -> str:
    for import_root in import_roots:
        try:
            relative = file_path.resolve().relative_to(import_root.resolve())
        except ValueError:
            continue
        parts = list(relative.parts)
        if not parts:
            continue
        filename = parts.pop()
        stem = Path(filename).stem
        if stem != "__init__":
            parts.append(stem)
        return ".".join(parts)
    return file_path.stem


def parameter_is_mutated(function: IndexedFunction, parameter: str) -> bool:
    """Return true for mutations that make element-level forwarding uncertain."""

    for node in _function_body_nodes(function.node):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets: Iterable[ast.AST]
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.Delete):
                targets = node.targets
            else:
                targets = (node.target,)
            if any(_targets_parameter(target, parameter) for target in targets):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == parameter:
                if node.func.attr in {"clear", "pop", "popitem", "setdefault", "update"}:
                    return True
    return False


def _python_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix in {".py", ".pyi"}:
            yield root
        return
    for path in sorted(root.rglob("*.py")):
        if not any(part in {".git", ".tox", ".venv", "venv", "__pycache__"} for part in path.parts):
            yield path.resolve()


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return "{}.{}".format(prefix, node.attr) if prefix else node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _is_overload_decorator(node: ast.AST) -> bool:
    return _decorator_name(node).split(".")[-1] == "overload"


def _function_body_nodes(function: FunctionNode) -> Iterable[ast.AST]:
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _targets_parameter(node: ast.AST, parameter: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == parameter
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        value = node.value
        return isinstance(value, ast.Name) and value.id == parameter
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_targets_parameter(item, parameter) for item in node.elts)
    return False
