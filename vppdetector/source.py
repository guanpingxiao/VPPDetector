"""Source indexing and Python-signature facts used by VPP rules."""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass, field
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

    @classmethod
    def from_arguments(cls, arguments: ast.arguments) -> "SignatureFacts":
        return cls(
            positional_only=tuple(arg.arg for arg in arguments.posonlyargs),
            positional_or_keyword=tuple(arg.arg for arg in arguments.args),
            keyword_only=tuple(arg.arg for arg in arguments.kwonlyargs),
            vararg=arguments.vararg.arg if arguments.vararg else None,
            kwarg=arguments.kwarg.arg if arguments.kwarg else None,
        )

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
    imports: dict = field(default_factory=dict)
    classes: Tuple[FunctionIdentity, ...] = ()
    _definition_index: object = field(default=None, init=False, repr=False)

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

    def resolve_imported(self, identity: FunctionIdentity) -> Optional[IndexedFunction]:
        """Resolve an exact import-backed API or source class through PCResolve."""

        if identity.file_path or identity.lineno:
            constructors = [
                item.function
                for item in self.constructors
                if item.class_identity.module == identity.module
                and item.class_identity.qualname == identity.qualname
                and (
                    not identity.file_path
                    or item.class_identity.file_path
                    and item.class_identity.file_path.resolve() == identity.file_path.resolve()
                )
                and (not identity.lineno or item.class_identity.lineno == identity.lineno)
            ]
            return constructors[0] if len(constructors) == 1 else None

        definitions = self._definitions()
        function = definitions.resolve_name(identity.module, "", identity.qualname, self.imports)
        if function is not None:
            return function
        class_identity = definitions.resolve_name(
            identity.module, "", identity.qualname, self.imports, kind="class"
        )
        if class_identity is None:
            return None
        constructors = [
            item.function for item in self.constructors if item.class_identity == class_identity
        ]
        return constructors[0] if len(constructors) == 1 else None

    def resolve_method_identity(self, identity: FunctionIdentity) -> Optional[FunctionIdentity]:
        """Canonicalize a class prefix; PCResolve still owns inherited lookup."""

        function = self.find(identity)
        if function is not None:
            return function.identity
        if identity.file_path or identity.lineno:
            return None
        owner, separator, method = identity.qualname.rpartition(".")
        if not separator:
            return None
        class_identity = self._definitions().resolve_name(
            identity.module, "", owner, self.imports, kind="class"
        )
        if class_identity is None:
            return None
        # Location belongs to the requested method, not to its declaring class.
        # An inherited implementation can be in a different source module.
        return FunctionIdentity(class_identity.module, class_identity.qualname + "." + method)

    def _definitions(self):
        if self._definition_index is None:
            from pcresolve.call_resolution import DefinitionIndex, DefinitionRecord

            grouped = {}
            for function in self.functions:
                key = (function.identity.module, function.identity.qualname)
                grouped.setdefault(key, []).append(function)
            records = []
            for (module, qualname), functions in grouped.items():
                implementations = [function for function in functions if not function.is_overload]
                selected = implementations if len(implementations) == 1 else functions
                records.extend(
                    DefinitionRecord(module, qualname, function) for function in selected
                )
            records.extend(
                DefinitionRecord(
                    identity.module,
                    identity.qualname,
                    identity,
                    kind="class",
                )
                for identity in self.classes
            )
            self._definition_index = DefinitionIndex(records)
        return self._definition_index

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
        self.classes: List[FunctionIdentity] = []

    def generic_visit(self, node: ast.AST) -> None:
        # Definitions live in statement structure, not inside expressions.
        # Traversing giant expression trees adds no API facts and can overflow
        # Python's recursion limit even when the source parses successfully.
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, ast.expr):
                self.visit(child)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_qualname = ".".join((*self.scope, node.name))
        class_identity = FunctionIdentity(
            module=self.module,
            qualname=class_qualname,
            file_path=self.file_path,
            lineno=node.lineno,
        )
        self.classes.append(class_identity)
        constructor = None
        # Match PCResolve's source constructor preference without inferring
        # metaclass behavior: direct __init__, otherwise direct __new__.
        for method in ("__init__", "__new__"):
            candidates = [
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method
            ]
            implementations = [
                item
                for item in candidates
                if not any(_is_overload_decorator(d) for d in item.decorator_list)
            ]
            if len(implementations) == 1:
                constructor = implementations[0]
                break
            if candidates:
                # A declared initializer with no unique implementation is not
                # evidence that construction instead uses the allocator body.
                break
        if constructor is not None:
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
    from pcresolve.import_facts import import_facts, resolve_relative_module
    from pcresolve.scope_facts import statement_scope_facts

    root = source.package_root.resolve()
    if not root.exists():
        raise FileNotFoundError("Package root does not exist: {}".format(root))
    import_roots = normalized_import_roots(source)
    normalized_source = SourceContext(package_root=root, import_roots=import_roots)
    files = tuple(_python_files(root))
    functions: List[IndexedFunction] = []
    constructors: List[IndexedConstructor] = []
    classes: List[FunctionIdentity] = []
    boundaries: List[AnalysisBoundary] = []
    imports = {}

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
        aliases = {}
        imported_bindings = {}
        rebound = set()
        for statement in tree.body:
            facts = import_facts(statement)
            if not facts:
                rebound.update(statement_scope_facts([statement]).bound)
            for fact in facts:
                imported_bindings[fact.python_binding] = (
                    imported_bindings.get(fact.python_binding, 0) + 1
                )
                if fact.kind == "import":
                    aliases[fact.python_binding] = fact.name if fact.asname else fact.python_binding
                else:
                    prefix = (
                        resolve_relative_module(
                            module,
                            file_path.name.startswith("__init__."),
                            fact.module,
                            fact.level,
                        )
                        if fact.level
                        else fact.module
                    )
                    aliases[fact.python_binding] = prefix + "." + fact.name
        imports[module] = {
            name: target
            for name, target in aliases.items()
            if name not in rebound and imported_bindings[name] == 1
        }
        collector = _FunctionCollector(module, file_path)
        collector.visit(tree)
        functions.extend(collector.functions)
        constructors.extend(collector.constructors)
        classes.extend(collector.classes)

    return SourceIndex(
        source=normalized_source,
        files=files,
        functions=tuple(functions),
        constructors=tuple(constructors),
        boundaries=tuple(boundaries),
        imports=imports,
        classes=tuple(classes),
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
