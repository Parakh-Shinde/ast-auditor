import ast
from dataclasses import dataclass
from typing import ClassVar

from ast_auditor.rules import PY001, PY002, PY003, PY004, PY005, PY006


@dataclass(frozen=True)
class Finding:
    """Represent a security finding produced by the scanner."""

    rule_id: str
    message: str
    line: int
    severity: str
    file: str | None = None


class _LocalBindingCollector(ast.NodeVisitor):
    """Collect names bound in a function without entering nested scopes."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.names.add(item.asname or item.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name != "*":
                self.names.add(item.asname or item.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Global(self, node: ast.Global) -> None:
        self.names.difference_update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.names.difference_update(node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def _visit_comprehension(self, node: ast.expr) -> None:
        # Comprehension iteration targets are scoped to the comprehension
        # in Python 3 and must not mark the enclosing function variable-local.
        for generator in node.generators:  # type: ignore[attr-defined]
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)  # type: ignore[attr-defined]

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)


class SecurityVisitor(ast.NodeVisitor):
    """Detect selected dangerous Python APIs with lightweight alias tracking."""

    DANGEROUS_FUNCTIONS: ClassVar[set[str]] = {"eval", "exec"}
    SUBPROCESS_FUNCTIONS: ClassVar[set[str]] = {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    }
    YAML_SAFE_LOADERS: ClassVar[set[str]] = {"SafeLoader", "CSafeLoader"}
    HTTP_REQUEST_FUNCTIONS: ClassVar[set[str]] = {
        "request", "get", "options", "head", "post", "put", "patch", "delete"
    }

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.bindings: dict[str, str | None] = {}
        self.builtins_modules: set[str] = set()
        self._class_outer_scopes: list[tuple[dict[str, str | None], set[str]]] = []
        self._class_namespace_bindings: list[dict[str, str | None]] = []

    def _resolve_dangerous_name(self, name: str) -> str | None:
        if name in self.bindings:
            return self.bindings[name]

        if name in self.DANGEROUS_FUNCTIONS:
            return name

        return None

    def _resolve_expression(self, value: ast.expr) -> str | None:
        """Resolve supported dangerous APIs and simple aliases."""
        if isinstance(value, ast.Name):
            return self._resolve_dangerous_name(value.id)

        if isinstance(value, ast.Call):
            # getattr(builtins, "eval")(...), a common dynamic spelling.
            if (
                isinstance(value.func, ast.Name)
                and value.func.id == "getattr"
                and len(value.args) >= 2
                and isinstance(value.args[0], ast.Name)
                and value.args[0].id in self.builtins_modules
                and isinstance(value.args[1], ast.Constant)
                and value.args[1].value in self.DANGEROUS_FUNCTIONS
            ):
                return str(value.args[1].value)
            return None

        if isinstance(value, ast.Attribute):
            if isinstance(value.value, ast.Name):
                if (
                    value.value.id in self.builtins_modules
                    and value.attr in self.DANGEROUS_FUNCTIONS
                ):
                    return value.attr

                module_binding = self._resolve_dangerous_name(value.value.id)
                if module_binding == "pickle_module":
                    if value.attr in {"load", "loads"}:
                        return f"pickle.{value.attr}"
                    if value.attr == "Unpickler":
                        return "pickle.Unpickler"
                if module_binding == "yaml_module" and value.attr == "load":
                    return "yaml.load"
                if (
                    module_binding in {"requests_module", "httpx_module"}
                    and value.attr in self.HTTP_REQUEST_FUNCTIONS
                ):
                    return "tls.verify_false"
                if (
                    module_binding == "yaml_module"
                    and value.attr in self.YAML_SAFE_LOADERS
                ):
                    return "yaml_safe_loader"
                if (
                    module_binding == "subprocess_module"
                    and value.attr in self.SUBPROCESS_FUNCTIONS
                ):
                    return f"subprocess.{value.attr}"
                if module_binding == "os_module" and value.attr in {"system", "popen"}:
                    return f"os.{value.attr}"

            if (
                isinstance(value.value, ast.Call)
                and value.attr == "load"
                and self._resolve_expression(value.value.func) == "pickle.Unpickler"
            ):
                return "pickle.Unpickler.load"

        return None

    @staticmethod
    def _dangerous_binding(value: str | None) -> bool:
        known_dangerous = {
            "eval",
            "exec",
            "pickle.load",
            "pickle.loads",
            "pickle.Unpickler.load",
            "yaml.load",
            "tls.verify_false",
            "os.system",
            "os.popen",
        }
        return value in known_dangerous or bool(
            value and value.startswith("subprocess.")
        )

    def _bind_name(self, name: str, value: ast.expr) -> None:
        """Track aliases and invalidate stale bindings."""
        is_builtins_module = (
            isinstance(value, ast.Name) and value.id in self.builtins_modules
        )
        dangerous_name = self._resolve_expression(value)

        self.bindings[name] = dangerous_name
        self.builtins_modules.discard(name)

        if is_builtins_module:
            self.builtins_modules.add(name)

    @staticmethod
    def _target_names(target: ast.expr) -> set[str]:
        """Return names assigned by a simple or destructuring target."""
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            return {
                name
                for element in target.elts
                for name in SecurityVisitor._target_names(element)
            }
        if isinstance(target, ast.Starred):
            return SecurityVisitor._target_names(target.value)
        return set()

    def _invalidate_target(self, target: ast.expr) -> None:
        """Invalidate aliases for assignments we cannot resolve precisely."""
        for name in self._target_names(target):
            self.bindings[name] = None
            self.builtins_modules.discard(name)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                self._bind_name(target.id, node.value)
            else:
                self._invalidate_target(target)
                self.visit(target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._invalidate_target(node.target)
        self.visit(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._invalidate_target(target)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)

        if node.value is not None:
            self.visit(node.value)

        if isinstance(node.target, ast.Name):
            if node.value is None:
                self.bindings[node.target.id] = None
                self.builtins_modules.discard(node.target.id)
            else:
                self._bind_name(node.target.id, node.value)
        else:
            self.visit(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)

        if isinstance(node.target, ast.Name):
            self._bind_name(node.target.id, node.value)
        else:
            self.visit(node.target)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            bound_name = item.asname or item.name.split(".")[0]
            self.bindings[bound_name] = None
            self.builtins_modules.discard(bound_name)

            if item.name == "builtins":
                self.builtins_modules.add(bound_name)
            elif item.name == "pickle":
                self.bindings[bound_name] = "pickle_module"
            elif item.name == "yaml":
                self.bindings[bound_name] = "yaml_module"
            elif item.name == "requests":
                self.bindings[bound_name] = "requests_module"
            elif item.name == "httpx":
                self.bindings[bound_name] = "httpx_module"
            elif item.name == "subprocess":
                self.bindings[bound_name] = "subprocess_module"
            elif item.name == "os":
                self.bindings[bound_name] = "os_module"

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name == "*":
                continue

            bound_name = item.asname or item.name

            if (
                node.level == 0
                and node.module == "builtins"
                and item.name in self.DANGEROUS_FUNCTIONS
            ):
                self.bindings[bound_name] = item.name
            elif (
                node.level == 0
                and node.module == "pickle"
                and item.name in {"load", "loads"}
            ):
                self.bindings[bound_name] = f"pickle.{item.name}"
            elif node.level == 0 and node.module == "yaml" and item.name == "load":
                self.bindings[bound_name] = "yaml.load"
            elif (
                node.level == 0
                and node.module in {"requests", "httpx"}
                and item.name in self.HTTP_REQUEST_FUNCTIONS
            ):
                self.bindings[bound_name] = "tls.verify_false"
            elif (
                node.level == 0
                and node.module == "yaml"
                and item.name in self.YAML_SAFE_LOADERS
            ):
                self.bindings[bound_name] = "yaml_safe_loader"
            elif (
                node.level == 0
                and node.module == "subprocess"
                and item.name in self.SUBPROCESS_FUNCTIONS
            ):
                self.bindings[bound_name] = f"subprocess.{item.name}"
            elif node.level == 0 and node.module == "os" and item.name == "system":
                self.bindings[bound_name] = "os.system"
            else:
                self.bindings[bound_name] = None

            self.builtins_modules.discard(bound_name)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before_bindings = self.bindings.copy()
        before_modules = self.builtins_modules.copy()

        for statement in node.body:
            self.visit(statement)
        body_bindings = self.bindings.copy()
        body_modules = self.builtins_modules.copy()

        self.bindings = before_bindings.copy()
        self.builtins_modules = before_modules.copy()
        for statement in node.orelse:
            self.visit(statement)
        else_bindings = self.bindings.copy()
        else_modules = self.builtins_modules.copy()

        merged: dict[str, str | None] = {}
        all_names = before_bindings.keys() | body_bindings.keys() | else_bindings.keys()
        for name in all_names:
            left = body_bindings.get(name)
            right = else_bindings.get(name)
            if left == right or self._dangerous_binding(left):
                merged[name] = left
            elif self._dangerous_binding(right):
                merged[name] = right
            else:
                merged[name] = None
        self.bindings = merged
        self.builtins_modules = body_modules & else_modules

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._invalidate_target(node.target)
        self.visit(node.target)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)  # same target-binding semantics

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._invalidate_target(item.optional_vars)
                self.visit(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        previous_bindings = self.bindings.copy()
        previous_modules = self.builtins_modules.copy()
        if node.name:
            self.bindings[node.name] = None
            self.builtins_modules.discard(node.name)
        for statement in node.body:
            self.visit(statement)
        self.bindings = previous_bindings
        self.builtins_modules = previous_modules

    def _visit_comprehension(self, node: ast.expr) -> None:
        previous_bindings = self.bindings
        previous_modules = self.builtins_modules
        self.bindings = previous_bindings.copy()
        self.builtins_modules = previous_modules.copy()
        try:
            for generator in node.generators:  # type: ignore[attr-defined]
                self.visit(generator.iter)
                self._invalidate_target(generator.target)
                self.visit(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)  # type: ignore[attr-defined]
        finally:
            self.bindings = previous_bindings
            self.builtins_modules = previous_modules

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def _visit_function_in_scope(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Scan a function with its local names predeclared."""
        for decorator in node.decorator_list:
            self.visit(decorator)

        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        parent_bindings = self.bindings
        parent_modules = self.builtins_modules

        # Bind the function name in the enclosing scope.
        parent_bindings[node.name] = None
        parent_modules.discard(node.name)

        collector = _LocalBindingCollector()
        for statement in node.body:
            collector.visit(statement)

        local_names = collector.names
        local_names.update(
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        )

        if node.args.vararg is not None:
            local_names.add(node.args.vararg.arg)

        if node.args.kwarg is not None:
            local_names.add(node.args.kwarg.arg)

        # Methods skip the class namespace during name resolution.
        # Preserve the enclosing lexical environment for method bodies.
        if (
            self._class_outer_scopes
            and self._class_namespace_bindings
            and parent_bindings is self._class_namespace_bindings[-1]
        ):
            lexical_bindings, lexical_modules = self._class_outer_scopes[-1]
        else:
            lexical_bindings, lexical_modules = parent_bindings, parent_modules

        self.bindings = lexical_bindings.copy()
        self.builtins_modules = lexical_modules.copy()

        # Python treats function-local assignments as local throughout
        # the function, even when the assignment appears later.
        for name in local_names:
            self.bindings[name] = None
            self.builtins_modules.discard(name)

        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.bindings = parent_bindings
            self.builtins_modules = parent_modules

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_in_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_in_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)

        for base in node.bases:
            self.visit(base)

        for keyword in node.keywords:
            self.visit(keyword.value)

        parent_bindings = self.bindings
        parent_modules = self.builtins_modules

        parent_bindings[node.name] = None
        parent_modules.discard(node.name)

        # Class namespaces are not enclosing lexical scopes for methods.
        # A method can still close over a function surrounding the class.
        if (
            self._class_outer_scopes
            and self._class_namespace_bindings
            and parent_bindings is self._class_namespace_bindings[-1]
        ):
            lexical_bindings, lexical_modules = self._class_outer_scopes[-1]
        else:
            lexical_bindings, lexical_modules = parent_bindings, parent_modules

        self._class_outer_scopes.append(
            (lexical_bindings.copy(), lexical_modules.copy())
        )
        self.bindings = parent_bindings.copy()
        self.builtins_modules = parent_modules.copy()
        self._class_namespace_bindings.append(self.bindings)

        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._class_namespace_bindings.pop()
            self._class_outer_scopes.pop()
            self.bindings = parent_bindings
            self.builtins_modules = parent_modules

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        parent_bindings = self.bindings
        parent_modules = self.builtins_modules

        self.bindings = parent_bindings.copy()
        self.builtins_modules = parent_modules.copy()

        local_names = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        }

        if node.args.vararg is not None:
            local_names.add(node.args.vararg.arg)

        if node.args.kwarg is not None:
            local_names.add(node.args.kwarg.arg)

        for name in local_names:
            self.bindings[name] = None
            self.builtins_modules.discard(name)

        try:
            self.visit(node.body)
        finally:
            self.bindings = parent_bindings
            self.builtins_modules = parent_modules

    def visit_Call(self, node: ast.Call) -> None:
        dangerous_name = self._resolve_expression(node.func)

        tls_verification_disabled = any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )
        if dangerous_name == "tls.verify_false" and tls_verification_disabled:
            self.findings.append(
                Finding(
                    rule_id=PY006,
                    message=(
                        "TLS certificate verification is disabled with verify=False; "
                        "the client may accept an impersonated server certificate"
                    ),
                    line=node.lineno,
                    severity="HIGH",
                )
            )

        shell_enabled = any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
        always_shell_apis = {
            "os.system",
            "os.popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }
        if dangerous_name in always_shell_apis or (
            dangerous_name is not None
            and dangerous_name.startswith("subprocess.")
            and shell_enabled
        ):
            self.findings.append(
                Finding(
                    rule_id=PY004,
                    message=(
                        "Shell command execution can enable command injection; "
                        "avoid shell=True with untrusted input"
                        if dangerous_name not in {"os.system", "os.popen"}
                        else (
                            f"{dangerous_name}() executes a command through a system shell"
                        )
                    ),
                    line=node.lineno,
                    severity="HIGH",
                )
            )
        elif dangerous_name == "yaml.load":
            loader_keyword = next(
                (keyword for keyword in node.keywords if keyword.arg == "Loader"),
                None,
            )
            loader_expression = (
                loader_keyword.value
                if loader_keyword is not None
                else node.args[1]
                if len(node.args) > 1
                else None
            )
            safe_loader = (
                loader_expression is not None
                and self._resolve_expression(loader_expression) == "yaml_safe_loader"
            )
            if not safe_loader:
                self.findings.append(
                    Finding(
                        rule_id=PY005,
                        message=(
                            "yaml.load() may deserialize untrusted data "
                            "unsafely; use safe_load() or a verified safe loader"
                        ),
                        line=node.lineno,
                        severity="HIGH",
                    )
                )
        elif dangerous_name in {"pickle.load", "pickle.loads", "pickle.Unpickler.load"}:
            self.findings.append(
                Finding(
                    rule_id=PY003,
                    message=(
                        "Pickle deserialization can execute code when loading "
                        "untrusted data"
                    ),
                    line=node.lineno,
                    severity="HIGH",
                )
            )
        elif dangerous_name == "eval":
            self.findings.append(
                Finding(
                    rule_id=PY001,
                    message="Use of eval() may execute untrusted code",
                    line=node.lineno,
                    severity="HIGH",
                )
            )
        elif dangerous_name == "exec":
            self.findings.append(
                Finding(
                    rule_id=PY002,
                    message="Use of exec() may execute untrusted code",
                    line=node.lineno,
                    severity="HIGH",
                )
            )

        self.generic_visit(node)


def scan_source(source: str) -> list[Finding]:
    """Analyze Python source without executing it."""
    tree = ast.parse(source)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    return visitor.findings
