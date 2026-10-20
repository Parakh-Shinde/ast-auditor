import ast
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class Finding:
    """Represent a security finding produced by the scanner."""

    rule_id: str
    message: str
    line: int
    severity: str


class SecurityVisitor(ast.NodeVisitor):
    """Find direct eval/exec calls and simple aliases."""

    DANGEROUS_FUNCTIONS: ClassVar[set[str]] = {"eval", "exec"}

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}

    def _update_alias(self, target: ast.expr, value: ast.expr) -> None:
        """Track simple assignments without retaining stale aliases."""
        if not isinstance(target, ast.Name):
            return

        if isinstance(value, ast.Name):
            if value.id in self.DANGEROUS_FUNCTIONS:
                self.aliases[target.id] = value.id
                return

            if value.id in self.aliases:
                self.aliases[target.id] = self.aliases[value.id]
                return

        self.aliases.pop(target.id, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Handle ordinary assignments."""
        self.visit(node.value)

        for target in node.targets:
            self._update_alias(target, node.value)

        for target in node.targets:
            if not isinstance(target, ast.Name):
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Handle annotated assignments."""
        self.visit(node.annotation)

        if node.value is not None:
            self.visit(node.value)
            self._update_alias(node.target, node.value)
        elif isinstance(node.target, ast.Name):
            self.aliases.pop(node.target.id, None)
        else:
            self.visit(node.target)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_in_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_in_scope(node)

    def _visit_function_in_scope(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Inspect a function without leaking its alias changes."""
        for decorator in node.decorator_list:
            self.visit(decorator)

        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        parent_aliases = self.aliases
        parent_aliases.pop(node.name, None)
        self.aliases = parent_aliases.copy()

        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.aliases = parent_aliases

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze a class body without leaking its aliases outward."""
        for decorator in node.decorator_list:
            self.visit(decorator)

        for base in node.bases:
            self.visit(base)

        for keyword in node.keywords:
            self.visit(keyword.value)

        parent_aliases = self.aliases
        parent_aliases.pop(node.name, None)
        self.aliases = parent_aliases.copy()

        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.aliases = parent_aliases

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Inspect a lambda body without leaking alias changes."""
        parent_aliases = self.aliases
        self.aliases = parent_aliases.copy()

        try:
            self.visit(node.body)
        finally:
            self.aliases = parent_aliases

    def visit_Call(self, node: ast.Call) -> None:
        """Report calls to eval/exec or tracked aliases."""
        if isinstance(node.func, ast.Name):
            function_name = node.func.id

            dangerous_function = (
                function_name
                if function_name in self.DANGEROUS_FUNCTIONS
                else self.aliases.get(function_name)
            )

            if dangerous_function == "eval":
                self.findings.append(
                    Finding(
                        rule_id="PY001",
                        message="Use of eval() may execute untrusted code",
                        line=node.lineno,
                        severity="HIGH",
                    )
                )
            elif dangerous_function == "exec":
                self.findings.append(
                    Finding(
                        rule_id="PY002",
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
