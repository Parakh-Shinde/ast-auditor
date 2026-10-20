import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    line: int
    severity: str


class SecurityVisitor(ast.NodeVisitor):
    """Find potentially dangerous Python function calls."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.findings.append(
                    Finding(
                        rule_id="PY001",
                        message="Use of eval() may execute untrusted code",
                        line=node.lineno,
                        severity="HIGH",
                    )
                )
            elif node.func.id == "exec":
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
