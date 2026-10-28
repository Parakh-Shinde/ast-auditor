"""Versioned metadata for AST Auditor's curated Python security rules.

Detection logic lives in :mod:`ast_auditor.security_scanner`; this registry is the
single source of truth for rule descriptions, severity, confidence, CWE mappings,
remediation guidance, and SARIF metadata.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

RULE_PACK_VERSION = "2026.2"
PY001 = "PY001"
PY002 = "PY002"
PY003 = "PY003"
PY004 = "PY004"
PY005 = "PY005"
PY006 = "PY006"


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Human-readable metadata and triage guidance for one detection rule."""

    rule_id: str
    name: str
    title: str
    description: str
    severity: str
    confidence: str
    cwe: str
    category: str
    remediation: str
    references: tuple[str, ...]
    security_score: str

    @property
    def cwe_number(self) -> str:
        return self.cwe.removeprefix("CWE-")


_RULES = {
    "PY001": RuleDefinition(
        rule_id="PY001",
        name="DangerousEval",
        title="Potentially dangerous eval() call",
        description="eval() evaluates a Python expression dynamically. If attacker-controlled data reaches it, code execution may result.",
        severity="HIGH",
        confidence="MEDIUM",
        cwe="CWE-95",
        category="dynamic-code-execution",
        remediation="Avoid eval(). Parse expected input with a constrained parser or use an explicit mapping of allowed operations.",
        references=("https://cwe.mitre.org/data/definitions/95.html",),
        security_score="7.5",
    ),
    "PY002": RuleDefinition(
        rule_id="PY002",
        name="DangerousExec",
        title="Potentially dangerous exec() call",
        description="exec() executes dynamically supplied Python statements and can enable arbitrary code execution when input is untrusted.",
        severity="HIGH",
        confidence="MEDIUM",
        cwe="CWE-94",
        category="dynamic-code-execution",
        remediation="Avoid exec() on dynamic input. Replace it with explicit functions or a constrained interpreter for a documented grammar.",
        references=("https://cwe.mitre.org/data/definitions/94.html",),
        security_score="8.0",
    ),
    "PY003": RuleDefinition(
        rule_id="PY003",
        name="UnsafePickleDeserialization",
        title="Potentially unsafe pickle deserialization",
        description="Unpickling untrusted or tampered data can invoke attacker-controlled behavior during deserialization.",
        severity="HIGH",
        confidence="MEDIUM",
        cwe="CWE-502",
        category="unsafe-deserialization",
        remediation="Do not unpickle data from untrusted sources. Prefer data-only formats such as JSON and validate the resulting schema.",
        references=(
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://docs.python.org/3/library/pickle.html#warning",
        ),
        security_score="8.0",
    ),
    "PY004": RuleDefinition(
        rule_id="PY004",
        name="ShellCommandExecution",
        title="Potentially unsafe shell command execution",
        description="Shell command APIs can enable command injection when untrusted input influences the command or arguments.",
        severity="HIGH",
        confidence="MEDIUM",
        cwe="CWE-78",
        category="command-injection",
        remediation="Prefer subprocess APIs with an argument list and shell=False. Validate inputs against an allowlist and avoid string concatenation for commands.",
        references=(
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://docs.python.org/3/library/subprocess.html#security-considerations",
        ),
        security_score="8.0",
    ),
    "PY005": RuleDefinition(
        rule_id="PY005",
        name="UnsafeYamlLoad",
        title="Potentially unsafe YAML deserialization",
        description="yaml.load() may construct arbitrary Python objects depending on the loader and library version.",
        severity="HIGH",
        confidence="MEDIUM",
        cwe="CWE-502",
        category="unsafe-deserialization",
        remediation="Use yaml.safe_load() or a carefully reviewed safe loader. Validate the resulting data against an expected schema.",
        references=(
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://pyyaml.org/wiki/PyYAMLDocumentation",
        ),
        security_score="7.5",
    ),
    "PY006": RuleDefinition(
        rule_id="PY006",
        name="DisabledTlsVerification",
        title="TLS certificate verification disabled in HTTP request",
        description="Disabling certificate verification in recognized requests or httpx module-level request calls permits server impersonation and weakens transport security.",
        severity="HIGH",
        confidence="MEDIUM",
        cwe="CWE-295",
        category="improper-certificate-validation",
        remediation="Remove verify=False and use the platform trust store or an explicitly configured trusted CA bundle. Do not disable verification to work around certificate errors.",
        references=(
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
            "https://www.python-httpx.org/advanced/ssl/",
        ),
        security_score="7.5",
    ),
}

RULES: Mapping[str, RuleDefinition] = MappingProxyType(_RULES)


def get_rule(rule_id: str) -> RuleDefinition:
    """Return registered metadata or raise a clear error for an unknown ID."""
    try:
        return RULES[rule_id]
    except KeyError as exc:
        raise KeyError(f"Unregistered AST Auditor rule: {rule_id}") from exc


def list_rules() -> tuple[RuleDefinition, ...]:
    """Return rule definitions in stable ID order."""
    return tuple(RULES[rule_id] for rule_id in sorted(RULES))
