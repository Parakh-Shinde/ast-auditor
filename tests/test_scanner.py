import pytest

from ast_auditor.scanner import scan_source


def test_detects_eval() -> None:
    source = "result = eval(user_input)"

    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1

def test_detects_exec() -> None:
    source = "exec(user_code)"

    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id =="PY002"
    assert findings[0].severity == "HIGH"

def test_ignores_safe_function_calls() -> None:
    source = """
print("Hello")
len([1, 2, 3])
"""

    findings = scan_source(source)

    assert findings == []

def test_report_correct_line_number() -> None:
    source = """
value = 10
result = eval(user_input)
"""

    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].line == 3

def test_invalid_python_raises_syntax_error() -> None:
   with pytest.raises(SyntaxError):
      scan_source("if true print ('invalid')")
