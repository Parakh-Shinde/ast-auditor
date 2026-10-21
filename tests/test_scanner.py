import pytest

from ast_auditor.scanner import scan_source


def test_detects_direct_eval() -> None:
    findings = scan_source('result = eval("1 + 1")')
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1


def test_detects_direct_exec() -> None:
    findings = scan_source('exec("print(1)")')
    assert len(findings) == 1
    assert findings[0].rule_id == "PY002"
    assert findings[0].severity == "HIGH"


def test_detects_both_dangerous_calls() -> None:
    findings = scan_source('eval("1 + 1")\nexec("print(1)")\n')
    assert [f.rule_id for f in findings] == ["PY001", "PY002"]
    assert [f.line for f in findings] == [1, 2]


def test_safe_source_has_no_findings() -> None:
    assert scan_source("result = 1 + 1\nprint(result)") == []


def test_tracks_eval_alias() -> None:
    findings = scan_source('run = eval\nrun("user_input")\n')
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 2


def test_tracks_exec_alias() -> None:
    findings = scan_source('run = exec\nrun("print(1)")\n')
    assert len(findings) == 1
    assert findings[0].rule_id == "PY002"


def test_tracks_chained_aliases() -> None:
    findings = scan_source(
        "first = eval\nsecond = first\nsecond('user_input')\n"
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 3


def test_safe_reassignment_removes_alias() -> None:
    findings = scan_source('run = eval\nrun = print\nrun("Hello")\n')
    assert findings == []


def test_reassignment_from_another_alias() -> None:
    findings = scan_source(
        "first = eval\nsecond = first\nsecond = print\nsecond('Hello')\n"
    )
    assert findings == []


def test_does_not_track_attribute_as_alias() -> None:
    findings = scan_source(
        'holder.run = eval\nholder.run("user_input")\n'
    )
    assert findings == []


def test_function_local_assignment_does_not_change_global_alias() -> None:
    source = '''
run = eval

def example():
    run = print
    run("Hello")
    run("user_input")

run("module_input")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_nested_function_does_not_change_outer_alias() -> None:
    source = '''
def outer():
    run = eval

    def inner():
        run = print
        run("Hello")

    run("user_input")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_uninvoked_global_function_does_not_change_module_alias() -> None:
    source = '''
run = eval

def example():
    global run
    run = print

run("Hello")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 8


def test_nonlocal_assignment_does_not_leak_into_outer_scope() -> None:
    source = '''
def outer():
    run = eval

    def inner():
        nonlocal run
        run = print

    inner()
    run("Hello")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 10


def test_uninvoked_nonlocal_function_does_not_change_outer_alias() -> None:
    source = '''
def outer():
    run = eval

    def inner():
        nonlocal run
        run = print

    run("user_input")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_function_body_does_not_leak_alias_to_module() -> None:
    source = '''
def example():
    run = eval
    run("user_input")

print("safe")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 4


def test_class_body_does_not_leak_alias_to_module() -> None:
    source = '''
class Example:
    run = eval
    run("user_input")

print("safe")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 4


def test_lambda_body_does_not_leak_alias_changes() -> None:
    source = '''
run = eval
callback = lambda: (run := print)
run("user_input")
'''
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 4


def test_syntax_error_is_not_silently_ignored() -> None:
    with pytest.raises(SyntaxError):
        scan_source("def broken(:\n    pass\n")


def test_empty_source_has_no_findings() -> None:
    assert scan_source("") == []


def test_shadowed_eval_name_is_not_reported_as_builtin() -> None:
    source = """
eval = print
eval("Hello")
"""
    assert scan_source(source) == []


def test_detects_eval_imported_from_builtins() -> None:
    source = """
from builtins import eval as run
run("user_input")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 3


def test_detects_qualified_builtins_eval_call() -> None:
    source = """
import builtins
builtins.eval("user_input")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 3


def test_local_eval_assignment_shadows_builtin_even_before_assignment() -> None:
    source = """
def run():
    eval("not the builtin")
    eval = print
"""
    assert scan_source(source) == []


def test_detects_alias_assigned_from_builtins_eval() -> None:
    source = """
import builtins
run = builtins.eval
run("user_input")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 4



def test_method_does_not_resolve_names_from_class_namespace() -> None:
    source = '''
run = eval

class Example:
    run = print

    def check(self):
        run("user-controlled input")
'''
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 8


def test_method_resolves_alias_from_enclosing_function() -> None:
    source = '''
def outer():
    run = eval

    class Example:
        run = print

        def check(self):
            run("user-controlled input")
'''
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9



def test_nested_function_in_method_resolves_method_local_alias() -> None:
    source = '''
class Example:
    def check(self):
        run = eval

        def inner():
            run("user-controlled input")
'''
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 7


def test_nested_class_in_method_resolves_method_local_alias() -> None:
    source = '''
class Example:
    def check(self):
        run = eval

        class Nested:
            def inner(self):
                run("user-controlled input")
'''
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 8
