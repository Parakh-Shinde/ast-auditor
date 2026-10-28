import pytest

from ast_auditor.security_scanner import scan_source


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
    findings = scan_source("first = eval\nsecond = first\nsecond('user_input')\n")
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
    findings = scan_source('holder.run = eval\nholder.run("user_input")\n')
    assert findings == []


def test_function_local_assignment_does_not_change_global_alias() -> None:
    source = """
run = eval

def example():
    run = print
    run("Hello")
    run("user_input")

run("module_input")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_nested_function_does_not_change_outer_alias() -> None:
    source = """
def outer():
    run = eval

    def inner():
        run = print
        run("Hello")

    run("user_input")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_uninvoked_global_function_does_not_change_module_alias() -> None:
    source = """
run = eval

def example():
    global run
    run = print

run("Hello")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 8


def test_nonlocal_assignment_does_not_leak_into_outer_scope() -> None:
    source = """
def outer():
    run = eval

    def inner():
        nonlocal run
        run = print

    inner()
    run("Hello")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 10


def test_uninvoked_nonlocal_function_does_not_change_outer_alias() -> None:
    source = """
def outer():
    run = eval

    def inner():
        nonlocal run
        run = print

    run("user_input")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_function_body_does_not_leak_alias_to_module() -> None:
    source = """
def example():
    run = eval
    run("user_input")

print("safe")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 4


def test_class_body_does_not_leak_alias_to_module() -> None:
    source = """
class Example:
    run = eval
    run("user_input")

print("safe")
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 4


def test_lambda_body_does_not_leak_alias_changes() -> None:
    source = """
run = eval
callback = lambda: (run := print)
run("user_input")
"""
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
    source = """
run = eval

class Example:
    run = print

    def check(self):
        run("user-controlled input")
"""
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 8


def test_method_resolves_alias_from_enclosing_function() -> None:
    source = """
def outer():
    run = eval

    class Example:
        run = print

        def check(self):
            run("user-controlled input")
"""
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 9


def test_nested_function_in_method_resolves_method_local_alias() -> None:
    source = """
class Example:
    def check(self):
        run = eval

        def inner():
            run("user-controlled input")
"""
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 7


def test_nested_class_in_method_resolves_method_local_alias() -> None:
    source = """
class Example:
    def check(self):
        run = eval

        class Nested:
            def inner(self):
                run("user-controlled input")
"""
    findings = scan_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].line == 8


def test_destructuring_assignment_invalidates_stale_alias() -> None:
    source = """
run = eval
run, other = print, 1
run("Hello")
"""
    assert scan_source(source) == []


def test_delete_invalidates_stale_alias() -> None:
    source = """
run = eval
del run
run("Hello")
"""
    assert scan_source(source) == []


def test_augmented_assignment_invalidates_stale_alias() -> None:
    source = """
run = eval
run += print
run("Hello")
"""
    assert scan_source(source) == []


def test_detects_pickle_load_and_loads() -> None:
    source = """
import pickle
pickle.load(handle)
pickle.loads(data)
"""
    findings = scan_source(source)
    assert [finding.rule_id for finding in findings] == ["PY003", "PY003"]
    assert [finding.line for finding in findings] == [3, 4]
    assert all(finding.severity == "HIGH" for finding in findings)


def test_detects_aliased_pickle_module() -> None:
    source = """
import pickle as serialization
serialization.loads(data)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY003"
    assert findings[0].line == 3


def test_detects_pickle_functions_imported_with_aliases() -> None:
    source = """
from pickle import load as read_object, loads
read_object(handle)
loads(data)
"""
    findings = scan_source(source)
    assert [finding.rule_id for finding in findings] == ["PY003", "PY003"]
    assert [finding.line for finding in findings] == [3, 4]


def test_tracks_alias_of_pickle_module() -> None:
    source = """
import pickle as serialization
codec = serialization
codec.load(handle)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY003"
    assert findings[0].line == 4


def test_pickle_alias_reassignment_removes_finding() -> None:
    source = """
from pickle import loads as decode
decode = json.loads
decode(data)
"""
    assert scan_source(source) == []


def test_does_not_flag_unrelated_load_functions() -> None:
    source = """
from json import loads
loads(data)
object.load()
"""
    assert scan_source(source) == []


def test_detects_subprocess_run_with_shell_true() -> None:
    source = """
import subprocess
subprocess.run(user_input, shell=True)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 3


def test_detects_aliased_subprocess_module_with_shell_true() -> None:
    source = """
import subprocess as proc
proc.Popen(command, shell=True)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"


def test_detects_imported_subprocess_function_with_shell_true() -> None:
    source = """
from subprocess import run as execute
execute(command, shell=True)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"
    assert findings[0].line == 3


def test_detects_os_system() -> None:
    source = """
import os
os.system(command)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"
    assert findings[0].severity == "HIGH"


def test_detects_imported_os_system_alias() -> None:
    source = """
from os import system as run_command
run_command(command)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"


def test_does_not_flag_subprocess_without_shell_true() -> None:
    source = """
import subprocess
subprocess.run(["echo", user_input])
subprocess.run(command, shell=False)
"""
    assert scan_source(source) == []


def test_does_not_flag_unrelated_run_with_shell_true() -> None:
    source = """
from my_library import run
run(command, shell=True)
"""
    assert scan_source(source) == []


def test_detects_yaml_load_without_explicit_loader() -> None:
    source = "import yaml\nyaml.load(data)\n"
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY005"
    assert findings[0].severity == "HIGH"


def test_detects_explicit_unsafe_yaml_loader() -> None:
    source = "import yaml\nyaml.load(data, Loader=yaml.Loader)\n"
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY005"


def test_detects_aliased_yaml_module() -> None:
    source = "import yaml as y\ny.load(data)\n"
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY005"


def test_detects_imported_yaml_load_alias() -> None:
    source = "from yaml import load as parse_yaml\nparse_yaml(data)\n"
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY005"


def test_does_not_flag_yaml_safe_load() -> None:
    source = "import yaml\nyaml.safe_load(data)\n"
    assert scan_source(source) == []


def test_does_not_flag_yaml_load_with_safe_loader() -> None:
    source = "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n"
    assert scan_source(source) == []


def test_does_not_flag_yaml_load_with_aliased_safe_loader() -> None:
    source = """
import yaml
safe_loader = yaml.SafeLoader
yaml.load(data, Loader=safe_loader)
"""
    assert scan_source(source) == []


def test_tracks_yaml_module_alias_assignment() -> None:
    source = """
import yaml
parser = yaml
parser.load(data)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY005"


def test_yaml_load_alias_reassignment_removes_finding() -> None:
    source = """
from yaml import load as parse_yaml
parse_yaml = print
parse_yaml(data)
"""
    assert scan_source(source) == []


def test_does_not_flag_unrelated_load_method() -> None:
    source = """
other.load(data)
"""
    assert scan_source(source) == []


def test_does_not_flag_yaml_load_with_c_safe_loader() -> None:
    source = """
import yaml
yaml.load(data, Loader=yaml.CSafeLoader)
"""
    assert scan_source(source) == []


def test_yaml_module_alias_reassignment_invalidates_binding() -> None:
    source = """
import yaml
parser = yaml
parser = other
parser.load(data)
"""
    assert scan_source(source) == []


def test_function_local_yaml_name_does_not_use_global_alias() -> None:
    source = """
import yaml

def parse(data):
    yaml = other
    yaml.load(data)
"""
    assert scan_source(source) == []


def test_yaml_safe_loader_alias_reassignment_is_not_trusted() -> None:
    source = """
import yaml
safe_loader = yaml.SafeLoader
safe_loader = yaml.Loader
yaml.load(data, Loader=safe_loader)
"""
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY005"


@pytest.mark.parametrize(
    "source",
    [
        "for eval in functions:\n    eval(data)\n",
        "with manager as eval:\n    eval(data)\n",
        "try:\n    pass\nexcept Exception as eval:\n    eval(data)\n",
        "values = [eval(item) for eval in functions]\n",
    ],
)
def test_does_not_flag_eval_when_shadowed_by_local_binding(source: str) -> None:
    assert scan_source(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.popen(command)\n",
        "import subprocess\nsubprocess.getoutput(command)\n",
        "import subprocess\nsubprocess.getstatusoutput(command)\n",
    ],
)
def test_detects_additional_shell_execution_apis(source: str) -> None:
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY004"


def test_detects_pickle_unpickler_load() -> None:
    findings = scan_source("import pickle\npickle.Unpickler(stream).load()\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY003"


def test_detects_getattr_for_builtins_eval() -> None:
    findings = scan_source("import builtins\ngetattr(builtins, 'eval')(data)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"


def test_detects_branch_dependent_dangerous_alias() -> None:
    source = (
        "if condition:\n    runner = eval\nelse:\n    runner = print\nrunner(data)\n"
    )
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"


def test_detects_pickle_in_lambda_default_expression() -> None:
    findings = scan_source("import pickle\nhandler = lambda x=pickle.loads(data): x\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY003"


@pytest.mark.parametrize(
    "source",
    [
        "from yaml import load, SafeLoader\nload(data, Loader=SafeLoader)\n",
        "from yaml import load, SafeLoader\nload(data, SafeLoader)\n",
        "import yaml\nyaml.load(data, yaml.SafeLoader)\n",
    ],
)
def test_does_not_flag_safe_yaml_loader_forms(source: str) -> None:
    assert scan_source(source) == []


def test_comprehension_target_does_not_shadow_builtin_in_function() -> None:
    source = "def scan(items):\n    values = [item for eval in items]\n    eval(data)\n"
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"


def test_except_target_is_local_throughout_function() -> None:
    source = "def scan():\n    eval(data)\n    try:\n        pass\n    except Exception as eval:\n        pass\n"
    assert scan_source(source) == []


@pytest.mark.parametrize(
    "local_import",
    [
        "import eval",
        "from safe_module import eval",
    ],
)
def test_local_import_binding_shadows_builtin_eval(local_import: str) -> None:
    source = f"""
def run():
    eval(user_input)
    {local_import}
"""
    assert scan_source(source) == []

@pytest.mark.parametrize(
    "source",
    [
        'import requests\nrequests.get(url, verify=False)\n',
        'import requests as req\nreq.post(url, verify=False)\n',
        'from requests import get as fetch\nfetch(url, verify=False)\n',
        'import httpx\nhttpx.request("GET", url, verify=False)\n',
        'from httpx import get\nget(url, verify=False)\n',
        'import requests\nclient = requests.get\nclient(url, verify=False)\n',
    ],
)
def test_detects_disabled_tls_verification(source: str) -> None:
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "PY006"
    assert findings[0].severity == "HIGH"


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nrequests.get(url)\n",
        "import requests\nrequests.get(url, verify=True)\n",
        "import httpx\nhttpx.post(url, verify=False)\n",
        "from unrelated import get\nget(url, verify=False)\n",
        "import requests\nrequests.get(url, verify=not secure)\n",
    ],
)
def test_does_not_flag_tls_calls_without_literal_false_or_known_api(source: str) -> None:
    assert scan_source(source) == []

