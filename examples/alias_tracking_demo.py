import builtins

# Expected: PY001 — direct eval call
eval("1 + 1")

# Expected: PY002 — direct exec call
exec("print('hello')")

# Expected: PY001 — alias imported from builtins
from builtins import eval as evaluate

evaluate("2 + 2")

# Expected: PY001 — qualified builtins call
builtins.eval("3 + 3")

# Expected: PY001 — alias assigned from builtins
run_code = builtins.eval
run_code("4 + 4")

# Expected: no finding — eval is shadowed locally
def safe_example():
    eval = print
    eval("This calls print")
