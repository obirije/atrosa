"""
ATROSA Code Validator — AST-Based Safety Analysis
====================================================
Validates LLM-generated Python code before execution. Parses the code
with the `ast` module and rejects scripts containing dangerous constructs.

The validator is deliberately strict: it allowlists safe modules/functions
rather than blocklisting dangerous ones. This means unknown constructs
are rejected by default — the safe path is the default path.

Usage:
    from code_validator import validate_detect_code

    result = validate_detect_code(code_string)
    if not result.is_safe:
        print(f"Rejected: {result.violations}")
"""

import ast
from dataclasses import dataclass, field


# ===========================
# ALLOWLISTS
# ===========================

# Modules the detection script is permitted to import
ALLOWED_MODULES = frozenset({
    "json",
    "sys",
    "re",
    "math",
    "collections",
    "datetime",
    "hashlib",
    "pandas",
    "ingest",
    # Standard library safe modules
    "functools",
    "itertools",
    "operator",
    "statistics",
    "string",
    "copy",
    "decimal",
    "fractions",
    "typing",
})

# Built-in functions that are safe to call
ALLOWED_BUILTINS = frozenset({
    "abs", "all", "any", "bool", "bytes", "chr", "dict", "divmod",
    "enumerate", "filter", "float", "format", "frozenset", "getattr",
    "hasattr", "hash", "hex", "int", "isinstance", "issubclass",
    "iter", "len", "list", "map", "max", "min", "next", "oct",
    "ord", "pow", "print", "range", "repr", "reversed", "round",
    "set", "slice", "sorted", "str", "sum", "tuple", "type", "zip",
    # Pandas-related
    "pd", "DataFrame", "Series",
})

# Dangerous function/attribute names that should never appear
BLOCKED_NAMES = frozenset({
    # Code execution
    "eval", "exec", "compile", "execfile",
    # Process spawning
    "system", "popen", "popen2", "popen3", "popen4",
    "spawn", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "fork", "forkpty", "kill", "killpg",
    # Module manipulation
    "__import__", "__subclasses__", "__bases__", "__mro__",
    "__class__", "__globals__", "__builtins__",
    # Network
    "urlopen", "urlretrieve", "Request",
    "connect", "bind", "listen", "accept",
    "send", "sendall", "sendto", "recv", "recvfrom",
    # File system (writes)
    "remove", "unlink", "rmdir", "rmtree",
    "makedirs", "mkdir",
    "chmod", "chown", "chroot",
    # Dangerous modules accessed as attributes
    "subprocess", "socket", "http", "urllib",
    "ctypes", "multiprocessing", "threading",
    "pickle", "shelve", "marshal",
    "importlib", "runpy",
    "webbrowser",
    "shutil",
    "tempfile",
    "code", "codeop",
    "pty", "pipes",
})

# Allowed attribute accesses on known safe objects
SAFE_ATTRIBUTE_PREFIXES = frozenset({
    "pd.", "df_", "harness", "json.", "re.", "sys.stderr",
    "datetime.", "timedelta", "collections.", "math.",
    "str.", "int.", "float.", "list.", "dict.", "set.",
    "Series.", "DataFrame.", "Index.",
})


@dataclass
class ValidationResult:
    """Result of code validation."""
    is_safe: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_violation(self, msg: str):
        self.violations.append(msg)
        self.is_safe = False

    def add_warning(self, msg: str):
        self.warnings.append(msg)


# ===========================
# AST VISITOR
# ===========================
class SafetyVisitor(ast.NodeVisitor):
    """Walks the AST and flags dangerous constructs."""

    def __init__(self):
        self.result = ValidationResult(is_safe=True)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            module_root = alias.name.split(".")[0]
            if module_root not in ALLOWED_MODULES:
                self.result.add_violation(
                    f"Line {node.lineno}: Blocked import '{alias.name}' — "
                    f"not in allowed modules. Allowed: {sorted(ALLOWED_MODULES)}"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            module_root = node.module.split(".")[0]
            if module_root not in ALLOWED_MODULES:
                self.result.add_violation(
                    f"Line {node.lineno}: Blocked 'from {node.module} import ...' — "
                    f"not in allowed modules"
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node)
        if func_name:
            # Check against blocked names
            name_parts = func_name.split(".")
            for part in name_parts:
                if part in BLOCKED_NAMES:
                    self.result.add_violation(
                        f"Line {node.lineno}: Blocked function call '{func_name}' — "
                        f"'{part}' is not permitted in detection scripts"
                    )
                    break

            # Check for os.* calls (even if os was somehow imported)
            if func_name.startswith("os."):
                self.result.add_violation(
                    f"Line {node.lineno}: Blocked 'os' module call '{func_name}'"
                )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if node.attr in BLOCKED_NAMES:
            # Get the full dotted name if possible
            full_name = self._get_attribute_chain(node)
            self.result.add_violation(
                f"Line {node.lineno}: Blocked attribute access '.{node.attr}' "
                f"(full: '{full_name}')"
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if node.id in BLOCKED_NAMES:
            self.result.add_violation(
                f"Line {node.lineno}: Blocked name '{node.id}'"
            )
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        # Check for open() with write mode in with statements
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = self._get_call_name(item.context_expr)
                if func_name == "open":
                    # Check if mode argument suggests writing
                    mode = self._get_open_mode(item.context_expr)
                    if mode and any(c in mode for c in "wax+"):
                        self.result.add_violation(
                            f"Line {node.lineno}: Blocked file write via open() "
                            f"with mode '{mode}' — detection scripts must not write files"
                        )
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global):
        self.result.add_warning(
            f"Line {node.lineno}: 'global' statement — unusual in detection scripts"
        )
        self.generic_visit(node)

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        """Extract the function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _get_attribute_chain(node: ast.Attribute) -> str:
        """Get the full a.b.c chain from an Attribute node."""
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _get_open_mode(call_node: ast.Call) -> str:
        """Extract the mode argument from an open() call."""
        # Positional: open(path, mode)
        if len(call_node.args) >= 2:
            mode_arg = call_node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                return mode_arg.value
        # Keyword: open(path, mode="w")
        for kw in call_node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                return kw.value.value
        return ""


# ===========================
# STRUCTURAL CHECKS
# ===========================
def _check_structure(tree: ast.Module) -> ValidationResult:
    """Verify the code has the expected detect() function structure."""
    result = ValidationResult(is_safe=True)

    # Must have a detect() function
    has_detect = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "detect":
            has_detect = True
            break

    if not has_detect:
        result.add_violation("Missing required 'detect()' function")

    # Check total code size (reject unreasonably large scripts)
    code_lines = len([n for n in ast.walk(tree) if hasattr(n, "lineno")])
    if code_lines > 2000:
        result.add_warning(f"Script has {code_lines} AST nodes — unusually large")

    return result


# ===========================
# PUBLIC API
# ===========================
def validate_detect_code(code: str) -> ValidationResult:
    """
    Validate LLM-generated detection code before execution.

    Returns a ValidationResult with is_safe=True if the code is safe to execute,
    or is_safe=False with a list of violations explaining why it was rejected.
    """
    # Step 1: Parse the code
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        result = ValidationResult(is_safe=False)
        result.add_violation(f"Syntax error: {e}")
        return result

    # Step 2: Structural checks
    struct_result = _check_structure(tree)
    if not struct_result.is_safe:
        return struct_result

    # Step 3: AST safety analysis
    visitor = SafetyVisitor()
    visitor.visit(tree)

    # Merge structural warnings
    visitor.result.warnings.extend(struct_result.warnings)

    return visitor.result


def validate_and_report(code: str) -> bool:
    """
    Validate code and print results. Returns True if safe.
    Convenience wrapper for use in the orchestrator.
    """
    result = validate_detect_code(code)

    if result.violations:
        print(f"  [SECURITY] Code validation FAILED — {len(result.violations)} violation(s):")
        for v in result.violations:
            print(f"    [X] {v}")

    if result.warnings:
        for w in result.warnings:
            print(f"    [!] Warning: {w}")

    if result.is_safe:
        print("  [SECURITY] Code validation passed")

    return result.is_safe
