import ast

from app.schemas.findings import SeverityLevel, VulnerabilityFinding


class ComplexityVisitor(ast.NodeVisitor):
    """Counts logical decision nodes in the AST to calculate cyclomatic complexity."""

    def __init__(self) -> None:
        self.decision_points = 0

    def visit_If(self, node: ast.If) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.decision_points += 1
        self.generic_visit(node)


DYNAMIC_TYPES = (ast.Name, ast.JoinedStr, ast.BinOp)


class ASTSecurityVisitor(ast.NodeVisitor):
    """
    Traverses the Abstract Syntax Tree looking for vulnerability patterns.
    Detects CWE-78 (Command Injection), CWE-502 (Insecure Deserialization),
    and CWE-22 (Path Traversal).
    """

    SEVERITY_MAP = {
        SeverityLevel.CRITICAL: 1.0,
        SeverityLevel.HIGH: 0.8,
        SeverityLevel.MEDIUM: 0.5,
        SeverityLevel.LOW: 0.3,
    }

    DESERIALIZATION_TARGETS: dict[str, dict[str, SeverityLevel]] = {
        "pickle": {
            "loads": SeverityLevel.CRITICAL,
            "load": SeverityLevel.CRITICAL,
            "Unpickler": SeverityLevel.CRITICAL,
        },
        "marshal": {
            "loads": SeverityLevel.CRITICAL,
            "load": SeverityLevel.CRITICAL,
        },
        "yaml": {
            "load": SeverityLevel.HIGH,
        },
        "shelve": {
            "open": SeverityLevel.HIGH,
        },
        "jsonpickle": {
            "decode": SeverityLevel.CRITICAL,
        },
    }

    JSONPICKLE_DEEP_FUNCTIONS = {"decode", "Unpickler"}

    SUBPROCESS_FUNCTIONS = {"run", "Popen", "call", "check_output"}

    OS_EXEC_FUNCTIONS = {"system", "popen", "popen2", "popen3", "popen4"}

    OS_SPAWN_FUNCTIONS = {
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    }

    PATH_IO_METHODS = {
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "open",
    }

    def __init__(
        self, file_path: str, source_code: str, complexity_score: float
    ) -> None:
        self.file_path = file_path
        self.source_code = source_code
        self.complexity_score = complexity_score
        self.findings: list[VulnerabilityFinding] = []
        self.current_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous_function = self.current_function
        self.current_function = node
        self.generic_visit(node)
        self.current_function = previous_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        previous_function = self.current_function
        self.current_function = node
        self.generic_visit(node)
        self.current_function = previous_function

    def visit_Call(self, node: ast.Call) -> None:
        self._check_command_injection(node)
        self._check_insecure_deserialization(node)
        self._check_path_traversal(node)
        self.generic_visit(node)

    def _has_dynamic_args(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, DYNAMIC_TYPES):
                return True
            if isinstance(arg, (ast.List, ast.Tuple)):
                for element in arg.elts:
                    if isinstance(element, DYNAMIC_TYPES):
                        return True
        return False

    def _add_finding(
        self, node: ast.Call, cwe_id: str, severity: SeverityLevel
    ) -> None:
        heuristic = self.SEVERITY_MAP[severity]

        if self.current_function:
            snippet = ast.get_source_segment(self.source_code, self.current_function)
        else:
            snippet = ast.get_source_segment(self.source_code, node)

        finding = VulnerabilityFinding(
            cwe_id=cwe_id,
            file_path=self.file_path,
            line_number=node.lineno,
            code_snippet=snippet or "",
            node_type="Call",
            severity=severity,
            exploit_path="Pending LLM semantic validation.",
            confidence=0.0,
            heuristic_score=heuristic,
            context_complexity=self.complexity_score,
        )
        self.findings.append(finding)

    def _has_shell_false(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                if kw.value.value is False or kw.value.value == 0:
                    return True
        return False

    def _check_command_injection(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            module = node.func.value.id
            func_name = node.func.attr

            if module == "subprocess" and func_name in self.SUBPROCESS_FUNCTIONS:
                if self._has_dynamic_args(node) and not self._has_shell_false(node):
                    self._add_finding(node, "CWE-78", SeverityLevel.HIGH)
                return

            if module == "os" and func_name in self.OS_EXEC_FUNCTIONS:
                self._add_finding(node, "CWE-78", SeverityLevel.HIGH)
                return

            if module == "os" and func_name in self.OS_SPAWN_FUNCTIONS:
                self._add_finding(node, "CWE-78", SeverityLevel.HIGH)
                return

        if isinstance(node.func, ast.Name):
            if node.func.id in self.SUBPROCESS_FUNCTIONS and self._has_dynamic_args(
                node
            ):
                if not self._has_shell_false(node):
                    self._add_finding(node, "CWE-78", SeverityLevel.HIGH)

    SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}

    def _is_safe_yaml_loader(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute):
                    if kw.value.attr in self.SAFE_YAML_LOADERS:
                        return True
                if isinstance(kw.value, ast.Name):
                    if kw.value.id in self.SAFE_YAML_LOADERS:
                        return True
        for arg in node.args:
            if isinstance(arg, ast.Attribute) and arg.attr in self.SAFE_YAML_LOADERS:
                return True
            if isinstance(arg, ast.Name) and arg.id in self.SAFE_YAML_LOADERS:
                return True
        return False

    def _check_insecure_deserialization(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute):
            return

        if isinstance(node.func.value, ast.Attribute):
            if (
                isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "jsonpickle"
                and node.func.value.attr == "unpickler"
                and node.func.attr in ("decode", "Unpickler")
            ):
                self._add_finding(node, "CWE-502", SeverityLevel.CRITICAL)
                return

        if not isinstance(node.func.value, ast.Name):
            return

        module_name = node.func.value.id
        func_name = node.func.attr

        module_targets = self.DESERIALIZATION_TARGETS.get(module_name)
        if not module_targets:
            return

        severity = module_targets.get(func_name)
        if severity is None:
            return

        if module_name == "yaml" and func_name == "load":
            if self._is_safe_yaml_loader(node):
                return

        if module_name in ("shelve", "jsonpickle") or func_name == "Unpickler":
            self._add_finding(node, "CWE-502", severity)
            return

        if not self._has_dynamic_args(node):
            return

        self._add_finding(node, "CWE-502", severity)

    def _unwrap_chained_call(self, node: ast.Call) -> ast.Call | None:
        """Walk up a method-call chain to find a Path() instantiation."""
        current = node.func
        while isinstance(current, ast.Attribute):
            if isinstance(current.value, ast.Call):
                inner = current.value
                if isinstance(inner.func, ast.Name) and inner.func.id == "Path":
                    return inner
                if (
                    isinstance(inner.func, ast.Attribute)
                    and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id == "pathlib"
                    and inner.func.attr == "Path"
                ):
                    return inner
                current = inner.func
            else:
                break
        return None

    def _check_path_traversal(self, node: ast.Call) -> None:
        # builtin open()
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if self._has_dynamic_args(node):
                self._add_finding(node, "CWE-22", SeverityLevel.HIGH)
            return

        # Path(user_input) direct instantiation
        if isinstance(node.func, ast.Name) and node.func.id == "Path":
            if self._has_dynamic_args(node):
                self._add_finding(node, "CWE-22", SeverityLevel.MEDIUM)
            return

        # pathlib.Path(user_input)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pathlib"
            and node.func.attr == "Path"
        ):
            if self._has_dynamic_args(node):
                self._add_finding(node, "CWE-22", SeverityLevel.MEDIUM)
            return

        if not isinstance(node.func, ast.Attribute):
            return

        attr = node.func.attr

        # os.remove(), os.path.join(), io.open()
        if isinstance(node.func.value, ast.Name):
            module = node.func.value.id

            if module == "os" and attr == "remove":
                if self._has_dynamic_args(node):
                    self._add_finding(node, "CWE-22", SeverityLevel.HIGH)
                return

            if module == "io" and attr == "open":
                if self._has_dynamic_args(node):
                    self._add_finding(node, "CWE-22", SeverityLevel.HIGH)
                return

        # os.path.join()
        if (
            isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "os"
            and node.func.value.attr == "path"
            and attr == "join"
        ):
            if self._has_dynamic_args(node):
                self._add_finding(node, "CWE-22", SeverityLevel.MEDIUM)
            return

        # Path(...).read_text(), Path(...).open(), etc.
        if attr in self.PATH_IO_METHODS:
            path_call = self._unwrap_chained_call(node)
            if path_call and self._has_dynamic_args(path_call):
                self._add_finding(node, "CWE-22", SeverityLevel.HIGH)


class CodeParser:
    """Main entry point for static ingestion and AST parsing."""

    def __init__(self, file_path: str, source_code: str) -> None:
        self.file_path = file_path
        self.source_code = source_code

    def analyze(self) -> list[VulnerabilityFinding]:
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError as e:
            print(f"[!] Syntax error in analyzed file: {e}")
            return []

        comp_visitor = ComplexityVisitor()
        comp_visitor.visit(tree)

        complexity_score = min(1.0, 0.2 + (comp_visitor.decision_points * 0.1))
        complexity_score = round(complexity_score, 2)

        visitor = ASTSecurityVisitor(self.file_path, self.source_code, complexity_score)
        visitor.visit(tree)

        return visitor.findings
