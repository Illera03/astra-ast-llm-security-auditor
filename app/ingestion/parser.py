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


class ASTSecurityVisitor(ast.NodeVisitor):
    """
    Traverses the Abstract Syntax Tree looking for vulnerability patterns.
    Specifically targets command injection via dynamic subprocess arguments.
    """

    # Map severity levels to heuristic scores for the scoring engine
    SEVERITY_MAP = {
        SeverityLevel.CRITICAL: 1.0,
        SeverityLevel.HIGH: 0.8,
        SeverityLevel.MEDIUM: 0.5,
        SeverityLevel.LOW: 0.3,
    }

    def __init__(
        self, file_path: str, source_code: str, complexity_score: float
    ) -> None:
        self.file_path = file_path
        self.source_code = source_code  # Store the original source code
        self.complexity_score = complexity_score
        self.findings: list[VulnerabilityFinding] = []
        self.current_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None

    # Track when the AST enters a function
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
        func_name = ""

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in ["run", "Popen", "call", "check_output"]:
            is_dynamic = False

            for arg in node.args:
                if isinstance(arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
                    is_dynamic = True
                    break
                elif isinstance(arg, (ast.List, ast.Tuple)):
                    for element in arg.elts:
                        if isinstance(element, (ast.Name, ast.JoinedStr, ast.BinOp)):
                            is_dynamic = True
                            break

            if is_dynamic:
                severity = SeverityLevel.HIGH
                heuristic = self.SEVERITY_MAP[severity]

                # Extract the current function from the original source text
                if self.current_function:
                    snippet = ast.get_source_segment(
                        self.source_code, self.current_function
                    )
                else:
                    snippet = ast.get_source_segment(self.source_code, node)

                finding = VulnerabilityFinding(
                    cwe_id="CWE-78",
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

        self.generic_visit(node)


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

        # Pass source_code so snippets can be extracted
        visitor = ASTSecurityVisitor(self.file_path, self.source_code, complexity_score)
        visitor.visit(tree)

        return visitor.findings
