import ast

from app.schemas.findings import SeverityLevel, VulnerabilityFinding


class ASTSecurityVisitor(ast.NodeVisitor):
    """
    Traverses the Abstract Syntax Tree looking for vulnerability patterns.
    Specifically targets command injection via dynamic subprocess arguments.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[VulnerabilityFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        """
        Triggered every time a function call is detected in the AST.
        """
        func_name = ""

        # Handle 'subprocess.run(...)' pattern
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                func_name = node.func.attr
        # Handle 'run(...)' pattern if imported directly
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # Target dangerous OS command functions
        if func_name in ["run", "Popen", "call", "check_output"]:
            is_dynamic = False

            # Check if any argument is dynamic (variable, f-string, or concatenation)
            for arg in node.args:
                # Direct dynamic argument
                if isinstance(arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
                    is_dynamic = True
                    break
                # Dynamic argument inside a list or tuple (e.g. ["ls", folder])
                elif isinstance(arg, (ast.List, ast.Tuple)):
                    for element in arg.elts:
                        if isinstance(element, (ast.Name, ast.JoinedStr, ast.BinOp)):
                            is_dynamic = True
                            break

            # If dynamic, it's a potential vulnerability for the LLM to validate
            if is_dynamic:
                finding = VulnerabilityFinding(
                    cwe_id="CWE-78",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    node_type="Call",
                    severity=SeverityLevel.HIGH,
                    exploit_path="Pending LLM semantic validation.",
                    confidence=0.0,
                )
                self.findings.append(finding)

        # Continue traversing child nodes
        self.generic_visit(node)


class CodeParser:
    """
    Main entry point for static ingestion and AST parsing.
    """

    def __init__(self, file_path: str, source_code: str) -> None:
        self.file_path = file_path
        self.source_code = source_code

    def analyze(self) -> list[VulnerabilityFinding]:
        """
        Parses the source code into an AST and extracts static findings.
        Returns an empty list if the file has syntax errors.
        """
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError as e:
            print(f"[!] Error de sintaxis en el archivo analizado: {e}")
            return []

        visitor = ASTSecurityVisitor(self.file_path)
        visitor.visit(tree)

        return visitor.findings
