from app.ingestion.parser import CodeParser


def test_parser_detects_dynamic_subprocess_call() -> None:
    """Test that the parser flags subprocess calls with dynamic variables."""
    source_code = """
import subprocess
user_input = get_user_input()
subprocess.run(f"ping -c 4 {user_input}", shell=True)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-78"
    assert findings[0].node_type == "Call"


def test_parser_ignores_static_subprocess_call() -> None:
    """Test that the parser ignores safe, hardcoded subprocess calls."""
    source_code = """
import subprocess
# This is safe because it uses a constant literal string
subprocess.run("ls -la", shell=True)
    """

    parser = CodeParser(file_path="test.py", source_code=source_code)
    findings = parser.analyze()

    # Should be empty to prevent false positives before even calling the LLM
    assert len(findings) == 0
