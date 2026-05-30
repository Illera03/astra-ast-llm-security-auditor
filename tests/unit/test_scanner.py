import os

from app.scanner import SecurityScanner


def test_scanner_integrates_parser_and_context(tmp_path: str) -> None:
    """Test that the scanner combines AST findings with code context."""

    # Create a fake vulnerable file
    test_file = os.path.join(tmp_path, "vuln_app.py")
    code = (
        "import subprocess\n"
        "\n"
        "def run_cmd(user_input):\n"
        "    subprocess.run(f'echo {user_input}', shell=True)\n"
    )

    with open(test_file, "w", encoding="utf-8") as f:
        f.write(code)

    # Run the engine
    scanner = SecurityScanner()
    results = scanner.scan_file(test_file)

    # 3. Verify it found the vulnerability AND extracted the context
    assert len(results) == 1
    finding, context = results[0]

    assert finding.cwe_id == "CWE-78"
    assert finding.line_number == 4
    assert "IMPORTS:" in context
    assert "import subprocess" in context
    assert "CODE SNIPPET (Lines 1-4):" in context
    assert "subprocess.run(f'echo" in context
