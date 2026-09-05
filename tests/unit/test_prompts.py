import pytest

from app.llm.prompts import PROMPT_TEMPLATES, get_prompt


def test_get_prompt_returns_cwe78_template() -> None:
    prompt = get_prompt("CWE-78")
    assert "Command Injection" in prompt


def test_get_prompt_returns_cwe502_template() -> None:
    prompt = get_prompt("CWE-502")
    assert "Deserialization" in prompt


def test_get_prompt_returns_cwe22_template() -> None:
    prompt = get_prompt("CWE-22")
    assert "Path Traversal" in prompt


def test_get_prompt_raises_for_unknown_cwe() -> None:
    with pytest.raises(ValueError, match="No prompt template for CWE-999"):
        get_prompt("CWE-999")


def test_all_prompts_require_same_json_schema() -> None:
    required_fields = ["is_exploitable", "confidence", "exploit_path"]
    for cwe_id, prompt in PROMPT_TEMPLATES.items():
        for field in required_fields:
            assert field in prompt, (
                f"Prompt for {cwe_id} missing required field '{field}'"
            )
