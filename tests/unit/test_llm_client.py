from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm.client import OllamaClient


@pytest.mark.asyncio
@patch("app.llm.client.httpx.AsyncClient")
async def test_llm_client_parses_valid_json_response(
    mock_async_client_class: AsyncMock,
) -> None:
    """Test that the client correctly parses a valid JSON response from Ollama."""
    client = OllamaClient()

    # Split the long string to satisfy Ruff line length rules
    fake_response_data = {
        "response": (
            '{"is_exploitable": true, "confidence": 0.85, '
            '"exploit_path": "Input flows directly to sink"}'
        )
    }

    # Create a synchronous mock for the HTTP response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = fake_response_data

    # Assign it as the return value of the async POST method
    mock_client_instance = mock_async_client_class.return_value.__aenter__.return_value
    mock_client_instance.post.return_value = mock_response

    result = await client.analyze_vulnerability("CWE-78", "subprocess.run(user_input)")

    assert result is not None
    assert result.is_exploitable is True
    assert result.confidence == 0.85
    assert "directly to sink" in result.exploit_path


@pytest.mark.asyncio
@patch("app.llm.client.httpx.AsyncClient")
async def test_llm_client_handles_invalid_json_gracefully(
    mock_async_client_class: AsyncMock,
) -> None:
    """Test that the client returns None if the LLM hallucinates bad JSON."""
    client = OllamaClient()

    fake_response_data = {"response": '{"is_exploitable": "yes", "confidence": "high"}'}

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = fake_response_data

    mock_client_instance = mock_async_client_class.return_value.__aenter__.return_value
    mock_client_instance.post.return_value = mock_response

    result = await client.analyze_vulnerability("CWE-78", "code")

    assert result is None
