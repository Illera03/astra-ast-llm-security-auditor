import json
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from app.config import settings


class LLMResponse(BaseModel):
    """Schema for the expected JSON response from the LLM."""

    is_exploitable: bool
    confidence: float
    exploit_path: str


class OllamaClient:
    """
    Asynchronous HTTP client to communicate with a local Ollama instance.
    """

    def __init__(
        self,
        model_name: str = settings.MODEL_NAME,
        base_url: str = settings.OLLAMA_HOST,
    ) -> None:
        self.model_name = model_name
        self.base_url = base_url

    async def analyze_vulnerability(
        self, cwe_id: str, code_context: str
    ) -> LLMResponse | None:
        """
        Sends the code context to the LLM and parses the JSON response.
        Returns None if the LLM hallucinates or the connection fails.
        """
        system_prompt = (
            "You are an expert cybersecurity auditor. "
            f"Analyze the following code snippet for {cwe_id}. "
            "You must respond ONLY in valid JSON format with three keys: "
            "'is_exploitable' (boolean), 'confidence' (float 0.0 to 1.0), "
            "and 'exploit_path' (string explaining the data flow). "
            "Do not include markdown formatting or any extra text."
        )

        payload: dict[str, Any] = {
            "model": self.model_name,
            "prompt": f"{system_prompt}\n\n{code_context}",
            "stream": False,
            "format": "json",
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/generate", json=payload, timeout=30.0
                )
                response.raise_for_status()

                data = response.json()
                llm_text = data.get("response", "{}")

                # Parse the raw text from Ollama into our Pydantic model
                parsed_json = json.loads(llm_text)
                return LLMResponse(**parsed_json)

            except (
                httpx.RequestError,
                json.JSONDecodeError,
                ValidationError,
                KeyError,
            ):
                # If Ollama is offline, times out, or returns invalid JSON,
                # we fail gracefully and return None.
                return None
