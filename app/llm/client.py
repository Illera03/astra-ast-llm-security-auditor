import json
import re
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


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
        system_prompt = f"""
        You are a strict security auditor. Analyze this Python code for {cwe_id} (Command Injection).
        
        STRICT EVALUATION RULES:
        1. Does the code import 'subprocess' or 'os'?
        2. Does the subprocess call explicitly contain 'shell=True'? If YES, it is highly likely to be vulnerable.
        3. Are the arguments passed to the command dynamically constructed (e.g., f-strings, concatenation) with user input?
        4. If 'shell=True' is present and arguments are dynamic, it IS exploitable.

        RESPOND STRICTLY IN THIS JSON FORMAT:
        {{
            "is_exploitable": true or false,
            "confidence": 0.9,
            "exploit_path": "Explain exactly if shell=True is present and if arguments are dynamic."
        }}
        """

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

                # Extract the raw response text
                raw_response = response.json().get("response", "").strip()

                # Robust extraction: Find the first JSON block (between braces)
                match = re.search(r"\{.*\}", raw_response, re.DOTALL)

                if not match:
                    logger.warning(
                        "llm_invalid_format",
                        raw_response=raw_response,
                        model=self.model_name,
                    )
                    return None

                clean_json = match.group(0)

                try:
                    result_dict = json.loads(clean_json)
                    return LLMResponse(**result_dict)
                except json.JSONDecodeError as e:
                    logger.error(
                        "json_decode_error",
                        error=str(e),
                        extracted_text=clean_json,
                        model=self.model_name,
                    )
                    return None
                except ValidationError as e:
                    logger.error(
                        "validation_error",
                        error=str(e),
                        extracted_text=clean_json,
                        model=self.model_name,
                    )
                    return None

            except httpx.RequestError as e:
                logger.error(
                    "ollama_request_failed",
                    error=str(e),
                    model=self.model_name,
                    base_url=self.base_url,
                )
                return None
            except KeyError as e:
                logger.error(
                    "ollama_response_malformed",
                    error=str(e),
                    model=self.model_name,
                )
                return None
