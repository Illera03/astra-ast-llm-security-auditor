import os

from dotenv import load_dotenv

# Carga las variables del archivo .env en el sistema
load_dotenv()


class Settings:
    """Centralized configuration manager for the application."""

    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    MODEL_NAME: str = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-Coder-1.5B")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LANGFUSE_ENABLED: bool = os.getenv("LANGFUSE_ENABLED", "false").lower() == "true"


settings = Settings()
