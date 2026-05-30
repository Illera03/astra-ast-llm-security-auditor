import os

from dotenv import load_dotenv

# Patch for the Anaconda bug on Windows with phantom SSL paths
ssl_cert = os.environ.get("SSL_CERT_FILE")
if ssl_cert and not os.path.exists(ssl_cert):
    del os.environ["SSL_CERT_FILE"]

# Load environment variables from the .env file into the system
load_dotenv()


class Settings:
    """Centralized configuration manager for the application."""

    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    MODEL_NAME: str = os.getenv("MODEL_NAME", "qwen2.5-coder:1.5b")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LANGFUSE_ENABLED: bool = os.getenv("LANGFUSE_ENABLED", "false").lower() == "true"


settings = Settings()
