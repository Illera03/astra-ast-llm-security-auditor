# ASTra - AST LLM Security Auditor

Security vulnerability scanner powered by Abstract Syntax Tree (AST) analysis and Large Language Models.

## 🎯 Overview

ASTra combines static code analysis with LLM-based reasoning to detect security vulnerabilities in Python codebases. It uses AST parsing to extract code context and a hybrid scoring engine to assess risk levels.

## 📋 Prerequisites

- **Python 3.11+**
- **Poetry** (Python dependency manager)
- **Ollama** (local LLM runtime)

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

Run the setup script that will install all dependencies and configure the environment:

```bash
./scripts/setup.sh
```

This script will:
1. Check for Ollama installation (installs if missing on macOS)
2. Pull the default model (`qwen2.5-coder:1.5b`)
3. Install Python dependencies via Poetry
4. Create `.env` file from template
5. Run verification checks

### Option 2: Manual Setup

#### 1. Install Ollama

**macOS:**
```bash
brew install ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**Windows:**
Download from [ollama.ai](https://ollama.ai)

#### 2. Start Ollama Service

```bash
ollama serve
```

Leave this running in a separate terminal.

#### 3. Pull the Model

```bash
ollama pull qwen2.5-coder:1.5b
```

This downloads the default model (~1GB). You can use other models by updating `.env`.

#### 4. Install Python Dependencies

```bash
poetry install
```

#### 5. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` if needed:
```env
OLLAMA_HOST=http://localhost:11434
MODEL_NAME=qwen2.5-coder:1.5b
LOG_LEVEL=INFO
LANGFUSE_ENABLED=false
```

## 🔧 Usage

### Run Security Analysis

Scan a Python file for vulnerabilities:

```bash
poetry run python -m app.cli scan <path-to-file.py>
```

Example with the demo file:
```bash
poetry run python -m app.cli scan demo.py
```

### Clear Cache

The tool caches LLM responses to optimize performance. To clear:

```bash
poetry run python clear_cache.py
```

## 🧪 Development

### Run Quality Checks

Execute all checks (format, lint, type-check, tests):

```bash
./scripts/check.sh
```

Individual checks:

```bash
# Format code
poetry run ruff format .

# Lint and auto-fix
poetry run ruff check --fix .

# Type checking
poetry run mypy .

# Run tests
poetry run pytest
```

### Project Structure

```
app/
├── cli.py              # CLI interface
├── scanner.py          # Main scanner orchestrator
├── config.py           # Configuration management
├── logging_config.py   # Structured logging setup
├── core/               # Core scanning engine
├── ingestion/          # AST parsing and context extraction
├── llm/                # LLM client (Ollama)
├── scoring/            # Risk scoring engine
└── schemas/            # Pydantic data models
```

## 🛠 Tech Stack

- **Tree-sitter**: AST parsing
- **Ollama**: Local LLM inference
- **structlog**: Structured logging
- **Pydantic**: Data validation
- **Poetry**: Dependency management

## 📊 Model Configuration

Default model: `qwen2.5-coder:1.5b` (lightweight, good for code analysis)

Alternative models:
- `qwen2.5-coder:7b` (more accurate, slower)
- `deepseek-coder:6.7b`
- `codellama:7b`

Update `MODEL_NAME` in `.env` and pull the model:
```bash
ollama pull <model-name>
```

## 🤝 Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make changes and run checks: `./scripts/check.sh`
3. Commit with conventional commits: `feat:`, `fix:`, `refactor:`, etc.
4. Push and open a PR to `dev` branch

## 📝 License

See [LICENSE](LICENSE) file.

## 🐛 Troubleshooting

### Ollama Connection Error
- Ensure Ollama is running: `ollama serve`
- Check `OLLAMA_HOST` in `.env` matches your Ollama instance

### Model Not Found
- Pull the model: `ollama pull qwen2.5-coder:1.5b`
- Verify with: `ollama list`

### Poetry Command Not Found
- Install Poetry: `curl -sSL https://install.python-poetry.org | python3 -`
- Add to PATH: `export PATH="$HOME/.local/bin:$PATH"`

### Python Version Mismatch
- Check version: `python --version` (needs 3.11+)
- Use pyenv to manage versions: `pyenv install 3.11 && pyenv local 3.11`
