# ASTra - AST LLM Security Auditor

Security vulnerability scanner powered by Abstract Syntax Tree (AST) analysis and Large Language Models.

## 🎯 Overview

ASTra combines static code analysis with LLM-based reasoning to detect security vulnerabilities in Python codebases. It uses AST parsing to extract code context and a hybrid scoring engine to assess risk levels.

## 📋 Prerequisites

- **Python 3.11+**

## 🚀 Quick Start (Automated Setup - macOS/Linux only)

For macOS and Linux users, you can use the automated setup script:

```bash
./scripts/setup.sh
```

This script will:
1. Check Python version
2. Install Poetry (if missing)
3. Install Ollama (if missing on macOS)
4. Start Ollama service
5. Pull the default model (`qwen2.5-coder:1.5b`)
6. Install Python dependencies
7. Create `.env` file from template
8. Run verification checks

**For Windows or manual installation, see the detailed OS-specific guides below.**

---

## 📖 Manual Installation & Setup

Choose your operating system for complete step-by-step setup instructions:

---

### 🍎 macOS

#### 1. Install Poetry (Python dependency manager)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Add Poetry to your PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Verify installation:
```bash
poetry --version
```

#### 2. Install Ollama (LLM runtime)

**Option A - Using Homebrew (recommended):**
```bash
brew install ollama
```

**Option B - Manual installation:**
1. Download from [ollama.ai/download](https://ollama.ai/download)
2. Open the `.dmg` file and drag Ollama to Applications
3. Launch Ollama from Applications

#### 3. Start Ollama Service

```bash
ollama serve
```

Leave this running in a separate terminal, or run in background:
```bash
brew services start ollama
```

#### 4. Pull the LLM Model

```bash
ollama pull qwen2.5-coder:1.5b
```

This downloads the default model (~1GB).

#### 5. Clone and Setup Project

```bash
git clone <repository-url>
cd astra-ast-llm-security-auditor
poetry install
cp .env.example .env
```

#### 6. Run Your First Scan

```bash
poetry run python -m app.cli scan demo.py
```

#### 7. Run Quality Checks (Development)

```bash
./scripts/check.sh
```

Or run individual checks:
```bash
poetry run ruff format .      # Format code
poetry run ruff check --fix .  # Lint
poetry run mypy .              # Type check
poetry run pytest              # Tests
```

---

### 🐧 Linux

#### 1. Install Poetry (Python dependency manager)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Add Poetry to your PATH (add to `~/.bashrc` or `~/.zshrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Reload shell configuration:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

Verify installation:
```bash
poetry --version
```

#### 2. Install Ollama (LLM runtime)

**Automated installation (Ubuntu, Debian, Fedora, CentOS, RHEL):**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**Manual installation:**
```bash
curl -L https://ollama.ai/download/ollama-linux-amd64 -o /usr/local/bin/ollama
chmod +x /usr/local/bin/ollama
```

**Setup as systemd service (optional, for auto-start):**
```bash
sudo useradd -r -s /bin/false -m -d /usr/share/ollama ollama
sudo curl -L https://raw.githubusercontent.com/ollama/ollama/main/dist/linux/ollama.service -o /etc/systemd/system/ollama.service
sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl start ollama
```

Verify installation:
```bash
ollama --version
```

#### 3. Start Ollama Service

If not using systemd:
```bash
ollama serve &
```

#### 4. Pull the LLM Model

```bash
ollama pull qwen2.5-coder:1.5b
```

This downloads the default model (~1GB).

#### 5. Clone and Setup Project

```bash
git clone <repository-url>
cd astra-ast-llm-security-auditor
poetry install
cp .env.example .env
```

#### 6. Run Your First Scan

```bash
poetry run python -m app.cli scan demo.py
```

#### 7. Run Quality Checks (Development)

```bash
./scripts/check.sh
```

Or run individual checks:
```bash
poetry run ruff format .      # Format code
poetry run ruff check --fix .  # Lint
poetry run mypy .              # Type check
poetry run pytest              # Tests
```

---

### 🪟 Windows

#### 1. Install Poetry (Python dependency manager)

**Option A - Using PowerShell (recommended):**
```powershell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

**Option B - Using pip:**
```powershell
pip install poetry
```

Add Poetry to your PATH:
- Open "Environment Variables" in System Properties
- Add `%APPDATA%\Python\Scripts` to your PATH
- Restart your terminal

Verify installation:
```powershell
poetry --version
```

#### 2. Install Ollama (LLM runtime)

1. Download the Windows installer from [ollama.ai/download](https://ollama.ai/download)
2. Run the `.exe` installer
3. Follow the installation wizard
4. Ollama will run automatically in the system tray

Verify installation:
```powershell
ollama --version
```

#### 3. Pull the LLM Model

```powershell
ollama pull qwen2.5-coder:1.5b
```

This downloads the default model (~1GB).

#### 4. Clone and Setup Project

```powershell
git clone <repository-url>
cd astra-ast-llm-security-auditor
poetry install
copy .env.example .env
```

#### 5. Run Your First Scan

```powershell
poetry run python -m app.cli scan demo.py
```

#### 6. Run Quality Checks (Development)

Run all checks with the PowerShell script:
```powershell
.\scripts\check.ps1
```

Or run checks individually:
```powershell
poetry run ruff format .      # Format code
poetry run ruff check --fix .  # Lint
poetry run mypy .              # Type check
poetry run pytest              # Tests
```



---

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
