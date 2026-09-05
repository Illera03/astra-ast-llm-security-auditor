# ASTra - AST + LLM Security Auditor

Hybrid security vulnerability scanner that combines Abstract Syntax Tree (AST) static analysis with LLM-based semantic reasoning to detect vulnerabilities in Python codebases.

## Overview

ASTra uses a three-stage pipeline:

1. **AST Analysis** — Parses Python source code and detects vulnerability patterns via `ast.NodeVisitor`
2. **LLM Validation** — Sends suspicious code to a local LLM (Ollama) for semantic verification
3. **Hybrid Scoring** — Combines AST heuristics (40%), LLM confidence (40%), and code complexity (20%) with a 0.65 threshold

### Supported Vulnerabilities

| CWE | Name | Detected Patterns |
|---|---|---|
| CWE-78 | Command Injection | `subprocess.*`, `os.system`, `os.popen*`, `os.spawn*` |
| CWE-502 | Insecure Deserialization | `pickle.*`, `marshal.*`, `yaml.load`, `shelve.open`, `jsonpickle.*` |
| CWE-22 | Path Traversal | `open()`, `os.remove()`, `os.path.join()`, `pathlib.Path()` chains |

## Benchmark Results

Evaluated on 160 files (150 synthetic + 10 from [Bandit's test suite](https://github.com/PyCQA/bandit/tree/main/examples)) using `qwen2.5-coder:7b`:

| Tool | Precision | Recall | F1-Score |
|---|---|---|---|
| **ASTra** | **0.84** | **0.72** | **0.78** |
| Bandit | 0.86 | 0.59 | 0.70 |
| Semgrep | 0.86 | 0.49 | 0.62 |

**Per CWE:**

| CWE | ASTra F1 | Bandit F1 | Semgrep F1 |
|---|---|---|---|
| CWE-22 (Path Traversal) | **0.72** | 0.07 | 0.07 |
| CWE-502 (Deserialization) | **0.81** | 0.81 | 0.79 |
| CWE-78 (Command Injection) | 0.79 | **0.85** | 0.68 |

> **Note on dataset bias:** 150 of the 160 test files are synthetic (created for this project). The 10 Bandit examples provide an external, neutral reference. The synthetic dataset was designed around ASTra's detection capabilities, which favors ASTra in CWE-22 (where Bandit/Semgrep lack rules for Python's `open()` patterns). Results should be interpreted as performance within ASTra's target scope, not as a general SAST tool comparison.

Run the benchmark yourself:

```bash
poetry run python -m benchmarks --manifest datasets/manifest.yaml --format table
```

## Known Limitations

- **No import alias resolution**: `from pickle import loads as foo; foo(data)` is not detected
- **Single-function scope**: Taint analysis does not cross function boundaries
- **3 CWEs only**: Does not cover SQL injection, XSS, SSRF, etc.
- **Local LLM latency**: ~7 min for 160 files with `qwen2.5-coder:7b` on CPU

## Roadmap

### Symbol Tracking (Import Alias Resolution)

The parser currently matches calls by module name (`pickle.loads`). Aliased imports like `from os import system as run_cmd` bypass detection entirely. A symbol table built during `visit_Import`/`visit_ImportFrom` would resolve aliases to their original module.function, closing the detection gap with Bandit on CWE-78.

### Intra-procedural Taint Analysis

Currently, the AST checks if a function argument is a variable (`ast.Name`) and flags it as dynamic. A lightweight taint tracker would trace variable definitions within the same function to determine if the source is user-controlled or a constant, reducing false positives and unnecessary LLM calls.

### Dynamic Rule Engine

Each new CWE requires a new `_check_*` method in the parser. A configuration-driven rule engine (YAML/JSON pattern definitions) would decouple detection logic from code, enabling new CWE coverage without modifying the parser.

### Multi-function Context

Real vulnerabilities often span multiple functions. Expanding the context window sent to the LLM to include caller/callee chains would leverage the model's semantic capabilities beyond single-function analysis.

## Prerequisites

- **Python 3.11+**
- **Ollama** with `qwen2.5-coder:7b` (or `1.5b` for faster, less accurate scans)

## Quick Start

```bash
# Automated setup (macOS/Linux)
./scripts/setup.sh

# Or manual
poetry install
cp .env.example .env
ollama pull qwen2.5-coder:7b

# Scan a file
poetry run python -m app.cli scan demo.py

# Run tests
poetry run pytest tests/unit/ -v
```

## Tech Stack

- **ast (stdlib)** — AST parsing and vulnerability pattern detection
- **Ollama** — Local LLM inference (`qwen2.5-coder:7b`)
- **Pydantic** — Data validation and schema enforcement
- **FastAPI** — API layer
- **structlog** — Structured logging
- **Poetry** — Dependency management

## Model Configuration

Default model: `qwen2.5-coder:7b`

Update `MODEL_NAME` in `.env` and pull the model:
```bash
ollama pull <model-name>
```

## Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make changes and run checks: `./scripts/check.sh`
3. Commit with conventional commits: `feat:`, `fix:`, `refactor:`, etc.
4. Push and open a PR to `dev` branch

## License

See [LICENSE](LICENSE) file.

## Troubleshooting

### Ollama Connection Error
- Ensure Ollama is running: `ollama serve`
- Check `OLLAMA_HOST` in `.env` matches your Ollama instance

### Model Not Found
- Pull the model: `ollama pull qwen2.5-coder:7b`
- Verify with: `ollama list`

### Benchmark Timeout Errors
- Reduce concurrency: `--concurrency 1`
- The default timeout is 120s per LLM call
