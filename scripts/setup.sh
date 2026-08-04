#!/bin/bash

# Colors
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_MODEL="qwen2.5-coder:1.5b"
OLLAMA_HOST="http://localhost:11434"

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ASTra - AST LLM Security Auditor     ║${NC}"
echo -e "${CYAN}║  Setup Script                          ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Check Python version
echo -e "${BLUE}[1/7]${NC} ${YELLOW}Checking Python version...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    REQUIRED_VERSION="3.11"
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
        echo -e "  ${GREEN}✓${NC} Python $PYTHON_VERSION detected"
    else
        echo -e "  ${RED}✗${NC} Python $REQUIRED_VERSION+ required, found $PYTHON_VERSION"
        exit 1
    fi
else
    echo -e "  ${RED}✗${NC} Python 3 not found. Please install Python 3.11+"
    exit 1
fi

# Step 2: Check/Install Poetry
echo -e "\n${BLUE}[2/7]${NC} ${YELLOW}Checking Poetry installation...${NC}"
if command_exists poetry; then
    echo -e "  ${GREEN}✓${NC} Poetry is already installed"
else
    echo -e "  ${YELLOW}Poetry not found. Installing...${NC}"
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
    if command_exists poetry; then
        echo -e "  ${GREEN}✓${NC} Poetry installed successfully"
    else
        echo -e "  ${RED}✗${NC} Poetry installation failed. Please install manually:"
        echo -e "     ${CYAN}https://python-poetry.org/docs/#installation${NC}"
        exit 1
    fi
fi

# Step 3: Check/Install Ollama
echo -e "\n${BLUE}[3/7]${NC} ${YELLOW}Checking Ollama installation...${NC}"
if command_exists ollama; then
    echo -e "  ${GREEN}✓${NC} Ollama is already installed"
else
    echo -e "  ${YELLOW}Ollama not found.${NC}"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists brew; then
            echo -e "  ${YELLOW}Installing Ollama via Homebrew...${NC}"
            brew install ollama
            if [ $? -eq 0 ]; then
                echo -e "  ${GREEN}✓${NC} Ollama installed successfully"
            else
                echo -e "  ${RED}✗${NC} Ollama installation failed"
                exit 1
            fi
        else
            echo -e "  ${RED}✗${NC} Homebrew not found. Please install Ollama manually:"
            echo -e "     ${CYAN}https://ollama.ai${NC}"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        echo -e "  ${YELLOW}Installing Ollama...${NC}"
        curl -fsSL https://ollama.ai/install.sh | sh
        if [ $? -eq 0 ]; then
            echo -e "  ${GREEN}✓${NC} Ollama installed successfully"
        else
            echo -e "  ${RED}✗${NC} Ollama installation failed"
            exit 1
        fi
    else
        echo -e "  ${RED}✗${NC} Unsupported OS. Please install Ollama manually:"
        echo -e "     ${CYAN}https://ollama.ai${NC}"
        exit 1
    fi
fi

# Step 4: Check if Ollama is running
echo -e "\n${BLUE}[4/7]${NC} ${YELLOW}Checking Ollama service...${NC}"
if curl -s "$OLLAMA_HOST" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Ollama service is running"
else
    echo -e "  ${YELLOW}Ollama service not running. Starting it...${NC}"
    echo -e "  ${CYAN}Note:${NC} Ollama will run in the background"

    # Start Ollama service
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - use brew services or background process
        if command_exists brew; then
            brew services start ollama 2>/dev/null || ollama serve >/dev/null 2>&1 &
        else
            ollama serve >/dev/null 2>&1 &
        fi
    else
        # Linux/Other
        ollama serve >/dev/null 2>&1 &
    fi

    # Wait for service to start
    sleep 3

    if curl -s "$OLLAMA_HOST" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Ollama service started successfully"
    else
        echo -e "  ${RED}✗${NC} Failed to start Ollama service"
        echo -e "  ${YELLOW}Please start it manually:${NC} ollama serve"
        exit 1
    fi
fi

# Step 5: Pull the model
echo -e "\n${BLUE}[5/7]${NC} ${YELLOW}Pulling LLM model ($DEFAULT_MODEL)...${NC}"
echo -e "  ${CYAN}This may take a few minutes (~1GB download)${NC}"

if ollama list | grep -q "$DEFAULT_MODEL"; then
    echo -e "  ${GREEN}✓${NC} Model $DEFAULT_MODEL already exists"
else
    ollama pull "$DEFAULT_MODEL"
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} Model pulled successfully"
    else
        echo -e "  ${RED}✗${NC} Failed to pull model"
        exit 1
    fi
fi

# Step 6: Install Python dependencies
echo -e "\n${BLUE}[6/7]${NC} ${YELLOW}Installing Python dependencies...${NC}"
poetry install
if [ $? -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} Dependencies installed successfully"
else
    echo -e "  ${RED}✗${NC} Failed to install dependencies"
    exit 1
fi

# Step 7: Create .env file
echo -e "\n${BLUE}[7/7]${NC} ${YELLOW}Setting up environment configuration...${NC}"
if [ -f ".env" ]; then
    echo -e "  ${YELLOW}⚠${NC}  .env file already exists. Skipping..."
else
    cp .env.example .env
    echo -e "  ${GREEN}✓${NC} .env file created from template"
fi

# Final verification
echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Running Verification Checks           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}Testing Ollama connection...${NC}"
if ollama list >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Ollama is accessible"
else
    echo -e "  ${RED}✗${NC} Ollama connection failed"
    exit 1
fi

echo -e "\n${YELLOW}Verifying Poetry environment...${NC}"
if poetry env info >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Poetry environment is configured"
else
    echo -e "  ${RED}✗${NC} Poetry environment verification failed"
    exit 1
fi

# Success message
echo -e "\n${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Setup completed successfully!       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}Next steps:${NC}"
echo -e "  1. Run a security scan:"
echo -e "     ${YELLOW}poetry run python -m app.cli scan demo.py${NC}"
echo -e "\n  2. Run quality checks:"
echo -e "     ${YELLOW}./scripts/check.sh${NC}"
echo -e "\n  3. Read the documentation:"
echo -e "     ${YELLOW}cat README.md${NC}"

echo -e "\n${CYAN}Configuration:${NC}"
echo -e "  • Model: ${YELLOW}$DEFAULT_MODEL${NC}"
echo -e "  • Ollama: ${YELLOW}$OLLAMA_HOST${NC}"
echo -e "  • Config: ${YELLOW}.env${NC}"

echo ""
