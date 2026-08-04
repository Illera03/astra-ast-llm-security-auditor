#!/bin/bash

# Definición de colores
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # Sin color

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN} Starting ASTra verifications...${NC}"
echo -e "${CYAN}========================================${NC}"

echo -e "\n${YELLOW}1. Formatting code (Ruff Format)...${NC}"
poetry run ruff format .

echo -e "\n${YELLOW}2. Fixing syntax and imports (Ruff Check)...${NC}"
poetry run ruff check --fix .

echo -e "\n${YELLOW}3. Checking strict type checking (MyPy)...${NC}"
poetry run mypy .
if [ $? -ne 0 ]; then
    echo -e "${RED}Error in MyPy. Stopping execution.${NC}"
    exit 1
fi

echo -e "\n${YELLOW}4. Running unit tests (Pytest)...${NC}"
poetry run pytest
if [ $? -ne 0 ]; then
    echo -e "${RED}Error in tests. Review your code.${NC}"
    exit 1
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN} Nice!${NC}"
echo -e "${GREEN}========================================${NC}"