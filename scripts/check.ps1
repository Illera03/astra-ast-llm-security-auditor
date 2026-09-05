# Windows PowerShell script to run code formatting, linting, type checking, and unit tests for the ASTra project.
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Starting ASTra verifications..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n1. Formatting code (Ruff Format)..." -ForegroundColor Yellow
poetry run ruff format .

Write-Host "`n2. Fixing syntax and imports (Ruff Check)..." -ForegroundColor Yellow
poetry run ruff check --fix .

Write-Host "`n3. Checking strict type checking (MyPy)..." -ForegroundColor Yellow
poetry run mypy .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error in MyPy. Stopping execution." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n4. Running unit tests (Pytest)..." -ForegroundColor Yellow
poetry run pytest
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error in tests. Review your code." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " Nice!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green