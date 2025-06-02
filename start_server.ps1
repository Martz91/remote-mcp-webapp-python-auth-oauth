# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Install dependencies (if needed)
Write-Host "Installing dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt

# Start the MCP FastAPI server
Write-Host "Starting MCP Server..." -ForegroundColor Green
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
