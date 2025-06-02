@echo off
echo Activating virtual environment...
call .\venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo Starting MCP FastAPI Server...
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
