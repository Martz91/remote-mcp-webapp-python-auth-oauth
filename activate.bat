@echo off
REM Activation script for Windows Command Prompt
call .\venv\Scripts\activate.bat
echo Virtual environment activated!
echo You can now run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
