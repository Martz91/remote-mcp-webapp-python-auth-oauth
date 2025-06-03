#!/usr/bin/env bash
# Activation script for bash/zsh
source venv/bin/activate
echo "Virtual environment activated!"
echo "You can now run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
