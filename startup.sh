#!/bin/bash

# Install requirements if not already installed
if [ ! -f /tmp/requirements_installed ]; then
    echo "Installing Python requirements..."
    pip install -r requirements.txt
    touch /tmp/requirements_installed
    echo "Requirements installed successfully"
fi

# Start the application
echo "Starting FastAPI application..."
python -m uvicorn main:app --host 0.0.0.0 --port 8000
