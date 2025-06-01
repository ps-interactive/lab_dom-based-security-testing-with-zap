#!/bin/bash
# Simple script to start a local server for the lab

echo "Starting server for DOM-Based Security Testing with ZAP Lab..."

# Check if Python is available
if command -v python3 &>/dev/null; then
    echo "Starting server with Python 3..."
    python3 -m http.server 3000
elif command -v python &>/dev/null; then
    echo "Starting server with Python..."
    python -m SimpleHTTPServer 3000
# Check if Node.js/npm is available
elif command -v npx &>/dev/null; then
    echo "Starting server with Node.js http-server..."
    npx http-server -p 3000
else
    echo "Error: Could not find Python or Node.js to start a web server."
    echo "Please install Python or Node.js, or manually start a web server."
    exit 1
fi
