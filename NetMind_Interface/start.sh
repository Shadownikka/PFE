#!/bin/bash

echo "================================================"
echo "NetMind Web Interface - Quick Start Script"
echo "================================================"
echo ""

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script needs root privileges."
    echo "   Restarting with sudo..."
    sudo "$0" "$@"
    exit $?
fi

echo "✓ Running with root privileges"
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    sudo -u $SUDO_USER python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Install dependencies if needed
if [ ! -f "venv/bin/flask" ]; then
    echo "📦 Installing Python dependencies..."
    sudo -u $SUDO_USER venv/bin/pip install -r requirements.txt
    echo "✓ Dependencies installed"
else
    echo "✓ Dependencies already installed"
fi
echo ""

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama is not installed!"
    echo ""
    echo "Install it with:"
    echo "  curl -fsSL https://ollama.ai/install.sh | sh"
    echo "  ollama pull llama3.1"
    echo ""
    exit 1
fi

echo "✓ Ollama is installed"

# Check if Llama model is available
if ! ollama list | grep -q "llama3.1"; then
    echo "⚠️  Llama 3.1 model not found"
    echo "   Pulling model (this may take a while)..."
    ollama pull llama3.1
fi

echo "✓ Llama 3.1 model available"
echo ""
# Start Ollama service if not running
if ! pgrep -x "ollama" > /dev/null; then
    echo "🚀 Starting Ollama service..."
    ollama serve &
    sleep 3
fi

echo "✓ Ollama service running"
echo ""

# Start the backend
echo "🚀 Starting NetMind Backend Server..."
echo ""
echo "================================================"
echo "Backend running on: http://localhost:5000"
echo "Frontend: Open index.html in your browser"
echo "          or run: python3 -m http.server 8080"
echo "================================================"
echo ""

python3 backend.py
