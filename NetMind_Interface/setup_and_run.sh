#!/bin/bash

# NetMind Interface - Complete Setup and Launch Script
# This script sets up everything and opens terminals to run the interface

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         NetMind Interface - Setup & Launch Script          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   print_error "Please do NOT run this script as root (without sudo)"
   exit 1
fi

# Step 1: Check Python 3
print_info "Checking Python 3..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
print_success "Found $PYTHON_VERSION"

# Step 2: Check if scapy dependencies are installed
print_info "Checking system dependencies..."
MISSING_DEPS=()

if ! command -v tcpdump &> /dev/null; then
    MISSING_DEPS+=("tcpdump")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    print_warning "Missing dependencies: ${MISSING_DEPS[*]}"
    print_info "Installing system dependencies..."
    sudo apt-get update
    sudo apt-get install -y "${MISSING_DEPS[@]}"
fi

# Step 3: Create virtual environment
print_info "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_success "Virtual environment already exists"
fi

# Step 4: Install Python dependencies
print_info "Installing Python packages..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt
print_success "Python packages installed"

# Step 5: Check network interface
print_info "Detecting network interface..."
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_IFACE" ]; then
    print_error "Could not detect default network interface"
    exit 1
fi
print_success "Network interface: $DEFAULT_IFACE"

# Step 6: Check Ollama
print_info "Checking Ollama installation..."
if ! command -v ollama &> /dev/null; then
    print_warning "Ollama is not installed"
    read -p "Do you want to install Ollama? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        print_success "Ollama installed"
    else
        print_warning "Skipping Ollama installation. AI features will not work."
    fi
else
    print_success "Ollama is installed"
fi

# Step 7: Detect terminal emulator
print_info "Detecting terminal emulator..."
TERMINAL=""

if command -v gnome-terminal &> /dev/null; then
    TERMINAL="gnome-terminal"
elif command -v konsole &> /dev/null; then
    TERMINAL="konsole"
elif command -v xfce4-terminal &> /dev/null; then
    TERMINAL="xfce4-terminal"
elif command -v xterm &> /dev/null; then
    TERMINAL="xterm"
elif command -v qterminal &> /dev/null; then
    TERMINAL="qterminal"
else
    print_error "No supported terminal emulator found"
    print_error "Please install one of: gnome-terminal, konsole, xfce4-terminal, xterm, qterminal"
    exit 1
fi

print_success "Using terminal: $TERMINAL"

# Step 8: Kill any existing processes on ports 5000 and 8081
print_info "Cleaning up old processes..."
sudo fuser -k 5000/tcp 2>/dev/null || true
fuser -k 8081/tcp 2>/dev/null || true
sleep 1
print_success "Ports cleaned"

# Step 9: Launch Ollama if not running
print_info "Checking Ollama service..."
if command -v ollama &> /dev/null; then
    if ! pgrep -x "ollama" > /dev/null; then
        print_info "Starting Ollama in background..."
        case $TERMINAL in
            gnome-terminal)
                gnome-terminal --title="Ollama Service" -- bash -c "ollama serve; exec bash" &
                ;;
            konsole)
                konsole --title "Ollama Service" -e bash -c "ollama serve; exec bash" &
                ;;
            xfce4-terminal)
                xfce4-terminal --title="Ollama Service" -e "bash -c 'ollama serve; exec bash'" &
                ;;
            qterminal)
                qterminal -e "bash -c 'ollama serve; exec bash'" &
                ;;
            xterm)
                xterm -T "Ollama Service" -e "bash -c 'ollama serve; exec bash'" &
                ;;
        esac
        sleep 3
        print_success "Ollama service started"
    else
        print_success "Ollama is already running"
    fi
    
    # Pull llama3.1 model if not present
    print_info "Checking Ollama model..."
    if ! ollama list | grep -q "llama3.1"; then
        print_info "Downloading llama3.1 model (this may take a while)..."
        ollama pull llama3.1
        print_success "Model downloaded"
    else
        print_success "Model llama3.1 is available"
    fi
fi

# Step 10: Launch Flask Backend
print_info "Starting Flask backend server..."
case $TERMINAL in
    gnome-terminal)
        gnome-terminal --title="NetMind Backend (Flask)" --working-directory="$SCRIPT_DIR" -- bash -c "sudo venv/bin/python3 backend.py; exec bash" &
        ;;
    konsole)
        konsole --title "NetMind Backend (Flask)" --workdir "$SCRIPT_DIR" -e bash -c "sudo venv/bin/python3 backend.py; exec bash" &
        ;;
    xfce4-terminal)
        xfce4-terminal --title="NetMind Backend (Flask)" --working-directory="$SCRIPT_DIR" -e "bash -c 'sudo venv/bin/python3 backend.py; exec bash'" &
        ;;
    qterminal)
        cd "$SCRIPT_DIR" && qterminal -e "bash -c 'sudo venv/bin/python3 backend.py; exec bash'" &
        ;;
    xterm)
        xterm -T "NetMind Backend (Flask)" -e "bash -c 'cd $SCRIPT_DIR && sudo venv/bin/python3 backend.py; exec bash'" &
        ;;
esac
sleep 3
print_success "Backend server started on port 5000"

# Step 11: Launch HTTP Server for Frontend
print_info "Starting HTTP server for frontend..."
case $TERMINAL in
    gnome-terminal)
        gnome-terminal --title="NetMind Frontend (HTTP Server)" --working-directory="$SCRIPT_DIR" -- bash -c "python3 -m http.server 8081; exec bash" &
        ;;
    konsole)
        konsole --title "NetMind Frontend (HTTP Server)" --workdir "$SCRIPT_DIR" -e bash -c "python3 -m http.server 8081; exec bash" &
        ;;
    xfce4-terminal)
        xfce4-terminal --title="NetMind Frontend (HTTP Server)" --working-directory="$SCRIPT_DIR" -e "bash -c 'python3 -m http.server 8081; exec bash'" &
        ;;
    qterminal)
        cd "$SCRIPT_DIR" && qterminal -e "bash -c 'python3 -m http.server 8081; exec bash'" &
        ;;
    xterm)
        xterm -T "NetMind Frontend (HTTP Server)" -e "bash -c 'cd $SCRIPT_DIR && python3 -m http.server 8081; exec bash'" &
        ;;
esac
sleep 2
print_success "Frontend server started on port 8081"

# Step 12: Wait for services to start
print_info "Waiting for services to initialize..."
sleep 3

# Step 13: Check if services are running
print_info "Verifying services..."

# Check backend
if curl -s http://localhost:5000/api/status > /dev/null 2>&1; then
    print_success "Backend API is responding"
else
    print_warning "Backend API might still be starting..."
fi

# Check frontend
if curl -s http://localhost:8081 > /dev/null 2>&1; then
    print_success "Frontend server is responding"
else
    print_warning "Frontend server might still be starting..."
fi

# Step 14: Open browser
print_info "Opening web interface in browser..."
sleep 2

if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8081/index.html &
elif command -v google-chrome &> /dev/null; then
    google-chrome http://localhost:8081/index.html &
elif command -v firefox &> /dev/null; then
    firefox http://localhost:8081/index.html &
else
    print_warning "Could not auto-open browser. Please open: http://localhost:8081/index.html"
fi

# Final message
echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                  🚀 Setup Complete! 🚀                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo -e "  ${GREEN}•${NC} Web Interface: ${YELLOW}http://localhost:8081/index.html${NC}"
echo -e "  ${GREEN}•${NC} Backend API:   ${YELLOW}http://localhost:5000/api/status${NC}"
echo ""
echo -e "${BLUE}Running Services:${NC}"
echo -e "  ${GREEN}•${NC} Backend (Flask)  - Port 5000 (requires sudo)"
echo -e "  ${GREEN}•${NC} Frontend (HTTP)  - Port 8081"
if command -v ollama &> /dev/null; then
    echo -e "  ${GREEN}•${NC} Ollama (AI)      - Port 11434"
fi
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo -e "  1. Click ${YELLOW}'Initialize System'${NC} in the web interface"
echo -e "  2. Click ${YELLOW}'Start Monitoring'${NC} to begin tracking"
echo -e "  3. Click on any device to see detailed activity"
echo ""
echo -e "${BLUE}To stop all services, run:${NC}"
echo -e "  ${YELLOW}sudo fuser -k 5000/tcp && fuser -k 8081/tcp${NC}"
echo ""
print_success "Happy monitoring! 🎉"
