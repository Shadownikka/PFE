#!/bin/bash

# NetMind Interface - Quick Launch Script
# Launches each component in a separate named terminal

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║        NetMind Interface - Quick Launcher             ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect terminal emulator
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
    echo -e "${RED}[ERROR]${NC} No supported terminal found!"
    exit 1
fi

echo -e "${GREEN}✓${NC} Using terminal: ${YELLOW}$TERMINAL${NC}"

# Kill old processes
echo -e "${BLUE}[INFO]${NC} Cleaning up old processes..."
sudo fuser -k 5000/tcp 2>/dev/null || true
fuser -k 8081/tcp 2>/dev/null || true
sleep 1

# Launch Ollama Service (if needed)
if command -v ollama &> /dev/null; then
    if ! pgrep -x "ollama" > /dev/null; then
        echo -e "${BLUE}[INFO]${NC} Starting Ollama AI Service..."
        case $TERMINAL in
            gnome-terminal)
                gnome-terminal --title="🤖 NetMind - Ollama AI Service" -- bash -c "
                    echo -e '\033]2;🤖 NetMind - Ollama AI Service\007'
                    clear
                    echo '╔═══════════════════════════════════════════════╗'
                    echo '║     🤖 OLLAMA AI SERVICE                     ║'
                    echo '║     Port: 11434                               ║'
                    echo '║     Model: llama3.1                          ║'
                    echo '╚═══════════════════════════════════════════════╝'
                    echo ''
                    ollama serve
                    exec bash
                " &
                ;;
            konsole)
                konsole --title "🤖 NetMind - Ollama AI Service" -e bash -c "
                    clear
                    echo '╔═══════════════════════════════════════════════╗'
                    echo '║     🤖 OLLAMA AI SERVICE                     ║'
                    echo '║     Port: 11434                               ║'
                    echo '╚═══════════════════════════════════════════════╝'
                    echo ''
                    ollama serve
                    exec bash
                " &
                ;;
            xfce4-terminal)
                xfce4-terminal --title="🤖 NetMind - Ollama AI Service" -e bash -c "
                    clear
                    echo '╔═══════════════════════════════════════════════╗'
                    echo '║     🤖 OLLAMA AI SERVICE                     ║'
                    echo '║     Port: 11434                               ║'
                    echo '╚═══════════════════════════════════════════════╝'
                    echo ''
                    ollama serve
                    exec bash
                " &
                ;;
            qterminal|xterm)
                $TERMINAL -e bash -c "
                    clear
                    echo '╔═══════════════════════════════════════════════╗'
                    echo '║     🤖 OLLAMA AI SERVICE                     ║'
                    echo '║     Port: 11434                               ║'
                    echo '╚═══════════════════════════════════════════════╝'
                    echo ''
                    ollama serve
                    exec bash
                " &
                ;;
        esac
        sleep 2
        echo -e "${GREEN}✓${NC} Ollama service started"
    else
        echo -e "${GREEN}✓${NC} Ollama already running"
    fi
fi

# Launch Backend Server
echo -e "${BLUE}[INFO]${NC} Starting Backend API Server..."
case $TERMINAL in
    gnome-terminal)
        gnome-terminal --title="⚙️  NetMind - Backend API Server (Port 5000)" --working-directory="$SCRIPT_DIR" -- bash -c "
            echo -e '\033]2;⚙️  NetMind - Backend API Server (Port 5000)\007'
            clear
            echo -e '${CYAN}╔═══════════════════════════════════════════════════════╗${NC}'
            echo -e '${CYAN}║          ⚙️  NETMIND BACKEND API SERVER              ║${NC}'
            echo -e '${CYAN}║                                                       ║${NC}'
            echo -e '${CYAN}║  ${GREEN}●${NC} Port: ${YELLOW}5000${NC}                                        ${CYAN}║${NC}'
            echo -e '${CYAN}║  ${GREEN}●${NC} API Endpoint: ${YELLOW}http://localhost:5000/api${NC}          ${CYAN}║${NC}'
            echo -e '${CYAN}║  ${GREEN}●${NC} Technology: ${YELLOW}Flask + Python${NC}                       ${CYAN}║${NC}'
            echo -e '${CYAN}║                                                       ║${NC}'
            echo -e '${CYAN}║  ${RED}Press Ctrl+C to stop${NC}                              ${CYAN}║${NC}'
            echo -e '${CYAN}╚═══════════════════════════════════════════════════════╝${NC}'
            echo ''
            sudo venv/bin/python3 backend.py
            exec bash
        " &
        ;;
    konsole)
        konsole --title "⚙️  NetMind - Backend API Server (Port 5000)" --workdir "$SCRIPT_DIR" -e bash -c "
            clear
            echo '╔═══════════════════════════════════════════════════════╗'
            echo '║          ⚙️  NETMIND BACKEND API SERVER              ║'
            echo '║                                                       ║'
            echo '║  ● Port: 5000                                         ║'
            echo '║  ● API: http://localhost:5000/api                     ║'
            echo '║  ● Tech: Flask + Python                               ║'
            echo '║  Press Ctrl+C to stop                                 ║'
            echo '╚═══════════════════════════════════════════════════════╝'
            echo ''
            sudo venv/bin/python3 backend.py
            exec bash
        " &
        ;;
    xfce4-terminal)
        xfce4-terminal --title="⚙️  NetMind - Backend API Server (Port 5000)" --working-directory="$SCRIPT_DIR" -e bash -c "
            clear
            echo '╔═══════════════════════════════════════════════════════╗'
            echo '║          ⚙️  NETMIND BACKEND API SERVER              ║'
            echo '║                                                       ║'
            echo '║  ● Port: 5000                                         ║'
            echo '║  ● API: http://localhost:5000/api                     ║'
            echo '║  Press Ctrl+C to stop                                 ║'
            echo '╚═══════════════════════════════════════════════════════╝'
            echo ''
            sudo venv/bin/python3 backend.py
            exec bash
        " &
        ;;
    qterminal|xterm)
        cd "$SCRIPT_DIR" && $TERMINAL -e bash -c "
            clear
            echo '╔═══════════════════════════════════════════════════════╗'
            echo '║          ⚙️  NETMIND BACKEND API SERVER              ║'
            echo '║  Port: 5000                                           ║'
            echo '║  Press Ctrl+C to stop                                 ║'
            echo '╚═══════════════════════════════════════════════════════╝'
            echo ''
            sudo venv/bin/python3 backend.py
            exec bash
        " &
        ;;
esac
sleep 2
echo -e "${GREEN}✓${NC} Backend server started"

# Launch Frontend Server
echo -e "${BLUE}[INFO]${NC} Starting Frontend Web Server..."
case $TERMINAL in
    gnome-terminal)
        gnome-terminal --title="🌐 NetMind - Frontend Web Server (Port 8081)" --working-directory="$SCRIPT_DIR" -- bash -c "
            echo -e '\033]2;🌐 NetMind - Frontend Web Server (Port 8081)\007'
            clear
            echo -e '${CYAN}╔═══════════════════════════════════════════════════════╗${NC}'
            echo -e '${CYAN}║         🌐 NETMIND FRONTEND WEB SERVER               ║${NC}'
            echo -e '${CYAN}║                                                       ║${NC}'
            echo -e '${CYAN}║  ${GREEN}●${NC} Port: ${YELLOW}8081${NC}                                        ${CYAN}║${NC}'
            echo -e '${CYAN}║  ${GREEN}●${NC} URL: ${YELLOW}http://localhost:8081/index.html${NC}            ${CYAN}║${NC}'
            echo -e '${CYAN}║  ${GREEN}●${NC} Technology: ${YELLOW}Python HTTP Server${NC}                   ${CYAN}║${NC}'
            echo -e '${CYAN}║                                                       ║${NC}'
            echo -e '${CYAN}║  ${RED}Press Ctrl+C to stop${NC}                              ${CYAN}║${NC}'
            echo -e '${CYAN}╚═══════════════════════════════════════════════════════╝${NC}'
            echo ''
            python3 -m http.server 8081
            exec bash
        " &
        ;;
    konsole)
        konsole --title "🌐 NetMind - Frontend Web Server (Port 8081)" --workdir "$SCRIPT_DIR" -e bash -c "
            clear
            echo '╔═══════════════════════════════════════════════════════╗'
            echo '║         🌐 NETMIND FRONTEND WEB SERVER               ║'
            echo '║                                                       ║'
            echo '║  ● Port: 8081                                         ║'
            echo '║  ● URL: http://localhost:8081/index.html              ║'
            echo '║  ● Tech: Python HTTP Server                           ║'
            echo '║  Press Ctrl+C to stop                                 ║'
            echo '╚═══════════════════════════════════════════════════════╝'
            echo ''
            python3 -m http.server 8081
            exec bash
        " &
        ;;
    xfce4-terminal)
        xfce4-terminal --title="🌐 NetMind - Frontend Web Server (Port 8081)" --working-directory="$SCRIPT_DIR" -e bash -c "
            clear
            echo '╔═══════════════════════════════════════════════════════╗'
            echo '║         🌐 NETMIND FRONTEND WEB SERVER               ║'
            echo '║  Port: 8081                                           ║'
            echo '║  URL: http://localhost:8081/index.html                ║'
            echo '║  Press Ctrl+C to stop                                 ║'
            echo '╚═══════════════════════════════════════════════════════╝'
            echo ''
            python3 -m http.server 8081
            exec bash
        " &
        ;;
    qterminal|xterm)
        cd "$SCRIPT_DIR" && $TERMINAL -e bash -c "
            clear
            echo '╔═══════════════════════════════════════════════════════╗'
            echo '║         🌐 NETMIND FRONTEND WEB SERVER               ║'
            echo '║  Port: 8081                                           ║'
            echo '║  URL: http://localhost:8081/index.html                ║'
            echo '╚═══════════════════════════════════════════════════════╝'
            echo ''
            python3 -m http.server 8081
            exec bash
        " &
        ;;
esac
sleep 2
echo -e "${GREEN}✓${NC} Frontend server started"

# Open browser
sleep 2
echo ""
echo -e "${BLUE}[INFO]${NC} Opening web interface in browser..."
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8081/index.html &
elif command -v google-chrome &> /dev/null; then
    google-chrome http://localhost:8081/index.html &
elif command -v firefox &> /dev/null; then
    firefox http://localhost:8081/index.html &
fi

# Summary
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              🚀 ALL SERVICES RUNNING! 🚀              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Running Terminals:${NC}"
echo -e "  ${YELLOW}1.${NC} 🤖 Ollama AI Service        (Port 11434)"
echo -e "  ${YELLOW}2.${NC} ⚙️  Backend API Server       (Port 5000)"
echo -e "  ${YELLOW}3.${NC} 🌐 Frontend Web Server      (Port 8081)"
echo ""
echo -e "${CYAN}Access:${NC}"
echo -e "  ${GREEN}●${NC} Web Interface: ${YELLOW}http://localhost:8081/index.html${NC}"
echo -e "  ${GREEN}●${NC} Backend API:   ${YELLOW}http://localhost:5000/api/status${NC}"
echo ""
echo -e "${CYAN}To stop all services:${NC}"
echo -e "  ${YELLOW}sudo fuser -k 5000/tcp && fuser -k 8081/tcp${NC}"
echo ""
echo -e "${GREEN}Happy monitoring! 🎉${NC}"
