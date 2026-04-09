#!/bin/bash
# NetMind Deployment Verification Script
# Run after: sudo docker-compose up -d

set -e

echo "======================================"
echo "NetMind Deployment Verification"
echo "======================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

# Helper functions
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 1. Check Docker Compose
echo "1. Checking Docker Compose..."
if docker-compose --version &>/dev/null; then
    check_pass "Docker Compose installed"
else
    check_fail "Docker Compose not found"
    exit 1
fi

# 2. Check containers running
echo ""
echo "2. Checking containers..."
CONTAINERS=("netmind-core" "netmind-ai-agent" "netmind-prometheus" "netmind-grafana")
for container in "${CONTAINERS[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        check_pass "Container $container is running"
    else
        check_fail "Container $container is not running"
    fi
done

# 3. Check ports
echo ""
echo "3. Checking ports..."
PORTS=(3000 9091 11434)
for port in "${PORTS[@]}"; do
    if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
        check_pass "Port $port is listening"
    elif ss -tuln 2>/dev/null | grep -q ":${port} "; then
        check_pass "Port $port is listening"
    else
        check_fail "Port $port is not listening"
    fi
done

# 4. Check Ollama model
echo ""
echo "4. Checking Ollama model..."
sleep 2  # Give Ollama time to start
if docker exec netmind-ai-agent ollama list 2>/dev/null | grep -q "llama3.2"; then
    check_pass "Llama 3.2 model is installed"
else
    check_warn "Llama 3.2 model not found (may still be downloading)"
    echo "   Run: docker exec netmind-ai-agent ollama pull llama3.2"
fi

# 5. Check metrics endpoint
echo ""
echo "5. Checking metrics endpoint..."
if curl -s http://localhost:9090/metrics &>/dev/null; then
    check_pass "Metrics endpoint responding"
    
    # Check for NetMind metrics
    if curl -s http://localhost:9090/metrics | grep -q "netmind_"; then
        check_pass "NetMind metrics are being exported"
    else
        check_warn "NetMind metrics not found (monitoring may not be started yet)"
    fi
else
    check_fail "Metrics endpoint not responding"
fi

# 6. Check Prometheus targets
echo ""
echo "6. Checking Prometheus..."
if curl -s http://localhost:9091/-/healthy &>/dev/null; then
    check_pass "Prometheus is healthy"
else
    check_fail "Prometheus health check failed"
fi

# 7. Check Grafana
echo ""
echo "7. Checking Grafana..."
if curl -s http://localhost:3000/api/health &>/dev/null; then
    GRAFANA_STATUS=$(curl -s http://localhost:3000/api/health | grep -o '"database":"ok"')
    if [ -n "$GRAFANA_STATUS" ]; then
        check_pass "Grafana is healthy"
    else
        check_warn "Grafana database not ready yet"
    fi
else
    check_fail "Grafana not responding"
fi

# 8. Check IP forwarding
echo ""
echo "8. Checking system configuration..."
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
    check_pass "IP forwarding is enabled"
else
    check_warn "IP forwarding is disabled (will be enabled when monitoring starts)"
fi

# 9. Check Docker volumes
echo ""
echo "9. Checking Docker volumes..."
VOLUMES=("docker_grafana_data" "docker_prometheus_data" "docker_ollama_data")
for volume in "${VOLUMES[@]}"; do
    if docker volume ls | grep -q "${volume}"; then
        check_pass "Volume $volume exists"
    else
        check_fail "Volume $volume not found"
    fi
done

# 10. Check configuration files
echo ""
echo "10. Checking configuration files..."
FILES=(
    "docker-compose.yml"
    "prometheus.yml"
    "Dockerfile"
    "Dockerfile.ai-agent"
    "metrics_exporter.py"
    "NetMind_Interface/grafana/datasources.yml"
    "NetMind_Interface/grafana/dashboards.yml"
    "NetMind_Interface/grafana/netmind-dashboard.json"
)
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        check_pass "File $file exists"
    else
        check_fail "File $file not found"
    fi
done

# Summary
echo ""
echo "======================================"
echo "Verification Summary"
echo "======================================"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Access Grafana: http://localhost:3000 (admin/admin)"
    echo "2. Attach to NetMind: sudo docker attach netmind-core"
    echo "3. Start monitoring: Choose option 2 or 3 from menu"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some checks failed${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check logs: sudo docker-compose logs"
    echo "2. Verify containers: sudo docker-compose ps"
    echo "3. See DEPLOYMENT_GUIDE.md for detailed help"
    echo ""
    exit 1
fi
