#!/bin/bash

echo "🚀 Starting Autonomous SOC System..."
echo "===================================="

# Check if API key is set
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠️  WARNING: ANTHROPIC_API_KEY not set!"
    echo "Please export your API key:"
    echo "export ANTHROPIC_API_KEY='your-key-here'"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Build and start
docker-compose up --build -d

echo ""
echo "✅ System starting..."
echo ""
echo "Services:"
echo "  - Dashboard:  http://localhost:8080"
echo "  - n8n:        http://localhost:5678 (admin/admin123)"
echo "  - Logs:       http://localhost:5000"
echo "  - Detection:  http://localhost:5001"
echo "  - AI Agents:  http://localhost:5002"
echo "  - Response:   http://localhost:5003"
echo ""
echo "Run 'docker-compose logs -f' to view logs"
echo "Run './attack.sh' to simulate attack"
