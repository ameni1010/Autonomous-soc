# Autonomous SOC System

AI-powered Security Operations Center with multi-agent workflow orchestration.

## Quick Start

1. **Set your API key:**
   ```bash
   export ANTHROPIC_API_KEY='your-anthropic-api-key'
   ```

2. **Start the system:**
   ```bash
   ./start.sh
   ```

3. **Access dashboards:**
   - Main Dashboard: http://localhost:8080
   - n8n Workflow: http://localhost:5678 (admin/admin123)

4. **Run attack simulation:**
   ```bash
   ./attack.sh
   ```

## Architecture

- **Client**: Attack simulator
- **Auth Server**: SSH server with logging
- **Log Collector**: Centralizes all logs
- **Detection Engine**: Pattern-based threat detection
- **AI Agents**: Multi-agent SOC workflow (Claude)
- **Response Engine**: Automated response actions
- **Dashboard**: Real-time visualization
- **n8n**: Workflow orchestration

## Services

| Service | Port | Description |
|---------|------|-------------|
| Dashboard | 8080 | Web UI |
| n8n | 5678 | Workflow engine |
| Log Collector | 5000 | Log ingestion |
| Detection Engine | 5001 | Threat detection |
| AI Agents | 5002 | Claude agents |
| Response Engine | 5003 | Response actions |
| Auth Server | 2222 | SSH target |

## Workflow

1. Attack executed → Logs generated
2. Detection engine identifies patterns
3. Alert sent to n8n webhook
4. n8n orchestrates AI agents:
   - Triage Agent (Tier 1)
   - Investigation Agent (Tier 2)
   - Threat Intel Agent
   - Decision Agent (SOC Lead)
   - Response Agent (SOAR)
   - Reporting Agent
5. Actions executed automatically
6. Dashboard updated in real-time

## Useful Commands

```bash
./start.sh      # Start all services
./stop.sh       # Stop all services
./attack.sh     # Run attack simulation
./logs.sh       # View logs
docker-compose ps   # Check service status
```

## n8n Workflow Setup

1. Open http://localhost:5678
2. Login with admin/admin123
3. Import workflow from `n8n-workflows/soc-workflow.json`
4. Activate the workflow

## Project Structure

```
autonomous-soc/
├── containers/         # Docker containers
│   ├── client/        # Attack simulator
│   ├── auth-server/   # SSH server
│   ├── log-collector/ # Log aggregation
│   ├── detection-engine/ # Threat detection
│   ├── ai-agents/     # Claude agents
│   ├── response-engine/  # Response automation
│   └── dashboard/     # Web dashboard
├── logs/              # Log files
├── n8n-workflows/     # n8n workflow definitions
├── docker-compose.yml # Service orchestration
└── *.sh               # Utility scripts
```

## License

MIT
