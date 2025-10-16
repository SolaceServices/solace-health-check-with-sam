# Solace Agent Mesh - Health Check

Multi-agent system for Solace broker monitoring and management.

## Quick Start

```bash
# 1. Create Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Create directories
mkdir -p config/{solace-broker,orch-agent,solace-bp-agent,solace-mcp-agent/repos}
mkdir -p data/{solace-broker/{config,spool,logs},orch-agent,solace-bp-agent,solace-mcp-agent,sam-artifacts}
chmod 777 data/sam-artifacts

# 3. Configure environment
cp .env.example .env  # Edit with your values

# 4. Create Docker network
docker network create sam-network

# 5. Start services
docker-compose up -d
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Solace Broker | 8080 | PubSub+ broker (admin/admin) |
| Orchestrator | 8001 | Main agent coordinator |
| BPA Agent | - | Best practices analyzer |
| MCP Agent | - | Solace monitoring/management |

## Health Checks

```bash
# All services
docker-compose ps

# Solace broker
curl http://localhost:5550/health-check/guaranteed-active

# Orchestrator
curl http://localhost:8001/health
```

## Common Commands

```bash
# View logs
docker-compose logs -f [service-name]

# Restart service
docker-compose restart [service-name]

# Stop all
docker-compose down

# Clean restart
docker-compose down
rm -rf data/*
# Re-run setup steps 2-5
```

## Directory Structure

```
├── config/              # All configuration files
│   ├── {service}/      # Service-specific configs
│   └── {agent}/        # Agent-specific configs
├── data/               # All runtime data (git-ignored)
│   ├── {service}/      # Service data
│   ├── {agent}/        # Agent data
│   └── sam-artifacts/  # Shared artifacts
├── .dev/               # Development specs & docs (git-ignored)
└── venv/               # Python virtual environment (git-ignored)
```


## Requirements

- Python 3.8+
- Docker & Docker Compose
- 8GB RAM minimum
- 10GB free disk space

## Environment Variables

Create `.env` file with:

```bash
# Solace
SOLACE_BROKER_URL=tcp://solace-broker:55555
SOLACE_VPN=default
SOLACE_USERNAME=admin
SOLACE_PASSWORD=admin
```

## Optional Services

MySQL, Qdrant, RAG, and SQL agents are available but not started by default.

**To enable:**
```bash
# Start all optional services
docker-compose --profile optional up -d

# Or start individually
docker-compose up -d mysql-server
docker-compose up -d qdrant
docker-compose up -d rag-agent
docker-compose up -d sql-agent
```

## Troubleshooting

