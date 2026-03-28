# 🚀 Quick Start Guide

Get the **Security Alert Triage System** running in 5 minutes.

This file describes the current recommended startup flow. For a concise reality-based summary, see [CURRENT_STARTUP_GUIDE.md](CURRENT_STARTUP_GUIDE.md).

---

## Step 1: Prerequisites (1 minute)

Ensure you have:

- **Docker** 20.10+ installed
  - macOS: `brew install docker`
  - Linux: `curl -fsSL https://get.docker.com | sh`
  - Windows: [Download Docker Desktop](https://www.docker.com/products/docker-desktop)

- **Docker Compose** 2.0+ (usually included with Docker)

Verify installation:
```bash
docker --version
docker-compose --version
```

---

## Step 2: Get LLM API Key (2 minutes)

The system needs an LLM API key to analyze alerts. Choose one:

### Option A: Qwen (通义千问) - Recommended for China 🇨🇳

1. Visit: https://bailian.console.aliyun.com/
2. Sign up / Log in
3. Get your API Key (starts with `sk-`)

### Option B: OpenAI

1. Visit: https://platform.openai.com/api-keys
2. Create an API key

### Option C: DeepSeek

1. Visit: https://platform.deepseek.com/
2. Sign up and get API key

---

## Step 3: Clone & Configure (1 minute)

```bash
# Clone repository
git clone https://github.com/yourname/security-triage.git
cd security-triage

# Create environment file
cp .env.docker.example .env

# Edit .env and add your API key
# On macOS/Linux:
nano .env

# On Windows:
notepad .env
```

**Minimal configuration in `.env`:**
```bash
# Required: Set your LLM API key
LLM_API_KEY=sk-your-actual-api-key-here
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1

# All other values have defaults - can be changed later
```

---

## Step 4: Start the System (1 minute)

```bash
# Make start script executable (macOS/Linux only)
chmod +x start-dev.sh

# Start development mode (current POC path)
./start-dev.sh
```

**What happens:**
1. ✅ Checks prerequisites
2. ✅ Pulls Docker images (~2-3 minutes first time)
3. ✅ Builds services (~2-3 minutes first time)
4. ✅ Starts infrastructure (PostgreSQL, Redis, RabbitMQ, ChromaDB)
5. ✅ Starts core services
6. ✅ Runs health checks
7. ✅ Displays access URLs

**Output:**
```
============================================================================
✓ System started successfully!
============================================================================

Web Dashboard:    http://localhost:3000
RabbitMQ UI:      http://localhost:15673
Alert Ingestor:   http://localhost:9001
AI Triage Agent:  http://localhost:9006
```

---

## Step 5: Access the Dashboard

Open your browser and navigate to:

**http://localhost:3000**

You should see the Security Triage Dashboard!

### Optional: Frontend-Only Container Path

If your host Node version is not compatible with the frontend toolchain, use the containerized frontend scripts from the project root:

```bash
./scripts/frontend-dev.sh
./scripts/frontend-build.sh
```

This runs the active frontend from `services/web_dashboard/` in a supported Node container without changing the host runtime.

---

## What's Running?

### Development Mode (current default)
| Service | Port | Description |
|---------|------|-------------|
| PostgreSQL | 5434 | Main database |
| Redis | 6381 | Cache |
| RabbitMQ | 5673, 15673 | Message queue + UI |
| ChromaDB | 8001 | Vector database |
| Alert Ingestor | 9001 | API endpoint |
| Alert Normalizer | 9002 | Alert standardization |
| Context Collector | 9003 | Context enrichment |
| AI Triage Agent | 9006 | AI analysis |
| Web Dashboard | 3000 | Web UI |

Development mode currently starts 9 containers total and is best treated as the current POC path rather than the full production graph.

### Production Mode (15 services)
To start all services including monitoring, analytics, etc.:
```bash
./start-dev.sh prod
```

In production mode, the current dashboard port is `3100`.

---

## Testing the System

### Method 1: Via Web Dashboard

1. Open http://localhost:3000
2. Navigate to "Alerts" → "Submit New Alert"
3. Fill in alert details and submit

### Method 2: Via API

```bash
curl -X POST http://localhost:9001/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-001",
    "timestamp": "2025-01-04T12:00:00Z",
    "alert_type": "malware",
    "severity": "high",
    "source_ip": "45.33.32.156",
    "target_ip": "10.0.0.50",
    "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "description": "Test malware alert"
  }'
```

### Method 3: Via CLI (Prototype)

```bash
# Install dependencies
pip install -r requirements.txt

# Process sample alerts
python main.py --sample
```

---

## Common Issues

### Issue: "Port already in use"

**Solution:** Stop the conflicting service or change ports in `.env`:
```bash
# Check what's using the port
lsof -i :3000  # macOS/Linux
netstat -ano | findstr :3000  # Windows

# Stop services
./start-dev.sh stop
```

### Issue: "LLM API connection failed"

**Solution:** Check your API key:
```bash
# Verify .env has correct values
cat .env | grep LLM

# Test API key manually
curl -X POST https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"test"}]}'
```

### Issue: "Services not healthy"

**Solution:** Check logs:
```bash
./start-dev.sh logs

# Or check specific service
docker-compose -f docker-compose.dev.yml logs ai-triage-agent
```

---

## Next Steps

1. **Explore the Dashboard**: Navigate through different sections
2. **Submit Test Alerts**: Try different alert types (malware, phishing, brute_force)
3. **View Analysis Results**: Check how AI triages alerts
4. **Read Documentation**: Check [README.md](README.md) for detailed info

---

## Stopping the System

```bash
# Stop all services
./start-dev.sh stop

# View logs before stopping
./start-dev.sh logs

# Check service status
./start-dev.sh status
```

---

## Getting Help

- 📖 **Documentation**: [README.md](README.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourname/security-triage/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourname/security-triage/discussions)

---

**Congratulations! 🎉** You have the Security Alert Triage System running!
