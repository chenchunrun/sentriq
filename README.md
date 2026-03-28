# 🔒 Security Alert Triage System

> AI-Powered Security Alert Analysis and Triage Platform

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-green.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![LLM](https://img.shields.io/badge/LLM-OpenAI%20Compatible-orange.svg)](https://platform.openai.com/)

**Security Alert Triage System** is an intelligent security operations platform that uses Large Language Models (LLMs) to automatically analyze, triage, and prioritize security alerts. It combines threat intelligence, contextual analysis, and AI-powered risk assessment to help security teams respond faster and more effectively.

---

## ✨ Key Features

### 🤖 AI-Powered Analysis
- **Intelligent Triage**: Uses LLMs to understand alert context and assess risk
- **Multi-LLM Support**: Works with Qwen, OpenAI, DeepSeek, and any OpenAI-compatible API
- **Natural Language Reports**: Generates human-readable analysis and recommendations

### 🔍 Threat Intelligence Integration
- **IOC Enrichment**: Automatically queries threat intelligence databases
- **Historical Matching**: Vector similarity search to find related past incidents
- **Risk Scoring**: Weighted risk assessment based on multiple factors

### 🏗️ Microservices Architecture
- **15 Production Services**: Scalable, distributed system design
- **Async Message-Driven**: RabbitMQ for reliable message processing
- **Multi-level Caching**: Redis for optimal performance

### 📊 Real-time Dashboard
- **React Web UI**: Modern, responsive interface
- **Live Metrics**: Real-time alert processing statistics
- **Workflow Management**: Track remediation actions

---

## 🚀 Quick Start

### Prerequisites

- **Docker** 20.10+ and **Docker Compose** 2.0+
- **LLM API Key** (Qwen, OpenAI, or compatible)

### Quick Startup

```bash
# Clone the repository
git clone https://github.com/chenchunrun/sentriq.git
cd sentriq

# Configure your LLM API key
cp .env.docker.example .env
# Edit .env and set LLM_API_KEY

# Start the current POC stack
docker compose -f docker-compose.dev.yml up -d
```

That's it! The system will:
1. Pull and build required images
2. Start infrastructure and core services
3. Expose the dashboard and service endpoints

**Access the Dashboard**: http://localhost:3000

To stop the stack:

```bash
docker compose -f docker-compose.dev.yml down
```

To start the full compose graph instead:

```bash
docker compose up -d
```

---

## 📁 Project Structure

```
security-triage/
├── services/                    # Microservices (15 services)
│   ├── alert_ingestor/         # Alert ingestion (REST, webhook, syslog)
│   ├── alert_normalizer/       # Alert standardization
│   ├── context_collector/      # Context enrichment
│   ├── threat_intel_aggregator/# Threat intelligence aggregation
│   ├── ai_triage_agent/        # AI analysis engine
│   ├── llm_router/             # Intelligent LLM routing
│   ├── similarity_search/      # Vector similarity search
│   ├── workflow_engine/        # Temporal workflow orchestration
│   ├── automation_orchestrator/# SOAR playbook execution
│   ├── api_gateway/            # Kong API Gateway
│   ├── notification_service/   # Multi-channel notifications
│   ├── user_management/        # RBAC and authentication
│   ├── reporting_service/      # Report generation
│   ├── data_analytics/         # Analytics processing
│   └── web_dashboard/          # React frontend (active path inside services/)
├── shared/                      # Shared libraries
│   ├── models/                 # Pydantic data models
│   ├── database/               # Database utilities
│   ├── messaging/              # RabbitMQ utilities
│   └── auth/                   # JWT authentication
├── docker-compose.yml           # Full production setup (15 services)
├── docker-compose.dev.yml       # Development setup (8 core services)
├── src/                         # Prototype/CLI version
├── docs/                        # Minimal public docs index
├── tests/                       # Test suite
└── services/web_dashboard/      # Active frontend
```

---

## 🎯 Usage Examples

### Example 1: Submit an Alert via API

```bash
curl -X POST http://localhost:9001/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "ALT-001",
    "timestamp": "2025-01-04T12:00:00Z",
    "alert_type": "malware",
    "severity": "high",
    "source_ip": "45.33.32.156",
    "target_ip": "10.0.0.50",
    "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "description": "Suspicious file execution detected"
  }'
```

### Example 2: Using the CLI (Prototype)

```bash
# Install dependencies
pip install -r requirements.txt

# Configure LLM API
cp .env.example .env
# Edit .env with your LLM_API_KEY

# Process sample alerts
python main.py --sample

# Interactive mode
python main.py --interactive

# Batch processing
python main.py --file data/sample_alerts.json
```

---

## 🔧 Configuration

### LLM API Setup

The system supports any OpenAI-compatible API:

#### Option 1: Qwen (通义千问) - Recommended for China
```bash
LLM_API_KEY=sk-your-qwen-api-key
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
```
Get your key: https://bailian.console.aliyun.com/

#### Option 2: OpenAI
```bash
LLM_API_KEY=sk-your-openai-api-key
LLM_BASE_URL=
```

#### Option 3: DeepSeek
```bash
LLM_API_KEY=sk-your-deepseek-api-key
LLM_BASE_URL=https://api.deepseek.com/v1
```

Additional startup notes are in [CURRENT_STARTUP_GUIDE.md](/Users/newmba/security/CURRENT_STARTUP_GUIDE.md).
                │
        ┌───────▼─────────────────────┐
        │      AI Triage Agent         │◄─────────┐
        └───────┬─────────────────────┘          │
                │                                │
        ┌───────▼─────────────────────┐   ┌──────▼──────┐
        │   Similarity Search          │───│  LLM Router  │
        └───────┬─────────────────────┘   └─────────────┘
                │
        ┌───────▼─────────────────────┐
        │     Workflow Engine          │
        └───────┬─────────────────────┘
                │
        ┌───────▼─────────────────────┐
        │ Automation Orchestrator      │
        └───────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11+, FastAPI, LangChain, Pydantic v2 |
| **Data** | PostgreSQL 15, Redis Cluster, RabbitMQ 3.12, ChromaDB |
| **AI/ML** | OpenAI-compatible APIs (Qwen, DeepSeek, etc.) |
| **Frontend** | React 18, TypeScript, Tailwind CSS |
| **DevOps** | Docker, Kubernetes (optional), Prometheus, Grafana |

---

## 📊 Output Example

```
================================================================================
🚨 SECURITY ALERT RECEIVED
================================================================================
Alert ID:        ALT-2025-001
Timestamp:       2025-01-04T12:00:00Z
Type:            malware
Severity:        HIGH
Source IP:       45.33.32.156
Target IP:       10.0.0.50
Description:     Detected suspicious file execution
File Hash:       5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
================================================================================

================================================================================
📊 TRIAGE ANALYSIS RESULT
================================================================================

🎯 RISK ASSESSMENT:
   Risk Score:      75.5/100
   Risk Level:      HIGH
   Confidence:      75.0%
   Key Factors:
      • Severity: high
      • Asset Criticality: high
      • Threat Intel Score: 7.0/10

🔍 THREAT INTELLIGENCE:
   • IOC: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
     Type: hash
     Threat Level: high
     ⚠️  MALICIOUS

🛠️  REMEDIATION ACTIONS:
   1. [IMMEDIATE] Isolate affected host (🤖 AUTO)
   2. [IMMEDIATE] Block malicious IP (🤖 AUTO)
   3. [HIGH] Initiate incident response (👤 MANUAL)
      Owner: Security Team

📋 ADDITIONAL INFO:
   Processing Time:  2.34 seconds
   Human Review:     ⚠️  REQUIRED
   Analysis Time:    2025-01-04 12:00:05

================================================================================
✅ ANALYSIS COMPLETED
================================================================================
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test types
pytest tests/ -m unit          # Unit tests only
pytest tests/ -m integration   # Integration tests
pytest tests/ -m e2e           # End-to-end tests

# Run with coverage
pytest tests/ --cov=services --cov-report=html

# Skip tests requiring external services
pytest tests/ -m "not requires_network"
```

---

## 📈 Development Roadmap

### ✅ Phase 1: MVP (Current)
- [x] Prototype system (CLI-based)
- [x] Microservices architecture (15 services)
- [x] Web dashboard
- [x] Docker deployment

### 🔄 Phase 2: Enhanced Features (In Progress)
- [ ] Real threat intelligence API integration
- [ ] Multi-tenancy support
- [ ] Advanced analytics with MITRE ATT&CK
- [ ] Performance optimization

### 📋 Phase 3: Production Ready
- [ ] Kubernetes deployment manifests
- [ ] High availability configuration
- [ ] Security hardening
- [ ] Comprehensive monitoring

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Code formatting
black services/
isort services/

# Type checking
mypy services/
```

---

## 📖 Documentation

- **[Development Roadmap](docs/DEVELOPMENT_ROADMAP.md)** - 🎯 Project status and development plan
- **[Architecture Overview](docs/01_architecture_overview.md)** - System design and architecture
- **[API Documentation](docs/05_api_design.md)** - REST API specifications
- **[Development Standards](standards/README.md)** - Coding standards and best practices
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment instructions
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

---

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **LangChain** - AI agent framework
- **FastAPI** - Modern Python web framework
- **Qwen (通义千问)** - LLM provider
- **OpenAI** - GPT models

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourname/security-triage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourname/security-triage/discussions)
- **Email**: your-email@example.com

---

<p align="center">
  <b>⭐ Star this repo if it helped you!</b>
</p>
