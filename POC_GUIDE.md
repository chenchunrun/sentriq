# Security Alert Triage System - POC Quick Start Guide

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Docker Desktop installed and running
- 8GB RAM available
- Ports available: 5434, 6381, 5673, 9001-9005

### Start the System

```bash
# 1. Navigate to project directory
cd /Users/newmba/security

# 2. Start infrastructure services
docker-compose up -d postgres redis rabbitmq

# 3. Start core processing services
docker-compose up -d alert-ingestor alert-normalizer context-collector threat-intel-aggregator llm-router

# 4. Check all services are healthy
docker-compose ps
```

### Send Test Alerts

```bash
# Using curl
curl -X POST http://localhost:9001/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-'$(date +%s)'",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "alert_type": "malware",
    "severity": "critical",
    "title": "Test Alert",
    "description": "Testing the system",
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.1.10",
    "file_hash": "5d41402abc4b2a76b9719d911017c592",
    "asset_id": "SRV-PROD-001"
  }'
```

### View Results

**1. Web Dashboard**
```bash
# Start the active frontend service path
./start-dev.sh

# Then open in browser
open http://localhost:3000
```

**2. Database Query**
```bash
docker-compose exec postgres psql -U triage_user -d security_triage \
  -c "SELECT alert_id, alert_type, severity, status FROM alerts ORDER BY created_at DESC LIMIT 10;"
```

**3. Service Logs**
```bash
# Alert processing
docker-compose logs -f --tail=50 alert-ingestor

# Context enrichment
docker-compose logs -f --tail=50 context-collector

# Threat intelligence
docker-compose logs -f --tail=50 threat-intel-aggregator
```

---

## 📊 System Architecture (POC)

### Services Running

| Service | Port | Purpose |
|---------|------|---------|
| Alert Ingestor | 9001 | Receive alerts via REST API |
| Alert Normalizer | 9002 | Standardize alert formats |
| Context Collector | 9003 | Enrich with asset/user context |
| Threat Intel Aggregator | 9004 | Query IOC databases |
| LLM Router | 9005 | AI analysis (Mock mode) |
| PostgreSQL | 5434 | Persistent storage |
| Redis | 6381 | Cache layer |
| RabbitMQ | 5673, 15673 | Message queue |

### Data Flow

```
1. Alert → Alert Ingestor (REST API)
2. Ingestor → RabbitMQ (alert.raw queue)
3. Alert Normalizer (consumes alert.raw)
4. Normalizer → RabbitMQ (alert.normalized queue)
5. Context Collector + Threat Intel (consume alert.normalized)
6. Enriched data stored in PostgreSQL
```

---

## 🎯 Key Features (POC)

### ✅ Implemented
- **Alert Ingestion**: REST API with validation
- **Data Persistence**: PostgreSQL with 9 tables
- **Context Enrichment**: JSON-based asset/user lookup
- **Threat Intelligence**: Internal IOC database (7 IOCs)
- **LLM Integration**: Mock mode for development
- **Web Dashboard**: Active frontend lives in `services/web_dashboard/`
- **Message Queue**: RabbitMQ async processing

### 📁 Data Files (JSON-based)

**`data/assets.json`** - 5 sample assets
- 3 production servers
- 1 developer workstation
- 1 network firewall

**`data/users.json`** - 4 sample users
- Developer, Team Lead, Security Analyst, Data Engineer
- With roles, departments, behavior profiles

**`data/internal_iocs.json`** - 7 known IOCs
- 2 malicious IPs (botnet C2, compromised internal)
- 2 malicious hashes (ransomware, trojan)
- 1 malicious domain (C2 server)
- 1 malicious URL (phishing)
- 1 malicious email

---

## 🔧 Configuration

### Environment Variables (.env)

```bash
# Database
DATABASE_URL=postgresql+asyncpg://triage_user:triage_password_change_me@postgres:5432/security_triage

# LLM (Mock mode enabled for POC)
LLM_MOCK_MODE=true

# Optional: Configure real API keys
# VIRUSTOTAL_API_KEY=your_key_here
# ABUSECH_API_KEY=your_key_here
```

### Port Mapping

To avoid conflicts with other projects:
- PostgreSQL: 5434 (instead of 5432)
- Redis: 6381 (instead of 6379)
- RabbitMQ: 5673, 15673 (instead of 5672, 15672)

---

## 📈 Test Scenarios

### 1. Known Malware Hash (Critical)
```json
{
  "alert_id": "TEST-001",
  "alert_type": "malware",
  "severity": "critical",
  "file_hash": "5d41402abc4b2a76b9719d911017c592",  // Known malicious
  "asset_id": "SRV-PROD-001"
}
```
**Expected**: Detected by internal IOC database

### 2. Botnet C2 Communication (High)
```json
{
  "alert_id": "TEST-002",
  "alert_type": "brute_force",
  "severity": "high",
  "target_ip": "45.33.32.156",  // Known malicious IP
  "user_id": "john.doe@example.com"
}
```
**Expected**: IP flagged by internal IOCs

### 3. Normal Alert (Medium/Low)
```json
{
  "alert_id": "TEST-003",
  "alert_type": "anomaly",
  "severity": "medium",
  "description": "Unusual login time"
}
```
**Expected**: No threat intel match, enriched with context

---

## 🛠️ Troubleshooting

### Services not starting
```bash
# Check Docker daemon
docker ps

# Check logs
docker-compose logs [service-name]

# Restart specific service
docker-compose restart [service-name]
```

### Port conflicts
```bash
# Check what's using the port
lsof -i :9001

# Change ports in docker-compose.yml
```

### Database connection errors
```bash
# Verify PostgreSQL is healthy
docker-compose ps postgres

# Check database exists
docker-compose exec postgres psql -U triage_user -d security_triage -c "\dt"
```

---

## 📚 Next Steps (From POC to Production)

### Week 1: Real API Integration
- Configure VirusTotal API key
- Integrate Abuse.ch URLhaus API
- Add AliVault OTX for IP reputation

### Week 2: True CMDB/LDAP Integration
- Replace JSON files with real CMDB API
- Implement LDAP/AD user lookup
- Add GeoIP service integration

### Week 3: Advanced Features
- ChromaDB vector similarity search
- Temporal workflow orchestration
- JWT authentication and RBAC
- Production-ready Web Dashboard

### Week 4: Hardening & Testing
- Security audit and penetration testing
- Performance testing (1000+ alerts/min)
- Deploy to Kubernetes cluster
- Set up monitoring and alerting

---

## 📞 Support

**Documentation**:
- `/docs/README.md` - Architecture overview
- `/docs/02_functional_requirements.md` - Feature specifications
- `/standards/README.md` - Development standards

**Project Location**:
- GitHub: [repository URL]
- Issues: [issues URL]

**Quick Commands**:
```bash
# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Restart all services
docker-compose restart

# Clean restart
docker-compose down -v
docker-compose up -d
```

---

**POC Version**: v1.0
**Last Updated**: 2026-01-27
**Status**: ✅ Functional - Ready for testing
