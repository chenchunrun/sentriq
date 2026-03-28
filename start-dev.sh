#!/bin/bash
# =============================================================================
# Security Triage System - Quick Start Script
# =============================================================================
# One-command startup for development environment
#
# Usage:
#   ./start-dev.sh          # Start development mode
#   ./start-dev.sh prod     # Start production mode (all services)
#   ./start-dev.sh stop     # Stop all services
#   ./start-dev.sh logs     # View logs
#   ./start-dev.sh status   # Check service status
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MODE=${1:-dev}
COMPOSE_FILE="docker-compose.dev.yml"
PROJECT_NAME="security-triage"
WEB_DASHBOARD_URL="http://localhost:3000"

# Helper functions
print_header() {
    echo -e "${BLUE}=============================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}=============================================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    print_success "Docker is installed"

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    print_success "Docker Compose is installed"

    # Check .env file
    if [ ! -f .env ]; then
        print_warning ".env file not found. Creating from .env.example..."
        cp .env.example .env
        print_warning "Please edit .env file with your API keys and configuration"
        print_warning "Especially set LLM_API_KEY for the system to work properly"
    else
        print_success ".env file exists"
    fi

    echo ""
}

# Stop all services
stop_services() {
    print_header "Stopping Services"

    if [ -f "docker-compose.dev.yml" ]; then
        docker-compose -f docker-compose.dev.yml down --remove-orphans
        print_success "Development services stopped"
    fi

    if [ -f "docker-compose.yml" ]; then
        docker-compose -f docker-compose.yml down --remove-orphans
        print_success "Production services stopped"
    fi

    echo ""
}

# View logs
view_logs() {
    print_header "Viewing Logs"
    docker-compose -f "$COMPOSE_FILE" logs -f --tail=100
}

# Check service status
check_status() {
    print_header "Service Status"
    docker-compose -f "$COMPOSE_FILE" ps
    echo ""

    print_header "Health Checks"
    echo "Checking service health endpoints..."
    echo ""

    # Check if services are responding
    services=(
        "postgres:5434"
        "redis:6381"
        "rabbitmq:5673"
        "alert-ingestor:9001"
        "alert-normalizer:9002"
        "context-collector:9003"
        "ai-triage-agent:9006"
    )

    if [ "$MODE" = "prod" ]; then
        services+=("web-dashboard:3100")
    else
        services+=("web-dashboard:3000")
    fi

    for service in "${services[@]}"; do
        name=$(echo $service | cut -d: -f1)
        port=$(echo $service | cut -d: -f2)

        if nc -z localhost $port 2>/dev/null; then
            print_success "$name is running on port $port"
        else
            print_error "$name is not responding on port $port"
        fi
    done

    echo ""
    print_header "Access URLs"
    echo "  Web Dashboard:    $WEB_DASHBOARD_URL"
    echo "  RabbitMQ UI:      http://localhost:15673 (admin/rabbitmq_password)"
    echo "  Alert Ingestor:   http://localhost:9001"
    echo "  AI Triage Agent:  http://localhost:9006"
    echo ""
}

# Start services
start_services() {
    print_header "Starting Security Triage System"
    echo "Mode: $MODE"
    echo ""

    # Select compose file
    if [ "$MODE" = "prod" ]; then
        COMPOSE_FILE="docker-compose.yml"
        WEB_DASHBOARD_URL="http://localhost:3100"
        print_warning "Starting in PRODUCTION mode (all 15 services)"
        print_warning "This will use significant system resources"
    else
        COMPOSE_FILE="docker-compose.dev.yml"
        WEB_DASHBOARD_URL="http://localhost:3000"
        print_success "Starting in DEVELOPMENT mode (core services only)"
    fi
    echo ""

    # Pull latest images
    print_header "Pulling Docker Images"
    docker-compose -f "$COMPOSE_FILE" pull
    echo ""

    # Build services
    print_header "Building Services"
    docker-compose -f "$COMPOSE_FILE" build --parallel
    echo ""

    # Start services
    print_header "Starting Services"
    docker-compose -f "$COMPOSE_FILE" up -d
    echo ""

    # Wait for services to be healthy
    print_header "Waiting for Services to Start"
    echo "This may take 30-60 seconds..."
    echo ""

    max_attempts=30
    attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # Check if core services are healthy
        healthy=true

        # Check PostgreSQL
        if ! docker-compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U triage_user &> /dev/null; then
            healthy=false
        fi

        # Check Redis
        if ! docker-compose -f "$COMPOSE_FILE" exec -T redis redis-cli ping &> /dev/null; then
            healthy=false
        fi

        if [ "$healthy" = true ]; then
            print_success "Core services are healthy!"
            break
        fi

        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done

    echo ""

    if [ $attempt -eq $max_attempts ]; then
        print_error "Services failed to start within expected time"
        print_warning "Check logs with: ./start-dev.sh logs"
        exit 1
    fi

    echo ""
    print_success "System started successfully!"
    echo ""

    # Show status
    sleep 5
    check_status

    print_header "Next Steps"
    echo "1. Open $WEB_DASHBOARD_URL in your browser"
    echo "2. View logs: ./start-dev.sh logs"
    echo "3. Check status: ./start-dev.sh status"
    echo "4. Stop services: ./start-dev.sh stop"
    echo ""
}

# Main script
main() {
    case $MODE in
        stop)
            stop_services
            ;;
        logs)
            view_logs
            ;;
        status)
            check_status
            ;;
        *)
            check_prerequisites
            stop_services
            start_services
            ;;
    esac
}

# Run main function
main
