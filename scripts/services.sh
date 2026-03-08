#!/bin/bash
# 统一服务管理脚本
# 解决进程管理混乱、端口冲突、启动顺序问题

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# PID文件目录
PID_DIR="$PROJECT_ROOT/.pids"
mkdir -p "$PID_DIR"

# 环境配置
ENV_FILE="$PROJECT_ROOT/.env.production"
if [ -f "$ENV_FILE" ]; then
    export $(cat "$ENV_FILE" | grep -v '^#' | xargs)
fi
export JWT_SECRET_KEY="dev-secret-key-min-32-chars-required-for-production"
export PYTHONPATH="$PROJECT_ROOT:$PROJECT_ROOT/services"

# 端口定义（根据PORT_ALLOCATION.md）
# 使用简单的变量代替关联数组，兼容bash 3.x
get_port() {
    case "$1" in
        api_gateway) echo "8000" ;;
        alert_ingestor) echo "8002" ;;
        ai_triage_agent) echo "8003" ;;
        similarity_search) echo "8004" ;;
        context_collector) echo "8005" ;;
        threat_intel) echo "8006" ;;
        workflow_engine) echo "8007" ;;
        automation_orchestrator) echo "8008" ;;
        web_dashboard) echo "9000" ;;
        *) echo "" ;;
    esac
}

# 服务列表
ALL_SERVICES="api_gateway alert_ingestor ai_triage_agent similarity_search context_collector threat_intel workflow_engine automation_orchestrator web_dashboard"

# 检查端口是否可用
check_port() {
    local port=$1
    if lsof -i :$port > /dev/null 2>&1; then
        return 1  # 端口被占用
    fi
    return 0  # 端口可用
}

# 等待端口释放
wait_for_port() {
    local port=$1
    local max_wait=10
    local count=0

    while ! check_port $port; do
        if [ $count -ge $max_wait ]; then
            log_error "端口 $port 仍然被占用"
            return 1
        fi
        sleep 1
        count=$((count + 1))
    done
    return 0
}

# 杀死服务进程
kill_service() {
    local service=$1
    local pid_file="$PID_DIR/$service.pid"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p $pid > /dev/null 2>&1; then
            log_info "停止 $service (PID: $pid)"
            kill -TERM $pid 2>/dev/null || true
            sleep 2
            # 如果还在运行，强制杀死
            if ps -p $pid > /dev/null 2>&1; then
                kill -KILL $pid 2>/dev/null || true
            fi
        fi
        rm -f "$pid_file"
    fi

    # 也通过进程名杀死（防止残留）
    case $service in
        web_dashboard)
            pkill -9 -f "python3.*web_dashboard" 2>/dev/null || true
            ;;
        api_gateway)
            pkill -9 -f "uvicorn.*api_gateway" 2>/dev/null || true
            ;;
        *)
            pkill -9 -f "python3.*$service" 2>/dev/null || true
            ;;
    esac
}

# 杀死所有服务
kill_all() {
    log_info "停止所有服务..."

    # 按相反顺序停止（依赖关系）
    for service in web_dashboard automation_orchestrator workflow_engine threat_intel context_collector similarity_search ai_triage_agent alert_ingestor api_gateway; do
        kill_service $service
    done

    sleep 2
    log_success "所有服务已停止"
}

# 启动单个服务
start_service() {
    local service=$1
    local port=$(get_port $service)
    local log_file="$PROJECT_ROOT/logs/$service.log"

    # 创建日志目录
    mkdir -p "$(dirname "$log_file")"

    # 检查端口
    if ! check_port $port; then
        log_warning "端口 $port 已被占用，等待释放..."
        if ! wait_for_port $port; then
            log_error "无法获取端口 $port，跳过 $service"
            return 1
        fi
    fi

    log_info "启动 $service (端口: $port)..."

    cd "$PROJECT_ROOT/services/$service"

    case $service in
        web_dashboard)
            PORT=$port python3 main.py > "$log_file" 2>&1 &
            ;;
        *)
            python3 -m uvicorn main:app --host 0.0.0.0 --port $port --log-level info > "$log_file" 2>&1 &
            ;;
    esac

    local pid=$!
    echo $pid > "$PID_DIR/$service.pid"

    # 等待服务启动
    sleep 2

    # 验证服务是否运行
    if ps -p $pid > /dev/null 2>&1; then
        log_success "$service 启动成功 (PID: $pid)"
    else
        log_error "$service 启动失败，查看日志: $log_file"
        return 1
    fi
}

# 启动所有服务
start_all() {
    log_info "启动所有服务..."

    # 基础设施服务检查
    log_info "检查基础设施服务..."

    if ! pg_isready -h localhost -p 5434 > /dev/null 2>&1; then
        log_warning "PostgreSQL未运行，请先启动: docker-compose -f docker-compose.simple.yml up -d postgres"
    fi

    if ! redis-cli -p 6381 ping > /dev/null 2>&1; then
        log_warning "Redis未运行，请先启动: docker-compose -f docker-compose.simple.yml up -d redis"
    fi

    if ! nc -z localhost 5673 2>/dev/null; then
        log_warning "RabbitMQ未运行，请先启动: docker-compose -f docker-compose.simple.yml up -d rabbitmq"
    fi

    echo ""

    # 按依赖顺序启动
    start_service "api_gateway"
    start_service "alert_ingestor"
    start_service "ai_triage_agent"
    start_service "similarity_search"
    start_service "context_collector"
    start_service "threat_intel"
    start_service "workflow_engine"
    start_service "automation_orchestrator"
    start_service "web_dashboard"

    echo ""
    log_success "所有服务启动完成！"
    show_status
}

# 显示服务状态
show_status() {
    echo ""
    echo "=========================================="
    echo "  服务状态"
    echo "=========================================="

    for service in $ALL_SERVICES; do
        local port=$(get_port $service)
        local pid_file="$PID_DIR/$service.pid"
        local status="❌"

        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if ps -p $pid > /dev/null 2>&1; then
                if curl -s http://localhost:$port/health > /dev/null 2>&1; then
                    status="✅"
                else
                    status="⚠️ "
                fi
            fi
        fi

        printf "%-25s %-6s %5s\n" "$service" "$status" "$port"
    done

    echo ""
    echo "=========================================="
    echo "  访问地址"
    echo "=========================================="
    echo "Web Dashboard:    http://localhost:9000"
    echo "API Gateway:      http://localhost:8000"
    echo "API Docs:         http://localhost:8000/docs"
    echo "RabbitMQ UI:      http://localhost:15673"
    echo "=========================================="
}

# 显示日志
show_logs() {
    local service=$1
    local log_file="$PROJECT_ROOT/logs/$service.log"

    if [ -z "$service" ]; then
        log_error "请指定服务名称"
        echo "可用服务: $ALL_SERVICES"
        return 1
    fi

    if [ ! -f "$log_file" ]; then
        log_error "日志文件不存在: $log_file"
        return 1
    fi

    tail -f "$log_file"
}

# 主函数
main() {
    case "${1:-help}" in
        start)
            if [ -n "$2" ]; then
                start_service "$2"
            else
                start_all
            fi
            ;;
        stop)
            if [ -n "$2" ]; then
                kill_service "$2"
            else
                kill_all
            fi
            ;;
        restart)
            if [ -n "$2" ]; then
                kill_service "$2"
                sleep 1
                start_service "$2"
            else
                kill_all
                sleep 2
                start_all
            fi
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs "$2"
            ;;
        build)
            bash "$SCRIPT_DIR/build-frontend.sh"
            ;;
        *)
            cat << EOF
使用方法:
    $0 <command> [service]

命令:
    start [service]  启动服务（不指定则启动所有）
    stop [service]   停止服务（不指定则停止所有）
    restart [service] 重启服务
    status          显示服务状态
    logs <service>  查看服务日志
    build           构建前端

可用服务:
    $ALL_SERVICES

示例:
    $0 start                    # 启动所有服务
    $0 start web_dashboard      # 只启动Web Dashboard
    $0 stop                     # 停止所有服务
    $0 restart api_gateway      # 重启API Gateway
    $0 logs web_dashboard       # 查看Web Dashboard日志
    $0 status                   # 查看所有服务状态
EOF
            ;;
    esac
}

main "$@"
