#!/bin/bash

# switchlog 日志查看与排查

set -e

CONTAINER_NAME="switchlog"
DATA_BASE_DIR="${SWITCHLOG_DATA_DIR:-$(pwd)}"
LOGS_DIR="${DATA_BASE_DIR}/logs"
LOG_FILE="${LOGS_DIR}/switchlog.log"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

show_help() {
    echo -e "${GREEN}switchlog 日志工具${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  follow, -f        实时跟踪容器日志（默认）"
    echo "  tail [N]          最后 N 行（默认 100）"
    echo "  app               实时跟踪应用日志文件"
    echo "  stats             只看统计行，判断收包和丢弃情况"
    echo "  gap               统计 UNKNOWN_MNEMONIC，看哪些规则该补"
    echo "  error             错误与警告"
    echo "  search [关键字]   搜索日志"
    echo "  selftest          容器内跑一次连库自检"
    echo "  health            容器状态与最近日志"
    echo "  clear             清空应用日志文件"
    echo "  help, -h          本帮助"
    echo ""
}

check_container() {
    if ! docker ps | grep -q "${CONTAINER_NAME}"; then
        echo -e "${RED}错误: 容器 ${CONTAINER_NAME} 未运行${NC}"
        echo -e "${YELLOW}提示: ./docker/app_start.sh${NC}"
        exit 1
    fi
}

follow_docker_logs() {
    check_container
    echo -e "${GREEN}实时跟踪容器日志 (Ctrl+C 退出)${NC}"
    echo ""
    docker logs -f "${CONTAINER_NAME}"
}

tail_docker_logs() {
    local lines=${1:-100}
    check_container
    docker logs --tail "${lines}" "${CONTAINER_NAME}"
}

tail_app_log() {
    if [ ! -f "${LOG_FILE}" ]; then
        echo -e "${YELLOW}应用日志文件还没生成: ${LOG_FILE}${NC}"
        echo -e "${YELLOW}改看容器日志...${NC}"
        echo ""
        follow_docker_logs
        return
    fi
    echo -e "${GREEN}实时跟踪 ${LOG_FILE} (Ctrl+C 退出)${NC}"
    echo ""
    tail -f "${LOG_FILE}"
}

# 统计行形如：统计 60s：收 1200（20/s），解析 1150，规则缺口 30
show_stats() {
    check_container
    echo -e "${GREEN}收包与处理统计${NC}"
    echo ""
    docker logs "${CONTAINER_NAME}" 2>&1 | grep -E "统计 |队列满丢弃" --color=always | tail -30
    echo ""
    echo -e "${YELLOW}丢弃非零说明 worker 跟不上收包速度，调大 config.workers 或 queue_size${NC}"
}

# 规则缺口：UNKNOWN_MNEMONIC 高频项就是下一批该补的规则
show_gap() {
    check_container
    echo -e "${GREEN}规则缺口 Top 20（UNKNOWN_MNEMONIC）${NC}"
    echo ""
    docker logs "${CONTAINER_NAME}" 2>&1 \
        | grep "UNKNOWN_MNEMONIC" \
        | awk '{print $5, $6}' \
        | sort | uniq -c | sort -rn | head -20
    echo ""
    echo -e "${YELLOW}左边是条数，右边是设备名和事件码。补规则时 vendor 抄这台设备的值${NC}"
}

show_error_logs() {
    check_container
    docker logs "${CONTAINER_NAME}" 2>&1 \
        | grep -iE "error|exception|traceback|warning" --color=always | tail -50
}

search_logs() {
    local keyword="$1"
    if [ -z "$keyword" ]; then
        echo -e "${RED}错误: 请提供搜索关键字${NC}"
        exit 1
    fi
    check_container
    docker logs "${CONTAINER_NAME}" 2>&1 | grep -i "${keyword}" --color=always
}

run_selftest() {
    check_container
    echo -e "${GREEN}容器内连库自检${NC}"
    echo ""
    docker exec "${CONTAINER_NAME}" python3 main.py --selftest
}

check_health() {
    check_container
    echo -e "${YELLOW}1. 容器状态${NC}"
    docker ps | grep "${CONTAINER_NAME}"
    echo ""

    echo -e "${YELLOW}2. 健康检查${NC}"
    health_status=$(docker inspect --format='{{.State.Health.Status}}' \
        "${CONTAINER_NAME}" 2>/dev/null || echo "unknown")
    if [ "$health_status" = "healthy" ]; then
        echo -e "${GREEN}✓ ${health_status}${NC}"
    else
        echo -e "${YELLOW}⚠ ${health_status}${NC}"
    fi
    echo ""

    echo -e "${YELLOW}3. UDP 端口监听${NC}"
    docker exec "${CONTAINER_NAME}" sh -c \
        "cat /proc/net/udp 2>/dev/null | awk 'NR>1 {print \$2}' | head -5" \
        || echo -e "${YELLOW}容器内没有查看工具${NC}"
    echo ""

    echo -e "${YELLOW}4. 最近统计${NC}"
    docker logs "${CONTAINER_NAME}" 2>&1 | grep "统计 " | tail -3
    echo ""

    echo -e "${YELLOW}5. 最近日志${NC}"
    docker logs --tail 10 "${CONTAINER_NAME}"
    echo ""
}

clear_logs() {
    echo -e "${YELLOW}确认清空 ${LOGS_DIR} 下的日志文件? (y/N)${NC}"
    read -r confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -f "${LOGS_DIR}"/*.log*
        echo -e "${GREEN}✓ 已清空${NC}"
    else
        echo -e "${YELLOW}已取消${NC}"
    fi
}

case "${1:-follow}" in
    follow|-f)   follow_docker_logs ;;
    tail)        tail_docker_logs "$2" ;;
    app)         tail_app_log ;;
    stats)       show_stats ;;
    gap)         show_gap ;;
    error)       show_error_logs ;;
    search)      search_logs "$2" ;;
    selftest)    run_selftest ;;
    health)      check_health ;;
    clear)       clear_logs ;;
    help|-h|--help) show_help ;;
    *)
        echo -e "${RED}未知选项: $1${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
