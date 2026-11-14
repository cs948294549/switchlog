#!/bin/bash

# switchlog 容器启动
#   ./docker/app_start.sh [tag] [宿主机UDP端口]
#
# 默认把宿主机 514/udp 映射进容器。514 是特权端口，容器内要有
# NET_BIND_SERVICE 才能 bind，脚本已经加了 --cap-add。
# 不想用特权端口的话传第二个参数（如 5514），同时改 config.listen_port
# 并在设备侧配 logging port。

set -e

CONTAINER_NAME="switchlog"
IMAGE_NAME="switchlog"
IMAGE_TAG="${1:-v1}"
HOST_PORT="${2:-5514}"
CONTAINER_PORT="5514"
# 和 central-server / network_bot 共用的网络，容器间可用容器名互访
DOCKER_NETWORK="${DOCKER_NETWORK:-netops}"

DATA_BASE_DIR="${SWITCHLOG_DATA_DIR:-$(pwd)}"
LOGS_DIR="${DATA_BASE_DIR}/logs"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cd "$(dirname "$0")/.."

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  switchlog 容器启动${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}容器:${NC} ${CONTAINER_NAME}"
echo -e "${YELLOW}镜像:${NC} ${IMAGE_NAME}:${IMAGE_TAG}"
echo -e "${YELLOW}端口:${NC} ${HOST_PORT}:${CONTAINER_PORT}/udp"
echo -e "${YELLOW}网络:${NC} ${DOCKER_NETWORK}"
echo ""

if ! docker images | grep -q "${IMAGE_NAME}.*${IMAGE_TAG}"; then
    echo -e "${RED}错误: 镜像 ${IMAGE_NAME}:${IMAGE_TAG} 不存在${NC}"
    echo -e "${YELLOW}请先构建:${NC} ./docker/app_build.sh"
    exit 1
fi

if [ ! -f "config/config.py" ]; then
    echo -e "${RED}错误: config/config.py 不存在${NC}"
    echo -e "${YELLOW}从模板创建并填好数据库口令:${NC}"
    echo -e "  cp config/config_example.py config/config.py"
    exit 1
fi

if docker ps -a | grep -q "${CONTAINER_NAME}"; then
    echo -e "${YELLOW}清理已存在的容器...${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    echo -e "${GREEN}✓${NC} 旧容器已清理"
    echo ""
fi

if ! docker network inspect "${DOCKER_NETWORK}" >/dev/null 2>&1; then
    echo -e "${YELLOW}创建 Docker 网络 ${DOCKER_NETWORK}...${NC}"
    docker network create "${DOCKER_NETWORK}"
    echo -e "${GREEN}✓${NC} 网络已创建"
    echo ""
fi

mkdir -p "${LOGS_DIR}"
echo -e "${GREEN}✓${NC} 日志目录: ${LOGS_DIR}"
echo ""

echo -e "${GREEN}启动容器...${NC}"
docker run -d \
    --name "${CONTAINER_NAME}" \
    --network "${DOCKER_NETWORK}" \
    -p ${HOST_PORT}:${CONTAINER_PORT}/udp \
    --cap-add=NET_BIND_SERVICE \
    -e PYTHONUNBUFFERED=1 \
    -v "${LOGS_DIR}:/app/logs" \
    -v "$(pwd)/config/config.py:/app/config/config.py:ro" \
    --restart unless-stopped \
    --health-cmd="ps aux | grep -v grep | grep -q 'python.*main.py' || exit 1" \
    --health-interval=60s \
    --health-timeout=10s \
    --health-retries=3 \
    "${IMAGE_NAME}:${IMAGE_TAG}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  启动成功${NC}"
echo -e "${GREEN}========================================${NC}"
docker ps | grep "${CONTAINER_NAME}"
echo ""
echo -e "${YELLOW}常用命令:${NC}"
echo -e "  查看日志:   ${GREEN}docker logs -f ${CONTAINER_NAME}${NC}"
echo -e "  应用日志:   ${GREEN}tail -f ${LOGS_DIR}/switchlog.log${NC}"
echo -e "  连库自检:   ${GREEN}docker exec ${CONTAINER_NAME} python3 main.py --selftest${NC}"
echo -e "  停止:       ${GREEN}docker stop ${CONTAINER_NAME}${NC}"
echo -e "  进入容器:   ${GREEN}docker exec -it ${CONTAINER_NAME} bash${NC}"
echo ""
echo -e "${YELLOW}发一条测试日志验证链路:${NC}"
echo -e "  ${GREEN}logger -n 127.0.0.1 -P ${HOST_PORT} -d \\${NC}"
echo -e "  ${GREEN}  \"<189>Nov 11 09:00:00 sw %ETHPORT-5-IF_DOWN: Interface Ethernet1/1, changed state to down\"${NC}"
echo ""

echo -e "${YELLOW}等待服务启动...${NC}"
sleep 3
docker logs --tail 20 "${CONTAINER_NAME}"
echo ""
