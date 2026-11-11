#!/bin/bash

# switchlog 镜像构建
#   ./docker/app_build.sh [tag]      tag 默认 v1

set -e

IMAGE_NAME="switchlog"
IMAGE_TAG="${1:-v1}"
DOCKERFILE_PATH="docker/Dockerfile"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cd "$(dirname "$0")/.."

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  switchlog 镜像构建${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}镜像:${NC} ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

if [ ! -f "${DOCKERFILE_PATH}" ]; then
    echo -e "${RED}错误: Dockerfile 不存在: ${DOCKERFILE_PATH}${NC}"
    exit 1
fi

echo -e "${YELLOW}检查必要文件...${NC}"
required_files=(
    "requirements.txt"
    "main.py"
    "config/config.py"
    "pipeline/runner.py"
    "db/database.py"
    "utils/logger.py"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}错误: $file 不存在${NC}"
        if [ "$file" = "config/config.py" ]; then
            echo -e "${YELLOW}  从模板创建: cp config/config_example.py config/config.py${NC}"
        fi
        exit 1
    fi
    echo -e "${GREEN}✓${NC} $file"
done
echo ""

echo -e "${GREEN}开始构建...${NC}"
docker build \
    --no-cache \
    --pull \
    -f "${DOCKERFILE_PATH}" \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -t "${IMAGE_NAME}:latest" \
    .

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  构建成功${NC}"
echo -e "${GREEN}========================================${NC}"
docker images | grep "${IMAGE_NAME}" | head -2
echo ""
echo -e "${YELLOW}启动容器:${NC} ${GREEN}./docker/app_start.sh${NC}"
echo ""
