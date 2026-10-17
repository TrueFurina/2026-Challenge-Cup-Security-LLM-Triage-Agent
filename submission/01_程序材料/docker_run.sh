#!/usr/bin/env bash
# XH-202609 Security-Agent 一键容器部署脚本
# 用法：bash docker_run.sh [端口，默认 8080]
set -e

PORT="${1:-8080}"
IMAGE="security-agent-xh202609:latest"

echo "==> 构建镜像 ${IMAGE}"
docker build -t "${IMAGE}" .

echo "==> 启动容器，映射宿主机 ${PORT} -> 容器 8080"
docker run -d --name security-agent-demo \
  -p "${PORT}:8080" \
  -e DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" \
  "${IMAGE}"

echo "==> 已启动。浏览器打开： http://127.0.0.1:${PORT}"
echo "==> 停止容器： docker stop security-agent-demo && docker rm security-agent-demo"
