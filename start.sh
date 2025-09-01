#!/usr/bin/env bash
set -euo pipefail

# Colors for pretty output
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

# Directories
BASE_DIR="$HOME/docker-elk"
MISP_DIR="$BASE_DIR/misp-docker"
OPENCTI_DIR="$BASE_DIR/opencti-docker"

# Check if in correct directory
if [[ "$(pwd)" != "$BASE_DIR" ]]; then
  echo -e "${RED}[ERROR]${RESET} Please run this script from: ${YELLOW}$BASE_DIR${RESET}"
  exit 1
fi

# Function to stop all stacks safely
cleanup() {
  echo -e "\n${YELLOW}[INFO] Shutting down all stacks...${RESET}"
  (cd "$OPENCTI_DIR" && docker compose down)
  (cd "$MISP_DIR" && docker compose down)
  (cd "$BASE_DIR" && docker compose down)
  echo -e "${GREEN}[OK] All stacks stopped safely.${RESET}"
  exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT

# Start docker-elk
echo -e "${YELLOW}[INFO] Starting docker-elk stack...${RESET}"
docker compose up -d
echo -e "${GREEN}[OK] docker-elk is up!${RESET}"

# Start misp-docker
echo -e "${YELLOW}[INFO] Starting misp-docker stack...${RESET}"
(cd "$MISP_DIR" && docker compose up -d)
echo -e "${GREEN}[OK] misp-docker is up!${RESET}"

# Start opencti-docker
echo -e "${YELLOW}[INFO] Starting opencti-docker stack...${RESET}"
(cd "$OPENCTI_DIR" && docker compose up -d)
echo -e "${GREEN}[OK] opencti-docker is up!${RESET}"

# Keep script running until Ctrl+C
echo -e "${YELLOW}[INFO] All stacks are running in detached mode.${RESET}"
echo -e "${YELLOW}[INFO] Press Ctrl+C to stop them safely.${RESET}"

# Infinite wait (until Ctrl+C)
while true; do
  sleep 1
done
