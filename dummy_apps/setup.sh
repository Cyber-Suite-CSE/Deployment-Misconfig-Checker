#!/usr/bin/env bash
# Minimal vulnerable WP lab - dynamically installs plugins from vulnerable_plugins.txt
# Usage:
#   ./setup.sh          # normal run
#   ./setup.sh --reset  # stop & delete volumes (fresh DB/files)

set -euo pipefail

# ---- config ----
PORT="${PORT:-31337}"
IMG_NAME="vuln-wordpress"
COMPOSE_FILE="docker-compose.yml"
PLUGINS_DIR="wp-content/plugins"
PLUGINS_LIST="vulnerable_plugins.txt"
# ---------------

YEL='\033[1;33m'; GRN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

if [[ "${1:-}" == "--reset" ]]; then
  echo -e "${YEL}Reset requested: stopping and deleting volumes...${NC}"
  docker compose down -v || true
fi

# 1) Fetch and install vulnerable plugins from file
echo -e "${YEL}Installing vulnerable plugins from ${PLUGINS_LIST}...${NC}"
mkdir -p "${PLUGINS_DIR}"

if [[ ! -f "${PLUGINS_LIST}" ]]; then
  echo -e "${RED}Error: ${PLUGINS_LIST} not found${NC}"
  exit 1
fi

while IFS='|' read -r plugin_name version download_url cve_id; do
  # Skip comments and empty lines
  [[ "$plugin_name" =~ ^#.*$ ]] && continue
  [[ -z "$plugin_name" ]] && continue
  
  zip_name="${plugin_name}-${version}.zip"
  
  echo -e "${YEL}Fetching ${plugin_name} (v${version}) - ${cve_id}...${NC}"
  curl -fSL "$download_url" -o "${PLUGINS_DIR}/${zip_name}"
  
  echo -e "${YEL}Extracting ${zip_name}...${NC}"
  unzip -o -q "${PLUGINS_DIR}/${zip_name}" -d "${PLUGINS_DIR}"
  
  rm -f "${PLUGINS_DIR}/${zip_name}"

  echo -e "${GRN}✓ ${plugin_name} v${version} installed (${cve_id})${NC}"
done < "${PLUGINS_LIST}"

# 2) Build and start containers
echo -e "${YEL}Building WordPress image...${NC}"
docker build -t "${IMG_NAME}:latest" .

echo -e "${YEL}Starting containers...${NC}"
docker compose up -d

# 3) Done — finish in browser
cat <<EOF

${GRN}Up and running!${NC}

Open WordPress installer:
  http://localhost:${PORT}

Database (auto-configured):
  host: db
  name: wordpress
  user: wordpress
  pass: wordpress

Then in WP Admin:
  Go to Plugins and activate the vulnerable plugins.

Common ops:
  Stop stack:      docker compose down
  Reset (wipe DB): ./setup.sh --reset

${RED}WARNING:${NC} This lab is intentionally vulnerable. Do NOT expose it to the internet.
EOF