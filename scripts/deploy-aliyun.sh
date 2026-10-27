#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/mcp-stack/apps/phosphene
DATA_DIR=/opt/mcp-stack/data/phosphene
SERVICE_DIR=/opt/mcp-stack/services/phosphene
CADDYFILE=/opt/mcp-stack/proxy/Caddyfile
DOMAIN=phosphene.xunzhou.space
REPOSITORY=https://github.com/d843636758-ui/Phosphene.git

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root (sudo)." >&2
  exit 1
fi

for command in docker git openssl python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 1
  }
done

docker network inspect mcp-edge >/dev/null 2>&1 || {
  echo "Docker network mcp-edge does not exist." >&2
  exit 1
}

mkdir -p "$(dirname "$APP_DIR")" "$DATA_DIR" "$SERVICE_DIR"
chmod 700 "$DATA_DIR" "$SERVICE_DIR"

if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  if [ -e "$APP_DIR" ] && [ "$(find "$APP_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "$APP_DIR exists and is not a Phosphene git checkout; refusing to overwrite it." >&2
    exit 1
  fi
  rmdir "$APP_DIR" 2>/dev/null || true
  git clone --depth 1 "$REPOSITORY" "$APP_DIR"
fi

if [ ! -f "$DATA_DIR/phosphene.sqlite" ] && [ "${ALLOW_EMPTY_PHOSPHENE_DATA:-0}" != "1" ]; then
  cat >&2 <<EOF
No migrated Phosphene database was found at:
  $DATA_DIR/phosphene.sqlite

Copy the complete Zeabur /data volume here before deploying, including any
SQLite WAL/SHM files and uploads. To intentionally create a fresh instance,
rerun with ALLOW_EMPTY_PHOSPHENE_DATA=1.
EOF
  exit 1
fi

ENV_FILE="$SERVICE_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  SETUP_TOKEN=$(openssl rand -hex 32)
  umask 077
  cat >"$ENV_FILE" <<EOF
NODE_ENV=production
PORT=8080
PUBLIC_URL=https://$DOMAIN
PHOSPHENE_SETUP_TOKEN=$SETUP_TOKEN
PHOSPHENE_MCP_AUTH_MODE=token
PHOSPHENE_DATA_DIR=/data
LOG_LEVEL=info
EOF
fi
chmod 600 "$ENV_FILE"

cat >"$SERVICE_DIR/compose.yaml" <<EOF
services:
  phosphene:
    build:
      context: $APP_DIR
    container_name: phosphene
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - $DATA_DIR:/data
    networks:
      - mcp-edge

networks:
  mcp-edge:
    external: true
EOF

if [ ! -f "$CADDYFILE" ]; then
  echo "Caddyfile not found at $CADDYFILE" >&2
  exit 1
fi

CADDY_BACKUP="$CADDYFILE.before-phosphene-$(date -u +%Y%m%dT%H%M%SZ)"
cp "$CADDYFILE" "$CADDY_BACKUP"

python3 - <<'PY'
from pathlib import Path
import re

path = Path("/opt/mcp-stack/proxy/Caddyfile")
text = path.read_text()
block = """phosphene.xunzhou.space {
    reverse_proxy phosphene:8080
}"""

pattern = re.compile(r"(?ms)^phosphene\.xunzhou\.space\s*\{.*?^\}")
if pattern.search(text):
    text = pattern.sub(block, text, count=1)
else:
    text = text.rstrip() + "\n\n" + block + "\n"
path.write_text(text)
PY

cd "$SERVICE_DIR"
docker compose up -d --build

if ! docker exec caddy caddy validate --config /etc/caddy/Caddyfile; then
  cp "$CADDY_BACKUP" "$CADDYFILE"
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile || true
  exit 1
fi

if ! docker exec caddy caddy reload --config /etc/caddy/Caddyfile; then
  cp "$CADDY_BACKUP" "$CADDYFILE"
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile || true
  exit 1
fi

for _ in $(seq 1 30); do
  if docker inspect -f '{{.State.Health.Status}}' phosphene 2>/dev/null | grep -qx healthy; then
    break
  fi
  sleep 2
done

if ! docker inspect -f '{{.State.Health.Status}}' phosphene 2>/dev/null | grep -qx healthy; then
  docker compose ps >&2
  docker logs --tail 100 phosphene >&2 || true
  exit 1
fi

curl -fsS --max-time 15 "https://$DOMAIN/healthz"
printf '\nPHOSPHENE_DEPLOYED\n'
printf 'Data directory: %s\n' "$DATA_DIR"
printf 'Environment: %s\n' "$ENV_FILE"
printf 'Caddy backup: %s\n' "$CADDY_BACKUP"
