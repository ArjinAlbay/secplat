#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

echo "[*] Eski calisan surecler temizleniyor..."
pkill -9 -f "secplat" 2>/dev/null || true
pkill -9 -f "next dev" 2>/dev/null || true
pkill -9 -f "uvicorn.*secplat" 2>/dev/null || true
pkill -9 -f "celery.*secplat" 2>/dev/null || true
sleep 1

# 1. Host development environment variables
if [ -f "$ROOT_DIR/.env.local" ]; then
    echo "[*] .env.local yukleniyor..."
    set -a
    . "$ROOT_DIR/.env.local"
    set +a
fi

# Fallbacks for host development if not set
export SECPLAT_DATABASE_URL="${SECPLAT_DATABASE_URL:-postgresql+psycopg://secplat:devpass@localhost:5434/secplat}"
export SECPLAT_REDIS_URL="${SECPLAT_REDIS_URL:-redis://localhost:6379/0}"

# 2. Docker Postgres & Redis kontrolu ve baslatilmasi
echo "[*] Postgres (5434) ve Redis (6379) Docker servisleri kontrol ediliyor..."
if command -v docker &> /dev/null; then
    docker compose up -d postgres || true
    docker compose up -d redis 2>/dev/null || true
else
    echo "[!] Docker komutu bulunamadi, mevcut servislerin calistigi varsayiliyor."
fi

# 3. DB Migration
echo "[*] Veritabani migration kontrol ediliyor..."
(cd "$BACKEND_DIR" && uv run alembic upgrade head) || {
    echo "[!] Migration calistirilamadi. Postgres 5434 portunda hazir olmayabilir."
}

cleanup() {
    echo ""
    echo "[!] Servisler durduruluyor..."
    kill $(jobs -p) 2>/dev/null || true
    pkill -9 -f "secplat" 2>/dev/null || true
    pkill -9 -f "next dev" 2>/dev/null || true
    pkill -9 -f "uvicorn.*secplat" 2>/dev/null || true
    pkill -9 -f "celery.*secplat" 2>/dev/null || true
    echo "[+] Tum servisler kapatildi."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[+] 1/4 Celery Worker baslatiliyor..."
(cd "$BACKEND_DIR" && uv run celery -A secplat.infrastructure.queue.app worker -Q scans -c 2 --max-tasks-per-child=50) &

echo "[+] 2/4 Celery Beat baslatiliyor..."
(cd "$BACKEND_DIR" && uv run celery -A secplat.infrastructure.queue.app beat --schedule /tmp/celerybeat-schedule) &

echo "[+] 3/4 FastAPI Backend (port 8000) baslatiliyor..."
(cd "$BACKEND_DIR" && uv run uvicorn secplat.presentation.main:app --reload --port 8000) &

echo "[+] 4/4 Next.js Frontend (port 3000) baslatiliyor..."
(cd "$FRONTEND_DIR" && npm run dev) &

echo ""
echo "========================================================="
echo "  Tum servisler basariyla baslatildi!"
echo "  - Frontend : http://localhost:3000"
echo "  - API Docs : http://localhost:8000/docs"
echo ""
echo "  Durdurmak icin bu terminalde CTRL + C tuslarina basin."
echo "========================================================="
echo ""

wait
