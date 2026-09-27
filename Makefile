COMPOSE := docker compose

.PHONY: help up down build dev dev-backend services migrate revision templates api worker beat test lint fmt frontend-install frontend-dev

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-18s %s\n", $$1, $$2}'

up: ## tum stack'i ayaga kaldir (build + detached)
	$(COMPOSE) up -d --build

down: ## stack'i durdur
	$(COMPOSE) down

build: ## imagelari yeniden insa et
	$(COMPOSE) build

services: ## sadece postgres ve redis'i Docker'da baslatir (hizli lokal gelistirme icin)
	$(COMPOSE) up -d postgres redis

dev-backend: ## sadece backend stack'i Docker'da baslatir (frontend disarida)
	$(COMPOSE) up -d --build postgres redis api worker beat

dev-local: ## tum servisleri (worker, beat, api, frontend) tek script ile baslatir
	./dev.sh

dev: dev-backend ## backend Docker + frontend hot-reload (ayri terminalde: make frontend-dev)
	@echo ""
	@echo "  Backend hazir. Simdi yeni bir terminalde su komutu calistir:"
	@echo "    make frontend-dev"
	@echo ""

migrate: ## migration'lari calistir (postgres ayakta olmali)
	cd backend && uv run alembic upgrade head

revision: ## otomatik migration olustur (m="mesaj")
	$(COMPOSE) run --rm api alembic revision --autogenerate -m "$(m)"

templates: ## nuclei template'lerini indir/guncelle
	$(COMPOSE) run --rm worker nuclei -ut -ud /opt/nuclei-templates

api: ## lokal API dev sunucusu
	cd backend && uv run uvicorn secplat.presentation.main:app --reload --port 8000

worker: ## lokal celery worker
	cd backend && uv run celery -A secplat.infrastructure.queue.app worker -Q scans -c 2

beat: ## lokal celery beat
	cd backend && uv run celery -A secplat.infrastructure.queue.app beat

test: ## backend testleri
	cd backend && uv run pytest

lint: ## ruff + import-linter
	cd backend && uv run ruff check src tests && uv run lint-imports

fmt: ## format + autofix
	cd backend && uv run ruff format src tests && uv run ruff check --fix src tests

frontend-install: ## frontend bagimliliklari
	cd frontend && npm install

frontend-dev: ## frontend dev sunucusu
	cd frontend && npm run dev
