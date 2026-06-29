.PHONY: help dev-backend dev-worker dev-frontend dev install test lint docker-up docker-up-sandbox docker-down docker-logs nvd-update

help:
	@echo "ScanR — Development Commands"
	@echo ""
	@echo "  make install            Install all dependencies"
	@echo "  make dev                Start backend API (uvicorn dev server)"
	@echo "  make dev-worker         Start Celery worker"
	@echo "  make dev-frontend       Start Vite dev server"
	@echo "  make test               Run pytest"
	@echo "  make docker-up          Start services via Docker Compose"
	@echo "  make docker-up-sandbox  Start with AI sandbox enabled"
	@echo "  make docker-down        Stop Docker Compose services"
	@echo "  make nvd-update         Download/update NVD CVE feeds"

install:
	cd backend && pip install -e ".[dev]"
	cd frontend && npm install

dev:
	cd backend && uvicorn scanr.main:app --reload --host 0.0.0.0 --port 8000

dev-worker:
	cd backend && celery -A scanr.tasks.celery_app worker --loglevel=info --concurrency=4

dev-frontend:
	cd frontend && npm run dev

test:
	cd backend && pytest tests/ -v --tb=short

lint:
	cd backend && ruff check scanr/ && mypy scanr/

docker-up:
	docker compose up -d

docker-up-sandbox:
	docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up -d

docker-logs:
	docker compose logs -f

docker-down:
	docker compose down

nvd-update:
	cd backend && python -m scanr.cli.main update-nvd
