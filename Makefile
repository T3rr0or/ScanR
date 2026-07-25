.PHONY: help dev-backend dev-worker dev-frontend dev install test lint docker-build docker-up docker-down docker-logs nvd-update

help:
	@echo "ScanR — Development Commands"
	@echo ""
	@echo "  make install            Install all dependencies"
	@echo "  make dev                Start backend API (uvicorn dev server)"
	@echo "  make dev-worker         Start Celery worker"
	@echo "  make dev-frontend       Start Vite dev server"
	@echo "  make test               Run pytest"
	@echo "  make docker-build       Build all images (including the sandbox relay)"
	@echo "  make docker-up          Start all services via Docker Compose"
	@echo "  make docker-down        Stop Docker Compose services"
	@echo "  make nvd-update         Download/update NVD CVE feeds"

install:
	@if [ -z "$$VIRTUAL_ENV" ] && [ -z "$$CONDA_PREFIX" ]; then \
		echo "ERROR: no Python virtual environment active." >&2; \
		echo "Create and activate one first, e.g.:" >&2; \
		echo "  cd backend && python -m venv .venv && source .venv/bin/activate" >&2; \
		exit 1; \
	fi
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

# The build-only profile carries sandbox-relay: the runner spawns it per agent
# run via the Docker API, so compose never starts it — but the image still has to
# exist locally, and a plain `docker compose build` skips profiled services.
docker-build:
	docker compose --profile build-only build

docker-up:
	docker compose up -d

docker-logs:
	docker compose logs -f

docker-down:
	docker compose down

nvd-update:
	cd backend && python -m scanr.cli.main update-nvd
