.PHONY: up down test build clean help

help:
	@echo "SentinelVAPT Engineering Operations:"
	@echo "  make up      - Launch SentinelVAPT platform and isolated lab targets"
	@echo "  make down    - Stop all containers and clean up networks"
	@echo "  make test    - Execute all backend unit and integration tests"
	@echo "  make build   - Build backend and frontend artifacts"
	@echo "  make clean   - Remove caches and temporary files"

up:
	docker-compose up -d

down:
	docker-compose down

test:
	python -m pytest backend/tests -v

build:
	cd frontend && npm run build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +

