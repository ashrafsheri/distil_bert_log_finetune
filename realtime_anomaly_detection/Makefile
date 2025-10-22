.PHONY: help build up down logs restart status test clean

# Default target
help:
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  Anomaly Detection API - Docker Commands"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "  make build       - Build Docker image"
	@echo "  make up          - Start API server (development)"
	@echo "  make up-prod     - Start API server (production)"
	@echo "  make down        - Stop API server"
	@echo "  make restart     - Restart API server"
	@echo "  make logs        - View API logs (follow)"
	@echo "  make status      - Check API status"
	@echo "  make health      - Check API health"
	@echo "  make test        - Test API endpoints"
	@echo "  make shell       - Open shell in container"
	@echo "  make clean       - Remove containers and images"
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"

# Build Docker image
build:
	@echo "🔨 Building Docker image..."
	docker-compose build

# Start services (development)
up:
	@echo "🚀 Starting API server (development)..."
	docker-compose up -d
	@echo "✅ API running at http://localhost:8000"
	@echo "📖 Documentation: http://localhost:8000/docs"

# Start services (production)
up-prod:
	@echo "🚀 Starting API server (production)..."
	docker-compose -f docker-compose.prod.yml up -d
	@echo "✅ API running at http://localhost:8000"

# Stop services
down:
	@echo "🛑 Stopping API server..."
	docker-compose down

# Restart services
restart:
	@echo "🔄 Restarting API server..."
	docker-compose restart
	@echo "✅ API restarted"

# View logs
logs:
	@echo "📋 Viewing API logs (Ctrl+C to exit)..."
	docker-compose logs -f anomaly-detection-api

# Check status
status:
	@echo "📊 Container status:"
	docker-compose ps
	@echo ""
	@echo "📊 API status:"
	@curl -s http://localhost:8000/status | python3 -m json.tool || echo "❌ API not responding"

# Health check
health:
	@echo "🏥 Checking API health..."
	@curl -s http://localhost:8000/health | python3 -m json.tool || echo "❌ API not healthy"

# Test API endpoints
test:
	@echo "🧪 Testing API endpoints..."
	@echo ""
	@echo "1. Health check:"
	@curl -s http://localhost:8000/health | python3 -m json.tool
	@echo ""
	@echo "2. Root endpoint:"
	@curl -s http://localhost:8000/ | python3 -m json.tool
	@echo ""
	@echo "3. Detect normal log:"
	@curl -s -X POST http://localhost:8000/detect \
		-H "Content-Type: application/json" \
		-d '{"log_line": "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET / HTTP/1.1\" 200 1234"}' \
		| python3 -m json.tool
	@echo ""
	@echo "4. Detect anomaly (XSS):"
	@curl -s -X POST http://localhost:8000/detect \
		-H "Content-Type: application/json" \
		-d '{"log_line": "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 1234"}' \
		| python3 -m json.tool

# Open shell in container
shell:
	@echo "🐚 Opening shell in container..."
	docker-compose exec anomaly-detection-api /bin/bash

# Clean up
clean:
	@echo "🧹 Cleaning up containers and images..."
	docker-compose down -v
	docker rmi anomaly-detection-api:latest || true
	@echo "✅ Cleanup complete"

# Install pre-commit hooks (optional)
install-hooks:
	@echo "📦 Installing pre-commit hooks..."
	pip install pre-commit
	pre-commit install

# Run linting
lint:
	@echo "🔍 Running linters..."
	black api/ models/
	flake8 api/ models/
	mypy api/ models/
