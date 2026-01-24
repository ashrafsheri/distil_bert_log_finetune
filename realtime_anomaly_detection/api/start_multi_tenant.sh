#!/bin/bash
# Start Multi-Tenant Anomaly Detection API Server
# Uses student-teacher architecture for SaaS deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "=============================================="
echo "  Multi-Tenant Log Anomaly Detection API"
echo "  Student-Teacher Architecture"
echo "=============================================="
echo -e "${NC}"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default configuration
export MODEL_DIR="${MODEL_DIR:-$PROJECT_ROOT/../artifacts/ensemble_model_export}"
export STORAGE_DIR="${STORAGE_DIR:-$PROJECT_ROOT/data/multi_tenant}"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-8000}"
export DEVICE="${DEVICE:-cpu}"
export WARMUP_THRESHOLD="${WARMUP_THRESHOLD:-10000}"
export TEACHER_UPDATE_DAYS="${TEACHER_UPDATE_DAYS:-7}"
export RELOAD="${RELOAD:-false}"

# Print configuration
echo -e "${YELLOW}Configuration:${NC}"
echo "  MODEL_DIR: $MODEL_DIR"
echo "  STORAGE_DIR: $STORAGE_DIR"
echo "  HOST: $HOST"
echo "  PORT: $PORT"
echo "  DEVICE: $DEVICE"
echo "  WARMUP_THRESHOLD: $WARMUP_THRESHOLD logs"
echo "  TEACHER_UPDATE_DAYS: $TEACHER_UPDATE_DAYS days"
echo ""

# Check if model directory exists
if [ ! -d "$MODEL_DIR" ]; then
    echo -e "${RED}Error: Model directory not found: $MODEL_DIR${NC}"
    echo "Please run the model export notebook first."
    exit 1
fi

# Create storage directory
mkdir -p "$STORAGE_DIR"

# Check Python environment
echo -e "${YELLOW}Checking Python environment...${NC}"
python3 --version

# Check required packages
echo -e "${YELLOW}Checking dependencies...${NC}"
python3 -c "import fastapi, uvicorn, torch, sklearn" 2>/dev/null || {
    echo -e "${RED}Missing dependencies. Installing...${NC}"
    pip install -r "$PROJECT_ROOT/requirements.txt"
}

echo -e "${GREEN}✓ Dependencies OK${NC}"
echo ""

# Start the server
echo -e "${GREEN}Starting Multi-Tenant API Server...${NC}"
echo -e "${CYAN}API will be available at: http://${HOST}:${PORT}${NC}"
echo -e "${CYAN}Documentation at: http://${HOST}:${PORT}/docs${NC}"
echo ""

cd "$SCRIPT_DIR"
python3 -m uvicorn server_multi_tenant:app \
    --host "$HOST" \
    --port "$PORT" \
    --log-level info \
    ${RELOAD:+--reload}
