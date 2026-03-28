#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "Security Triage Dashboard"
echo "======================================"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js is not installed${NC}"
    echo "Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v)
echo -e "${GREEN}✓ Node.js version: ${NODE_VERSION}${NC}"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}✗ npm is not installed${NC}"
    exit 1
fi

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo ""
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install
    echo -e "${GREEN}✓ Dependencies installed${NC}"
else
    echo -e "${GREEN}✓ Dependencies already installed${NC}"
fi

echo ""
echo "======================================"
echo "Configuration"
echo "======================================"
echo ""
echo "Dashboard URL: http://localhost:3000"
echo "API Gateway: http://localhost:8080"
echo ""

# Check if API Gateway is running
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API Gateway is running${NC}"
else
    echo -e "${YELLOW}⚠ API Gateway is not running${NC}"
    echo ""
    echo "Start API Gateway in another terminal:"
    echo "  cd /Users/newmba/security/services/api_gateway"
    echo "  python main.py"
    echo ""
fi

echo ""
echo "======================================"
echo "Starting Development Server"
echo "======================================"
echo ""

# Start dev server
npm run dev
