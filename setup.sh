#!/bin/bash
# setup.sh — One-shot setup script for sshmini demo
# Run this from the project root directory.

set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     sshmini Setup & Demo Script      ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. Build
echo "[1/4] Building all binaries..."
make all
echo "      ✓ Done"

# 2. Generate certs
echo "[2/4] Generating TLS certificates..."
make certs
echo "      ✓ Certificates in ./certs/"

# 3. Add demo users
echo "[3/4] Creating demo users..."
./sshmini-adduser alice     password123
./sshmini-adduser bob       s3cr3t
./sshmini-adduser benchuser benchpass
echo "      ✓ users.db created"

echo ""
echo "[4/4] Setup complete! To run the demo:"
echo ""
echo "  Terminal 1 (server):"
echo "    ./sshmini-server"
echo ""
echo "  Terminal 2 (client):"
echo "    ./sshmini-client 127.0.0.1"
echo "    Username: alice"
echo "    Password: password123"
echo ""
echo "  Terminal 2 (benchmark):"
echo "    ./sshmini-bench 127.0.0.1 4422 8 20"
echo ""
