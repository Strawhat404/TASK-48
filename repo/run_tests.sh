#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if .env exists; if not, copy .env.example to .env
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        echo "No .env file found. Copying .env.example to .env..."
        cp .env.example .env
    else
        echo "ERROR: Neither .env nor .env.example found!"
        exit 1
    fi
fi

# Source the .env file
set -a
source .env
set +a

echo "========================================="
echo "  Meridian Academy — Full Test Suite"
echo "========================================="

FAILED=0

# Determine how to run cargo: prefer local cargo, fall back to docker
if command -v cargo &>/dev/null; then
    RUN_CARGO="cargo"
    echo "  Using local cargo: $(cargo --version)"
else
    echo "  cargo not found locally — running tests via Docker (rust:1.87-bookworm)"
    # Ensure the rust image is available
    docker pull rust:1.87-bookworm --quiet || true
    # Wrapper: docker run with the workspace mounted and host network so API tests
    # can reach the backend at http://localhost:8000
    RUN_CARGO="docker run --rm \
        --network host \
        -v ${SCRIPT_DIR}:/workspace \
        -w /workspace \
        -e BACKEND_URL=http://localhost:8000 \
        rust:1.87-bookworm \
        cargo"
fi

echo ""
echo "-----------------------------------------"
echo "  Running unit tests (unit_tests crate)"
echo "-----------------------------------------"
if $RUN_CARGO test -p unit_tests -- --nocapture 2>&1; then
    echo "  ✓ Unit tests PASSED"
else
    echo "  ✗ Unit tests FAILED"
    FAILED=1
fi

echo ""
echo "-----------------------------------------"
echo "  Running frontend tests (frontend_tests crate)"
echo "-----------------------------------------"
if $RUN_CARGO test -p frontend_tests -- --nocapture 2>&1; then
    echo "  ✓ Frontend tests PASSED"
else
    echo "  ✗ Frontend tests FAILED"
    FAILED=1
fi

echo ""
echo "-----------------------------------------"
echo "  Running API/integration tests (API_tests crate)"
echo "-----------------------------------------"
if $RUN_CARGO test -p API_tests -- --nocapture 2>&1; then
    echo "  ✓ API tests PASSED"
else
    echo "  ✗ API tests FAILED"
    FAILED=1
fi

echo ""
echo "========================================="
if [ $FAILED -ne 0 ]; then
    echo "  RESULT: SOME TESTS FAILED"
    exit 1
else
    echo "  RESULT: ALL TESTS PASSED"
    exit 0
fi
