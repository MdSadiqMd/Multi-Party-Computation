#!/usr/bin/env bash
set -e

echo "Multi-Party Computation Test Suite"
echo "===================================="
echo ""

echo "Checking prerequisites..."
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Cargo not found"
    exit 1
fi
echo "✓ Cargo installed"

if ! command -v rustc &> /dev/null; then
    echo "ERROR: Rust compiler not found"
    exit 1
fi
echo "✓ Rust compiler installed"
echo ""

# Build without blockchain
echo "Building MPC core (without blockchain features)..."
cargo build --lib 2>&1 | tail -3
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "✓ Build successful"
else
    echo "✗ Build failed"
    exit 1
fi
echo ""

# Run tests
echo "Running tests..."
cargo test --lib 2>&1 | tail -10
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "✓ Tests passed"
else
    echo "✗ Tests failed"
    exit 1
fi
echo ""

echo "===================================="
echo "All checks passed!"
echo ""
echo "To build with blockchain support:"
echo "  cargo build --features blockchain"
echo ""
