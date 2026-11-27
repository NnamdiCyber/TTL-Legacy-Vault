#!/usr/bin/env bash
set -euo pipefail

echo "Running TTL-Legacy tests..."
cargo test --manifest-path contracts/ttl_vault/Cargo.toml
cargo test --manifest-path contracts/zk_verifier/Cargo.toml
echo "All tests passed."
