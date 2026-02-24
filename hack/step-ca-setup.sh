#!/bin/bash
set -euo pipefail

echo "Generating Step-CA artifacts..."
go run ./cmd/step-ca-setup/main.go
