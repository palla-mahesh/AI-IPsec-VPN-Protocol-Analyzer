#!/usr/bin/env bash
# ==============================================================================
# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
# Problem Statement ID: 26160 | Organisation: NTRO
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================================="
echo "  AI-Powered IPsec VPN Protocol Analyzer (NTRO PS-26160)"
echo "====================================================================="

# Check virtual environment
if [ ! -d ".venv" ]; then
    echo "[!] Virtual environment not detected. Initializing via setup_env.sh..."
    bash setup_env.sh
fi

# Ensure trained model exists
if [ ! -f "ml/saved_models/ipsec_classifier.joblib" ]; then
    echo "[+] Training ML Traffic Classification model..."
    .venv/bin/python ml/train_model.py
fi

# Ensure benchmark PCAP suite exists
if [ ! -f "testbed/samples/scenario_1_enterprise_secure.pcap" ]; then
    echo "[+] Generating synthetic IPsec testbed benchmark scenarios..."
    .venv/bin/python testbed/traffic_generator.py
fi

PORT=${PORT:-8000}
HOST=${HOST:-"0.0.0.0"}

echo ""
echo "[✓] System Ready!"
echo "[*] Launching Interactive Web Dashboard & REST Service on http://localhost:${PORT}"
echo "[*] Press Ctrl+C to stop the server."
echo ""

exec .venv/bin/uvicorn web.app:app --host "$HOST" --port "$PORT" --reload
