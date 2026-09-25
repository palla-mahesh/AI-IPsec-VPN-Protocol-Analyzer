#!/usr/bin/env bash
# ==============================================================================
# Environment Setup Script for AI-Powered IPsec VPN Protocol Analyzer
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[+] Creating Python 3 virtual environment..."
python3 -m venv .venv

echo "[+] Upgrading pip..."
.venv/bin/pip install --upgrade pip

echo "[+] Installing framework dependencies..."
.venv/bin/pip install -r requirements.txt

echo "[+] Training ML Traffic Classifier..."
.venv/bin/python ml/train_model.py

echo "[+] Synthesizing Benchmark Testbed PCAP Traces..."
.venv/bin/python testbed/traffic_generator.py

echo "[✓] Environment setup completed successfully!"
