#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  Digital Forensics Collector - Linux/macOS"
echo "============================================"
echo

# Navigate to collector directory
cd "$(dirname "$0")"

# --- Find Python 3.10+ ---
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY_VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        if [ -n "$PY_VER" ]; then
            PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
            PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
            if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
                PYTHON_CMD="$cmd"
                break
            fi
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "[ERROR] Python 3.10+ is required but not found."
    echo "        Install via your package manager:"
    echo "          Ubuntu/Debian: sudo apt install python3 python3-venv"
    echo "          macOS:         brew install python@3.12"
    exit 1
fi

echo "[OK] Found Python $PY_VER ($PYTHON_CMD)"

# --- Detect OS ---
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Linux*)  REQ_FILE="requirements/linux.txt"  ;;
    Darwin*) REQ_FILE="requirements/macos.txt"  ;;
    *)
        echo "[ERROR] Unsupported OS: $OS_TYPE"
        exit 1
        ;;
esac

echo "[OK] Detected OS: $OS_TYPE -> $REQ_FILE"

# --- Check libusb (needed for mobile device USB access) ---
if [ "$OS_TYPE" = "Darwin" ]; then
    if ! brew list libusb &>/dev/null 2>&1; then
        echo
        echo "[WARN] libusb not found. Mobile device USB access may not work."
        echo "       Install with: brew install libusb"
    fi
elif [ "$OS_TYPE" = "Linux" ]; then
    if ! ldconfig -p 2>/dev/null | grep -q libusb; then
        if ! dpkg -s libusb-1.0-0 &>/dev/null 2>&1; then
            echo
            echo "[WARN] libusb not found. Mobile device USB access may not work."
            echo "       Install with: sudo apt install libusb-1.0-0-dev"
        fi
    fi
fi

# --- Create venv if not exists ---
if [ ! -f ".venv/bin/activate" ]; then
    echo
    echo "[INFO] Creating virtual environment..."
    "$PYTHON_CMD" -m venv .venv 2>/dev/null || {
        echo "[ERROR] Failed to create virtual environment."
        echo "        On Ubuntu/Debian, install: sudo apt install python3-venv"
        exit 1
    }
    echo "[OK] Virtual environment created."
fi

# Activate venv
source .venv/bin/activate

# --- Install dependencies ---
echo
echo "[INFO] Installing dependencies ($REQ_FILE)..."
pip install -r "$REQ_FILE" --quiet 2>&1 || {
    echo "[WARN] Some packages failed. Trying base packages only..."
    pip install -r requirements/base.txt --quiet
}
echo "[OK] Dependencies installed."

# --- Launch application ---
echo
echo "[INFO] Starting collector..."
echo
python src/main.py
