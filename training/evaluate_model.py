"""Compatibility entry point for the supported scripts/evaluate_model.py command."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evaluate_model import main

if __name__ == "__main__":
    main()