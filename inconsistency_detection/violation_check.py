"""Compatibility entry point for the reconstructed inconsistency detector."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from protocolguard.detection import main

if __name__ == "__main__":
    main()
