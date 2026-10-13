"""Compatibility entry point for stream-aware PCAP extraction."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from protocolguard.packets import main
if __name__ == "__main__":
    main()
