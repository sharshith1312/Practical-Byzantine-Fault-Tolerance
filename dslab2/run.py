#!/usr/bin/env python3
"""
PBFT CLI Launcher
"""
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)


if __name__ == "__main__":
    from client.client import main
    main()
