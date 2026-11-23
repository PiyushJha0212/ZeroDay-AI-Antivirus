"""
run_desktop.py — Desktop entry point for standalone PyInstaller executable.
"""
import os
import sys

# Ensure root directory is in sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from avscan.gui import main

if __name__ == "__main__":
    sys.exit(main())
