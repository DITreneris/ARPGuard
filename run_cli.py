#!/usr/bin/env python3
"""
ARPGuard CLI Runner
This script allows direct execution of the ARPGuard CLI for testing and development.
"""

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.components.cli import main

if __name__ == "__main__":
    main() 