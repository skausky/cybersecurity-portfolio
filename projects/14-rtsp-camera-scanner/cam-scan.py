#!/usr/bin/env python3
"""cam-scan entrypoint shim."""
import sys

from cam_scan.cli import main

if __name__ == "__main__":
    sys.exit(main())
