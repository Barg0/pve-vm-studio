#!/usr/bin/env python3
"""Entry point: ./cisv.py <command> ... (or python3 -m cisv from this folder)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cisv.__main__ import main  # noqa: E402

sys.exit(main())
