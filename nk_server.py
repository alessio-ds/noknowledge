#!/usr/bin/env python3
"""Frozen entry point for a noknowledge relay."""

from noknowledge.server.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())