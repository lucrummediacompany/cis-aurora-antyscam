#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thin wrapper delegujący do analizatora (analyzer_core.py).
Użycie: python anty_scam.py <ETH_ADDRESS>
"""
import os, sys, subprocess

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

if len(sys.argv) < 2:
    print("Usage: python anty_scam.py <ETH_ADDRESS>")
    sys.exit(1)

address = sys.argv[1].strip()
ANALYZE_CMD = f'python -u analyzer_core.py --address {address}'

print(f"[NEXUS] Delegating analysis to: {ANALYZE_CMD}")
ret = subprocess.call(ANALYZE_CMD, cwd=APP_ROOT, shell=True)
sys.exit(ret)
