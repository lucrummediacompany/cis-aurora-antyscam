#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Helper: show latest report from ANALYZE/* in console.
"""
import os, glob

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
ANALYZE_DIR = os.path.join(APP_ROOT, "ANALYZE")

def latest_report():
    """
    Zwraca najnowszy raport z katalogu ANALYZE/by_id/
    (pojedynczy plik JSON tworzony przez analyzer_core.py)
    """
    by_id_dir = os.path.join(ANALYZE_DIR, "by_id")
    if not os.path.exists(by_id_dir):
        return None
    files = glob.glob(os.path.join(by_id_dir, "*.json"))
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0] if files else None

if __name__ == "__main__":
    p = latest_report()
    if not p:
        print("No reports found.")
    else:
        print(f"Latest: {p}")
        print("-" * 80)
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            print(fh.read()[-4000:])
