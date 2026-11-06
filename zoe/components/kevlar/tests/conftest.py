"""Shared fixtures for Kevlar tests."""
import sys
import os

# Ensure policy module is importable from tests/
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
