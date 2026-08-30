"""
terminal_ui.py — Interactive terminal UI for SecretScan.

The UI never reads or prints Finding.matched_text directly. It uses
the redacted value and redacted line context supplied by scanner.py.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

from reporter import write_json_report, write_html_report


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
