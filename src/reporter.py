"""
reporter.py — Output formatting for secretscan.

Two output modes: human-readable (colored terminal text via raw ANSI
codes) and machine-readable JSON. Zero third-party dependencies.
"""

import json
import time


# Raw ANSI escape codes — stdlib has no colour module, so we do it by hand.
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _supports_color():
    """Best-effort check; disable colour if not a real terminal (e.g. piped output)."""
    import sys
    return sys.stdout.isatty()


def format_human(findings, files_scanned, elapsed_seconds, use_color=None):
    if use_color is None:
        use_color = _supports_color()

    def c(code, text):
        return f"{code}{text}{RESET}" if use_color else text

    lines = []
    lines.append(f"Scanning complete — {files_scanned} file(s) checked.\n")

    if not findings:
        lines.append(c(GREEN, "✓ No secrets found."))
        lines.append(f"\nScan finished in {elapsed_seconds:.2f}s. Exit code: 0")
        return "\n".join(lines)

    lines.append(c(RED, c(BOLD, f"⚠ FOUND {len(findings)} potential secret(s):")))
    lines.append("")

    for f in findings:
        confidence_color = RED if f.confidence == "HIGH" else YELLOW
        lines.append(f"  {c(BOLD, f.filepath)}:{f.line_number}")
        lines.append(f"    Type: {f.rule_name}")
        lines.append(f"    Match: {f.redacted()}")
        lines.append(f"    Confidence: {c(confidence_color, f.confidence)}")
        lines.append("")

    lines.append(f"Scan finished in {elapsed_seconds:.2f}s. Exit code: 1")
    return "\n".join(lines)


def format_json(findings, files_scanned, elapsed_seconds):
    payload = {
        "files_scanned": files_scanned,
        "elapsed_seconds": round(elapsed_seconds, 4),
        "findings_count": len(findings),
        "findings": [
            {
                "file": f.filepath,
                "line": f.line_number,
                "type": f.rule_name,
                "match_redacted": f.redacted(),
                "confidence": f.confidence,
            }
            for f in findings
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    return json.dumps(payload, indent=2)
