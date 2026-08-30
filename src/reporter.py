"""
reporter.py — Safe output formatting for SecretScan.

Human output, JSON output and an HTML report. Raw detected values are
never emitted; only redacted values and redacted line context are used.
"""

from __future__ import annotations

import html
import json
import time


RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _supports_color():
    import sys
    return sys.stdout.isatty()


def _finding_context(finding):
    return getattr(finding, "line_context", "") or "[REDACTED CONTEXT UNAVAILABLE]"


def _skip_summary_dict(skipped):
    """Normalize a SkipLog (or dict, or None) to a plain dict, or None
    if there's nothing to report."""
    if skipped is None:
        return None
    if hasattr(skipped, "as_dict"):
        skipped = skipped.as_dict()
    if not skipped.get("counts"):
        return None
    return skipped


def _skip_reason_label(reason):
    try:
        from scanner import SKIP_REASON_LABELS
        return SKIP_REASON_LABELS.get(reason, reason)
    except ImportError:
        return reason


def format_human(
    findings,
    files_scanned,
    elapsed_seconds,
    use_color=None,
    show_fix_suggest=False,
    skipped=None,
):
    if use_color is None:
        use_color = _supports_color()

    def c(code, text):
        return f"{code}{text}{RESET}" if use_color else text

    high = sum(f.confidence == "HIGH" for f in findings)
    medium = sum(f.confidence == "MEDIUM" for f in findings)
    low = sum(f.confidence == "LOW" for f in findings)

    lines = [
        "Scanning complete.",
        f"Files scanned: {files_scanned}",
        f"Findings: {len(findings)} "
        f"(HIGH={high}, MEDIUM={medium}, LOW={low})",
        f"Scan finished in {elapsed_seconds:.2f}s.",
    ]

    skip_summary = _skip_summary_dict(skipped)
    if skip_summary:
        breakdown = ", ".join(
            f"{_skip_reason_label(reason)}={count}"
            for reason, count in sorted(skip_summary["counts"].items())
        )
        lines.append(
            f"Files skipped: {skip_summary['total']} ({breakdown}) "
            "— re-run with --json for the individual paths."
        )

    lines.append("")

    if not findings:
        lines.append(c(GREEN, "✓ No secrets found."))
        lines.append("Exit code: 0")
        return "\n".join(lines)

    if high:
        lines.append(c(RED, c(BOLD, f"⚠ FOUND {len(findings)} potential secret(s):")))
    else:
        lines.append(c(YELLOW, c(BOLD, f"⚠ {len(findings)} potential secret(s) need review:")))
    lines.append("")

    for finding in findings:
        confidence_color = {
            "HIGH": RED,
            "MEDIUM": YELLOW,
            "LOW": GREEN,
        }.get(finding.confidence, DIM)

        lines.append(f"  {c(BOLD, finding.filepath)}:{finding.line_number}")
        lines.append(f"    Type: {finding.rule_name}")
        lines.append(f"    Match: {finding.redacted()}")
        lines.append(f"    Context: {_finding_context(finding)}")
        lines.append(
            f"    Confidence: {c(confidence_color, finding.confidence)}"
        )
        if show_fix_suggest and getattr(finding, "suggestion", ""):
            lines.append(f"    Suggestion: {finding.suggestion}")
        lines.append("")

    # Severity policy: HIGH blocks; MEDIUM/LOW only warns.
    exit_code = 1 if high else 0
    lines.append(
        f"Exit code: {exit_code} "
        f"({'HIGH confidence finding(s) detected' if high else 'warning-only findings'})"
    )
    return "\n".join(lines)


def format_json(findings, files_scanned, elapsed_seconds, skipped=None):
    skip_summary = _skip_summary_dict(skipped) or {
        "total": 0,
        "counts": {},
        "samples": [],
    }

    payload = {
        "files_scanned": files_scanned,
        "elapsed_seconds": round(elapsed_seconds, 4),
        "findings_count": len(findings),
        "severity_counts": {
            "HIGH": sum(f.confidence == "HIGH" for f in findings),
            "MEDIUM": sum(f.confidence == "MEDIUM" for f in findings),
            "LOW": sum(f.confidence == "LOW" for f in findings),
        },
        "files_skipped": skip_summary["total"],
        "files_skipped_by_reason": skip_summary["counts"],
        "files_skipped_samples": skip_summary["samples"],
        "findings": [
            {
                "file": f.filepath,
                "line": f.line_number,
                "type": f.rule_name,
                "match_redacted": f.redacted(),
                "line_context": _finding_context(f),
                "confidence": f.confidence,
                "suggestion": getattr(f, "suggestion", ""),
                "fingerprint": getattr(f, "fingerprint", ""),
            }
            for f in findings
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "exit_code": 1 if any(f.confidence == "HIGH" for f in findings) else 0,
    }
    return json.dumps(payload, indent=2)

def write_json_report(
    findings,
    files_scanned,
    elapsed_seconds,
    output_path,
    skipped=None,
):
    """Write the JSON scan report to disk."""
    document = format_json(
        findings,
        files_scanned,
        elapsed_seconds,
        skipped=skipped,
    )

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(document)
        handle.write("\n")

def write_html_report(
    findings,
    files_scanned,
    elapsed_seconds,
    output_path,
    target,
    skipped=None,
):
    """Write a self-contained, dependency-free HTML report."""
    high = sum(f.confidence == "HIGH" for f in findings)
    medium = sum(f.confidence == "MEDIUM" for f in findings)
    low = sum(f.confidence == "LOW" for f in findings)

    skip_summary = _skip_summary_dict(skipped)
    skip_badge = ""
    skip_section = ""
    if skip_summary:
        skip_badge = f'<span class="badge">Skipped: {skip_summary["total"]}</span>'
        reason_items = "".join(
            f"<li>{html.escape(_skip_reason_label(reason))}: {count}</li>"
            for reason, count in sorted(skip_summary["counts"].items())
        )
        sample_items = "".join(
            f"<li><code>{html.escape(str(s['path']))}</code> "
            f"— {html.escape(_skip_reason_label(s['reason']))}</li>"
            for s in skip_summary["samples"]
        )
        sample_note = (
            f"<p class=\"note\">Showing {len(skip_summary['samples'])} "
            f"of {skip_summary['total']} skipped file(s); re-run with "
            "--json for the complete list.</p>"
            if skip_summary["total"] > len(skip_summary["samples"])
            else ""
        )
        skip_section = f"""
<h2>Skipped Files</h2>
<p class="note">Files excluded from this scan (binary, .gitignore match,
over the size cap, or unreadable) — no secret in a skipped file can be
detected, so this section exists so that's never silent.</p>
<ul>{reason_items}</ul>
{sample_items and f"<ul>{sample_items}</ul>"}
{sample_note}
"""

    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.filepath))}</td>"
            f"<td>{finding.line_number}</td>"
            f"<td>{html.escape(str(finding.rule_name))}</td>"
            f"<td>{html.escape(finding.redacted())}</td>"
            f"<td><code>{html.escape(_finding_context(finding))}</code></td>"
            f"<td>{html.escape(str(finding.confidence))}</td>"
            f"<td>{html.escape(str(getattr(finding, 'suggestion', '')))}</td>"
            "</tr>"
        )

    if not rows:
        rows.append(
            '<tr><td colspan="7">No findings.</td></tr>'
        )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecretScan Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: .6rem; text-align: left; vertical-align: top; }}
th {{ background: #f3f3f3; }}
code {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
.badge {{ display: inline-block; padding: .2rem .5rem; border: 1px solid #bbb; border-radius: .4rem; margin-right: .5rem; }}
.note {{ color: #555; }}
</style>
</head>
<body>
<h1>SecretScan Report</h1>
<p class="note">Target: {html.escape(str(target))}</p>
<p>
<span class="badge">Files: {files_scanned}</span>
<span class="badge">Findings: {len(findings)}</span>
<span class="badge">HIGH: {high}</span>
<span class="badge">MEDIUM: {medium}</span>
<span class="badge">LOW: {low}</span>
<span class="badge">Time: {elapsed_seconds:.4f}s</span>
{skip_badge}
</p>
<p class="note">Detected values and line context are redacted.</p>
<table>
<thead><tr>
<th>File</th><th>Line</th><th>Rule</th><th>Match</th>
<th>Redacted line context</th><th>Confidence</th><th>Suggestion</th>
</tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
{skip_section}
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(document)
