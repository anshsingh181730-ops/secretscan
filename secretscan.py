#!/usr/bin/env python3

"""
secretscan — zero-dependency local secrets leak scanner.

Examples:
    python secretscan.py scan <path>
    python secretscan.py scan <path> --json
    python secretscan.py scan <path> --html-report report.html
    python secretscan.py scan <path> --fix-suggest
    python secretscan.py scan <path> --staged-only
    python secretscan.py scan <path> --update-baseline
    python secretscan.py ui
    python secretscan.py install-hook --path .
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from config import load_config
from reporter import (
    format_human,
    format_json,
    write_html_report,
    write_json_report,
)
from rules import configure_entropy, find_entropy_matches, find_pattern_matches
from scanner import (
    apply_baseline,
    finding_fingerprint,
    scan_path,
)
from terminal_ui import TerminalUI, validate_target


PRE_COMMIT_HOOK_TEMPLATE = """#!/bin/sh
# Installed by SecretScan — blocks commits containing HIGH-confidence findings.
SCANNER={scanner_path}
PYTHON={python_executable}

if [ -x "$PYTHON" ]; then
    "$PYTHON" "$SCANNER" scan --staged-only .
else
    python3 "$SCANNER" scan --staged-only .
fi
exit $?
"""


def _load_baseline(path):
    if not os.path.isfile(path):
        return {"version": 1, "fingerprints": []}

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
            return data
    except (OSError, ValueError):
        pass

    return {"version": 1, "fingerprints": []}


def _write_baseline(path, findings):
    payload = {
        "version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "fingerprints": sorted(
            {
                finding.fingerprint
                for finding in findings
                if finding.fingerprint
            }
        ),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _resolve_config_path(scan_path, configured):
    if os.path.isabs(configured):
        return configured
    root = scan_path if os.path.isdir(scan_path) else os.path.dirname(scan_path)
    return os.path.join(root, configured)

def _report_base_name(scan_path):
    """Return a safe report filename base derived from the scan target."""
    from pathlib import Path
    import re

    path = Path(scan_path)

    if path.is_file():
        name = path.stem
    else:
        name = path.name

    # Windows-safe filename characters
    name = re.sub(r'[<>:"/\\|?*]', "_", name)
    name = name.strip(" ._")

    return name or "scan"

def cmd_scan(args):
    start = time.perf_counter()
    target = os.path.abspath(args.path)

    if not os.path.exists(target):
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2

    config = load_config(
        target if os.path.isdir(target) else os.path.dirname(target)
    )

    configure_entropy(config.entropy_threshold, config.min_entropy_len)
    findings, files_scanned = scan_path(
        target,
        pattern_finder=find_pattern_matches,
        entropy_finder=find_entropy_matches,
        staged_only=args.staged_only,
        extra_ignore_dirs=config.ignore_dirs,
        max_file_size_bytes=int(config.max_file_size_mb * 1024 * 1024),
    )

    baseline_path = _resolve_config_path(target, args.baseline or config.baseline_file)
    baseline = _load_baseline(baseline_path)

    if args.update_baseline:
        _write_baseline(baseline_path, findings)
        # Updating the baseline explicitly accepts the current findings.
        findings = []

    else:
        findings = apply_baseline(findings, baseline)

    elapsed = time.perf_counter() - start

    # ---------------------------------------------------------
    # REPORT GENERATION
    # ---------------------------------------------------------

    report_base = _report_base_name(target)

    # HTML report
    if args.html_report:
        requested_report = args.html_report
        requested_dir = os.path.dirname(requested_report)

        if requested_dir:
            html_filename = f"{report_base}_report.html"
            html_path = _resolve_config_path(
                target,
                os.path.join(requested_dir, html_filename),
            )
        else:
            html_path = _resolve_config_path(
                target,
                f"{report_base}_report.html",
            )

        write_html_report(
            findings,
            files_scanned,
            elapsed,
            html_path,
            target,
        )

        print(f"HTML report written to: {html_path}")

    # JSON report
    if args.json:
        json_path = _resolve_config_path(
            target,
            f"{report_base}_report.json",
        )

        write_json_report(
            findings,
            files_scanned,
            elapsed,
            json_path,
            target,
        )

        print(f"JSON report written to: {json_path}")

        # Also display JSON in terminal
        print(format_json(findings, files_scanned, elapsed))

    else:
        print(
            format_human(
                findings,
                files_scanned,
                elapsed,
                show_fix_suggest=args.fix_suggest,
            )
        )  
   
        

    if args.json:
        print(format_json(findings, files_scanned, elapsed))
    else:
        print(
            format_human(
                findings,
                files_scanned,
                elapsed,
                show_fix_suggest=args.fix_suggest,
            )
        )

    # HIGH blocks; MEDIUM/LOW only warn.
    return 1 if any(f.confidence == "HIGH" for f in findings) else 0


def scan_target_with_ui(
    ui: TerminalUI,
    path: str,
    fix_suggest: bool = False,
) -> None:
    target = os.path.abspath(path)

    if not os.path.exists(target):
        ui.error(f"Path does not exist: {target}")
        ui.pause()
        return

    ui.show_scan_start(target)
    start = time.perf_counter()

    config = load_config(target if os.path.isdir(target) else os.path.dirname(target))
    configure_entropy(config.entropy_threshold, config.min_entropy_len)

    try:
        findings, files_scanned = scan_path(
            target,
            pattern_finder=find_pattern_matches,
            entropy_finder=find_entropy_matches,
            extra_ignore_dirs=config.ignore_dirs,
            max_file_size_bytes=int(config.max_file_size_mb * 1024 * 1024),
        )
    except (OSError, UnicodeError) as exc:
        ui.error(f"Scan failed: {exc}")
        ui.pause()
        return
    except Exception as exc:
        ui.error(f"Unexpected scanner error: {exc}")
        ui.pause()
        return

    elapsed = time.perf_counter() - start
    ui.findings_loop(
        PathLike(target),
        findings,
        files_scanned,
        elapsed,
        show_fix_suggest=fix_suggest,
    )


def PathLike(path):
    # Local helper avoids importing pathlib solely for the UI call.
    from pathlib import Path
    return Path(path)


def cmd_ui(args):
    ui = TerminalUI()

    while True:
        choice = ui.show_main_menu()

        if choice == "1":
            path = ui.ask_path("Project path")
            if not validate_target(path, expect_directory=True):
                ui.error("That path is not a valid directory.")
                ui.pause()
                continue

            ui.clear()
            ui.title("PROJECT READY", "Review target before scanning")
            ui.show_target(path, "Directory")
            ui.show_project_preview(path)

            if ui.confirm_scan(path):
                scan_target_with_ui(
                    ui,
                    str(path),
                    fix_suggest=args.fix_suggest,
                )

        elif choice == "2":
            path = ui.ask_path("File path")
            if not validate_target(path, expect_directory=False):
                ui.error("That path is not a valid file.")
                ui.pause()
                continue

            ui.clear()
            ui.title("FILE READY", "Review target before scanning")
            ui.show_target(path, "File")

            if ui.confirm_scan(path):
                scan_target_with_ui(
                    ui,
                    str(path),
                    fix_suggest=args.fix_suggest,
                )

        elif choice == "3":
            ui.clear()
            ui.title("GIT PRE-COMMIT HOOK", "Protect commits from likely secrets")
            path = ui.ask_path("Git repository path")

            result = cmd_install_hook(
                argparse.Namespace(path=str(path))
            )

            if result == 0:
                ui.success("Git pre-commit hook installed successfully.")
            ui.pause()

        elif choice == "4":
            ui.show_about()

        elif choice == "5":
            ui.clear()
            ui.title("SECRETSCAN", "Goodbye")
            print()
            ui.success("Exiting.")
            print()
            return 0

        else:
            ui.warning("Invalid option. Choose 1, 2, 3, 4, or 5.")
            ui.pause()


def cmd_install_hook(args):
    repo_path = os.path.abspath(args.path)
    git_dir = os.path.join(repo_path, ".git")

    if not os.path.isdir(git_dir):
        print(
            f"Error: {repo_path} is not a git repository (.git not found).",
            file=sys.stderr,
        )
        return 1

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    hook_path = os.path.join(hooks_dir, "pre-commit")
    scanner_path = os.path.abspath(__file__)
    python_executable = os.path.abspath(sys.executable)

    content = PRE_COMMIT_HOOK_TEMPLATE.format(
        scanner_path=scanner_path,
        python_executable=python_executable,
    )

    with open(hook_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)

    try:
        os.chmod(hook_path, 0o755)
    except OSError:
        pass

    print(f"Installed pre-commit hook at {hook_path}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Zero-dependency local secrets leak scanner.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a file or directory for secrets.",
    )
    scan_p.add_argument("path", help="File or directory to scan.")
    scan_p.add_argument("--json", action="store_true",
                        help="Output machine-readable JSON.")
    scan_p.add_argument("--staged-only", action="store_true",
                        help="Scan only files currently staged in Git.")
    scan_p.add_argument("--fix-suggest", action="store_true",
                        help="Show remediation suggestions.")
    scan_p.add_argument("--baseline",
                        help="Path to baseline JSON file.")
    scan_p.add_argument("--update-baseline", action="store_true",
                        help="Accept current findings into the baseline.")
    scan_p.add_argument("--html-report", metavar="PATH",
                        help="Write an HTML report to PATH.")
    scan_p.set_defaults(func=cmd_scan)

    ui_p = subparsers.add_parser(
        "ui",
        help="Launch the interactive terminal interface.",
    )
    ui_p.add_argument("--fix-suggest", action="store_true",
                      help="Show remediation suggestions in the UI.")
    ui_p.set_defaults(func=cmd_ui)

    hook_p = subparsers.add_parser(
        "install-hook",
        help="Install as a Git pre-commit hook.",
    )
    hook_p.add_argument(
        "--path",
        default=".",
        help="Path to the Git repo root (default: .)",
    )
    hook_p.set_defaults(func=cmd_install_hook)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
