#!/usr/bin/env python3

"""
secretscan — zero-dependency local secrets leak scanner.

Examples:
    python secretscan.py scan <path>
    python secretscan.py scan <path> --json
    python secretscan.py scan <path> --html-report report.html
    python secretscan.py scan <path> --fix-suggest
    python secretscan.py scan <path> --include-shell-history
    python secretscan.py scan <path> --update-baseline
    python secretscan.py scan <file1> <file2> <file3>   # multiple explicit paths
    python secretscan.py ui
    python secretscan.py install-hook --path .

No part of this program invokes an external tool (git, etc.) at
runtime — see STDLIB.md for how the pre-commit hook avoids that.
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
    scan_path,
)
from terminal_ui import TerminalUI, validate_target


# The hook is a plain POSIX shell script executed BY GIT as part of its
# own commit machinery — this is what every pre-commit hook does, by
# definition, and is not this program invoking an external tool on its
# own initiative. Crucially, secretscan.py itself never calls out to
# git: the hook asks git which files are staged, then passes that
# filename list as ordinary positional arguments to `scan`, so all
# actual secret detection still runs through pure standard-library
# code with zero knowledge of git at all. See STDLIB.md.
#
# Filenames are never captured into a shell variable and re-expanded
# ($STAGED_FILES) — POSIX shell word-splits unquoted expansions on
# whitespace, so a staged path containing a space would be sliced into
# bogus fragments, and a filename starting with "-" (e.g.
# "-secrets.env") could be parsed as a flag instead of a path. Command
# substitution is also unsafe here for a subtler reason: shell
# variables can't reliably hold embedded NUL bytes, so even a
# NUL-delimited `git diff -z` output gets silently truncated if
# assigned to a variable first.
#
# Instead: (1) a `git diff --quiet` probe decides whether there's
# anything staged, with no filenames touched at all, and (2) the
# actual filenames are streamed straight from `git diff -z` (NUL
# delimited, so any character including spaces/newlines is safe)
# through `xargs -0` directly into the scanner, with `--` before the
# path list so argparse always treats every argument after it as a
# path, never as an option.
PRE_COMMIT_HOOK_TEMPLATE = """#!/bin/sh
# Installed by SecretScan — blocks commits containing HIGH-confidence findings.
SCANNER={scanner_path}
PYTHON={python_executable}

# Nothing staged (of the types we care about)? Nothing to scan.
if git diff --cached --quiet --diff-filter=ACMR; then
    exit 0
fi

if [ -x "$PYTHON" ]; then
    RUNNER="$PYTHON"
else
    RUNNER=python3
fi

# -z / -0: NUL-delimited end to end, so spaces, quotes and newlines in
# a staged filename can never be mis-split. "--" stops argparse from
# treating a filename that starts with "-" as an option.
git diff --cached --name-only --diff-filter=ACMR -z \\
    | xargs -0 "$RUNNER" "$SCANNER" scan --
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


def _resolve_config_path(default_root, configured):
    """Resolve a possibly-relative config/report/baseline path.

    Relative paths resolve against the current working directory
    (where the user ran the command from), not against whatever
    file/directory happens to be the scan target — otherwise scanning
    a single file elsewhere on disk would scatter baseline/report
    files into that file's directory instead of the user's project.
    """
    if os.path.isabs(configured):
        return configured
    return os.path.join(os.getcwd(), configured)


def _report_base_name(scan_paths):
    """Return a safe report filename base derived from the scan target(s)."""
    from pathlib import Path
    import re

    if len(scan_paths) == 1:
        path = Path(scan_paths[0])
        name = path.stem if path.is_file() else path.name
    else:
        name = "multi_target_scan"

    name = re.sub(r'[<>:"/\\|?*]', "_", name)
    name = name.strip(" ._")

    return name or "scan"


def cmd_scan(args):
    start = time.perf_counter()
    targets = [os.path.abspath(p) for p in args.paths]

    missing = [p for p in targets if not os.path.exists(p)]
    if missing:
        for p in missing:
            print(f"Error: path does not exist: {p}", file=sys.stderr)
        return 2

    # Config is loaded from the first target's directory (or the
    # target itself, if it's a directory) — good enough for the
    # common case of scanning one project.
    first = targets[0]
    config = load_config(first if os.path.isdir(first) else os.path.dirname(first))

    configure_entropy(config.entropy_threshold, config.min_entropy_len)
    findings, files_scanned, skipped = scan_path(
        targets,
        pattern_finder=find_pattern_matches,
        entropy_finder=find_entropy_matches,
        extra_ignore_dirs=config.ignore_dirs,
        max_file_size_bytes=int(config.max_file_size_mb * 1024 * 1024),
        include_history=args.include_shell_history,
    )

    baseline_path = _resolve_config_path(first, args.baseline or config.baseline_file)
    baseline = _load_baseline(baseline_path)

    if args.update_baseline:
        _write_baseline(baseline_path, findings)
        # Updating the baseline explicitly accepts the current findings.
        findings = []
    else:
        findings = apply_baseline(findings, baseline)

    elapsed = time.perf_counter() - start
    report_base = _report_base_name(args.paths)

    if args.html_report:
        html_path = _resolve_config_path(first, args.html_report)
        write_html_report(
            findings, files_scanned, elapsed, html_path, ", ".join(args.paths),
            skipped=skipped,
        )
        print(f"HTML report written to: {html_path}")

    if args.json:
        json_path = _resolve_config_path(first, f"{report_base}_report.json")
        write_json_report(findings, files_scanned, elapsed, json_path, skipped=skipped)
        print(f"JSON report written to: {json_path}")
        print(format_json(findings, files_scanned, elapsed, skipped=skipped))
    else:
        print(
            format_human(
                findings,
                files_scanned,
                elapsed,
                show_fix_suggest=args.fix_suggest,
                skipped=skipped,
            )
        )

    # HIGH blocks; MEDIUM/LOW only warn.
    return 1 if any(f.confidence == "HIGH" for f in findings) else 0


def scan_target_with_ui(
    ui: TerminalUI,
    path: str,
    fix_suggest: bool = False,
) -> None:
    from pathlib import Path

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
        findings, files_scanned, skipped = scan_path(
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
        Path(target),
        findings,
        files_scanned,
        elapsed,
        show_fix_suggest=fix_suggest,
        skipped=skipped,
    )


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
                scan_target_with_ui(ui, str(path), fix_suggest=args.fix_suggest)

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
                scan_target_with_ui(ui, str(path), fix_suggest=args.fix_suggest)

        elif choice == "3":
            ui.clear()
            ui.title("GIT PRE-COMMIT HOOK", "Protect commits from likely secrets")
            path = ui.ask_path("Git repository path")

            result = cmd_install_hook(argparse.Namespace(path=str(path)))

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

    if os.path.exists(hook_path) and not getattr(args, "force", False):
        print(
            f"Error: {hook_path} already exists. Re-run with --force to overwrite it.",
            file=sys.stderr,
        )
        return 1

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

    scan_p = subparsers.add_parser("scan", help="Scan one or more files/directories for secrets.")
    scan_p.add_argument("paths", nargs="+", help="File(s) or directory(ies) to scan.")
    scan_p.add_argument("--json", action="store_true", help="Output machine-readable JSON.")
    scan_p.add_argument("--fix-suggest", action="store_true", help="Show remediation suggestions.")
    scan_p.add_argument("--baseline", help="Path to baseline JSON file.")
    scan_p.add_argument("--update-baseline", action="store_true",
                        help="Accept current findings into the baseline.")
    scan_p.add_argument("--html-report", metavar="PATH", help="Write an HTML report to PATH.")
    scan_p.add_argument("--include-shell-history", action="store_true",
                        help="Also scan common shell history files (off by default).")
    scan_p.set_defaults(func=cmd_scan)

    ui_p = subparsers.add_parser("ui", help="Launch the interactive terminal interface.")
    ui_p.add_argument("--fix-suggest", action="store_true",
                      help="Show remediation suggestions in the UI.")
    ui_p.set_defaults(func=cmd_ui)

    hook_p = subparsers.add_parser("install-hook", help="Install as a Git pre-commit hook.")
    hook_p.add_argument("--path", default=".", help="Path to the Git repo root (default: .)")
    hook_p.add_argument("--force", action="store_true", help="Overwrite an existing hook.")
    hook_p.set_defaults(func=cmd_install_hook)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
