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


def terminal_supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def shorten_path(path: str, max_length: int = 72) -> str:
    if len(path) <= max_length:
        return path
    if max_length < 12:
        return path[:max_length]
    return "..." + path[-(max_length - 3):]


def safe_text(value: Any, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value)
    return text if text else default

def report_base_name(path):
    """Return a safe filename based on the scanned file or directory."""
    path = Path(path)

    if path.is_file():
        name = path.name

        # Preserve dotfiles such as .env
        if name.startswith(".") and name.count(".") == 1:
            name = name
        else:
            name = path.stem
    else:
        name = path.name

    # Remove characters that are invalid in Windows filenames
    name = re.sub(r'[<>:"/\\|?*]', "_", name)

    # Remove problematic trailing/leading filename characters
    name = name.strip(" ._")

    return name or "scan"


def report_filename(path, extension):
    """Generate a report filename based on the scan target."""
    base = report_base_name(path)
    return f"{base}_report.{extension}"

class TerminalUI:
    WIDTH = 78

    def __init__(self) -> None:
        self.use_color = terminal_supports_color()

    def style(self, text: str, *styles: str) -> str:
        if not self.use_color:
            return text
        return "".join(styles) + text + RESET

    def clear(self) -> None:
        # Avoid executing arbitrary terminal input; only fixed commands.
        print("\033[2J\033[H", end="")

    def line(self, character: str = "─") -> None:
        print(character * self.WIDTH)

    def box_top(self) -> None:
        print(self.style("╔" + "═" * (self.WIDTH - 2) + "╗", CYAN))

    def box_bottom(self) -> None:
        print(self.style("╚" + "═" * (self.WIDTH - 2) + "╝", CYAN))

    def title(self, title: str, subtitle: str = "") -> None:
        print()
        self.box_top()
        print(
            self.style(
                "║ " + title.center(self.WIDTH - 4) + " ║",
                CYAN,
                BOLD,
            )
        )
        if subtitle:
            print(
                self.style(
                    "║ " + subtitle.center(self.WIDTH - 4) + " ║",
                    CYAN,
                )
            )
        self.box_bottom()

    def section(self, name: str) -> None:
        print()
        print(self.style(f"  {name}", CYAN, BOLD))
        self.line()

    def success(self, message: str) -> None:
        print(f"  {self.style('✓', GREEN, BOLD)} {message}")

    def warning(self, message: str) -> None:
        print(f"  {self.style('!', YELLOW, BOLD)} {message}")

    def error(self, message: str) -> None:
        print(f"  {self.style('✗', RED, BOLD)} {message}")

    def info(self, message: str) -> None:
        print(f"  {self.style('•', CYAN)} {message}")

    def show_main_menu(self) -> str:
        self.clear()
        self.title(
            "S E C R E T S C A N",
            "Zero-Dependency Local Security Scanner",
        )
        print()
        print(self.style("  SECURITY TOOL", BOLD, CYAN))
        print()
        print("  [1]  Scan a project")
        print("  [2]  Scan a single file")
        print("  [3]  Install Git pre-commit hook")
        print("  [4]  About SecretScan")
        print("  [5]  Exit")
        print()
        return input("  Select an option: ").strip()

    def ask_path(self, prompt: str) -> Path:
        value = input(f"\n  {prompt}: ").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        return Path(value).expanduser()

    def validate_directory(self, path: Path) -> bool:
        return path.exists() and path.is_dir()

    def validate_file(self, path: Path) -> bool:
        return path.exists() and path.is_file()

    def show_target(self, path: Path, target_type: str) -> None:
        self.section("SCAN TARGET")
        print()
        print(f"  Type       : {target_type}")
        print(f"  Name       : {path.name}")
        print(f"  Location   : {path}")

    def show_project_preview(self, path: Path, max_entries: int = 30) -> None:
        self.section("PROJECT PREVIEW")
        try:
            entries = sorted(
                path.iterdir(),
                key=lambda item: (not item.is_dir(), item.name.lower()),
            )
        except OSError as exc:
            self.error(f"Unable to read project: {exc}")
            return

        if not entries:
            self.warning("The selected directory is empty.")
            return

        shown = entries[:max_entries]
        print()
        for entry in shown:
            print(f"  {'📁' if entry.is_dir() else '📄'}  {entry.name}")

        if len(entries) > len(shown):
            print()
            print(self.style(
                f"  ... and {len(entries) - len(shown)} more entries",
                DIM,
            ))

        print()
        self.info(f"Project entries visible: {len(entries)}")

    def confirm_scan(self, path: Path) -> bool:
        print()
        self.line()
        print(self.style("  Ready to scan:", BOLD))
        print(f"  {path}")
        self.line()
        answer = input("\n  Start security scan? [Y/n]: ").strip().lower()
        return answer in {"", "y", "yes"}

    def show_scan_start(self, path: Path) -> None:
        self.clear()
        self.title("S E C R E T S C A N", "Security analysis in progress")
        print()
        print(self.style("  TARGET", BOLD, CYAN))
        print()
        print(f"  {path}")
        print()
        self.line()
        print()
        print(self.style("  SCANNING...", BOLD, CYAN))
        print()
        print("  Analyzing files and detection rules.")
        print("  Binary, ignored and oversized files are skipped.")
        print()

    @staticmethod
    def _get(finding: Any, field: str, default: Any = None) -> Any:
        if isinstance(finding, dict):
            return finding.get(field, default)
        return getattr(finding, field, default)

    def finding_filepath(self, finding: Any) -> str:
        value = self._get(finding, "filepath")
        if value is None:
            value = self._get(finding, "file")
        return safe_text(value, "Unknown file")

    def finding_line(self, finding: Any) -> str:
        value = self._get(finding, "line_number")
        if value is None:
            value = self._get(finding, "line")
        return safe_text(value, "?")

    def finding_rule(self, finding: Any) -> str:
        value = self._get(finding, "rule_name")
        if value is None:
            value = self._get(finding, "rule")
        return safe_text(value, "Unknown rule")

    def finding_confidence(self, finding: Any) -> str:
        return safe_text(
            self._get(finding, "confidence"),
            "Unknown",
        ).upper()

    def finding_redacted(self, finding: Any) -> str:
        method = getattr(finding, "redacted", None)
        if callable(method):
            try:
                return str(method())
            except Exception:
                return "[REDACTED]"
        value = self._get(finding, "match_redacted")
        return safe_text(value, "[REDACTED]")

    def finding_context(self, finding: Any) -> str:
        return safe_text(
            self._get(finding, "line_context"),
            "[REDACTED CONTEXT UNAVAILABLE]",
        )

    def finding_suggestion(self, finding: Any) -> str:
        return safe_text(
            self._get(finding, "suggestion"),
            "",
        )

    def confidence_icon(self, confidence: str) -> str:
        confidence = confidence.upper()
        if confidence == "HIGH":
            return self.style("●", RED, BOLD)
        if confidence == "MEDIUM":
            return self.style("●", YELLOW, BOLD)
        if confidence == "LOW":
            return self.style("●", GREEN, BOLD)
        return self.style("●", DIM)

    def show_results(
        self,
        path: Path,
        findings: list[Any],
        files_scanned: int,
        elapsed: float,
        show_fix_suggest: bool = False,
    ) -> None:
        self.clear()
        self.title("S E C R E T S C A N", "Security scan complete")
        print()
        print(self.style("  TARGET", BOLD, CYAN))
        print()
        print(f"  {path}")
        print()
        self.line()

        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for finding in findings:
            confidence = self.finding_confidence(finding)
            counts[confidence if confidence in counts else "UNKNOWN"] += 1

        print()
        print(self.style("  SCAN SUMMARY", BOLD, CYAN))
        print()
        print(f"  {self.style('●', RED)} HIGH confidence   : {counts['HIGH']}")
        print(f"  {self.style('●', YELLOW)} MEDIUM confidence : {counts['MEDIUM']}")
        print(f"  {self.style('●', GREEN)} LOW confidence    : {counts['LOW']}")
        print(f"  {self.style('●', DIM)} UNKNOWN           : {counts['UNKNOWN']}")
        print()
        print(f"  Files scanned : {files_scanned}")
        print(f"  Findings      : {len(findings)}")
        print(f"  Scan time     : {elapsed:.4f} seconds")
        print()

        if not findings:
            self.line()
            print()
            print(self.style("  ✓ NO POTENTIAL SECRETS DETECTED", GREEN, BOLD))
            print()
            self.info("No configured detections were reported.")
            return

        self.line()
        print()
        print(self.style("  FINDINGS", BOLD, CYAN))
        print()

        for index, finding in enumerate(findings, start=1):
            confidence = self.finding_confidence(finding)
            rule = self.finding_rule(finding)
            filepath = self.finding_filepath(finding)
            line = self.finding_line(finding)

            print(
                f"  {index:>3}. "
                f"{self.confidence_icon(confidence)} "
                f"{confidence:<7} "
                f"{rule}"
            )
            print(f"       {shorten_path(filepath, 54)}:{line}")
            print(f"       Match: {self.finding_redacted(finding)}")
            print(f"       Context: {self.finding_context(finding)}")
            if show_fix_suggest:
                suggestion = self.finding_suggestion(finding)
                if suggestion:
                    print(f"       Suggestion: {suggestion}")
            print()

        self.line()

        if counts["HIGH"]:
            self.warning("HIGH confidence findings will return exit code 1.")
        else:
            self.info("Only warning-level findings were detected; exit code 0.")

    def show_finding_details(
        self,
        finding: Any,
        index: int,
        show_fix_suggest: bool = False,
    ) -> None:
        self.clear()
        self.title("FINDING DETAILS", f"Finding #{index}")

        confidence = self.finding_confidence(finding)
        print()
        print(self.style("  DETECTION INFORMATION", BOLD, CYAN))
        print()
        print(f"  Confidence : {self.confidence_icon(confidence)} {confidence}")
        print(f"  Rule       : {self.finding_rule(finding)}")
        print(f"  File       : {self.finding_filepath(finding)}")
        print(f"  Line       : {self.finding_line(finding)}")
        print()

        self.line()
        print()
        print(self.style("  REDACTED DETECTION", BOLD, CYAN))
        print()
        print(f"  Match   : {self.finding_redacted(finding)}")
        print(f"  Context : {self.finding_context(finding)}")
        print()
        self.warning("The potential secret value is redacted for safety.")

        if show_fix_suggest:
            suggestion = self.finding_suggestion(finding)
            if suggestion:
                print()
                print(self.style("  SUGGESTED FIX", BOLD, CYAN))
                print()
                print(f"  {suggestion}")

        print()
        self.line()
        print()
        self.info("Review the indicated file and line before committing or publishing.")
        print()
        input("  Press Enter to return to findings...")

    def choose_finding(self, findings: list[Any]) -> int | None:
        if not findings:
            return None

        print()
        print(self.style("  Enter a finding number to inspect.", DIM))
        print(self.style("  Enter B to go back.", DIM))
        value = input("\n  Selection: ").strip().lower()

        if value in {"", "b", "back"}:
            return None

        try:
            number = int(value)
        except ValueError:
            self.warning("Please enter a valid number.")
            self.pause()
            return None

        index = number - 1
        if not 0 <= index < len(findings):
            self.warning("That finding number does not exist.")
            self.pause()
            return None

        return index

    def export_json(
        self,
        path: Path,
        findings: list[Any],
        files_scanned: int,
        elapsed: float,
    ) -> None:
        output_path = path.parent / report_filename(path, "json")

        try:
            write_json_report(
                findings,
                files_scanned,
                elapsed,
                output_path,
            )
            self.success(f"JSON report saved to: {output_path}")
        except OSError as exc:
            self.error(f"Could not save JSON report: {exc}")

        self.pause()


    def export_html(
        self,
        path: Path,
        findings: list[Any],
        files_scanned: int,
        elapsed: float,
    ) -> None:
        output_path = path.parent / report_filename(path, "html")

        try:
            write_html_report(
                findings,
                files_scanned,
                elapsed,
                output_path,
                str(path),
            )
            self.success(f"HTML report saved to: {output_path}")
        except OSError as exc:
            self.error(f"Could not save HTML report: {exc}")

        self.pause()

    def findings_loop(
        self,
        path: Path,
        findings: list[Any],
        files_scanned: int,
        elapsed: float,
        show_fix_suggest: bool = False,
    ) -> None:
        while True:
            self.show_results(
                path,
                findings,
                files_scanned,
                elapsed,
                show_fix_suggest=show_fix_suggest,
            )

            print()
            self.line()
            print()
            print(self.style("  ACTIONS", BOLD, CYAN))
            print()
            print("  Enter a finding number to inspect it.")
            print("  [J] Export JSON report")
            print("  [H] Export HTML report")
            print("  [B] Back")
            print()

            value = input("  Selection: ").strip().lower()

            if value in {"b", "back", ""}:
                return

            if value in {"j", "json"}:
                self.export_json(
                    path,
                    findings,
                    files_scanned,
                    elapsed,
                )
                continue

            if value in {"h", "html"}:
                self.export_html(
                    path,
                    findings,
                    files_scanned,
                    elapsed,
                )
                continue

            try:
                number = int(value)
            except ValueError:
                self.warning(
                    "Please enter a finding number, J, H, or B."
                )
                self.pause()
                continue

            index = number - 1

            if not 0 <= index < len(findings):
                self.warning("That finding number does not exist.")
                self.pause()
                continue

            self.show_finding_details(
                findings[index],
                index + 1,
                show_fix_suggest=show_fix_suggest,
            )

    def show_about(self) -> None:
        self.clear()
        self.title("ABOUT SECRETSCAN", "Zero-Dependency Security Scanner")
        print()
        print("  SecretScan is a local developer-security tool")
        print("  designed to detect potential hardcoded secrets")
        print("  before they are committed or published.")
        print()
        print(self.style("  FEATURES", BOLD, CYAN))
        print()
        for item in (
            "Local recursive scanning",
            "Pattern and entropy detection",
            "Redacted values and redacted line context",
            ".gitignore and default directory filtering",
            ".bash_history / .zsh_history scanning",
            "Inline secretscan-ignore support",
            "Severity-aware exit codes",
            "Baseline support",
            "Fix suggestions",
            "JSON and HTML reports",
            "Git pre-commit integration",
            "TOML configuration",
            "Python standard library only",
            "No network calls",
        ):
            print(f"  • {item}")
        print()
        self.line()
        print()
        self.warning("A finding is not proof that a value is active.")
        print()
        self.pause()

    def pause(self) -> None:
        input("\n  Press Enter to continue...")


def validate_target(path: Path, expect_directory: bool = True) -> bool:
    if not path.exists():
        return False
    return path.is_dir() if expect_directory else path.is_file()
