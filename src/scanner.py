"""
scanner.py — Core scanning logic for SecretScan.

Standard-library-only scanner with:
- recursive directory scanning
- .gitignore-aware filtering
- binary/oversize skipping
- .bash_history / .zsh_history scanning (opt-in)
- inline ignore support
- safe redacted line context
- baseline fingerprints

No part of this module invokes an external tool (git, etc.) at
runtime. Staged-file scanning is handled entirely by the pre-commit
hook shell script (see secretscan.py's PRE_COMMIT_HOOK_TEMPLATE),
which passes the already-staged file list to `scan` as ordinary
positional arguments. That keeps the git interaction inside git's own
hook mechanism instead of making this artifact shell out to git
itself — see STDLIB.md for the reasoning.
"""

from __future__ import annotations

import hashlib
import re
import os

from rules import is_inline_ignored


DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".exe", ".dll", ".so", ".pyc", ".woff", ".woff2", ".ttf",
    ".mp4", ".mp3", ".bin", ".class", ".jar", ".7z", ".rar", ".webp",
    ".mov", ".avi", ".wasm", ".dylib",
}

# Common shell history filenames.  History is still opt-in because it can
# contain sensitive commands/arguments unrelated to the project being scanned.
HISTORY_FILENAMES = {
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".ksh_history",
    ".mksh_history",
    ".ash_history",
    ".csh_history",
    ".tcsh_history",
    ".history",
    "fish_history",
    "ConsoleHost_history.txt",  # PowerShell / PSReadLine
}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def _read_gitignore(path):
    """Read one .gitignore file, preserving rule order."""
    patterns = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\r\n")
                if not line or line.lstrip().startswith("#"):
                    continue
                patterns.append(line)
    except OSError:
        pass
    return patterns


def load_ignore_patterns(root: str):
    """Read .gitignore rules from the scan root and its subdirectories.

    Git applies a .gitignore to the directory containing it and everything
    below that directory.  We keep the source directory with every rule so
    rooted patterns and nested .gitignore files behave correctly.
    """
    root = os.path.abspath(root)
    result = []

    if os.path.isfile(root):
        root = os.path.dirname(root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE_DIRS]
        if ".gitignore" in filenames:
            ignore_path = os.path.join(dirpath, ".gitignore")
            base = os.path.relpath(dirpath, root).replace(os.sep, "/")
            if base == ".":
                base = ""
            for pattern in _read_gitignore(ignore_path):
                result.append((base, pattern))

    return result


def _glob_to_regex(pattern: str) -> str:
    """Translate the glob subset used by .gitignore into a path regex.

    Unlike fnmatch, '*' and '?' never cross '/' boundaries.  '**' can cross
    directory boundaries, which is the important semantic difference for
    gitignore compatibility.
    """
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                while i + 1 < len(pattern) and pattern[i + 1] == "*":
                    i += 1
                if i + 1 < len(pattern) and pattern[i + 1] == "/":
                    i += 1
                    out.append(r"(?:.*/)?")
                else:
                    out.append(r".*")
            else:
                out.append(r"[^/]*")
        elif char == "?":
            out.append(r"[^/]")
        elif char == "[":
            end = pattern.find("]", i + 1)
            if end != -1:
                cls = pattern[i:end + 1]
                if cls.startswith("[!"):
                    cls = "[^" + cls[2:]
                out.append(cls)
                i = end
            else:
                out.append(r"\[")
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def _gitignore_rule_matches(relpath: str, pattern: str, is_dir: bool) -> bool:
    """Return whether one gitignore rule matches this path."""
    pattern = pattern.strip().replace("\\", "/")
    if not pattern or pattern.startswith("#"):
        return False

    if pattern.startswith("!"):
        pattern = pattern[1:]
        if not pattern:
            return False

    directory_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if directory_only and not is_dir:
        # A directory-only pattern also excludes descendants of that
        # directory, so the caller checks ancestors separately.
        return False

    pattern = pattern.lstrip("/")

    # A pattern containing no slash is a basename rule and applies at every
    # directory level.  Otherwise it is relative to the .gitignore location.
    if "/" not in pattern:
        regex = _glob_to_regex(pattern)
        return re.fullmatch(regex, os.path.basename(relpath)) is not None

    regex = _glob_to_regex(pattern)
    return re.fullmatch(regex, relpath) is not None


def _path_matches_gitignore_rule(
    relpath: str,
    pattern: str,
    is_dir: bool,
) -> bool:
    """Match a rule against a path, including directory descendants."""
    pattern = pattern.strip().replace("\\", "/")
    if not pattern:
        return False

    directory_only = pattern.endswith("/")

    if directory_only:
        # A directory-only rule matches the named directory or anything
        # below it.  This is why "build/" ignores build/app.py too.
        candidates = [relpath]
        parts = relpath.split("/")
        candidates.extend("/".join(parts[:i]) for i in range(1, len(parts)))
        return any(
            _gitignore_rule_matches(candidate, pattern, True)
            for candidate in candidates
        )

    return _gitignore_rule_matches(relpath, pattern, is_dir)


def is_ignored_by_patterns(relpath: str, patterns, is_dir=False) -> bool:
    """Apply gitignore rules in order, including negation rules.

    `patterns` may be the structured output of load_ignore_patterns() or the
    legacy list-of-strings form used by older callers/tests.  Later rules
    override earlier rules, so `*.log` followed by `!important.log` works.
    """
    relpath = relpath.replace(os.sep, "/").lstrip("./")
    ignored = False

    if patterns and isinstance(patterns[0], tuple):
        rules = patterns
    else:
        rules = [("", pattern) for pattern in patterns]

    for base, raw_pattern in rules:
        pattern = raw_pattern.strip().replace("\\", "/")
        if not pattern or pattern.startswith("#"):
            continue

        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
            if not pattern:
                continue

        # Convert the path into the coordinate system of this .gitignore.
        if base:
            prefix = base.rstrip("/") + "/"
            if relpath != base and not relpath.startswith(prefix):
                continue
            local_path = relpath[len(prefix):] if relpath.startswith(prefix) else ""
        else:
            local_path = relpath

        if _path_matches_gitignore_rule(local_path, pattern, is_dir):
            ignored = not negated

    return ignored


# Reasons a file can be excluded from a scan. Every one of these used
# to be silent — no count, no listing, anywhere in CLI/JSON/HTML
# output — so a secret in, say, a file just over the 5MB cap would
# disappear with zero signal. SkipLog (below) exists to close that gap.
SKIP_REASON_BINARY = "binary_extension"
SKIP_REASON_GITIGNORE = "gitignore_match"
SKIP_REASON_OVERSIZE = "oversize"
SKIP_REASON_UNREADABLE = "unreadable"
SKIP_REASON_HISTORY_EXCLUDED = "shell_history_excluded"
SKIP_REASON_IGNORED_DIR = "ignored_directory"

SKIP_REASON_LABELS = {
    SKIP_REASON_BINARY: "binary extension",
    SKIP_REASON_GITIGNORE: ".gitignore match",
    SKIP_REASON_OVERSIZE: "over size limit",
    SKIP_REASON_UNREADABLE: "unreadable",
    SKIP_REASON_HISTORY_EXCLUDED: "shell history (excluded by default)",
    SKIP_REASON_IGNORED_DIR: "inside a default-ignored directory (build/, node_modules/, .git/, etc.)",
}

# Cap on how many individual skipped paths we remember for reporting —
# counts are always exact and complete; the sample list is just there
# so a report can point at a few concrete examples without holding
# every skipped path (potentially thousands) in memory.
MAX_SKIP_SAMPLES = 25


class SkipLog:
    """Tracks files excluded from a scan, with exact counts per reason
    and a capped sample of individual paths for reporting."""

    __slots__ = ("counts", "samples")

    def __init__(self):
        self.counts = {}
        self.samples = []

    def record(self, fpath: str, reason: str) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + 1
        if len(self.samples) < MAX_SKIP_SAMPLES:
            self.samples.append({"path": fpath, "reason": reason})

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "counts": dict(self.counts),
            "samples": list(self.samples),
        }


def _file_skip_reason(fpath: str, relpath: str, ignore_patterns, include_history: bool):
    """Return why fpath would be excluded, or None if it's eligible."""
    fname = os.path.basename(fpath)
    ext = os.path.splitext(fname)[1].lower()
    is_history_file = fname in HISTORY_FILENAMES

    if is_history_file and not include_history:
        return SKIP_REASON_HISTORY_EXCLUDED

    if ext in BINARY_EXTENSIONS and not is_history_file:
        return SKIP_REASON_BINARY

    if is_ignored_by_patterns(relpath, ignore_patterns):
        return SKIP_REASON_GITIGNORE

    try:
        if os.path.getsize(fpath) > MAX_FILE_SIZE_BYTES:
            return SKIP_REASON_OVERSIZE
    except OSError:
        return SKIP_REASON_UNREADABLE

    return None


def iter_target_files(
    root: str,
    extra_ignore_dirs=None,
    max_file_size_bytes=None,
    include_history=False,
    skip_log: "SkipLog | None" = None,
):
    """Yield eligible files under root.

    Shell history files (.bash_history, .zsh_history) are skipped by
    default — set include_history=True (--include-shell-history on
    the CLI) to opt in, since scanning a user's shell history is more
    invasive than scanning a project's own source files.

    Pass a SkipLog to also record every file this walk excludes and
    why (binary extension, .gitignore match, over the size cap, or
    unreadable) — otherwise files are excluded exactly as before, just
    without a record of it.
    """
    if os.path.isfile(root):
        yield root
        return

    ignore_patterns = load_ignore_patterns(root)
    ignored_dirs = set(DEFAULT_IGNORE_DIRS) | set(extra_ignore_dirs or [])
    max_size = max_file_size_bytes or MAX_FILE_SIZE_BYTES

    for dirpath, dirnames, filenames in os.walk(root):
        pruned = [d for d in dirnames if d in ignored_dirs]
        dirnames[:] = [d for d in dirnames if d not in ignored_dirs]

        if skip_log is not None:
            for d in pruned:
                # Record the directory itself, once, rather than walking
                # into it just to count files — that would defeat the
                # point of pruning it. This still gives visibility (the
                # path and the fact that an entire subtree was excluded)
                # instead of the previous behavior, where files inside
                # build/, node_modules/, .git/, dist/, venv/, etc. vanished
                # from every report with no signal anywhere.
                skip_log.record(os.path.join(dirpath, d), SKIP_REASON_IGNORED_DIR)

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            relpath = os.path.relpath(fpath, root)

            reason = _file_skip_reason(fpath, relpath, ignore_patterns, include_history)
            if reason is not None:
                if skip_log is not None:
                    skip_log.record(fpath, reason)
                continue

            try:
                if os.path.getsize(fpath) > max_size:
                    if skip_log is not None:
                        skip_log.record(fpath, SKIP_REASON_OVERSIZE)
                    continue
            except OSError:
                if skip_log is not None:
                    skip_log.record(fpath, SKIP_REASON_UNREADABLE)
                continue

            yield fpath


def _redact_line(line: str, spans) -> str:
    """Redact all detected secret spans from a source line."""
    if not spans:
        return line.rstrip("\r\n")

    merged = []
    for start, end in sorted(spans):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    pieces = []
    cursor = 0
    for start, end in merged:
        pieces.append(line[cursor:start])
        pieces.append("[REDACTED]")
        cursor = end
    pieces.append(line[cursor:])

    return "".join(pieces).rstrip("\r\n")


def finding_fingerprint(filepath: str, root: str, line_number: int,
                        rule_name: str, matched_text: str) -> str:
    """
    Stable non-reversible identifier for a finding.

    The raw secret is only used as input to SHA-256 and is never stored.
    """
    try:
        relpath = os.path.relpath(filepath, root).replace(os.sep, "/")
    except ValueError:
        relpath = os.path.abspath(filepath)

    material = "\0".join(
        [relpath, str(line_number), rule_name, matched_text]
    )
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()


class Finding:
    """A detected potential secret; raw value remains in memory only."""

    __slots__ = (
        "filepath",
        "line_number",
        "rule_name",
        "matched_text",
        "confidence",
        "line_context",
        "fingerprint",
        "suggestion",
    )

    def __init__(
        self,
        filepath,
        line_number,
        rule_name,
        matched_text,
        confidence,
        line_context="",
        fingerprint="",
        suggestion="",
    ):
        self.filepath = filepath
        self.line_number = line_number
        self.rule_name = rule_name
        self.matched_text = matched_text
        self.confidence = confidence
        self.line_context = line_context
        self.fingerprint = fingerprint
        self.suggestion = suggestion

    def redacted(self):
        """Return only a masked representation of the detected value."""
        t = self.matched_text
        if len(t) <= 8:
            return "*" * len(t)
        return t[:4] + "*" * (len(t) - 8) + t[-4:]


def _suggestion_for(rule_name: str) -> str:
    """Return a remediation suggestion without exposing any secret."""
    if rule_name == "Private Key Header":
        return "Move the private key to a secure secret store and rotate it if exposed."
    if rule_name == "JWT Token":
        return "Do not commit the token; use environment/configured secrets and rotate it if real."
    if rule_name.startswith("AWS"):
        return "Move AWS credentials to the AWS credential chain/environment and rotate them if real."
    if rule_name == "GitHub Token":
        return "Move the token to a secure secret store and revoke/rotate it if real."
    if rule_name == "Slack Token":
        return "Move the token to a secure secret store and revoke/rotate it if real."
    if rule_name.startswith("High-entropy"):
        return "Move the value to an environment variable or secret manager; verify it is not a test value."
    return "Move the value to an environment variable or secret manager and keep it out of source control."


def _normalize_match(item, line: str):
    """Normalize a (name, text, confidence[, span]) match tuple to 4-tuple form.

    Both find_pattern_matches() and find_entropy_matches() return 4-tuples
    that already include a span, but scan_file() also accepts the legacy
    3-tuple form (used by simpler custom finders, including in tests) by
    locating the matched text in the line itself.
    """
    if len(item) == 4:
        return item
    name, matched_text, confidence = item
    idx = line.find(matched_text)
    span = (idx, idx + len(matched_text)) if idx >= 0 else (0, 0)
    return name, matched_text, confidence, span


def scan_file(filepath: str, pattern_finder, entropy_finder, root=None):
    """Scan one text file and return Finding objects."""
    findings = []
    root = root or os.path.dirname(os.path.abspath(filepath))

    try:
        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as handle:
            for line_number, line in enumerate(handle, start=1):
                pattern_matches = pattern_finder(line)
                spans = []

                for item in pattern_matches:
                    name, matched_text, confidence, span = _normalize_match(item, line)
                    spans.append(span)

                    # A rule-specific ignore can suppress just this finding.
                    if is_inline_ignored(line, name):
                        continue

                    findings.append(
                        Finding(
                            filepath,
                            line_number,
                            name,
                            matched_text,
                            confidence,
                        )
                    )

                entropy_matches = entropy_finder(line, spans)

                for item in entropy_matches:
                    name, matched_text, confidence, span = _normalize_match(item, line)

                    if is_inline_ignored(line, name):
                        continue

                    spans.append(span)
                    findings.append(
                        Finding(
                            filepath,
                            line_number,
                            name,
                            matched_text,
                            confidence,
                        )
                    )

                if findings:
                    line_findings = [
                        f for f in findings
                        if f.filepath == filepath
                        and f.line_number == line_number
                    ]
                    context = _redact_line(line, spans)
                    for finding in line_findings:
                        finding.line_context = context
                        finding.fingerprint = finding_fingerprint(
                            filepath,
                            root,
                            line_number,
                            finding.rule_name,
                            finding.matched_text,
                        )
                        finding.suggestion = _suggestion_for(
                            finding.rule_name
                        )

    except (OSError, UnicodeError):
        pass

    return findings


def scan_path(
    roots,
    pattern_finder,
    entropy_finder,
    extra_ignore_dirs=None,
    max_file_size_bytes=None,
    include_history=False,
):
    """
    Scan one or more files/directories and return
    (findings, files_scanned, skip_log).

    `roots` may be a single path string or a list of path strings —
    the pre-commit hook passes a list of already-staged files here
    (obtained by the hook script itself via `git diff --cached`), so
    this module never needs to query git directly.

    skip_log is a SkipLog recording every file excluded from the scan
    (binary extension, .gitignore match, over the size cap, unreadable,
    or shell-history-excluded) and why, so callers can surface that
    instead of it disappearing silently.
    """
    if isinstance(roots, str):
        roots = [roots]

    all_findings = []
    files_scanned = 0
    skip_log = SkipLog()

    for root in roots:
        root = os.path.abspath(root)
        scan_root = root if os.path.isdir(root) else os.path.dirname(root)

        for filepath in iter_target_files(
            root,
            extra_ignore_dirs,
            max_file_size_bytes,
            include_history,
            skip_log=skip_log,
        ):
            files_scanned += 1
            all_findings.extend(
                scan_file(
                    filepath,
                    pattern_finder,
                    entropy_finder,
                    root=scan_root,
                )
            )

    return all_findings, files_scanned, skip_log


def apply_baseline(findings, baseline):
    """Remove findings whose fingerprint is already accepted."""
    if not baseline:
        return list(findings)

    accepted = set(baseline.get("fingerprints", []))
    return [
        finding for finding in findings
        if finding.fingerprint not in accepted
    ]
