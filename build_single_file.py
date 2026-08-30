#!/usr/bin/env python3
"""
build_single_file.py — deterministic single-file bundler for secretscan.

Merges secretscan.py + everything under src/ into ONE standalone file:
dist/secretscan_single.py

Why this exists (hackathon bonus challenges):
  - "Single File (+5)": the output of this script is the entire project
    as one genuinely useful, runnable source file.
  - "Reproducible Build (+5)": this script is fully deterministic (fixed
    module order, no timestamps, no environment-dependent output,
    stable sorting of collected imports), so running it twice produces
    byte-identical output. See scripts/verify_reproducible_build.sh.

This script itself is stdlib-only (ast, pathlib) — bundling the project
does not add a third-party dependency to the project.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "src"
OUT_DIR = ROOT / "dist"
OUT_FILE = OUT_DIR / "secretscan_single.py"

# Fixed, dependency-respecting order:
#   rules     -> no local deps
#   config    -> no local deps
#   reporter  -> no local deps
#   scanner   -> depends on rules (is_inline_ignored)
#   terminal_ui -> depends on reporter (write_json_report, write_html_report)
#   secretscan (entrypoint) -> depends on all of the above
MODULE_ORDER = ["rules", "config", "reporter", "scanner", "terminal_ui"]

# Local module names that must NOT be imported in the bundle (they are
# inlined instead). Any `import X` / `from X import ...` referencing one
# of these is stripped.
LOCAL_MODULES = {"config", "reporter", "rules", "scanner", "terminal_ui"}


def split_docstring(tree: ast.Module, source_lines: list[str]) -> tuple[str | None, int]:
    """Return (docstring_text_or_None, first_line_after_docstring_0indexed)."""
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        node = tree.body[0]
        return ast.get_source_segment("\n".join(source_lines), node), node.end_lineno
    return None, 0


def strip_imports(source: str) -> tuple[str, set[str]]:
    """
    Remove all top-level import / from-import lines from `source`.
    Returns (remaining_source, set_of_external_import_statements_kept_as_text).
    Local-module imports (config/reporter/rules/scanner/terminal_ui) are
    dropped entirely since those modules are inlined into the bundle.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    external_imports: set[str] = set()
    remove_line_ranges: list[tuple[int, int]] = []

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            remove_line_ranges.append((node.lineno, node.end_lineno))
            if node.module not in LOCAL_MODULES and node.module != "__future__":
                names = ", ".join(
                    (a.name if a.asname is None else f"{a.name} as {a.asname}")
                    for a in node.names
                )
                external_imports.add(f"from {node.module} import {names}")
        elif isinstance(node, ast.Import):
            remove_line_ranges.append((node.lineno, node.end_lineno))
            for alias in node.names:
                if alias.name not in LOCAL_MODULES:
                    stmt = f"import {alias.name}" if alias.asname is None else f"import {alias.name} as {alias.asname}"
                    external_imports.add(stmt)

    remove_lines = set()
    for start, end in remove_line_ranges:
        for ln in range(start, end + 1):
            remove_lines.add(ln)

    kept = [line for i, line in enumerate(lines, start=1) if i not in remove_lines]
    return "\n".join(kept), external_imports


def strip_sys_path_block(source: str) -> str:
    """Remove the `SRC_DIR = ...` / `sys.path.insert(...)` block that only
    exists so the modular secretscan.py can find src/ at runtime. Not
    needed once everything lives in one file."""
    marker_start = 'SRC_DIR = os.path.join'
    marker_end_snippet = 'sys.path.insert(0, SRC_DIR)'
    lines = source.splitlines()
    out = []
    skipping = False
    for line in lines:
        if marker_start in line:
            skipping = True
            continue
        if skipping:
            if marker_end_snippet in line:
                skipping = False
            continue
        out.append(line)
    return "\n".join(out)


def build() -> Path:
    all_external_imports: set[str] = set()
    module_bodies: dict[str, str] = {}

    for name in MODULE_ORDER:
        text = (SRC / f"{name}.py").read_text(encoding="utf-8")
        tree = ast.parse(text)
        lines = text.splitlines()
        _doc, after = split_docstring(tree, lines)
        body_source = "\n".join(lines[after:])
        stripped, ext = strip_imports(body_source)
        all_external_imports |= ext
        module_bodies[name] = stripped.strip("\n")

    entry_text = (ROOT / "secretscan.py").read_text(encoding="utf-8")
    entry_tree = ast.parse(entry_text)
    entry_lines = entry_text.splitlines()
    entry_doc, after = split_docstring(entry_tree, entry_lines)
    entry_body = "\n".join(entry_lines[after:])
    entry_body = strip_sys_path_block(entry_body)
    entry_stripped, entry_ext = strip_imports(entry_body)
    all_external_imports |= entry_ext

    ordered_imports = sorted(all_external_imports)

    header = (
        (entry_doc or '"""secretscan — zero-dependency local secrets leak scanner."""')
        + "\n\n"
        + "# NOTE: this file is generated by build_single_file.py from secretscan.py\n"
        + "# and src/*.py. Edit those sources, not this file, then re-run the build.\n"
        + "# Build is deterministic: two runs produce byte-identical output — see\n"
        + "# scripts/verify_reproducible_build.sh.\n\n"
        + "from __future__ import annotations\n\n"
        + "\n".join(ordered_imports)
        + "\n"
    )

    sections = []
    for name in MODULE_ORDER:
        sections.append(f"\n\n# {'=' * 76}\n# --- {name}.py " + "-" * max(0, 60 - len(name)) + "\n" + f"# {'=' * 76}\n\n" + module_bodies[name])

    sections.append(
        "\n\n# " + "=" * 76 + "\n# --- secretscan.py (entrypoint) " + "-" * 42 + "\n# " + "=" * 76 + "\n\n" + entry_stripped.strip("\n")
    )

    bundled = header + "".join(sections) + "\n"

    OUT_DIR.mkdir(exist_ok=True)
    OUT_FILE.write_bytes(bundled.encode("utf-8"))
    return OUT_FILE


if __name__ == "__main__":
    path = build()
    print(f"Wrote {path} ({path.stat().st_size} bytes)")
