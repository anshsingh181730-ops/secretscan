# secretscan

A zero-dependency local secrets leak scanner. Catches hardcoded API keys,
tokens, private keys, and other high-entropy secrets in your codebase —
before they get committed — using nothing but the Python standard
library.

**Track:** E — Security & Crypto Utilities
**Language:** Python 3.10+ (developed and tested on 3.12, targets 3.14)
**Team size:** 4


## The Problem

Developers accidentally commit secrets to version control constantly —
an AWS key left in a config file, a Slack token pasted in for a quick
test, a `.env` file that was never added to `.gitignore`. Existing
scanners (`gitleaks`, `detect-secrets`, `truffleHog`) solve this well,
but they are themselves dependencies you have to install — binaries to
download, or packages to `pip install`. That's a little ironic for a
*security* tool. `secretscan` needs nothing beyond a Python interpreter
that's already on your machine.


## What It Does

### Detection Engine

Two layers of detection run together on every scanned line:

1. **Pattern matching** — recognizes known secret formats: AWS access
   keys, AWS secret keys, GitHub tokens, Slack tokens, private key
   headers, JWTs, and generic `key = "..."` style assignments.
2. **Entropy analysis** — flags quoted strings with high Shannon
   entropy ("looks random") even when they don't match a known format,
   catching custom or unusual secret formats pattern rules would miss.

Findings are always shown **redacted** (`AKIA****...MPLE`) — the full
secret is never printed to your terminal, logs, or any output file.


### Beyond Basic Detection

- **Line-level context** — every finding shows not just the file and
  line number, but the surrounding line itself (with the secret
  redacted in place), so you can see exactly what needs fixing without
  opening the file.
- **Shell history scanning** — optionally scans `.bash_history` /
  `.zsh_history` for secrets typed directly into the terminal
  (`export API_KEY=...`), a leak source most scanners ignore entirely.
- **Inline ignore comments** — mark an intentional test/dummy secret
  with `# secretscan-ignore` on the same line to exclude it from
  results, without disabling detection project-wide.
- **Severity-aware exit codes** — HIGH-confidence findings can gate a
  commit or CI pipeline; MEDIUM-confidence findings warn without
  blocking, so noisy heuristics don't stall a team's workflow.
- **Baseline file support** — accepted/reviewed findings can be
  recorded in `.secretscan-baseline.json` so re-scans don't repeatedly
  flag the same already-triaged result.
- **Fix suggestions** (`--fix-suggest`) — beyond pointing at the
  problem, the scanner suggests moving the value to `.env` and checks
  whether `.env` is already covered by `.gitignore`.
- **Scan summary output** — a concise end-of-run summary (files
  scanned, findings by severity, elapsed time) for quick confirmation
  a scan actually ran and what it covered.
- **`.gitignore`-aware scanning** — files already excluded from version
  control are skipped by default, since a file that can never be
  committed doesn't need to be flagged. Only files that could actually
  reach a commit are scanned — which is precisely why a `.env` file
  missing from `.gitignore` gets flagged: that's the exact scenario
  the tool exists to catch.


## How To Run It

No installation step required beyond Python itself.


### Getting the code

You can obtain the project either by cloning the repository or by
downloading it as a ZIP archive from GitHub:

```bash
git clone https://github.com/<your-org>/secretscan.git
cd secretscan
```

Or, from the GitHub repository page: **Code → Download ZIP**, then
extract the archive and open a terminal inside the extracted
`secretscan` folder before running any command below.


### Finding a file or folder's path (Windows)

Every command below takes a `<path>` argument pointing at the project
you want to scan. To get that path on Windows:

1. Open **File Explorer** and navigate to the file or folder you want
   to scan.
2. Click once on the **address bar** at the top (or right-click the
   file/folder and choose **Copy as path**).
3. The full path is now copied — paste it directly into your terminal
   command.
4. If the path contains spaces (e.g. `Smart Resume Builder`), wrap it
   in double quotes: `"C:\Users\you\Downloads\Smart Resume Builder"`.

On macOS/Linux, right-click the file/folder and look for **Copy Path**
(Finder) or run `pwd` inside the target folder in a terminal (Linux).


### Common commands

```bash
# Scan a single file
python3 secretscan.py scan config.py

# Scan an entire project directory (recursively)
python3 secretscan.py scan ./my-project

# Scan a folder on Windows with a path containing spaces
python3 secretscan.py scan "C:\Users\you\Downloads\Smart Resume Builder"

# Machine-readable output, for CI pipelines
python3 secretscan.py scan ./my-project --json

# Include fix suggestions alongside findings
python3 secretscan.py scan ./my-project --fix-suggest

# Also scan shell history for leaked secrets
python3 secretscan.py scan ./my-project --include-shell-history

# Install as a git pre-commit hook
python3 secretscan.py install-hook --path .
```

Note: on Windows, use `python` instead of `python3` if your Python
installation registers itself under that name.

Or with `make` (Linux/macOS, or Windows with `make` installed):

```bash
make run PATH=./my-project
make test                  # run the full test suite
make verify-zero-deps      # prove zero third-party dependencies
make install-hook          # install as a git pre-commit hook
```

**Exit codes:** `0` = clean or only MEDIUM/low-severity findings,
`1` = at least one HIGH-confidence secret found. This lets CI pipelines
and git hooks gate on real risk rather than treating every heuristic
match as a hard failure.

---


## Marking a Known-Safe Line

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"  # secretscan-ignore
```

Use sparingly, and only for genuinely intentional test/dummy values —
this is an escape hatch, not a way to silence real findings.

## What It Ignores

- `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`,
  `build`, and common cache directories — always skipped.
- Anything matched by patterns in a `.gitignore` at the scan root —
  since a file that can't be committed doesn't need flagging.
- Binary file extensions (images, archives, compiled binaries, fonts,
  media files).
- Files larger than 5 MB (very unlikely to be hand-written source).
- Lines explicitly marked with `# secretscan-ignore`.
- Findings already recorded in `.secretscan-baseline.json`.

## Honest Limitations

This is a heuristic scanner, not a guarantee. Being upfront about where
it falls short:

- **False positives happen.** A sufficiently random-looking string (a
  hash, a UUID, test fixture data) can trigger the entropy detector.
  This is a known, accepted trade-off in every secret scanner,
  including the popular ones — catching more real secrets means
  tolerating some noise. Severity levels and the baseline file exist
  specifically to make this manageable in practice.
- **False negatives happen too.** A secret split across multiple
  lines, heavily obfuscated, or in a format not covered by our pattern
  list (`PATTERN_RULES` in `src/rules.py`) will be missed. This tool is
  a safety net, not a substitute for careful review or a secrets
  manager.
- **Entropy threshold is a tuned constant** (4.3 bits/char, 20-char
  minimum), not a proven-optimal value. Hex-only strings (16 possible
  symbols) cap out near 4.0 bits/char and can fall just under this
  threshold — a limitation we found during our own testing against
  real-shaped fake tokens, not just a theoretical edge case.
- **No network calls, ever.** This is a design choice, not just a
  limitation — the tool never phones home, never validates whether a
  key is "live," and never sends your code anywhere. Detection is
  100% local pattern/entropy analysis, verifiable by running with
  `python -S` (site-packages disabled) and confirming it still works.
- **`.gitignore` support is basic.** It uses `fnmatch` glob matching,
  not full gitignore-spec semantics (no negation patterns, no
  directory-only markers). Good enough for common cases, not a full
  implementation.
- **Shell history scanning is opt-in and best-effort.** History file
  formats vary by shell and configuration; we handle the common
  `.bash_history` / `.zsh_history` cases, not every possible setup.


## Project Layout

```
secretscan/
  README.md
  STDLIB.md
  Makefile
  secretscan.py            # CLI entry point
  src/
    rules.py                # pattern + entropy detection rules
    scanner.py                # file/directory walking and scan orchestration
    reporter.py                 # human-readable + JSON output formatting
  tests/
    test_scanner.py             # unittest suite
    fixtures/                     # sample files with fake secrets for testing
  requirements.txt           # empty — zero dependencies
  deps-proof.txt              # verification that no third-party package is used
  .zero-dep.toml                # track + pitch declaration
  .secretscan-baseline.json       # (generated) accepted findings, if used
```


## Testing

```bash
python3 -m unittest discover -s tests -v
```

The suite covers: every pattern rule against a known fake-secret
format, entropy detection on random vs. normal strings, redaction
correctness, directory-walk exclusions (`.git`, `node_modules`), and
false-positive checks on ordinary code.

All test fixtures use **fake secrets only** — no real credentials are
used anywhere in this repository. The AWS example key
(`AKIAIOSFODNN7EXAMPLE`) is AWS's own published example key, safe to
use in test code.


## Why Zero Dependencies, For a Security Tool Specifically

A tool whose entire job is catching supply-chain and credential risk
shouldn't itself add supply-chain surface area. Every package you
install is code you didn't write and don't fully audit, running with
access to your source tree. `secretscan` runs with nothing beyond the
Python interpreter already on your machine — verified by running it
with `python -S`, which disables site-packages entirely and confirms
the tool still works correctly.
