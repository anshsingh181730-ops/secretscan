# secretscan

A zero-dependency local secrets leak scanner. Catches hardcoded API keys, tokens, private keys, and other high-entropy secrets in your codebase — before they get committed — using nothing but the Python standard library.

**Track:** E — Security & Crypto Utilities  
**Language:** Python 3.11+ (developed and tested on 3.12, targets 3.14)  
**Team size:** 4

## The Problem

Developers accidentally commit secrets to version control constantly — an AWS key left in a config file, a Slack token pasted in for a quick test, or a `.env` file that was never added to `.gitignore`.

Existing scanners such as `gitleaks`, `detect-secrets`, and `truffleHog` solve this well, but they require additional dependencies or binaries.

`secretscan` needs nothing beyond a Python interpreter that's already on your machine.

## What It Does

### Detection Engine

1. **Pattern matching** — recognizes common secret formats across cloud, source-control, SaaS, authentication, key-material, and database families, including AWS, Google, Azure, GitHub, GitLab, Bitbucket, Slack, Discord, Stripe, SendGrid, npm, PyPI, Twilio, Heroku, Mailgun, Shopify, OpenAI, Hugging Face, Databricks, JWT, Bearer, Basic credentials, private keys, generic credential assignments, authorization headers, and database credential URLs.

2. **Entropy analysis** — checks quoted strings that look random even when they do not match a known provider format. Entropy findings use conservative context rules to reduce false positives.

### Beyond Basic Detection

- **Line-level context** — findings include the file, line number, and surrounding line with the secret redacted.

- **Shell history scanning** — optionally scans common shell history files for secrets typed directly into the terminal.

- **Inline ignore comments** — use `# secretscan-ignore` on a line containing an intentional test value.

- **Severity-aware exit codes** — HIGH-confidence findings return exit code `1`; clean or MEDIUM/low findings return `0`.

- **Baseline support** — reviewed findings can be recorded in `.secretscan-baseline.json`.

- **Fix suggestions** — `--fix-suggest` suggests moving secrets to `.env` and checks `.gitignore` coverage.

- **Scan summary** — reports files scanned, findings by severity, skipped files, and elapsed time.

- **`.gitignore`-aware scanning** — files excluded by `.gitignore` are skipped by default.

- **Skipped-file reporting** — skipped files are counted and categorized instead of silently disappearing.

## How To Run It

No installation step is required beyond Python.

### Getting the Code

```bash
git clone https://github.com/anshsingh181730-ops/secretscan.git
cd secretscan
```

Or download the repository using **GitHub → Code → Download ZIP**, extract it, and open a terminal inside the `secretscan` folder.

### Windows

On Windows, use `python` instead of `python3`.

## Running SecretScan

### Scan a Single File

```bash
python secretscan.py scan config.py
```

Example:

```bash
python secretscan.py scan "C:\Users\you\Downloads\config.py"
```

### Scan an Entire Folder

```bash
python secretscan.py scan ./my-project
```

Windows example:

```bash
python secretscan.py scan "C:\Users\you\Downloads\my-project"
```

### JSON Output

For CI pipelines or machine-readable output:

```bash
python secretscan.py scan ./my-project --json
```

### Fix Suggestions

```bash
python secretscan.py scan ./my-project --fix-suggest
```

### Scan Shell History

```bash
python secretscan.py scan ./my-project --include-shell-history
```

### Interactive Terminal UI

Launch the interactive terminal UI with:

```bash
python secretscan.py
```

If the CLI provides the explicit `ui` command, you can also use:

```bash
python secretscan.py ui
```

The UI allows you to select/load a file or project directory and start a scan interactively.

For a direct scan without the UI:

```bash
python secretscan.py scan "PATH_TO_FILE_OR_FOLDER"
```

Example:

```bash
python secretscan.py scan "C:\Users\JohnDoe\Downloads\my-project"
```

## Finding a File or Folder Path on Windows

1. Open **File Explorer**.
2. Navigate to the file or folder.
3. Click the address bar.
4. Copy the full path.
5. Paste it into the command.
6. If the path contains spaces, keep it inside double quotes.

Example:

```text
"C:\Users\JohnDoe\Downloads\Smart Resume Builder"
```

## Git Pre-Commit Hook

Install the SecretScan pre-commit hook:

```bash
python secretscan.py install-hook --path .
```

After installation, SecretScan automatically checks staged files before a commit.

A commit containing a HIGH-confidence secret is blocked.

## Exit Codes

```text
0 = clean or only MEDIUM/low-severity findings
1 = at least one HIGH-confidence secret found
```

This allows SecretScan to be used in CI pipelines and Git hooks.

## Marking a Known-Safe Line

For intentional test or dummy secrets, add `# secretscan-ignore`:

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"  # secretscan-ignore
```

Use this only for genuinely safe test values.

## What It Ignores

SecretScan skips:

- `.git`
- `node_modules`
- `__pycache__`
- `.venv`
- `venv`
- `dist`
- `build`
- common cache directories
- files matched by `.gitignore`
- binary files
- files larger than 5 MB
- lines containing `# secretscan-ignore`
- findings already recorded in `.secretscan-baseline.json`

The pre-commit hook scans the actual staged files directly, so force-added ignored files can still be checked.

## Bugs Found And Fixed

### Unquoted Filenames in the Git Hook

The generated hook previously mishandled filenames containing spaces or filenames beginning with `-`.

The hook was changed to use NUL-delimited staged filenames and `--` so filenames are safely passed to the scanner.

An integration test covers this case.

### Silently Skipped Files

Skipped files previously disappeared without being reported.

SecretScan now tracks skipped files and reports counts and reasons in human-readable, JSON, HTML, and UI output.

### Makefile PATH Issue

The README previously documented:

```bash
make run PATH=./my-project
```

`PATH` is a reserved environment variable, so this could break Python lookup.

The correct command is:

```bash
make run TARGET=./my-project
```

### `.gitignore` Semantics

The scanner supports ordered rules, negation, directory-only patterns, `**` globbing, and nested `.gitignore` files.

### Shell History Coverage

Shell history support was expanded beyond Bash and Zsh to cover common POSIX/sh, ksh/mksh, Fish, csh/tcsh, and PowerShell history files.

### HTML Report Path

`--html-report PATH` now writes the report exactly to the requested path.

## Honest Limitations

This is a heuristic scanner, not a guarantee.

- Entropy detection can still produce false positives.
- Detector coverage is finite and cannot recognize every vendor-specific credential format.
- Secrets split across multiple lines or heavily obfuscated may be missed.
- The entropy threshold is a tuned heuristic rather than a mathematically optimal value.
- The scanner does not validate whether a key is live.
- No network calls are made.
- `.gitignore` compatibility is implemented locally and is intended to be practical rather than a byte-for-byte replacement for every Git edge case.
- Shell history scanning is opt-in and best-effort.

SecretScan is a safety net, not a replacement for careful review or a secrets manager.

## Project Layout

```text
secretscan/
├── dist/
│   └── secretscan_single.py
├── examples/
│   └── sample-scan-report.json
├── scripts/
│   └── verify_reproducible_build.sh
├── src/
│   ├── config.py
│   ├── reporter.py
│   ├── rules.py
│   ├── scanner.py
│   └── terminal_ui.py
├── tests/
│   └── fixtures/
│     ├── clean_code.py
│     └── sample_leak.py
│   ├── test_scanner.py
├── .gitignore
├── .zero-dep.toml
├── LICENSE
├── Makefile
├── README.md
├── STDLIB.md
├── build_single_file.py
├── deps-proof.txt
├── requirements.txt
└── secretscan.py
```

## Single-File Build

The modular project can be bundled into one standalone Python file.

Build it with:

```bash
python build_single_file.py
```

Then run the generated standalone scanner:

```bash
python dist/secretscan_single.py scan <path>
```

Example:

```bash
python dist/secretscan_single.py scan ./my-project
```

The generated file contains the scanner, detection rules, reporting, configuration, terminal UI, and CLI functionality.

## Reproducible Build

The single-file build is deterministic.

Run:

```bash
sh scripts/verify_reproducible_build.sh
```

Two builds from the same source should produce byte-identical output.

Verified SHA256:

```text
Build #1: 1e44cd80b0d15e3b0599b19d15744eb7d60a66ab055ecd1aa669eb7d00fd4a22
Build #2: 1e44cd80b0d15e3b0599b19d15744eb7d60a66ab055ecd1aa669eb7d00fd4a22
```

If the source changes, rebuild and update the published hashes.

## Testing

Run the complete test suite with:

```bash
python -m unittest discover -s tests -v
```

The test suite covers:

- provider-specific secret patterns
- entropy detection
- false-positive handling
- secret redaction
- directory exclusions
- `.gitignore` behavior
- skipped-file tracking
- JSON output
- HTML output
- baseline support
- shell-history scanning
- pre-commit hook integration
- filenames containing spaces
- filenames beginning with `-`
- single-file functionality

All test fixtures use fake secrets only.

The AWS example key:

```text
AKIAIOSFODNN7EXAMPLE
```

is AWS's published example key and is safe for test purposes.

## Make Commands

On Linux/macOS, or Windows with `make` installed:

```bash
# Run SecretScan
make run TARGET=./my-project

# Run the complete test suite
make test

# Verify zero third-party dependencies
make verify-zero-deps

# Install the Git pre-commit hook
make install-hook
```

## Hackathon Bonus Challenges — Completed

### Single File (+5) — COMPLETED

The entire SecretScan project can be bundled into:

```text
dist/secretscan_single.py
```

Build it with:

```bash
python build_single_file.py
```

Run it with:

```bash
python dist/secretscan_single.py scan <path>
```

### Reproducible Build (+5) — COMPLETED

The single-file artifact is generated deterministically.

Verify it with:

```bash
sh scripts/verify_reproducible_build.sh
```

Verified hashes:

```text
Build #1: 1e44cd80b0d15e3b0599b19d15744eb7d60a66ab055ecd1aa669eb7d00fd4a22
Build #2: 1e44cd80b0d15e3b0599b19d15744eb7d60a66ab055ecd1aa669eb7d00fd4a22
```

### Package Killer (+3) — COMPLETED

SecretScan provides secrets scanning using only the Python standard library.

No third-party runtime dependency is required.

### STDLIB Log (+3) — COMPLETED

`STDLIB.md` documents the standard-library approach and explains the replacements used instead of third-party packages.

**Bonus challenge status: 4/4 completed.**

## Why Zero Dependencies, For a Security Tool Specifically

A tool whose job is catching supply-chain and credential risk should avoid adding unnecessary supply-chain surface area itself.

Every third-party package adds code that must be trusted and maintained.

`secretscan` runs with nothing beyond the Python interpreter already installed on the machine.

The project can also be tested with:

```bash
python -S secretscan.py scan ./my-project
```

`-S` disables automatic loading of the `site-packages` directory, helping verify that the scanner does not depend on third-party packages.

SecretScan performs detection locally using pattern matching and entropy analysis and does not send source code or credentials over the network.
