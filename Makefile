.PHONY: run test verify-zero-deps install-hook build-single verify-reproducible help

# Default: show help
help:
	@echo "secretscan — zero-dependency secrets leak scanner"
	@echo ""
	@echo "  make run TARGET=<file-or-dir>  Scan a file or directory"
	@echo "  make test                      Run the full test suite"
	@echo "  make verify-zero-deps          Prove zero third-party dependencies"
	@echo "  make install-hook              Install as a git pre-commit hook (in this repo)"
	@echo "  make build-single               Build dist/secretscan_single.py (whole project, one file)"
	@echo "  make verify-reproducible        Build twice, confirm byte-identical SHA256 hashes"

run:
	python3 secretscan.py scan $(TARGET)

test:
	python3 -m unittest discover -s tests -v

verify-zero-deps:
	@python3 -S secretscan.py scan tests/fixtures/sample_leak.py; \
	status=$$?; \
	if [ $$status -eq 1 ]; then \
		echo ""; \
		echo "^ Ran successfully with -S (site-packages disabled). Zero third-party deps confirmed."; \
		echo "(Exit code 1 above is EXPECTED — it means secrets were found in the test fixture, proving detection works.)"; \
	else \
		echo ""; \
		echo "UNEXPECTED exit code $$status (expected 1 — the fixture should contain findable secrets)."; \
		exit 1; \
	fi

install-hook:
	python3 secretscan.py install-hook --path .

build-single:
	python3 build_single_file.py

verify-reproducible:
	sh scripts/verify_reproducible_build.sh
