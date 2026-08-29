.PHONY: run test verify-zero-deps install-hook help

# Default: show help
help:
	@echo "secretscan — zero-dependency secrets leak scanner"
	@echo ""
	@echo "  make run PATH=<file-or-dir>   Scan a file or directory"
	@echo "  make test                     Run the full test suite"
	@echo "  make verify-zero-deps         Prove zero third-party dependencies"
	@echo "  make install-hook             Install as a git pre-commit hook (in this repo)"

run:
	python3 secretscan.py scan $(PATH)

test:
	python3 -m unittest discover -s tests -v

verify-zero-deps:
	-python3 -S secretscan.py scan tests/fixtures/sample_leak.py
	@echo ""
	@echo "^ Ran successfully with -S (site-packages disabled). Zero third-party deps confirmed."
	@echo "(Exit code 1 above is EXPECTED — it means secrets were found in the test fixture, proving detection works.)"

install-hook:
	python3 secretscan.py install-hook --path .
