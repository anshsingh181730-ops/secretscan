#!/bin/sh
# verify_reproducible_build.sh
#
# Builds dist/secretscan_single.py TWICE from source, hashes both
# outputs with Python's own hashlib (not the external `sha256sum`
# binary — that's a GNU coreutils tool that isn't present by default
# on macOS, and this project's whole point is not depending on
# externally installed tools when the standard library already
# covers it), and confirms they are byte-for-byte identical.
#
# Usage:
#   sh scripts/verify_reproducible_build.sh
#
# Exit code 0 + "REPRODUCIBLE" means both builds hashed identically.

set -e
cd "$(dirname "$0")/.."

sha256() {
    python3 -c "
import hashlib, sys
with open(sys.argv[1], 'rb') as f:
    print(hashlib.sha256(f.read()).hexdigest())
" "$1"
}

echo "Build #1..."
python3 build_single_file.py
cp dist/secretscan_single.py /tmp/secretscan_single_build1.py
HASH1=$(sha256 /tmp/secretscan_single_build1.py)

echo "Build #2 (fresh run, same source)..."
rm -rf dist
python3 build_single_file.py
cp dist/secretscan_single.py /tmp/secretscan_single_build2.py
HASH2=$(sha256 /tmp/secretscan_single_build2.py)

echo ""
echo "Build #1 SHA256: $HASH1"
echo "Build #2 SHA256: $HASH2"
echo ""

if [ "$HASH1" = "$HASH2" ]; then
    echo "REPRODUCIBLE: both builds are byte-for-byte identical."
    exit 0
else
    echo "NOT REPRODUCIBLE: hashes differ."
    diff /tmp/secretscan_single_build1.py /tmp/secretscan_single_build2.py || true
    exit 1
fi
