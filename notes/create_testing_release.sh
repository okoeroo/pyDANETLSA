#!/bin/bash
set -e
cd "$(dirname "$0")/.."
if ! python3 -c 'import sys; sys.exit(sys.prefix != sys.base_prefix)'; then
    echo "Use system Python for pyDANETLSA: deactivate your virtual environment first." >&2
    exit 1
fi
if ! python3 -c 'import build, twine' >/dev/null 2>&1; then
    echo "Missing build tools for $(command -v python3)." >&2
    echo "Install system tools with: sudo apt install python3-build python3-venv twine" >&2
    exit 1
fi

VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml)


read -p "Detected version in pyproject.toml is \"$VERSION\". Is this correct? " ANSWER
if [ "$ANSWER" != 'y' ]; then
    exit 1
fi


echo "Removing dist..."
rm -rf dist build *.egg-info

echo "Building..."
python3 -m build || exit 1


echo "Inspecting:"
echo "---"
tar tzf dist/pydanetlsa-${VERSION}.tar.gz
echo "---"


read -p "Upload to testpypi? [y/N] " ANSWER
if [ "$ANSWER" = 'y' ]; then
    echo
    echo "Twine..."
    python3 -m twine upload --repository testpypi dist/* --verbose || exit 1
fi


echo

echo "test install with:"
echo "

cd /tmp
rm -r /tmp/testingground
mkdir /tmp/testingground

cp `pwd`/test/m.py /tmp/testingground

cd /tmp/testingground
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography pyOpenSSL requests dnspython
python3 -m pip install -i https://test.pypi.org/simple/ pyDANETLSA==${VERSION}

python3 m.py
"
