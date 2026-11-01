#!/usr/bin/env bash
# Install pinned, checksum-verified scanner binaries into $1 (Linux x86_64 runners).
# Checksums are pinned here rather than fetched alongside the binary, so a compromised
# release page cannot swap both. Bump versions and hashes together.
set -euo pipefail

dest="${1:?usage: install-scanners.sh <dest-dir>}"
mkdir -p "$dest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
  echo "::warning::scanners are pinned for Linux x86_64 only; gitleaks/osv checks will report an error"
  exit 0
fi

fetch() {  # url sha256 output
  curl --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 -o "$3" "$1"
  echo "$2  $3" | sha256sum --check --strict --quiet
}

GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  "$GITLEAKS_SHA256" "$work/gitleaks.tgz"
tar -xzf "$work/gitleaks.tgz" -C "$work" gitleaks
install -m 0755 "$work/gitleaks" "$dest/gitleaks"

OSV_VERSION=2.7.0
OSV_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
fetch "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
  "$OSV_SHA256" "$work/osv-scanner"
install -m 0755 "$work/osv-scanner" "$dest/osv-scanner"

ACTIONLINT_VERSION=1.7.12
ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
fetch "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
  "$ACTIONLINT_SHA256" "$work/actionlint.tgz"
tar -xzf "$work/actionlint.tgz" -C "$work" actionlint
install -m 0755 "$work/actionlint" "$dest/actionlint"

"$dest/gitleaks" version
"$dest/osv-scanner" --version | head -1
"$dest/actionlint" -version | head -1
