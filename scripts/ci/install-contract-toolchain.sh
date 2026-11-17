#!/usr/bin/env bash
set -euo pipefail

toolchain_bin="${1:?usage: install-contract-toolchain.sh <toolchain-bin-directory>}"
mkdir -p "$(dirname "$toolchain_bin")"
toolchain_root="$(cd "$(dirname "$toolchain_bin")" && pwd)"
downloads="$toolchain_root/downloads"
staging="$toolchain_root/staging"

mkdir -p "$toolchain_bin" "$downloads" "$staging"

download() {
  local url="$1"
  local destination="$2"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$destination" "$url"
}

verify_sha256() {
  local expected="$1"
  local artifact="$2"
  local actual
  actual="$(sha256sum "$artifact" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA-256 mismatch for $artifact" >&2
    exit 1
  fi
}

buf_archive="$downloads/buf-Linux-x86_64"
download \
  'https://github.com/bufbuild/buf/releases/download/v1.72.0/buf-Linux-x86_64' \
  "$buf_archive"
verify_sha256 \
  '8720830e26a733da55bb89bcd3cb44849c0965fc0c44fb5d691cccdc64dca5af' \
  "$buf_archive"
install -m 0755 "$buf_archive" "$toolchain_bin/buf"

protoc_archive="$downloads/protoc-35.1-linux-x86_64.zip"
protoc_extract="$staging/protoc-35.1-linux-x86_64"
download \
  'https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip' \
  "$protoc_archive"
unzip -oq "$protoc_archive" -d "$protoc_extract"
verify_sha256 \
  'd2c65c3ea5eeb59427f684ed3e0a0cd458386122fc9f1b98de946a7242b53d31' \
  "$protoc_extract/bin/protoc"
install -m 0755 "$protoc_extract/bin/protoc" "$toolchain_bin/protoc"

[[ "$("$toolchain_bin/buf" --version)" == '1.72.0' ]]
[[ "$("$toolchain_bin/protoc" --version)" == 'libprotoc 35.1' ]]
