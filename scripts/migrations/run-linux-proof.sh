#!/usr/bin/env bash
# Run only on an approved disposable CI runner; never install system services.
set -euo pipefail
umask 077
[[ $(uname -s) == Linux ]] || { echo 'This CI build requires Linux' >&2; exit 78; }
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
scratch=${1:?A new external proof directory is required}
[[ $scratch = /* && ! -e $scratch ]] || { echo 'Proof directory must be new and absolute' >&2; exit 78; }
mkdir -m 700 "$scratch"
curl --fail --location --proto '=https' --tlsv1.2 \
  https://ftp.postgresql.org/pub/source/v18.6/postgresql-18.6.tar.bz2 \
  --output "$scratch/postgresql-18.6.tar.bz2"
printf '%s  %s\n' '555610c24d53e4316da5b7d3fc25c279d96856d5e0e23ee308c328c5fa881d9f' \
  "$scratch/postgresql-18.6.tar.bz2" | sha256sum --check --status
tar -xjf "$scratch/postgresql-18.6.tar.bz2" -C "$scratch" --no-same-owner
(
  cd "$scratch/postgresql-18.6"
  ./configure --prefix="$scratch/pgsql18" --without-icu --without-readline --with-ssl=openssl > "$scratch/configure.log"
  make -j2 > "$scratch/build.log"
  make install > "$scratch/install.log"
  make -C contrib/pgcrypto -j2 > "$scratch/pgcrypto-build.log"
  make -C contrib/pgcrypto install > "$scratch/pgcrypto-install.log"
)
# Reproduce the archive without changing the repository's trusted manifest.
archive="$scratch/tegaris-legacy-db-db5e64b.tar.gz"
python3 "$repo/scripts/migrations/compatibility.py" build --output "$archive" --manifest "$scratch/reproduced-manifest.json"
python3 "$repo/scripts/migrations/compatibility.py" verify --archive "$archive"
python3 "$repo/tests/migration/run-baseline-proof.py" --pg-bin "$scratch/pgsql18/bin" \
  --archive "$archive" --work-dir "$scratch/proof"
