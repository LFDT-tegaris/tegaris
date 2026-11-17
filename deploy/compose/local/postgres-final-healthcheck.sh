#!/bin/sh
set -eu

# The temporary bootstrap server is a grandchild of docker-entrypoint.sh.
# With Docker's init enabled, the final server is its direct child. Keep the
# legacy PID-1 server check for existing retained containers during adoption.
if [ "$(cat /proc/1/comm)" = docker-init ]; then
  final_servers=0
  for child in $(cat /proc/1/task/1/children); do
    case "$child" in ''|*[!0-9]*) exit 1 ;; esac
    [ -r "/proc/$child/comm" ] || continue
    if [ "$(cat "/proc/$child/comm")" = postgres ]; then
      final_servers=$((final_servers + 1))
    fi
  done
  [ "$final_servers" = 1 ]
else
  [ "$(cat /proc/1/comm)" = postgres ]
fi

password_file="${POSTGRES_PASSWORD_FILE:?POSTGRES_PASSWORD_FILE is required}"
[ -f "$password_file" ] && [ ! -L "$password_file" ]
export PGPASSWORD="$(cat "$password_file")"

database="${POSTGRES_DB:?POSTGRES_DB is required}"
user="${POSTGRES_USER:?POSTGRES_USER is required}"
result="$(psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$user" -d "$database" \
  -c 'select current_database()')"
[ "$result" = "$database" ]
