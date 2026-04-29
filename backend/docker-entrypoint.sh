#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/reports /app/nvd_cache /app/wordlists/builtin /app/wordlists/user
    chown -R scanr:scanr /app/reports /app/nvd_cache /app/wordlists
    exec gosu scanr "$@"
fi

exec "$@"
