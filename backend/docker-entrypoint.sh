#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/reports /app/nvd_cache /app/wordlists/builtin /app/wordlists/user
    chown -R scanr:scanr /app/reports /app/nvd_cache /app/wordlists

    if [ "${SELF_UPDATE_ENABLED:-false}" = "true" ] && [ -S /var/run/docker.sock ]; then
        docker_gid="$(stat -c '%g' /var/run/docker.sock)"
        if ! getent group "$docker_gid" >/dev/null; then
            groupadd -g "$docker_gid" scanr-docker
        fi
        docker_group="$(getent group "$docker_gid" | cut -d: -f1)"
        usermod -aG "$docker_group" scanr
    fi

    exec gosu scanr "$@"
fi

exec "$@"
