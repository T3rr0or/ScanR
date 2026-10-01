#!/bin/sh
# Download ScanR and use its existing configuration/startup helper.
set -eu

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat <<'EOF'
Usage: sh install.sh [--admin-email you@example.com] [--origin https://scanr.example.com]

Installs ScanR into $HOME/scanr and starts its Docker Compose services.
Set SCANR_INSTALL_DIR to choose a different, new installation directory.
Requires Git, Python 3.10+, Docker Engine and Docker Compose v2.
Remote access requires an HTTPS reverse proxy configured separately.
EOF
    exit 0
fi

fail() {
    printf '%s\n' "Install failed: $*" >&2
    exit 1
}

for dependency in git python3 docker; do
    command -v "$dependency" >/dev/null 2>&1 || fail "Install $dependency first, then rerun this script."
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || fail 'Python 3.10 or newer is required.'
docker compose version >/dev/null 2>&1 || fail 'Install the Docker Compose v2 plugin first.'
docker info >/dev/null 2>&1 || fail 'Docker must be running and accessible to your current user.'

install_dir=${SCANR_INSTALL_DIR:-"$HOME/scanr"}
# An absolute path also prevents a leading dash from becoming a Git option.
case "$install_dir" in
    /*) ;;
    *) install_dir="$PWD/$install_dir" ;;
esac
if [ -e "$install_dir" ] || [ -L "$install_dir" ]; then
    fail "$install_dir already exists. To restart an existing install, run python3 scripts/setup.py --start from that directory."
fi

printf 'Downloading ScanR into %s...\n' "$install_dir"
git clone --depth 1 --branch master https://github.com/T3rr0or/ScanR.git "$install_dir"
printf 'Configuring and starting ScanR in %s...\n' "$install_dir"
exec python3 "$install_dir/scripts/setup.py" --start "$@"
