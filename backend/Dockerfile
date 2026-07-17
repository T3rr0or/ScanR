FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    libcairo2 \
    gcc \
    perl \
    wget \
    unzip \
    libcap2-bin \
    # docker-compose: required by the OPTIONAL in-app self-update feature
    # (docker-compose.self-update.yml) — the update command runs `docker
    # compose` inside the api container against the mounted host socket.
    # Off by default; drop this package if you never enable self-update.
    docker-compose \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# SecLists wordlists for web content discovery (best-effort — plugin falls back to embedded list)
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt || true && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/big.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt || true && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt || true

# Install Nuclei — verify checksum against official checksums file before executing
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_checksums.txt \
    && wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip \
    && grep "nuclei_3.3.9_linux_amd64.zip" nuclei_3.3.9_checksums.txt | sha256sum -c - \
    && unzip nuclei_3.3.9_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.3.9_linux_amd64.zip nuclei_3.3.9_checksums.txt \
    && nuclei -update-templates -silent 2>/dev/null || true

WORKDIR /app

# Keep Playwright browsers in a system path shared by build-time root and the
# runtime scanr user. Without this, runtime resolves browsers under /app/.cache
# while the image build may install them under root's cache.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install Python deps from the pinned, hash-verified lock file (generated from
# pyproject.toml incl. the [ai] extra — regenerate with:
#   uv pip compile pyproject.toml --extra ai --python-version 3.12 --generate-hashes -o requirements.txt
# ). The editable install afterwards only adds the scanr package itself; every
# dependency is already satisfied by the lock, so pip changes nothing.
# AI features stay disabled at runtime until a provider API key is configured.
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
# Editable installs need scanr/ present.
COPY scanr/ ./scanr/
RUN pip install --no-cache-dir -e ".[ai]"

# Install Playwright + Chromium (separate layer so code changes don't re-download browser)
RUN playwright install --with-deps chromium

# Copy migration assets
COPY alembic/ ./alembic/
COPY alembic.ini .

# Built-in wordlists
RUN mkdir -p /app/wordlists/builtin
COPY scanr/wordlists/builtin/ /app/wordlists/builtin/
COPY docker-entrypoint.sh /usr/local/bin/scanr-entrypoint

# Non-root user — grant nmap/masscan raw socket access via file capabilities
# so the worker can run scans without NET_ADMIN or running as root.
RUN groupadd -r scanr && useradd -r -g scanr -d /app -s /bin/false scanr \
    && chown -R scanr:scanr /app /ms-playwright \
    && chmod +x /usr/local/bin/scanr-entrypoint \
    && setcap cap_net_raw+ep /usr/bin/nmap \
    && (setcap cap_net_raw+ep /usr/bin/masscan || true)

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["scanr-entrypoint"]
