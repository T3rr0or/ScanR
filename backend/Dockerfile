FROM python:3.12-slim

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

# Install Python deps after copying package source. Editable installs need scanr/ present.
# Include the [ai] extra so the AI provider SDKs ship in the image; AI features
# stay disabled at runtime until a provider API key is configured.
COPY pyproject.toml .
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
