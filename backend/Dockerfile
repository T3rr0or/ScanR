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
    && rm -rf /var/lib/apt/lists/*

# SecLists wordlists for web content discovery (best-effort — plugin falls back to embedded list)
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt || true && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/big.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt || true && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt || true

# Install Nuclei (separate layer — cached unless version changes)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip \
    && unzip nuclei_3.3.9_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.3.9_linux_amd64.zip \
    && nuclei -update-templates -silent 2>/dev/null || true

WORKDIR /app

# Install Python deps first (cached layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Install Playwright + Chromium (separate layer so code changes don't re-download browser)
RUN playwright install --with-deps chromium

# Copy source
COPY scanr/ ./scanr/
COPY alembic/ ./alembic/
COPY alembic.ini .

# Built-in wordlists
RUN mkdir -p /app/wordlists/builtin
COPY scanr/wordlists/builtin/ /app/wordlists/builtin/

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
