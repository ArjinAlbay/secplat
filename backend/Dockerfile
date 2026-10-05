FROM python:3.13-slim-bookworm

ARG NUCLEI_VERSION=3.11.1
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libglib2.0-0 \
        libharfbuzz0b libffi8 libcairo2 fonts-dejavu-core; \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh; \
    /usr/local/bin/uv --version; \
    base="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"; \
    cd /tmp; \
    curl -fsSL -O "${base}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    curl -fsSL -O "${base}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" "nuclei_${NUCLEI_VERSION}_checksums.txt" | sha256sum -c -; \
    unzip -j -o "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" nuclei -d /usr/local/bin; \
    /usr/local/bin/nuclei -version; \
    useradd -r -m -u 10001 scanner; \
    mkdir -p /opt/nuclei-templates; chown -R scanner:scanner /opt/nuclei-templates; \
    rm -rf /var/lib/apt/lists/* "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" "nuclei_${NUCLEI_VERSION}_checksums.txt"

ARG SUBFINDER_VERSION=2.16.0
RUN set -eux; \
    base="https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}"; \
    cd /tmp; \
    curl -fsSL -O "${base}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"; \
    curl -fsSL -O "${base}/subfinder_${SUBFINDER_VERSION}_checksums.txt"; \
    grep "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" "subfinder_${SUBFINDER_VERSION}_checksums.txt" | sha256sum -c -; \
    unzip -j -o "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" subfinder -d /usr/local/bin; \
    /usr/local/bin/subfinder -version; \
    rm -f "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" "subfinder_${SUBFINDER_VERSION}_checksums.txt"

ARG TRIVY_VERSION=0.74.0
RUN set -eux; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    cd /tmp; \
    curl -fsSL -O "${base}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -fsSL -O "${base}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C /usr/local/bin trivy; \
    /usr/local/bin/trivy --version; \
    rm -f "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt"

ARG GITLEAKS_VERSION=8.24.0
RUN set -eux; \
    base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"; \
    cd /tmp; \
    curl -fsSL -O "${base}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    curl -fsSL -O "${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    grep "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -C /usr/local/bin gitleaks; \
    /usr/local/bin/gitleaks version; \
    rm -f "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"

WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

ARG SEMGREP_VERSION=1.177.0
RUN uv pip install --python /app/.venv/bin/python "semgrep==${SEMGREP_VERSION}" \
    && /app/.venv/bin/semgrep --version
RUN mkdir -p /home/scanner/.cache/trivy /home/scanner/.semgrep \
    && chown -R scanner:scanner /home/scanner/.cache /home/scanner/.semgrep
COPY alembic.ini ./
COPY alembic ./alembic
ENV PATH="/app/.venv/bin:${PATH}"
USER scanner
