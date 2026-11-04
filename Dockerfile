# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    ca-certificates \
    git \
    pkg-config \
    cargo \
    rustc \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .

RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    ca-certificates \
    zlib1g \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled packages from builder
COPY --from=builder /install /usr/local

# Only the application code: no tests, docs, test keys or local state.
COPY app/ ./app/

# Unprivileged user (fixed UID so host-mounted log directories can be
# granted to it: chown 10001 <log dir>). It owns /app for flask_session/ and
# instance/.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin issuer \
 && mkdir -p /etc/eudiw/pid-issuer/cert/ /etc/eudiw/pid-issuer/privKey/ /tmp/log \
 && chown -R issuer:issuer /app /tmp/log

USER issuer

ENV FLASK_APP="app:create_app"

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]