FROM python:3.10-slim-bullseye

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    gcc \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Add a non root user for the application to run on
RUN groupadd -r flaskuser && useradd -r -g flaskuser flaskuser

RUN mkdir -p /home/flaskuser/eudi-srv-web-issuing-eudiw-py \
    && chown -R flaskuser:flaskuser /home/flaskuser

RUN mkdir -p /tmp/log_dev
RUN chmod -R 755 /tmp/log_dev
RUN flaskuser:flaskuser /tmp/log_dev

USER flaskuser

# install cargo into user land
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/flaskuser/.cargo/bin:${PATH}"

# copy application contents into container
WORKDIR /home/flaskuser/eudi-srv-web-issuing-eudiw-py
COPY --chown=flaskuser:flaskuser ./app /home/flaskuser/eudi-srv-web-issuing-eudiw-py/app

RUN python3 -m venv venv
RUN ./venv/bin/pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

ENV FLASK_APP=app \
    FLASK_RUN_PORT=5000 \
    FLASK_RUN_HOST=0.0.0.0 \
    SERVICE_URL="https://127.0.0.1:5000/" \
    EIDAS_NODE_URL="https://preprod.issuer.eudiw.dev/EidasNode/" \
    DYNAMIC_PRESENTATION_URL="https://dev.verifier-backend.eudiw.dev/ui/presentations/" \
    SECRETS_CONFIG_DIR="/home/flaskuser/secrets"
# copy entrypoint script to conntainer
COPY --chown=flaskuser:flaskuser docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
