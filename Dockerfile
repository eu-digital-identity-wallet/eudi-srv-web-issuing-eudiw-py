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

RUN git clone https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py.git /root/eudi-srv-web-issuing-eudiw-py

# copy application contents into container
WORKDIR /home/flaskuser/eudi-srv-web-issuing-eudiw-py
COPY --chown=flaskuser:flaskuser ./app /home/flaskuser/eudi-srv-web-issuing-eudiw-py/app

RUN python3 -m venv venv
RUN ./venv/bin/pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

ENV FLASK_APP=app\
    FLASK_RUN_PORT=5000\
    FLASK_RUN_HOST=0.0.0.0\
    SERVICE_URL="https://127.0.0.1:5000/" \
    EIDAS_NODE_URL="https://preprod.issuer.eudiw.dev/EidasNode/"\
    DYNAMIC_PRESENTATION_URL="https://dev.verifier-backend.eudiw.dev/ui/presentations/"

CMD ["sh", "-c", "cp /root/secrets/config_secrets.py /root/eudi-srv-web-issuing-eudiw-py/app/app_config/ && export REQUESTS_CA_BUNDLE=/root/secrets/cert.pem && /root/eudi-srv-web-issuing-eudiw-py/venv/bin/flask run --cert=/root/secrets/cert.pem --key=/root/secrets/key.pem"]
