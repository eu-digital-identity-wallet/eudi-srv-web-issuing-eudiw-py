FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3.10 \
    python3.10-venv \
    python3.10-dev \
    python3-pip \
    git \
    gcc \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt /app/

RUN mkdir -p /etc/eudiw/pid-issuer/cert/

RUN mkdir -p /etc/eudiw/pid-issuer/privkey/

COPY app/private/certs/ /etc/eudiw/pid-issuer/cert/

COPY app/private/privkeys/ /etc/eudiw/pid-issuer/privkey/

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /app

ENV REQUESTS_CA_BUNDLE=app/cert.pem

EXPOSE 5000

ENV FLASK_APP=app
ENV FLASK_RUN_PORT=5000
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["flask", "run", "--cert=app/cert.pem", "--key=app/key.pem"]
