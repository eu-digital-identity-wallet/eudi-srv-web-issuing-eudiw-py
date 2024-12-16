FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y

#RUN apt-get install -y python3.10 python3.10-venv python3.10-dev python3-pip git gcc build-essential libssl-dev nano

RUN apt-get install -y python3 python3-venv python3-dev python3-pip git gcc build-essential libssl-dev nano

RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /tmp/log_dev
RUN chmod -R 755 /tmp/log_dev

COPY ./ /root/eudi-srv-web-issuing-eudiw-py

WORKDIR /root/eudi-srv-web-issuing-eudiw-py

RUN python3 -m venv venv

RUN /root/eudi-srv-web-issuing-eudiw-py/venv/bin/pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

ENV FLASK_APP=app\
    FLASK_RUN_PORT=5000\
    FLASK_RUN_HOST=0.0.0.0\
    SERVICE_URL="https://mdl-test.regitra.lt/" \
    EIDAS_NODE_URL="https://preprod.issuer.eudiw.dev/EidasNode/"\
    DYNAMIC_PRESENTATION_URL="https://dev.verifier-backend.eudiw.dev/ui/presentations/"

CMD ["sh", "-c", "cp ./config_secrets/config_secrets.py /root/eudi-srv-web-issuing-eudiw-py/app/app_config/ && export REQUESTS_CA_BUNDLE=./config_secrets/cert.pem && /root/eudi-srv-web-issuing-eudiw-py/venv/bin/flask run"]
