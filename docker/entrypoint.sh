#!/bin/sh

if [ ! -f "$SECRETS_CONFIG_DIR/config_secrets.py" ]; then
    echo "Error: config_secrets.py not found in $SECRETS_CONFIG_DIR. Exiting."
    exit 1
fi

cp "$SECRETS_CONFIG_DIR/config_secrets.py" /home/flaskuser/eudi-srv-web-issuing-eudiw-py/app/app_config/

FLASK_RUN_CMD="./venv/bin/flask run"

if [ -f "$SECRETS_CONFIG_DIR/cert.pem" ] && [ -f "$SECRETS_CONFIG_DIR/key.pem" ]; then
    export REQUESTS_CA_BUNDLE="$SECRETS_CONFIG_DIR/cert.pem"
    FLASK_RUN_CMD="$FLASK_RUN_CMD --cert=$SECRETS_CONFIG_DIR/cert.pem --key=$SECRETS_CONFIG_DIR/key.pem"
else
    echo "No SSL certificate and key provided, running Flask without SSL."
fi

eval $FLASK_RUN_CMD
