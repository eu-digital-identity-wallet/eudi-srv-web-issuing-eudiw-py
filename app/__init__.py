# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The PID Issuer Web service is a component of the PID Provider backend. 
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This __init__.py serves double duty: it will contain the application factory, and it tells Python that the flaskr directory should be treated as a package.
"""

import os

from flask import Flask, session
from flask_session import Session
from flask_cors import CORS



def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev'
    )

    if test_config is None:
        # load the instance config (in instance directory), if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    #@app.route('/hello')
    #def hello():
    #    return 'Hello, World!'

    # register blueprint for the /pid route 
    from . import route_pid, route_eidasnode, route_formatter, route_ee_tara, route_pt_cmd
    app.register_blueprint(route_pid.pid)
    app.register_blueprint(route_eidasnode.eidasnode)
    app.register_blueprint(route_formatter.formatter)
    app.register_blueprint(route_ee_tara.tara)
    app.register_blueprint(route_pt_cmd.cmd)

    # config session
    app.config['SESSION_FILE_THRESHOLD'] = 50
    app.config['SESSION_PERMANENT'] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one. 
    CORS(app, supports_credentials=True)

    return app

#
# Usage examples:
# flask --app app run --debug
# flask --app app run --debug --cert=app/certs/certHttps.pem --key=app/certs/key.pem --host=127.0.0.1 --port=4430
# 