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

"""

"""
import os

from flask import Flask, render_template, session
from flask_session import Session
from flask_cors import CORS
from werkzeug.debug import *
from werkzeug.exceptions import HTTPException
from idpyoidc.configure import Configuration
from idpyoidc.configure import create_from_config_file
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server import Server
from urllib.parse import urlparse
import route_eidasnode, route_formatter, route_qeaa, route_oidc


# Log
from app_config.config_service import ConfService as log


def handle_exception(e):
    # pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    log.logger_info.exception("- WARN - Error 500")
    # now you're handling non-HTTP exceptions only
    return (
        render_template(
            "route_pid/500.html",
            error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            error_code="Internal Server Error",
        ),
        500,
    )


def page_not_found(e):
    log.logger_info.exception("- WARN - Error 404")
    return (
        render_template(
            "route_pid/500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    app.config.from_mapping(SECRET_KEY="dev")

    if test_config is None:
        # load the instance config (in instance directory), if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    # @app.route('/hello')
    # def hello():
    #    return 'Hello, World!'

    # register blueprint for the /pid route
    app.register_blueprint(route_eidasnode.eidasnode)
    app.register_blueprint(route_formatter.formatter)
    app.register_blueprint(route_qeaa.qeaa)
    app.register_blueprint(route_oidc.oidc)

    # config session
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one.
    CORS(app, supports_credentials=True)

    log.logger_info.info(" - DEBUG - FLASK started")

    dir_path = os.path.dirname(os.path.realpath(__file__))

    config = create_from_config_file(
        Configuration,
        entity_conf=[
            {"class": OPConfiguration, "attr": "op", "path": ["op", "server_info"]}
        ],
        filename=dir_path + "/app_config/oid_config.json",
        base_path=dir_path,
    )

    app.srv_config = config.op

    server = Server(config.op, cwd=dir_path)

    for endp in server.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split("/")
        if _vpath[0] == "":
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    app.server = server

    return app


app = create_app()


#
# Usage examples:
# gunicorn app:app -b 127.0.0.1:5000
# flask run
#
 """