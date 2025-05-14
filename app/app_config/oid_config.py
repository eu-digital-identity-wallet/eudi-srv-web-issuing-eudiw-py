from urllib.parse import urlparse
from config_service import ConfService as cfgservice

parsed_url = urlparse(cfgservice.service_url)
subdomain = parsed_url.netloc

CONFIG = {
  "logging": {
    "version": 1,
    "disable_existing_loggers": False,
    "root": {
      "handlers": [
        "console",
        "file"
      ],
      "level": "ERROR"
    },
    "loggers": {
      "idp": {
        "level": "ERROR"
      }
    },
    "handlers": {
      "console": {
        "class": "logging.StreamHandler",
        "stream": "ext://sys.stdout",
        "formatter": "default"
      },
      "file": {
        "class": "logging.FileHandler",
        "filename": cfgservice.log_dir + "/" + cfgservice.log_file_info,
        "formatter": "default"
      }
    },
    "formatters": {
      "default": {
        "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
      }
    }
  },
  "port": 5000,
  "domain": subdomain,
  "server_name": "{domain}",
  "base_url": "https://{domain}",
  "op": {
    "server_info": {
      "add_ons": {
        "pkce": {
          "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
          "kwargs": {
            "essential": False,
            "code_challenge_method": "S256 S384 S512"
          }
        }
      },
      "authz": {
        "class": "idpyoidc.server.authz.AuthzHandling",
        "kwargs": {
          "grant_config": {
            "usage_rules": {
              "authorization_code": {
                "supports_minting": [
                  "access_token",
                  "refresh_token",
                  "id_token"
                ],
                "max_usage": 1
              },
              "access_token": {},
              "refresh_token": {
                "supports_minting": [
                  "access_token",
                  "refresh_token"
                ]
              }
            },
            "expires_in": 43200
          }
        }
      },
      "authentication": {
        "user": {
          "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
          "class": "idpyoidc.server.user_authn.user.PidIssuerAuth",
          "kwargs": {
            "user": "diana"
          }
        }
      },
      "capabilities": {
        "subject_types_supported": [
          "public",
          "pairwise"
        ],
        "grant_types_supported": [
          "authorization_code",
          "implicit",
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
          "refresh_token"
        ],
        "request_object_signing_alg_values_supported": [
          "RS256",
          "RS384",
          "RS512",
          "ES256",
          "ES384",
          "ES512",
          "HS256",
          "HS384",
          "HS512",
          "PS256",
          "PS384",
          "PS512"
        ]
      },
      "claims_interface": {
        "class": "idpyoidc.server.session.claims.ClaimsInterface",
        "kwargs": {}
      },
      "cookie_handler": {
        "class": "idpyoidc.server.cookie_handler.CookieHandler",
        "kwargs": {
          "keys": {
            "private_path": "private/cookie_jwks.json",
            "key_defs": [
              {
                "type": "OCT",
                "use": [
                  "enc"
                ],
                "kid": "enc"
              },
              {
                "type": "OCT",
                "use": [
                  "sig"
                ],
                "kid": "sig"
              }
            ],
            "read_only": False
          },
          "name": {
            "session": "oidc_op",
            "register": "oidc_op_rp",
            "session_management": "sman"
          }
        }
      },
      "endpoint": {
        "webfinger": {
          "path": ".well-known/webfinger",
          "class": "idpyoidc.server.oidc.discovery.Discovery",
          "kwargs": {
            "client_authn_method": None
          }
        },
        "provider_info": {
          "path": ".well-known/openid-configuration",
          "class": "idpyoidc.server.oidc.provider_config.ProviderConfiguration",
          "kwargs": {
            "client_authn_method": None
          }
        },
        "registration": {
          "path": "registration",
          "class": "idpyoidc.server.oidc.registration.Registration",
          "kwargs": {
            "client_authn_method": None,
            "client_secret_expiration_time": 432000
          }
        },
        "registration_api": {
          "path": "registration_api",
          "class": "idpyoidc.server.oidc.read_registration.RegistrationRead",
          "kwargs": {
            "client_authn_method": [
              "bearer_header"
            ]
          }
        },
        "introspection": {
          "path": "introspection",
          "class": "idpyoidc.server.oauth2.introspection.Introspection",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt"
            ],
            "release": [
              "username"
            ]
          }
        },
        "authorization": {
          "path": "authorization",
          "class": "idpyoidc.server.oidc.authorization.Authorization",
          "kwargs": {
            "client_authn_method": None,
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": None,
            "response_types_supported": [
              "code",
              "token",
              "id_token",
              "code token",
              "code id_token",
              "id_token token",
              "code id_token token",
              "none"
            ],
            "response_modes_supported": [
              "query",
              "fragment",
              "form_post"
            ]
          }
        },
        "token": {
          "path": "token",
          "class": "idpyoidc.server.oidc.token.Token",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt",
              "public"
            ]
          }
        },
        "userinfo": {
          "path": "userinfo",
          "class": "idpyoidc.server.oidc.userinfo.UserInfo",
          "kwargs": {
            "claim_types_supported": [
              "normal",
              "aggregated",
              "distributed"
            ]
          }
        },
        "end_session": {
          "path": "session",
          "class": "idpyoidc.server.oidc.session.Session",
          "kwargs": {
            "logout_verify_url": "verify_logout",
            "post_logout_uri_path": "post_logout",
            "signing_alg": "ES256",
            "frontchannel_logout_supported": True,
            "frontchannel_logout_session_supported": True,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
            "check_session_iframe": "check_session_iframe"
          }
        },
        "pushed_authorization": {
          "path": "pushed_authorization",
          "class": "idpyoidc.server.oauth2.pushed_authorization.PushedAuthorization",
          "kwargs": {
              "client_authn_method": [
                  "client_secret_post",
                  "client_secret_basic",
                  "client_secret_jwt",
                  "private_key_jwt",
                  "public"
              ]
          }
        },
        "notification": {
          "path": "notification",
          "class": "openid4v.openid_credential_issuer.notification.Notification",
          "kwargs":{}
        },
        "nonce": {
          "path": "nonce",
          "class": "openid4v.openid_credential_issuer.nonce.Nonce",
          "kwargs":{}
        },
        "deferred_credential": {
          "path": "deferred_credential",
          "class": "openid4v.openid_credential_issuer.deferred_credential.Deferred_Credential",
          "kwargs":{}
        },
        "credential": {
          "path": "credential",
          "class": "openid4v.openid_credential_issuer.credential.Credential",
          "kwargs": {
              "credential_constructor": {
                  "class": "openid4v.openid_credential_issuer.credential.CredentialConstructor",
                  "kwargs": {}
              }
          }
        }
      },
      "httpc_params": {
        "verify": False
      },
      "issuer": "https://{domain}",
      "keys": {
        "private_path": "private/jwks.json",
        "key_defs": [
          {
            "type": "RSA",
            "use": [
              "sig"
            ]
          },
          {
            "type": "EC",
            "crv": "P-256",
            "use": [
              "sig"
            ]
          }
        ],
        "public_path": "static/jwks.json",
        "read_only": False,
        "uri_path": "static/jwks.json"
      },
      "template_dir": "templates",
      "token_handler_args": {
        "jwks_file": "private/token_jwks.json",
        "code": {
          "kwargs": {
            "lifetime": 600
          }
        },
        "token": {
          "class": "idpyoidc.server.token.jwt_token.JWTToken",
          "kwargs": {
            "lifetime": 3600,
            "add_claims": [
              "email",
              "email_verified",
              "phone_number",
              "phone_number_verified"
            ],
            "add_claims_by_scope": True,
            "aud": [
              "https://example.org/appl"
            ]
          }
        },
        "refresh": {
          "kwargs": {
            "lifetime": 86400
          }
        },
        "id_token": {
          "class": "idpyoidc.server.token.id_token.IDToken",
          "kwargs": {
            "base_claims": {
              "email": {
                "essential": True
              },
              "email_verified": {
                "essential": True
              }
            }
          }
        }
      },
      "userinfo": {
        "class": "idpyoidc.server.user_info.UserInfo"
      }
    }
  },
  "webserver": {
    "server_cert": "certs/client.crt",
    "server_key": "certs/client.key",
    "ca_bundle": None,
    "verify_user": False,
    "port": 5000,
    "domain": subdomain,
    "debug": True
  }
}
