from functools import wraps
from types import ModuleType
from typing import Callable
from typing import Tuple
from typing import Union

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials  # noqa: F401
from firebase_admin import db  # noqa: F401
from firebase_admin import exceptions  # noqa: F401
from firebase_admin import firestore  # noqa: F401
from firebase_admin import instance_id  # noqa: F401
from firebase_admin import messaging  # noqa: F401
from firebase_admin import ml  # noqa: F401
from firebase_admin import project_management  # noqa: F401
from firebase_admin import storage  # noqa: F401
from firebase_admin import tenant_mgt  # noqa: F401
from flask import current_app
from flask import Flask
from flask import make_response
from flask import Request
from flask import request
from flask import Response

from .status_codes import HTTP_401_UNAUTHORIZED


FIREBASE_ADMIN_AUTHORIZATION_SCHEME = "Bearer"
FIREBASE_ADMIN_CHECK_REVOKED = True
FIREBASE_ADMIN_PAYLOAD_ATTR = "jwt_payload"
FIREBASE_ADMIN_NAME = firebase_admin._DEFAULT_APP_NAME
FIREBASE_ADMIN_RAISE_IF_APP_EXISTS = True


class FirebaseAdmin(object):
    realm = "API"

    auth: ModuleType = auth
    credentials: ModuleType = credentials  # noqa: F811
    db: ModuleType = db  # noqa: F811
    exceptions: ModuleType = exceptions  # noqa: F811
    firestore: ModuleType = firestore  # noqa: F811
    instance_id: ModuleType = instance_id  # noqa: F811
    messaging: ModuleType = messaging  # noqa: F811
    ml: ModuleType = ml  # noqa: F811
    project_management: ModuleType = project_management  # noqa: F811
    storage: ModuleType = storage  # noqa: F811
    tenant_mgt: ModuleType = tenant_mgt  # noqa: F811

    def __init__(self, app: Flask = None) -> None:
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.config.setdefault("FIREBASE_ADMIN_CREDENTIAL")
        app.config.setdefault("FIREBASE_ADMIN_OPTIONS")
        app.config.setdefault("FIREBASE_ADMIN_NAME", FIREBASE_ADMIN_NAME)
        app.config.setdefault(
            "FIREBASE_ADMIN_AUTHORIZATION_SCHEME",
            FIREBASE_ADMIN_AUTHORIZATION_SCHEME,
        )
        app.config.setdefault(
            "FIREBASE_ADMIN_CHECK_REVOKED", FIREBASE_ADMIN_CHECK_REVOKED
        )
        app.config.setdefault(
            "FIREBASE_ADMIN_PAYLOAD_ATTR", FIREBASE_ADMIN_PAYLOAD_ATTR
        )
        app.config.setdefault(
            "FIREBASE_ADMIN_RAISE_IF_APP_EXISTS", FIREBASE_ADMIN_RAISE_IF_APP_EXISTS
        )

        raise_if_app_exists = app.config["FIREBASE_ADMIN_RAISE_IF_APP_EXISTS"]

        cred = app.config["FIREBASE_ADMIN_CREDENTIAL"]
        options = app.config["FIREBASE_ADMIN_OPTIONS"]
        name = app.config["FIREBASE_ADMIN_NAME"]

        self._admin = try_initialize_app(cred, options, name, raise_if_app_exists)

    @property
    def admin(self) -> firebase_admin.App:
        return self._admin

    def jwt_required(self, f: Callable) -> Callable:
        @wraps(f)
        def wrap(*args, **kwargs):
            header = get_authorization_header(request)
            if header is None:
                return self.make_401("No credentials provided")

            expected_prefix = current_app.config["FIREBASE_ADMIN_AUTHORIZATION_SCHEME"]
            header_prefix, token = parse_header_credentials(header)
            if header_prefix is None or token is None:
                return self.make_401(
                    "Invalid authorization header format, expecting: "
                    f"{expected_prefix} <token>"
                )

            if header_prefix != expected_prefix:
                return self.make_401(
                    f"Invalid authorization scheme, expecting: {expected_prefix}"
                )

            try:
                payload_attr = current_app.config["FIREBASE_ADMIN_PAYLOAD_ATTR"]
                jwt_payload = self.decode_token(token)
                setattr(request, payload_attr, jwt_payload)
            except (
                auth.InvalidIdTokenError,
                auth.ExpiredIdTokenError,
                auth.RevokedIdTokenError,
                auth.CertificateFetchError,
            ):
                return self.make_401("Token validation Failed")

            return f(*args, **kwargs)

        return wrap

    def decode_token(self, token):
        check_revoked = current_app.config["FIREBASE_ADMIN_CHECK_REVOKED"]
        return auth.verify_id_token(token, self.admin, check_revoked)

    def make_401(self, message: str) -> Response:
        body = {"error": {"message": message}}
        status = HTTP_401_UNAUTHORIZED
        auth_scheme = current_app.config["FIREBASE_ADMIN_AUTHORIZATION_SCHEME"]
        headers = {
            "WWW-Authenticate": f'{auth_scheme} realm="{self.realm}", charset="UTF-8"'
        }
        return make_response((body, status, headers))


def get_authorization_header(request: Request) -> Union[None, str]:
    return request.headers.get("Authorization")


def parse_header_credentials(header: str) -> Union[Tuple[None, None], Tuple[str, str]]:
    try:
        values = header.split(" ")
        if len(values) != 2:
            return None, None
        type_, credential = values
        return type_, credential
    except ValueError:
        return None, None


def try_initialize_app(
    cred, options, name, raise_if_app_exists: bool = True
) -> firebase_admin.App:
    try:
        return firebase_admin.initialize_app(cred, options=options, name=name)
    except ValueError:
        if raise_if_app_exists:
            msg = (
                f"The firebase admin app [{name!r}] already exists. If this is "
                "expected set app.config['FIREBASE_ADMIN_RAISE_IF_APP_EXISTS'] = False "
                "to have flask-firebase-admin to use the existing firebase admin app."
            )
            raise RuntimeError(msg)
        return firebase_admin.get_app(name)
