from functools import wraps
from types import ModuleType
from typing import Callable
from typing import Tuple
from typing import Union

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials
from firebase_admin import db
from firebase_admin import exceptions
from firebase_admin import firestore
from firebase_admin import instance_id
from firebase_admin import messaging
from firebase_admin import ml
from firebase_admin import project_management
from firebase_admin import storage
from firebase_admin import tenant_mgt
from flask import current_app
from flask import Flask
from flask import make_response
from flask import Request
from flask import request
from flask import Response

from .status_codes import HTTP_401_UNAUTHORIZED


FIREBASE_ADMIN_AUTHORIZATION_SCHEME = "JWT"
FIREBASE_ADMIN_CHECK_REVOKED = True


class FirebaseAdmin(object):
    realm = "API"

    def __init__(self, app: Flask = None) -> None:
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.config.setdefault("FIREBASE_ADMIN_CREDENTIAL")
        app.config.setdefault(
            "FIREBASE_ADMIN_AUTHORIZATION_SCHEME",
            FIREBASE_ADMIN_AUTHORIZATION_SCHEME,
        )
        app.config.setdefault(
            "FIREBASE_ADMIN_CHECK_REVOKED", FIREBASE_ADMIN_CHECK_REVOKED
        )

        cred = app.config["FIREBASE_ADMIN_CREDENTIAL"]
        self._admin = firebase_admin.initialize_app(cred)

    @property
    def admin(self) -> firebase_admin.App:
        return self._admin

    @property
    def auth(self) -> ModuleType:
        return auth

    @property
    def credentials(self) -> ModuleType:
        return credentials

    @property
    def db(self) -> ModuleType:
        return db

    @property
    def exceptions(self) -> ModuleType:
        return exceptions

    @property
    def firestore(self) -> ModuleType:
        return firestore

    @property
    def instance_id(self) -> ModuleType:
        return instance_id

    @property
    def messaging(self) -> ModuleType:
        return messaging

    @property
    def ml(self) -> ModuleType:
        return ml

    @property
    def project_management(self) -> ModuleType:
        return project_management

    @property
    def storage(self) -> ModuleType:
        return storage

    @property
    def tenant_mgt(self) -> ModuleType:
        return tenant_mgt

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
                    "Invalid Authorization header format, expecting: "
                    f"{expected_prefix} <token>"
                )

            if header_prefix != expected_prefix:
                return self.make_401(
                    "Invalid Authorization header prefix, "
                    f"expecting prefix: {expected_prefix}"
                )

            try:
                check_revoked = current_app.config["FIREBASE_ADMIN_CHECK_REVOKED"]
                user = auth.verify_id_token(token, self.admin, check_revoked)
                request.user = user  # type: ignore
            except (
                auth.InvalidIdTokenError,
                auth.ExpiredIdTokenError,
                auth.RevokedIdTokenError,
                auth.CertificateFetchError,
            ):
                return self.make_401("Token validation Failed")

            return f(*args, **kwargs)

        return wrap

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
