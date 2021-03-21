from unittest.mock import MagicMock

import flask
import pytest
from firebase_admin import auth
from pytest_mock import MockerFixture

import flask_firebase_admin


@pytest.fixture
def app(request):
    app = flask.Flask(request.module.__name__)
    app.testing = True
    return app


AppFixture = flask.Flask


@pytest.fixture
def initialize_app(mocker: MockerFixture):
    return mocker.patch("firebase_admin.initialize_app")


InitializeAppFixture = MagicMock


@pytest.fixture
def try_initialize_app(mocker: MockerFixture):
    return mocker.patch("flask_firebase_admin.flask_firebase_admin.try_initialize_app")


TryInitializeAppFixture = MagicMock


@pytest.fixture
def verify_id_token(mocker: MockerFixture):
    return mocker.patch("firebase_admin.auth.verify_id_token")


VerifyIdTokenFixture = MagicMock


@pytest.fixture
def decode_token(mocker: MockerFixture):
    dt = mocker.patch(
        "flask_firebase_admin.flask_firebase_admin.FirebaseAdmin.decode_token"
    )
    dt.return_value = {"email": "test@email.com"}
    return


DecodeTokenFixture = MagicMock


@pytest.fixture
def decode_token_raises(mocker: MockerFixture):
    dt = mocker.patch(
        "flask_firebase_admin.flask_firebase_admin.FirebaseAdmin.decode_token"
    )
    dt.side_effect = auth.InvalidIdTokenError("test message")
    return


DecodeTokenRaisesFixture = MagicMock


@pytest.fixture
def get_app(mocker: MockerFixture):
    return mocker.patch("firebase_admin.get_app")


GetAppFixture = MagicMock


@pytest.fixture
def sample_app(
    app: AppFixture,
    try_initialize_app: TryInitializeAppFixture,
    decode_token: DecodeTokenFixture,
):
    admin = flask_firebase_admin.FirebaseAdmin(app)

    @app.route("/protected", methods=["GET", "POST"])
    @admin.jwt_required
    def protected():
        # we now access the JWT payload using request.firebase_jwt
        return {"message": f"Hello {flask.request.jwt_payload['email']}!"}

    return app


SampleAppFixture = flask.Flask


@pytest.fixture
def sample_app_no_valid_token(
    app: AppFixture,
    try_initialize_app: TryInitializeAppFixture,
    decode_token_raises: DecodeTokenRaisesFixture,
):
    admin = flask_firebase_admin.FirebaseAdmin(app)

    @app.route("/protected", methods=["GET", "POST"])
    @admin.jwt_required
    def protected():
        # we now access the JWT payload using request.firebase_jwt
        return {"message": f"Hello {flask.request.jwt_payload['email']}!"}

    return app


SampleAppNoValidTokenFixture = flask.Flask
