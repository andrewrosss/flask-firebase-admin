from typing import Tuple

import firebase_admin
import pytest
from flask.helpers import url_for
from pytest_mock.plugin import MockerFixture

import flask_firebase_admin
import flask_firebase_admin.flask_firebase_admin as ffa
from tests.conftest import AppFixture
from tests.conftest import GetAppFixture
from tests.conftest import InitializeAppFixture
from tests.conftest import SampleAppFixture
from tests.conftest import TryInitializeAppFixture
from tests.conftest import VerifyIdTokenFixture


class TestDefaultConfig:
    def test_init_with___init__(
        self, app: AppFixture, try_initialize_app: TryInitializeAppFixture
    ):
        # create and initialize the extension
        admin = flask_firebase_admin.FirebaseAdmin(app)

        assert admin.app is not None
        assert app.config["FIREBASE_ADMIN_APP"] is None
        assert app.config["FIREBASE_ADMIN_AUTHORIZATION_SCHEME"] == "Bearer"
        assert app.config["FIREBASE_ADMIN_CHECK_REVOKED"] is True
        assert app.config["FIREBASE_ADMIN_PAYLOAD_ATTR"] == "jwt_payload"
        assert app.config["FIREBASE_ADMIN_CREDENTIAL"] is None
        assert app.config["FIREBASE_ADMIN_OPTIONS"] is None
        assert app.config["FIREBASE_ADMIN_NAME"] == firebase_admin._DEFAULT_APP_NAME
        assert app.config["FIREBASE_ADMIN_RAISE_IF_APP_EXISTS"] is True
        try_initialize_app.assert_called_once_with(
            None, None, firebase_admin._DEFAULT_APP_NAME, True
        )
        assert admin.admin is not None

    def test_init_with_init_app(
        self, app: AppFixture, try_initialize_app: TryInitializeAppFixture
    ):
        # create the extension
        admin = flask_firebase_admin.FirebaseAdmin()

        assert admin.app is None
        assert "FIREBASE_ADMIN_APP" not in app.config
        assert "FIREBASE_ADMIN_AUTHORIZATION_SCHEME" not in app.config
        assert "FIREBASE_ADMIN_CHECK_REVOKED" not in app.config
        assert "FIREBASE_ADMIN_PAYLOAD_ATTR" not in app.config
        assert "FIREBASE_ADMIN_CREDENTIAL" not in app.config
        assert "FIREBASE_ADMIN_OPTIONS" not in app.config
        assert "FIREBASE_ADMIN_NAME" not in app.config
        assert "FIREBASE_ADMIN_RAISE_IF_APP_EXISTS" not in app.config
        assert admin.app is None
        try_initialize_app.assert_not_called()

        with pytest.raises(AttributeError):
            admin.admin

        # initialize the extension
        admin.init_app(app)

        assert app.config["FIREBASE_ADMIN_APP"] is None
        assert app.config["FIREBASE_ADMIN_AUTHORIZATION_SCHEME"] == "Bearer"
        assert app.config["FIREBASE_ADMIN_CHECK_REVOKED"] is True
        assert app.config["FIREBASE_ADMIN_PAYLOAD_ATTR"] == "jwt_payload"
        assert app.config["FIREBASE_ADMIN_CREDENTIAL"] is None
        assert app.config["FIREBASE_ADMIN_OPTIONS"] is None
        assert app.config["FIREBASE_ADMIN_NAME"] == firebase_admin._DEFAULT_APP_NAME
        assert app.config["FIREBASE_ADMIN_RAISE_IF_APP_EXISTS"] is True
        try_initialize_app.assert_called_once_with(
            None, None, firebase_admin._DEFAULT_APP_NAME, True
        )
        assert admin.admin is not None

    def test_expected_number_of_config_parameter(self, app: AppFixture, initialize_app):
        # this check is a reminder that if more configuration
        # is added then TestDefaultConfig needs to be updated
        flask_firebase_admin.FirebaseAdmin(app)
        assert len([k for k in app.config if k.startswith("FIREBASE_ADMIN")]) == 8


class TestCustomConfig:
    def test_firebase_admin_app(
        self, app: AppFixture, try_initialize_app: TryInitializeAppFixture
    ):
        admin_app = "this-is-my-admin-app"
        app.config["FIREBASE_ADMIN_APP"] = admin_app
        admin = flask_firebase_admin.FirebaseAdmin(app)

        try_initialize_app.assert_not_called()
        # whatever was passed as config should simply be forwarded to FirebaseAdmin
        assert admin.admin == admin_app
        # becauase we explicitly specificied FIREBASE_ADMIN_APP the following
        # config should be ignored/left unconfigured
        assert "FIREBASE_ADMIN_CREDENTIAL" not in app.config
        assert "FIREBASE_ADMIN_OPTIONS" not in app.config
        assert "FIREBASE_ADMIN_NAME" not in app.config
        assert "FIREBASE_ADMIN_RAISE_IF_APP_EXISTS" not in app.config

    def test_firebase_firebase_admin_credentials(
        self, app: AppFixture, try_initialize_app: TryInitializeAppFixture
    ):
        cred = "my-creds"
        options = "my-options"
        name = "my-name"
        raise_if_app_exists = False
        app.config["FIREBASE_ADMIN_CREDENTIAL"] = cred
        app.config["FIREBASE_ADMIN_OPTIONS"] = options
        app.config["FIREBASE_ADMIN_NAME"] = name
        app.config["FIREBASE_ADMIN_RAISE_IF_APP_EXISTS"] = raise_if_app_exists

        admin = flask_firebase_admin.FirebaseAdmin(app)

        assert admin.admin is try_initialize_app.return_value
        try_initialize_app.assert_called_once_with(
            cred, options, name, raise_if_app_exists
        )


class TestJWTRequired:
    protected_route = "/protected"

    def test_no_auth_header_provided(self, sample_app, client):
        expected_message = "No credentials provided"
        expected_status_code = 401

        get_response = client.get(self.protected_route)
        assert get_response.status_code == expected_status_code
        assert get_response.json["error"]["message"] == expected_message

        post_response = client.post(self.protected_route)
        assert post_response.status_code == expected_status_code
        assert post_response.json["error"]["message"] == expected_message

    def test_bad_header_format(self, sample_app, client):
        expected_message = (
            "Invalid authorization header format. Expected: Bearer <token>"
        )
        expected_status_code = 401

        get_response = client.get(
            self.protected_route, headers={"Authorization": "{{TOKEN}}"}
        )
        assert get_response.status_code == expected_status_code
        assert get_response.json["error"]["message"] == expected_message

        post_response = client.post(
            self.protected_route, headers={"Authorization": "{{TOKEN}}"}
        )
        assert post_response.status_code == expected_status_code
        assert post_response.json["error"]["message"] == expected_message

    def test_bad_auth_scheme(self, sample_app, client):
        expected_message = "Invalid authorization scheme. Expected: Bearer"
        expected_status_code = 401

        get_response = client.get(
            self.protected_route, headers={"Authorization": "JWT {{TOKEN}}"}
        )
        assert get_response.status_code == expected_status_code
        assert get_response.json["error"]["message"] == expected_message

        post_response = client.post(
            self.protected_route, headers={"Authorization": "JWT {{TOKEN}}"}
        )
        assert post_response.status_code == expected_status_code
        assert post_response.json["error"]["message"] == expected_message

    def test_bad_token(self, sample_app_no_valid_token, client):
        expected_message = "Token validation Failed"
        expected_status_code = 401

        get_response = client.get(
            self.protected_route, headers={"Authorization": "Bearer {{TOKEN}}"}
        )
        assert get_response.status_code == expected_status_code
        assert get_response.json["error"]["message"] == expected_message

        post_response = client.post(
            self.protected_route, headers={"Authorization": "Bearer {{TOKEN}}"}
        )
        assert post_response.status_code == expected_status_code
        assert post_response.json["error"]["message"] == expected_message

    def test_valid_token(self, sample_app, client):
        expected_message = "Hello test@email.com!"
        expected_status_code = 200

        get_response = client.get(
            self.protected_route, headers={"Authorization": "Bearer {{TOKEN}}"}
        )
        assert get_response.status_code == expected_status_code
        assert get_response.json["message"] == expected_message

        post_response = client.post(
            self.protected_route, headers={"Authorization": "Bearer {{TOKEN}}"}
        )
        assert post_response.status_code == expected_status_code
        assert post_response.json["message"] == expected_message


class TestDecodeToken:
    @pytest.mark.parametrize(["check_revoked"], [[True], [False]])
    def test_method_calls_verify_id_token(
        self,
        app: AppFixture,
        try_initialize_app: TryInitializeAppFixture,  # to mock call to initialize_app
        verify_id_token: VerifyIdTokenFixture,
        check_revoked,
    ):
        app.config["FIREBASE_ADMIN_CHECK_REVOKED"] = check_revoked
        admin = flask_firebase_admin.FirebaseAdmin(app)

        token = "abc"
        decoded_token = admin.decode_token(token)

        verify_id_token.assert_called_once_with(token, admin.admin, check_revoked)
        assert decoded_token is verify_id_token.return_value


class TestMake401:
    @pytest.mark.parametrize(
        ["message", "auth_scheme", "expected_header"],
        [
            ("my-error-msg", "AuthScheme", 'AuthScheme realm="API", charset="UTF-8"'),
            ("another-error", "JWT", 'JWT realm="API", charset="UTF-8"'),
        ],
    )
    def test_generated_response_object(
        self, app: AppFixture, message, auth_scheme, expected_header
    ):
        app.config["FIREBASE_ADMIN_AUTHORIZATION_SCHEME"] = auth_scheme

        # we don't need a fully initialized extension
        admin = flask_firebase_admin.FirebaseAdmin()

        response = admin.make_401(message)

        assert response.headers["WWW-Authenticate"] == expected_header
        assert response.status_code == 401
        assert response.is_json and response.json["error"]["message"] == message


class TestTryInitializeApp:
    def test_calls_firebase_admin_initialize_app(
        self, initialize_app: InitializeAppFixture
    ):
        cred, options, name = "my-creds", "my-options", "my-name"
        ffa.try_initialize_app(cred, options, name)
        initialize_app.assert_called_once_with(cred, options=options, name=name)

    def test_raises_RuntimeError_by_default_when_admin_app_already_initialize(
        self, initialize_app: InitializeAppFixture
    ):
        initialize_app.side_effect = ValueError()
        cred, options, name = "my-creds", "my-options", "my-name"
        with pytest.raises(RuntimeError):
            ffa.try_initialize_app(cred, options, name)
        initialize_app.assert_called_once_with(cred, options=options, name=name)

    def test_suppresses_ValueError_when_admin_app_already_exists_if_configured(
        self, initialize_app: InitializeAppFixture, get_app: GetAppFixture
    ):
        initialize_app.side_effect = ValueError()
        cred, options, name = "my-creds", "my-options", "my-name"
        raise_if_app_exists = False

        admin = ffa.try_initialize_app(cred, options, name, raise_if_app_exists)

        initialize_app.assert_called_once_with(cred, options=options, name=name)
        get_app.assert_called_once_with(name)
        assert admin is get_app.return_value


# FIREBASE_ADMIN_CHECK_REVOKED
# FIREBASE_ADMIN_PAYLOAD_ATTR
# FIREBASE_ADMIN_CREDENTIAL
# FIREBASE_ADMIN_OPTIONS
# FIREBASE_ADMIN_NAME
# FIREBASE_ADMIN_RAISE_IF_APP_EXISTS


class TestParseHeaderCredentials:
    @pytest.mark.parametrize(
        ["header", "expected"],
        [
            ("", (None, None)),  # empty string
            ("abc", (None, None)),  # No space-separated values
            ("Bearer abc def", (None, None)),  # too many space-separated values
        ],
    )
    def test_badly_formatted(self, header: str, expected: Tuple[None, None]):
        assert expected == ffa.parse_header_credentials(header)

    @pytest.mark.parametrize(
        ["header", "expected"],
        [
            ("Bearer abc", ("Bearer", "abc")),
            ("part1 part2", ("part1", "part2")),
        ],
    )
    def test_correctly_formatted(self, header: str, expected: Tuple[str, str]):
        assert expected == ffa.parse_header_credentials(header)


class TestGetAuthorizationHeader:
    def test_function_calls_request_headers_get(self, mocker: MockerFixture):
        req = mocker.MagicMock()
        ffa.get_authorization_header(req)

        req.headers.get.assert_called_once_with("Authorization")
