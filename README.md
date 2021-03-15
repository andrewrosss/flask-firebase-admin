# Flask Firebase Admin

Add Firebase (a Firebase Admin app) to a Flask application.

## Installation

```bash
pip install flask-firebase-admin
```

## Quickstart

In the simplest case, let's protect a route, specifically, we'll require a user to provide a firebase jwt to one of our routes:

```python
from flask import Flask, request
from flask_firebase_admin import FirebaseAdmin

app = Flask(__name__)
firebase = FirebaseAdmin(app)  # uses GOOGLE_APPLICATION_CREDENTIALS

@app.route("/unprotected")
def unprotected():
    return {"message": "Hello anonymous user!"}

@app.route("/protected")
@firebase.jwt_required  # This route now requires authorization via firebase jwt
def protected():
    # By default JWT payload is stored under request.jwt_payload
    return {"message": f"Hello {request.jwt_payload['email']}!"}

if __name__ == "__main__":
    app.run(debug=True)
```

Assuming the code above is located in a module named `app.py`, start the Flask application:

```bash
GOOGLE_APPLICATION_CREDENTIALS="/path/to/service_account.json" python app.py
```

And in a separate terminal window, ping the unprotected route:

```bash
$ curl http://127.0.0.1:5000/unprotected
{
  "message": "Hello anonymous user!"
}
```

Looks good. Now the protected route:

```bash
$ curl http://127.0.0.1:5000/protected
{
  "error": {
    "message": "No credentials provided"
  }
}
```

OK, makes sense. Now with some credentials:

```bash
$ TOKEN="your-firebase-token ..."
$ curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:5000/protected
{
  "message": "Hello <your@email.com>!"
}
```

Excellent. We now have a application with routes (one route) which require the user to provide their Firebase JWT to access!

Internally the `jwt_required` method provided by the `FirebaseAdmin` object calls the `firebase_admin.auth.verify_id_token` function which returns a dictionary of key-value pairs parsed from the decoded JWT. This dictionary is accessible via the `request` object provided by flask, specifically, this information is attached to the `request.jwt_payload` attribute by default.

## Configuration

The `FirebaseAdmin` object can be configured in the following ways:

- `FIREBASE_ADMIN_CREDENTIAL`

  **Defaults to `None`**. This is the credential passed to the call to `firebase_admin.initialize_app`. When this parameter is None the Firebase Admin application tries to initialize using `GOOGLE_APPLICATION_CREDENTIALS`. If initializing the Firebase Admin app with the `GOOGLE_APPLICATION_CREDENTIALS` environment variable is undesirebale, credentials can be created manually, for example:

  ```python
  app = Flask(__name__)
  app.config["FIREBASE_ADMIN_CREDENTIAL"] = credentials.Certificate("/path/to/key.json")
  firebase = FirebaseAdmin(app)  # no longer uses GOOGLE_APPLICATION_CREDENTIALS
  ```

  Or perhaps something like:

  ```python
  app = Flask(__name__)
  cert = {
      "type": "service_account",
      "project_id": os.getenv("PROJECT_ID"),
      "private_key_id": os.getenv("PRIVATE_KEY_ID"),
      "private_key": os.getenv("PRIVATE_KEY"),
      "client_email": os.getenv("CLIENT_EMAIL"),
      "client_id": os.getenv("CLIENT_ID"),
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
      "client_x509_cert_url": os.getenv("CLIENT_X509_CERT_URL"),
  }
  app.config["FIREBASE_ADMIN_CREDENTIAL"] = credentials.Certificate(cert)
  firebase = FirebaseAdmin(app)  # no longer uses GOOGLE_APPLICATION_CREDENTIALS
  ```

- `FIREBASE_ADMIN_OPTIONS`

  **Defaults to `None`**. This config is passed directly to `admin.initialize_app()` as the second `options` argument. From the Firebase Admin SDK docs: _A dictionary of configuration options (optional). Supported options include **databaseURL**, **storageBucket**, **projectId**, **databaseAuthVariableOverride**, **serviceAccountId** and **httpTimeout**. If httpTimeout is not set, the SDK uses a default timeout of 120 seconds._

- `FIREBASE_ADMIN_NAME`

  **Defaults to `'[DEFAULT]'`**. This config is passed directly to `admin.initialize_app()` as the third `name` argument.

- `FIREBASE_ADMIN_AUTHORIZATION_SCHEME`

  **Defaults to `'Bearer'`**. This is the authorization scheme expected by the `FirebaseAdmin` object. Changing this parameter changes the format of the auth header that is required by the client. For example, if we set this to `'JWT'` we would then need to include an authorization header of the form: `Authorization: JWT <token>` when making requests to protected routes.

- `FIREBASE_ADMIN_CHECK_REVOKED`

  **Defaults to `True`**. This parameter is passed as the `check_revoked` argument in the call to `firebase_admin.auth.verify_id_token()`.

- `FIREBASE_ADMIN_PAYLOAD_ATTR`

  **Defaults to `'jwt_payload'`**. This is attribute on the flask `request` object from which we can access the JWT payload data. If we were to change this to, say, `'jwt'` we would then access the JWT payload using `request.jwt`

- `FIREBASE_ADMIN_RAISE_IF_APP_EXISTS`

  **Defaults to `True`**. Internally, `flask-firebase-admin` calls `admin.initialize_app()`, if the app with the configured name already exists the Firebase Admin SDK raises a `ValueError` exception. When this config variable is set to `False`, `flask-firebase-admin` will catch this error, get, and subsequently use the existing admin app by the given name.

An example using more of the available configuration:

```python
from flask import Flask, request
from firebase_admin import credentials
from flask_firebase_admin import FirebaseAdmin

app = Flask(__name__)
app.config["FIREBASE_ADMIN_CREDENTIAL"] = credentials.Certificate("/path/to/key.json")
app.config["FIREBASE_ADMIN_AUTHORIZATION_SCHEME"] = "JWT"
app.config["FIREBASE_ADMIN_CHECK_REVOKED"] = False  # don't check for revoked tokens
app.config["FIREBASE_ADMIN_PAYLOAD_ATTR"] = "firebase_jwt"

# initialized with credentials defined above, not GOOGLE_APPLICATION_CREDENTIALS
firebase = FirebaseAdmin(app)

@app.route("/unprotected")
def unprotected():
    return {"message": "Hello anonymous user!"}

@app.route("/protected")
@firebase.jwt_required  # This route now requires authorization via firebase jwt
def protected():
    # we now access the JWT payload using request.firebase_jwt
    return {"message": f"Hello {request.firebase_jwt['email']}!"}

if __name__ == "__main__":
    app.run(debug=True)
```

To call the `/protected` route we have to update our auth header that we sent originally:

```bash
$ TOKEN="your-firebase-token ..."
$ curl -H "Authorization: JWT ${TOKEN}" http://127.0.0.1:5000/protected
{
  "message": "Hello <your@email.com>!"
}
```

## Extras

For convenience, the modules in the `firebase_admin` package are aliased as class-level attributes on the `FirebaseAdmin` object. For example:

```python
from flask import Flask
from flask_firebase_admin import FirebaseAdmin

app = Flask(__name__)
firebase = FirebaseAdmin(app)
db = firebase.firestore.client()  # <-- connect firestore client

@app.route("/unprotected")
def unprotected():
    return {"message": "Hello anonymous user!"}

@app.route("/protected")
@firebase.jwt_required
def protected():
    # do stuff in firestore using the db object defined above.
    ...

if __name__ == "__main__":
    app.run(debug=True)
```
