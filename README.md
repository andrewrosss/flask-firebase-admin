# Flask Firebase Admin

Add firebase (a firebase admin app) to a Flask application.

## Installation

```bash
pip install flask-firebase-admin
```

## Quickstart

In the simplest case, let's protect a route, requiring a user to provide a firebase jwt:

```python
from flask import Flask
from flask_firebase_admin import FirebaseAdmin

app = Flask(__name__)
firebase = FirebaseAdmin(app) # uses GOOGLE_APPLICATION_CREDENTIALS

@app.route("/unprotected")
def unprotected():
    return {"message": "Hello from unprotected route!"}

@app.route("/protected")
@firebase.jwt_required  # This route now requires a firebase jwt token
def protected():
    return {"message": "Hello from protected route!"}

if __name__ == "__main__":
    app.run(debug=True)
```

Assuming the code above is located in module, `app.py`, start the Flask application:

```bash
GOOGLE_APPLICATION_CREDENTIALS="/path/to/service_account.json" python app.py
```

And in a separate terminal window, ping the unprotected route:

```bash
$ curl http://127.0.0.1:5000/unprotected
{
  "message": "Hello from unprotected route!"
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

OK, still looking good. Now with some credentials:

```bash
$ TOKEN="your-firebase-token ..."
$ curl -H "Authorization: JWT ${TOKEN}" http://127.0.0.1:5000/protected
{
  "message": "Hello from protected route!"
}
```

Excellent. We now have a application with routes (one route) which require the user to provide their Firebase JWT!
