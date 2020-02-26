#!/usr/bin/env python
"""Basic authentication example
This example demonstrates how to protect Flask endpoints with basic
authentication, using secure hashed passwords.
After running this example, visit http://localhost:5000 in your browser. To
gain access, you can use (username=Worldboss, password=hello) or
(username=Kartel, password=bye).
"""
from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "Worldboss": generate_password_hash("hello"),
    "Kartel": generate_password_hash("bye")
}


@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False


@app.route('/secret')
@auth.login_required
def index():
    return "Hello, %s!" % auth.username()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
