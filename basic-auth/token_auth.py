#!/usr/bin/env python
"""Token authentication example
This example demonstrates how to protect Flask endpoints with token
authentication, using tokens.
When this application starts, a token is generated for each of the two users.
To gain access, you can use a command line HTTP client such as curl, passing
one of the tokens:
    curl -X GET -H "Authorization: Bearer <jws-token>" http://localhost:5000/
The response should include the username, which is obtained from the token.
"""
from flask import Flask, g
from flask_httpauth import HTTPTokenAuth
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
token_serializer = Serializer(app.config['SECRET_KEY'], expires_in=3600)


auth = HTTPTokenAuth('Bearer')

users = ['john', 'susan']
for user in users:
    token = token_serializer.dumps({'username': user}).decode('utf-8')
    print('*** token for {}: {}\n'.format(user, token))


@auth.verify_token
def verify_token(token):
    g.user = None
    try:
        data = token_serializer.loads(token)
    except:  # noqa: E722
        return False
    if 'username' in data:
        g.user = data['username']
        return True
    return False


@app.route('/')
@auth.login_required
def index():
    return "Hello, %s!" % g.user


if __name__ == '__main__':
    app.run()


# curl -X GET -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsImlhdCI6MTU4Mjc1NzU4NiwiZXhwIjoxNTgyNzYxMTg2fQ.eyJ1c2VybmFtZSI6ImpvaG4ifQ.KMUozQeWHySUfMlmwP6KsMHepLbpzlrxShhW3CLMCyIxdOlD8pXeWHHBDfk_NoeRjQjBv5dgjudI2tnVcLqbqQ" http://localhost:5000/
# curl -X GET \
#   http://localhost:5000/ \
#   -H 'Accept: */*' \
#   -H 'Accept-Encoding: gzip, deflate' \
#   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsImlhdCI6MTU4Mjc1NzU4NiwiZXhwIjoxNTgyNzYxMTg2fQ.eyJ1c2VybmFtZSI6ImpvaG4ifQ.KMUozQeWHySUfMlmwP6KsMHepLbpzlrxShhW3CLMCyIxdOlD8pXeWHHBDfk_NoeRjQjBv5dgjudI2tnVcLqbqQ' \
#   -H 'Cache-Control: no-cache' \
#   -H 'Connection: keep-alive' \
#   -H 'Content-Type: application/json' \
#   -H 'Host: localhost:5000' \
#   -H 'Postman-Token: b60d0e4d-88f3-42fe-a69a-a35ec3d1793a,cb5c572c-9f93-4ecf-acd2-c639fd5677be' \
#   -H 'User-Agent: PostmanRuntime/7.18.0' \
#   -H 'cache-control: no-cache'

# OkHttpClient client = new OkHttpClient();
#
# Request request = new Request.Builder()
#   .url("http://localhost:5000/")
#   .get()
#   .addHeader("Content-Type", "application/json")
#   .addHeader("Authorization", "Bearer eyJhbGciOiJIUzUxMiIsImlhdCI6MTU4Mjc1NzU4NiwiZXhwIjoxNTgyNzYxMTg2fQ.eyJ1c2VybmFtZSI6ImpvaG4ifQ.KMUozQeWHySUfMlmwP6KsMHepLbpzlrxShhW3CLMCyIxdOlD8pXeWHHBDfk_NoeRjQjBv5dgjudI2tnVcLqbqQ")
#   .addHeader("User-Agent", "PostmanRuntime/7.18.0")
#   .addHeader("Accept", "*/*")
#   .addHeader("Cache-Control", "no-cache")
#   .addHeader("Postman-Token", "b60d0e4d-88f3-42fe-a69a-a35ec3d1793a,f68430c0-a31e-4b11-ba21-fecb57fae002")
#   .addHeader("Host", "localhost:5000")
#   .addHeader("Accept-Encoding", "gzip, deflate")
#   .addHeader("Connection", "keep-alive")
#   .addHeader("cache-control", "no-cache")
#   .build();
#
# Response response = client.newCall(request).execute();
