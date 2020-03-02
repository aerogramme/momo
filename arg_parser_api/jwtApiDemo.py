# pip install Flask-JWT
# curl -X GET http://localhost:5000/api/v1/private
# curl -H "Content-Type: application/json" -X POST -d '{"username":"masnun","password":"abc123"}' http://localhost:5000/auth # generate token
# curl -X GET http://localhost:5000/api/v1/private -H "Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1ODI4NDQxNjMsImlhdCI6MTU4Mjg0Mzg2MywibmJmIjoxNTgyODQzODYzLCJpZGVudGl0eSI6MTIzfQ.HOwKOsqjh4f8Uyt7hi7dUMcgRAau5FOhCKfTKHHJ9hA"

# There needs to be two functions – one for authenticating the user, this would be quite similar to the verify function we wrote in our last tutorial (http auth tutorial).
# The second function’s job is to identify user from a token. Let’s call this function identity.
# The authentication function must return an object instance that has an attribute named id.
# To secure an endpoint, we use the @jwt_required decorator.
# An API endpoint is setup at /auth that accepts username and password via JSON payload and returns access_token which is the JSON Web Token we can use.
# We must pass the token as part of the Authorization header, like – JWT <token>.
#

from flask import Flask
from flask_restful import Resource, Api
from flask_jwt import JWT, jwt_required, current_identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret'
api = Api(app, prefix="/api/v1")

USER_DATA = {
    "masnun": "abc123"
}


class User(object):
    def __init__(self, id):
        self.id = id

    def __str__(self):
        return "User(id='%s')" % self.id


def verify(username, password):
    if not (username and password):
        return False
    if USER_DATA.get(username) == password:
        return User(id=123)

# The identity function will receive the decoded JWT.
def identity(payload):
    user_id = payload['identity']
    return {"user_id": user_id}


jwt = JWT(app, verify, identity)


class PrivateResource(Resource):
    @jwt_required()
    def get(self):
        return  {"meaning_of_life": 42} #dict(current_identity)


api.add_resource(PrivateResource, '/private')

if __name__ == '__main__':
    app.run(debug=True)
