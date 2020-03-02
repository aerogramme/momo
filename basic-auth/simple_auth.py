# curl -X GET http://localhost:5000/api/v1/private
# curl -X GET http://localhost:5000/api/v1/private --user admin:SuperSecretPwd

from flask import Flask
from flask_restful import Resource, Api
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
api = Api(app, prefix="/api/v1")
auth = HTTPBasicAuth()

USER_DATA = {
    "admin": "SuperSecretPwd"
}

@auth.verify_password
def verify(username, password):
    if not (username and password):
        return False
    return USER_DATA.get(username) == password


class PrivateResource(Resource):
    @auth.login_required
    def get(self):
        return {"meaning_of_life": 42}


# end point
api.add_resource(PrivateResource, '/private')

if __name__ == '__main__':
    app.run(debug=True)
