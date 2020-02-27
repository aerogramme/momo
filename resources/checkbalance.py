from flask import request, jsonify, make_response
from flask_restful import Resource

from common.util import verifyCredentials
from common.config import app, mail, api, mongo
from flask_restful import Api
#from flask_restplus import Resource, Api

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

#app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "freeworldboss": generate_password_hash("cq#4&Ds6~K+0iwU_"),
    "Kartel": generate_password_hash("bye")
}

@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized Access'}), 401)

#@app.route('/momo/api/v1.0/balance', endpoint = '/balance')
#@auth.login_required
class CheckBalance(Resource):
    @auth.login_required
    def post(self):
        postedData = request.get_json()
        phone = postedData["fromPhone"]
        username = postedData["username"]
        password = postedData["password"]

        retJson, error = verifyCredentials(phone, password)
        if error:
            return jsonify(retJson)

        retJson = mongo.db.Register.find({
            "Phone": phone
        }, {
            "Password": 0,  # projection
            "_id": 0
        })[0]
        return make_response(jsonify(retJson), 200) #jsonify(retJson)
