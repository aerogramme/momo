from flask import request, jsonify, make_response
from flask_restful import Resource

from common.auth import auth, unauthorized, verify_password, users
from common.config import mongo
from common.util import verifyCredentials

# make sure to retrieve data from database
verify_password(users.get("username"), users.get("password"))
unauthorized

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
