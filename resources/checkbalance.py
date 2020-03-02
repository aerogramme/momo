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
        """
       This examples uses FlaskRESTful Resource
       It works also with swag_from, schemas and spec_dict
       ---
       parameters:
         - in: path
           name: username
           type: string
           required: true
         - in: path
           name: password
           type: string
           required: true
         - in: path
           name: phone
           type: string
           required: false
       responses:
         200:
           description: Check Balance on MoMo Wallet
           schema:
             id: CheckBalance
             properties:
               username:
                 type: string
                 description: The username of the user
                 default: freeworldboss
               password:
                 type: string
                 description: The password of the user
                 default: cq#4&Ds6~K+0iwU_
               phone:
                 type: string
                 description: The phone of the user
                 default: 0243559227
        """
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
