from flask import request, jsonify
from flask_restful import Resource

# from common.util import flask_run

# _, mongo,_,_ = flask_run()

class CheckBalance(Resource):
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
        return jsonify(retJson)


