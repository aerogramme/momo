from flask import request, jsonify
from flask_restful import Resource
from passlib.handlers.sha2_crypt import sha256_crypt

from common.util import getNetworkName, verifyCredentials, cashWithUser, debtWithUser, updateAccount, updateDebt, \
    transaction_id, date_time, generateReturnDictionary, UserExist, generateApiKeys


# _, mongo,_,_ = flask_run()

class Registration(Resource):
    def post(self):
        # Step 1 is to get posted data by the user
        postedData = request.get_json()
        # Get the data
        firstname = postedData["firstname"]
        lastname = postedData["lastname"]
        email = postedData["email"]
        phone = postedData["fromPhone"]
        username = postedData["username"]
        password = postedData["password"]
        network = getNetworkName(phone)

        if UserExist(phone):
            return jsonify(generateReturnDictionary(301, "Invalid Username/Phone", "FAILURE"))

        hashed_pw = sha256_crypt.hash(password)
        apiKey = generateApiKeys()

        # Store username,pw, phone, network into the database
        mongo.db.Register.insert_one({
            "FirstName": firstname,
            "LastName": lastname,
            "Email": email,
            "Phone": phone,
            "Network": network,
            "Username": username,
            "Password": hashed_pw,
            "Balance": float(0.0),
            "Debt": float(0.0),
            "DateTimeCreated": date_time(),
            "apiKeys": apiKey
        })

        retJson = {
            "code": 200,
            "msg": "You successfully signed up for the mobile money wallet",
            "apiKey": apiKey,
            "status": "SUCCESS"
        }
        return jsonify(retJson)
