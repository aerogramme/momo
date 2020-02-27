# WITHDRAW MONEY
from flask import request, jsonify
from flask_restful import Resource

from common.auth import verify_password, users, unauthorized, auth
from common.config import mongo
from common.util import getNetworkName, verifyCredentials, cashWithUser, updateAccount, transaction_id, date_time, \
    generateReturnDictionary

# make sure to retrieve data from database
verify_password(users.get("username"), users.get("password"))
unauthorized

class WithdrawMoney(Resource):
    @auth.login_required
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]
        phone = postedData["fromPhone"]
        network = getNetworkName(phone)

        retJson, error = verifyCredentials(phone, password)
        if error:
            return jsonify(retJson)

        # Current Balance
        balance = cashWithUser(phone)

        if balance < money:
            return jsonify(generateReturnDictionary(303, "Not Enough Cash in your wallet", "FAILURE"))
        elif money < float(0):
            return jsonify(generateReturnDictionary(303, "You cannot withdraw negative amount", "FAILURE"))
        elif balance < float(0):
            return jsonify(
                generateReturnDictionary(303, "Your balance is in negative, please TopUp with some cash", "FAILURE"))

        updateAccount(phone, balance - money)

        # Insert data into Withdrawal Collection
        mongo.db.Withdrawal.insert_one({
            "Username": username,
            "Amount": round(float(money), 2),
            "Network": network,
            "Phone": phone,
            "Transaction_Id": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Money Withdrawn from your wallet", "SUCCESS"))
