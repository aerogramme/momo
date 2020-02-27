from flask import request, jsonify
from flask_restful import Resource

from common.auth import verify_password, users, unauthorized, auth
from common.config import mongo
from common.util import getNetworkName, verifyCredentials, cashWithUser, debtWithUser, updateAccount, updateDebt, \
    transaction_id, date_time, generateReturnDictionary

# make sure to retrieve data from database
verify_password(users.get("username"), users.get("password"))
unauthorized

class PayLoan(Resource):
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

        cash = cashWithUser(phone)
        debt = debtWithUser(phone)

        if cash < money:
            return jsonify(generateReturnDictionary(303, "Not enough cash in your account", "FAILURE"))
        elif money > debt:
            return jsonify(generateReturnDictionary(303, "You can't overpay your loan", "FAILURE"))
        elif debt < float(0):
            return jsonify(generateReturnDictionary(303, "Your debt is in negative", "FAILURE"))

        # update accounts
        updateAccount(phone, round(float(cash - money), 2))
        updateDebt(phone, round(float(debt - money), 2))

        # Insert data into payloan Collection
        mongo.db.Payloan.insert_one({
            "Username": username,
            "AmountPaid": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "TransactionID": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Loan Amount Paid Successfully", "SUCCESS"))
