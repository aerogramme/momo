from flask import request, jsonify
from flask_restful import Resource

from common.util import getNetworkName, verifyCredentials, cashWithUser, debtWithUser, updateAccount, updateDebt, \
    transaction_id, date_time, generateReturnDictionary


# _, mongo,_,_ = flask_run()

class TakeLoan(Resource):
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
        # update accounts
        updateAccount(phone, round(float(cash + money), 2))
        updateDebt(phone, round(float(debt + money), 2))

        # Insert data into take loan Collection
        mongo.db.Takeloan.insert_one({
            "Username": username,
            "Loan_Amount": round(float(money), 2),
            "Network": network,
            "Phone": phone,
            "TransactionID": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Loan Amount Added to Your Account Successfully", "SUCCESS"))
