from flask import request, jsonify
from flask_restful import Resource

from common.util import getNetworkName, verifyCredentials, cashWithUser, updateAccount, transaction_id, date_time, \
    generateReturnDictionary, UserExist, transactionFee

from common.config import app, mail, api, mongo
# _, mongo,_,_ = flask_run()

class TransferMoney(Resource):
    def post(self):
        # get json data
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]
        fromPhone = postedData["fromPhone"]
        toPhone = postedData["toPhone"]
        # extract network name
        fromNetwork = getNetworkName(fromPhone)
        toNetwork = getNetworkName(toPhone)

        # verify sender credentials
        retJson, error = verifyCredentials(fromPhone, password)
        if error:
            return jsonify(retJson)

        # cash = cashWithUser(username)
        cash_from = cashWithUser(fromPhone)
        cash_to = cashWithUser(toPhone)
        bank_cash = cashWithUser("0240000000")

        if cash_from <= float(0):
            return jsonify(
                generateReturnDictionary(303, "You are out of money, Please Topup some Cash or take a loan", "FAILURE"))
        elif money <= float(1):
            return jsonify(generateReturnDictionary(304, "The amount entered must be greater than GHS 1.00", "FAILURE"))

        if not UserExist(toPhone):
            return jsonify(generateReturnDictionary(301, "Received username/phone is invalid", "FAILURE"))

        fees = transactionFee(money)
        money_after = round(money - fees, 2)
        try:
            updateAccount("0240000000", round(float(bank_cash + fees), 2))  # add fees to bank
            updateAccount(toPhone, round(float(cash_to + money_after), 2))  # add to receiving account
            updateAccount(fromPhone, round(float(cash_from - money_after), 2))  # deduct money from sending account
        except ValueError as err:
            print("Update to DB was not successful : {}" + err)

        # save to transfer collection
        mongo.db.Transfer.insert_one({
            "Username": username,
            "AmountBeforeFees": round(float(money), 2),
            "AmountAfterFees": round(float(money_after), 2),
            "FromPhone": fromPhone,
            "ToPhone": toPhone,
            "ToNetwork": toNetwork,
            "FromNetwork": fromNetwork,
            "TransactionID": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Amount added successfully to account", "SUCCESS"))
