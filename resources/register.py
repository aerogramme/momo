from flask import request, jsonify
from flask_restful import Resource
from passlib.handlers.sha2_crypt import sha256_crypt
import re

from common.util import getNetworkName, date_time, generateReturnDictionary, UserExist, generateApiKeys
from common.config import app, mail, api, mongo
from Users.mongodbObjects import UsersRegisteration

from flask_restful.reqparse import RequestParser

# Make a regular expression
# for validating an Email
regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'

def valid_email(email_str):
    if(re.search(regex, email_str)):
        return True
    else:
        return False

def email(email_str):
    """Return email_str if valid, raise an exception in other case."""
    if valid_email(email_str):
        return email_str
    else:
        raise ValueError('{} is not a valid email'.format(email_str))

def argParser():
    parser = RequestParser(bundle_errors=True)
    parser.add_argument("firstname", type=str, required=True, help="First Name Required")
    parser.add_argument("lastname", type=str, required=True, help="Last Name Required")
    parser.add_argument("email", type=email, required=True, help="Email Required")
    parser.add_argument("fromPhone", type=str, required=True, help="Phone Number Required")
    parser.add_argument("username", type=str, required=True, help="Username Required")
    parser.add_argument("password", type=str, required=True, help="Password Required")
    return parser

class Registration(Resource):

    def get(self):
        pass

    def post(self):
        # Step 1 is to get posted data by the user
        # postedData = request.get_json()
        # # Get the data
        # firstname = postedData["firstname"]
        # lastname = postedData["lastname"]
        # email = postedData["email"]
        # phone = postedData["fromPhone"]
        # username = postedData["username"]
        # password = postedData["password"]

        args = argParser.parse_args()

        firstname = args.get("firstname")
        lastname = args.get("lastname")
        email = args.get("email")
        phone = args.get("fromPhone")
        username = args.get("username")
        password = args.get("password")
        network = getNetworkName(phone)
        hashed_pw = sha256_crypt.hash(password)

        users = UsersRegisteration(firstname, lastname, email, phone, username, hashed_pw, network, balance=0.0, debt=0.0)

        if UserExist(phone):
            return jsonify(generateReturnDictionary(400, "Username/Phone Already Exists", "FAILURE"))

        # Store username,pw, phone, network into the database
        try:
            mongo.db.Register.insert_one({
                "FirstName": users.firstname,
                "LastName": users.lastname,
                "Email": users.email,
                "Phone": users.phone,
                "Network": users.network,
                "Username": users.username,
                "Password": users.hashed_pw,
                "Balance": users.balance,
                "Debt": users.debt,
                "DateCreated": date_time(),
                "DateUpdated": date_time(),
                "apiKeys": generateApiKeys()
            })

            retJson = {
                "code": 201,
                "msg": "You successfully signed up for mobile money wallet",
                "status": "SUCCESS"
            }
            return jsonify(retJson)
        except Exception as e:
            retJson = {
                "code": 409,
                "msg": "There was an error while trying to create your account -> , try again!",
                "status": "FAILURE: {0}".format(e.message)
            }
            return jsonify(retJson)
