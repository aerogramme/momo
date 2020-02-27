from flask import Flask
from flask_mail import Mail
from flask_pymongo import PyMongo
from flask_restful import Api

app = Flask(__name__)
app.config.update(dict(
    DEBUG=True,
    MAIL_SERVER='smtp.googlemail.com',
    MAIL_PORT=465,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='theodondre@gmail.com',
    MAIL_PASSWORD='offpjnvauklxwivk'
))

app.config['SECRET_KEY'] = "MobileMoney"
# app.config["MONGO_URI"] = "mongodb://localhost:27017/MobileMoneyDB"
app.config["MONGO_URI"] = "mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority"
mongo = PyMongo(app)
api   = Api(app)
mail  = Mail(app)
