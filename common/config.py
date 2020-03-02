from flask import Flask
from flask_mail import Mail
from flask_pymongo import PyMongo
from flask_restful import Api
from common.mongo_cred import data
from flasgger import Swagger

# MongoDB Credentials
DB = data.get("DB")
USERNAME = data.get("username")
PASSWORD = data.get("password")

app = Flask(__name__,template_folder='template')
swagger = Swagger(app)

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
app.config["MONGO_URI"] = "mongodb+srv://{0}:{1}@mobilemoney-q3w48.mongodb.net/{2}?retryWrites=true&w=majority".format(USERNAME, PASSWORD, DB)

mongo = PyMongo(app)
api   = Api(app)
mail  = Mail(app)
