#!/usr/bin/python

import os
import random
import uuid
from binascii import hexlify
from datetime import datetime
from functools import wraps
from threading import Thread

from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask import render_template, flash, redirect, url_for, session
from flask_mail import Mail
from flask_mail import Message
from flask_paginate import Pagination, get_page_args
from flask_pymongo import PyMongo
from flask_restful import Api, Resource
from itsdangerous import URLSafeTimedSerializer
# from pymongo import MongoClient
from passlib.hash import sha256_crypt
from wtforms import Form, StringField, PasswordField, validators

#############################################
# Author: Theophilus Siameh
#############################################

app = Flask(__name__)
app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.googlemail.com',
    MAIL_PORT = 465,
    MAIL_USE_TLS = False,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = 'theodondre@gmail.com',
    MAIL_PASSWORD = 'offpjnvauklxwivk'
))


app.config['SECRET_KEY'] = "MobileMoney"
#app.config["MONGO_URI"] = "mongodb://localhost:27017/MobileMoneyDB"
app.config["MONGO_URI"] = "mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority"

mongo = PyMongo(app)
api = Api(app)
mail = Mail(app)

#######################################################################################################################
#client = MongoClient("mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority")
#mongo = client.MobileMoneyDB
#users = db["Users"]

# mongo = pymongo.MongoClient('mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority', maxPoolSize=50, connect=False)
# db = pymongo.database.Database(mongo, 'mydatabase')
# col = pymongo.collection.Collection(db, 'mycollection')
# col_results = json.loads(dumps(col.find().limit(5).sort("time", -1)))
#######################################################################################################################

users = list(range(100))

#Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

def date_time():
    '''current date and time'''
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def getPrettyTime():
    """Get user's pretty current time"""
    rightnow = datetime.today()
    prettytime = rightnow.ctime()
    return prettytime

def transaction_id():
    '''Generate Transaction ID'''
    return str(uuid.uuid4())

def getNetworkName(phoneNumber):
    '''get network name given phone number'''
    switcher = {"024":"MTN",
                "054":"MTN",
                "055":"MTN",
                "059":"MTN",
                "026":"AIRTEL",
                "056":"AIRTEL",
                "027":"TIGO",
                "057":"TIGO",
                "020":"VODAFONE",
                "030":"VODAFONE",
                "050":"VODAFONE"
                }
    return switcher.get(phoneNumber[0:3],"Unsupported phone number for network detected")

def generateApiKeys(passlen = 16):
    ''' Generate API Keys '''
    return hexlify(os.urandom(passlen)).decode("utf-8")

def gen_reset_password(passlen = 16):
    '''generate reset password'''
    s = "!_*&abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ#@(~+"
    generated_password = "".join(random.sample(s,passlen))
    return str(generated_password)

def get_users(offset=0, per_page=3):
    # mongo.db.Register.find({}).skip(offset).limit(offset + per_page)
    return users[offset: offset + per_page]


###########################################################
# 	FUNC SECTION
###########################################################

def UserExist(phone):
    '''Check if Phone Number Exist in DB'''
    userAccount = mongo.db.Register
    if userAccount.count_documents({"Phone":phone}) == 0:
        return False
    else:
        return True


def verifyPw(phone, password):
    if not UserExist(phone):
        return False

    hashed_pw = mongo.db.Register.find_one({"Phone":phone})["Password"]

    if sha256_crypt.verify(password, hashed_pw):
        return True
    else:
        return False

def cashWithUser(phone):
    cash = mongo.db.Register.find_one({
        "Phone":phone
    })["Balance"]
    return cash

def debtWithUser(phone):
    debt = mongo.db.Register.find_one({
        "Phone":phone
    })["Debt"]
    return debt


def generateReturnDictionary(code, msg, status):
    retJson = {
        "code":code,
        "msg": msg,
        "status": status
    }
    return retJson

def verifyCredentials(phone, password):
    if not UserExist(phone):
        return generateReturnDictionary(301, "Invalid Username/Phone", "FAILURE"), True

    correct_pw = verifyPw(phone, password)

    if not correct_pw:
        return generateReturnDictionary(302, "Incorrect Password", "FAILURE"), True

    return None, False

def updateAccount(phone, balance):
    mongo.db.Register.update_one({
        "Phone": phone
    },{
        "$set":{
            "Balance": round(float(balance),2)
        }
    })

def updateDebt(phone, balance):
    mongo.db.Register.update_one({
        "Phone": phone
    },{
        "$set":{
            "Debt": round(float(balance),2)
        }
    })

def transactionFee(amount):
    ''' 1% Transaction Fees '''
    return amount * 0.01


# Index
@app.route('/')
def index():
    #return jsonify({'ip': request.remote_addr}), 200
    #register = mongo.db.Register
    #list_users = register.insert_one({"Username":"Anthony"})
    return render_template('home.html')

############################################
# send email
############################################
def send_mail(subject,body,recipients):
    try:
        msg = Message(subject,sender="theodondre@gmail.com",recipients= [recipients])
        msg.body = body
        mail.send(msg)
        return 'Mail sent!'
    except Exception as e:
        return(str(e))


def send_email(subject, recipients, html_body):
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()

def send_password_reset_email(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    password_reset_url = url_for(
        'reset_with_token',
        token = password_reset_serializer.dumps(user_email, salt='password-reset-salt'),
        _external=True)

    html = render_template(
        'email_password_reset.html',
        password_reset_url = password_reset_url)

    send_email('Password Reset Requested', user_email, html)

#######################
# Search
#######################
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.Register

        # search db
        searchResult = findByUsername.find({"$or":[
                                                    {"Username":{'$regex': q}},
                                                    {"Email":{'$regex': q}},
                                                    {"Phone":{'$regex': q}}
                                                ]})

        return render_template('search.html', searchResult = searchResult)

    return render_template('search.html')


@app.route('/searchtop', methods=['GET', 'POST'])
def searchtop():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.TopUps

        # search db
        searchTop = findByUsername.find({"$or":[
                                                    {"Username":{'$regex': q}},
                                                    {"Email":{'$regex': q}},
                                                    {"Phone":{'$regex': q}}
                                                ]})

        return render_template('searchtop.html', searchTop = searchTop)

    return render_template('searchtop.html')


@app.route('/searchloan', methods=['GET', 'POST'])
def searchloan():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.Takeloan

        # search db
        searchLoan = findByUsername.find({"$or":[
                                                    {"Username":{'$regex': q}},
                                                    {"Email":{'$regex': q}},
                                                    {"Phone":{'$regex': q}}
                                                ]})

        return render_template('searchloan.html', searchLoan = searchLoan)

    return render_template('searchloan.html')

@app.route('/searchPay', methods=['GET', 'POST'])
def searchPay():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.Payloan

        # search db
        searchPay = findByUsername.find({"$or":[
                                                    {"Username":{'$regex': q}},
                                                    {"Email":{'$regex': q}},
                                                    {"Phone":{'$regex': q}}
                                                ]})

        return render_template('searchpay.html', searchPay = searchPay)

    return render_template('searchpay.html')

@app.route('/listusers')
def listusers():
    registeredUsers = mongo.db.Register
    listUsers = registeredUsers.find({})
    #total = listUsers.count()

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    listUser = listUsers.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("listusers.html",
                           listUser = listUser,
                           page = page,
                           per_page = per_page,
                           pagination = pagination)

@app.route('/withdraw')
def withdraw():
    withdrawHistory = mongo.db.Withdrawal
    withdrawalObject = withdrawHistory.find({})

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    withdrawalObject = withdrawalObject.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("withdrawal.html",
                            withdrawalObject = withdrawalObject,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

@app.route('/balance')
def balance():
    balanceHistory = mongo.db.Register
    balanceObject = balanceHistory.find({})

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    balanceObject = balanceObject.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("checkbalance.html",
                            balanceObject = balanceObject,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

@app.route('/topups')
def topups():
    tops = mongo.db.TopUps
    topup = tops.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    topup = topup.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("topups.html",
                            topup = topup,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

@app.route('/loan')
def loan():
    loans = mongo.db.Takeloan
    loanObject = loans.find({})

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    loanObject = loanObject.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("takeloan.html",
                            loanObject = loanObject,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

@app.route('/pay')
def pay():
    payloans = mongo.db.Payloan
    payloanObject = payloans.find({})

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    payloanObject = payloanObject.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("payloan.html",
                            payloanObject = payloanObject,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

@app.route('/transfer')
def transfer():
    transfers = mongo.db.Transfer
    transfersObject = transfers.find({})

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    transfersObject = transfersObject.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("transfer.html",
                            transfersObject = transfersObject,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

@app.route("/dashboard")
def dashboard():
    all_account = mongo.db.Register
    momo_account = all_account.find({})

    total = len(users)

    page, per_page, offset = get_page_args(page_parameter = 'page', per_page_parameter = 'per_page')

    momo_account = momo_account.skip((page - 1) * per_page).limit(per_page)

    pagination = Pagination(page = page, per_page = per_page, total = total, css_framework = 'bootstrap4')

    return render_template("dashboard.html",
                            momo_account = momo_account,
                            page = page,
                            per_page = per_page,
                            pagination = pagination)

# Register Form Class
class RegisterForm(Form):
    firstname = StringField('First Name', [validators.DataRequired(), validators.Length(min=1, max=50)])
    lastname = StringField('Last Name', [validators.DataRequired(), validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=50)])
    phone = StringField('Phone', [validators.DataRequired(), validators.Length(min=10, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


class LogonForm(Form):
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired(), validators.Length(min=4, max=25)])

@app.route('/show')
def showdata():
    data = mongo.db.Register.find_one({"Username":"Theo.kartel"})

    return dumps(data['Username'] + ':' + data['Password'])

# User Register
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    '''User Registeration'''
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        # fields
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        phone = form.phone.data
        username = form.username.data
        password = form.password.data
        network = getNetworkName(phone)

        # check if phone number exist
        if UserExist(phone):
            return jsonify(generateReturnDictionary(301,'Invalid Username/Phone', "FAILURE"))

        reg = mongo.db.Register
        existing_user = reg.find_one({"Phone": phone})
        if existing_user is None:
            # hash password
            hashed_pw = sha256_crypt.hash(str(password))
            # insert into db
            reg.insert_one({
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
                "apiKeys": generateApiKeys()
                })

        flash('You successfully signed up for the mobile money wallet, you can now log-in', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''User login'''
    form = LogonForm(request.form)
    if request.method == 'POST':
        # Get Form Fields
        # phone = form.phone.data # request.form['phone']
        username = form.username.data # request.form['username']
        password_candidate = form.password.data # request.form['password']

        # Get user by username
        # Get stored hash
        hashed_pw = mongo.db.Register.find_one({"Username": username})

        # Compare Passwords
        if sha256_crypt.verify(str(password_candidate), hashed_pw['Password']):
            #passed
            session['logged_in'] = True
            session['username'] = username

            flash('You are now logged in', 'success')
            return redirect(url_for('dashboard'))

        if not sha256_crypt.verify(str(password_candidate), hashed_pw['Password']):
            error = 'Invalid password'
            return render_template('login.html', error = error)
        if username is None or username =='':
            error = 'Username is required'
            return render_template('login.html', error = error)
        if password_candidate is None or password_candidate =='':
            error = 'Password is required'
            return render_template('login.html', error = error)
        if password_candidate=='' and username=='':
            error = 'Password/Username is required'
            return render_template('login.html', error = error)
    return render_template('login.html')

# Balance Form Class
class BalanceForm(Form):
    balance = StringField('Balance')
    debt = StringField('Debt')

#####################
# change password
#####################

@app.route("/change_password/", methods=['GET', 'POST'])
@is_logged_in
def change_password():
    if request.method=='GET': #Send the change password form
        return render_template('change_password.html')

    elif request.method=='POST':
        #Get the post data
        username = request.form['username'] # email = request.form.get('email')
        current_password = request.form['current_password']
        new_password = request.form['password']
        confirm_new_password = request.form['confirm_password']

        #Checks
        errors = []
        if username is None or username=='':
            errors.append('Username is required')
        if current_password is None or current_password=='':
            errors.append('Current Password is required')
        if new_password is None or new_password=='':
            errors.append('New Password is required')
        if confirm_new_password is None or confirm_new_password=='':
            errors.append('Confirm New Password is required')
        if new_password!=confirm_new_password:
            errors.append('New Passwords do not match')
        # current hashed password
        usernameByPassword = mongo.db.Register.find_one({"Username":username})["Password"]

        if usernameByPassword:
            if not sha256_crypt.verify(current_password,usernameByPassword):
                errors.append("Password is incorrect")
            # Query for user from database and check password
            elif len(errors) == 0:
                #if verifyPw(username, current_password):
                hashed_pw = sha256_crypt.hash(new_password)
                    # update password
                mongo.db.Register.update_one({
                    "Username": username
                    },{
                        "$set":{
                        "Password": hashed_pw
                        }
                    })
                #return "Password Changed"
                flash('Password Changed Successfully', 'success')
                return redirect(url_for('login'))
        else: #No usable password
            errors.append("User has no Password")

        #Error Message
        if len(errors) > 0:
            return render_template('change_password.html', errors=errors)

######################
# send email
######################
class EmailForm(Form):
    email = StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=50)])
    #email = StringField('Email', validators=[validators.DataRequired(), Email(), Length(min=6, max=40)])

class PasswordForm(Form):
    password = PasswordField('Password', [validators.DataRequired()])


@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if request.method == 'POST' and form.validate():
        try:
            #user = User.query.filter_by(email=form.email.data).first_or_404()
            email = form.email.data
            emailFound = mongo.db.Register.find_one({"Email":email})["Email"]
        except:
            flash('There is no account with that email. You must register first.!', 'error')
            return render_template('password_reset_email.html', form=form)

        if emailFound:
            send_password_reset_email(emailFound)
            flash('Please check your email for a password reset link.', 'success')
        else:
            flash('Your email address must be confirmed before attempting a password reset.', 'error')
        return redirect(url_for('login'))

    return render_template('password_reset_email.html', form=form)


@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    form = PasswordForm()

    if form.validate():
        try:
            #user = User.query.filter_by(email=email).first_or_404()
            emailFound = mongo.db.Register.find_one({"Email":email})["Email"]
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('login'))

        # user.password = form.password.data
        # db.session.add(user)
        # db.session.commit()

        password = form.password.data

        mongo.db.Register.update_one({
            "Username": username
            },{
                "$set":{
                "Password": password
                }
            })

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password_with_token.html', form=form, token=token)


@app.route("/forgot_password/", methods=['GET', 'POST'])
def forgot_password():
    '''Forgot Password'''
    if request.method=='GET': #Send the forgot password form
        return render_template('forgot_password.html')

    elif request.method=='POST':
        # Get the post data
        emailFound = request.form.get('email')
        username   = request.form.get('username')

        if username is None or username=='':
            flash('Username is required')

        # Generate Random Pass and Set it to User object
        #pw_hash = bcrypt.generate_password_hash(generated_password).decode('utf-8')

        generated_password = gen_reset_password()
        hashed_pw = sha256_crypt.hash(generated_password)
        # update password
        mongo.db.Register.update_one({
            "Username": username
            },{
                "$set":{
                "Password": hashed_pw
                }
            })

        # Send Reset Mail
        # message = sendmail.SendPasswordResetMail(user, generated_password)
        send_mail("Password Reset","Password Reset has been sent to your Email. \nHere is your new password : {0}".format(generated_password),emailFound)
        flash('Password Reset Link has been sent to your Email.', 'success')
        return redirect(url_for('login'))
        #if message is not None:
        #    return "Password Reset Link has been sent to your Email. "
        #else:
        #    errors.append("Could Not Send Mail. Try Again Later.")

        #if len(errors) > 0:
        #    return render_template('error.html', errors=errors)

# Edit Balance
@app.route('/edit_balance/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_balance(id):
    # Create cursor
    bal = mongo.db.Register.find_one({"_id":ObjectId(id)}) #["Password"]
    # Get form
    form = BalanceForm(request.form)

    # Populate balance form fields
    form.balance.data = bal['Balance']
    form.debt.data = bal['Debt']

    if request.method == 'POST' and form.validate():
        balance = request.form['balance']
        debt = request.form['debt']
        # Update Query Execute
        mongo.db.Register.update_one({
            "_id": ObjectId(id)
        },{
            "$set":{
                "Balance": round(float(balance),2),
                "Debt": round(float(debt),2)
            }
        },upsert=True)

        flash('Balance/Debt Updated', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_balance.html', form = form)

# Delete Account
@app.route('/delete_account/<string:id>', methods=['POST'])
@is_logged_in
def delete_account(id):
    # Create cursor
    account = mongo.db.Register.find_one({"_id":ObjectId(id)}) #["Password"]

    if account is None:
        flash('Account does not exist', 'failure')
    else:
        mongo.db.Register.delete_one({"_id": ObjectId(account['_id'])})

    flash('Account Deleted', 'success')
    return redirect(url_for('dashboard'))

###########################################################
# 	API SECTION
###########################################################

class Register(Resource):
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
        network = getNetworkName(phone) # postedData["network"]

        if UserExist(phone):
            return jsonify(generateReturnDictionary(301, "Invalid Username/Phone", "FAILURE"))

        hashed_pw = sha256_crypt.hash(password)
        apiKey = generateApiKeys()

        # Store username,pw, phone, network into the database
        mongo.db.Register.insert_one({
                "FirstName":firstname,
                "LastName":lastname,
                "Email":email,
                "Phone":phone,
                "Network":network,
                "Username":username,
                "Password":hashed_pw,
                "Balance":float(0.0),
                "Debt":float(0.0),
                "DateTimeCreated":date_time(),
                "apiKeys":apiKey
                })

        retJson = {
            "code": 200,
            "msg": "You successfully signed up for the mobile money wallet",
            "apiKey": apiKey,
            "status": "SUCCESS"
        }
        return jsonify(retJson)

# TOPUP MONEY
class TopUp(Resource):
    def post(self):
        # get json data
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]
        phone = postedData["fromPhone"]
        # network = postedData["network"]
        network = getNetworkName(phone)

        retJson, error = verifyCredentials(phone, password)
        if error:
            return jsonify(retJson)

        if money <= float(0):
            return jsonify(generateReturnDictionary(304, "The money amount entered must be greater than 0", "FAILURE"))

        cash = cashWithUser(phone)
        # Transaction fee
        fees = transactionFee(money)
        money = round(money - fees, 2)

        # Add transaction fee to bank account
        bank_cash = cashWithUser("0240000000")
        updateAccount("0240000000", round(float(bank_cash + fees), 2))
        # Add remaining money to user account
        updateAccount(phone, round(float(cash + money),2))

        # Insert data into TopUp Collection
        mongo.db.TopUps.insert_one({
            "Username": username,
            "Amount": round(float(money), 2),
            "Network": network,
            "Phone": phone,
            "TransactionID": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Amount Added Successfully to account", "SUCCESS"))

# TRANSFER MONEY
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
        cash_to  = cashWithUser(toPhone)
        bank_cash = cashWithUser("0240000000")

        if cash_from <= float(0):
            return jsonify(generateReturnDictionary(303, "You are out of money, Please Topup some Cash or take a loan", "FAILURE"))
        elif money <= float(1):
            return jsonify(generateReturnDictionary(304, "The amount entered must be greater than GHS 1.00", "FAILURE"))

        if not UserExist(toPhone):
            return jsonify(generateReturnDictionary(301, "Received username/phone is invalid", "FAILURE"))

        fees = transactionFee(money)
        money_after = round(money - fees, 2)

        updateAccount("0240000000", round(float(bank_cash + fees), 2))  # add fees to bank
        updateAccount(toPhone, round(float(cash_to + money_after), 2)) # add to receiving account
        updateAccount(fromPhone, round(float(cash_from - money_after), 2)) # deduct money from sending account

        # save to transfer collection
        mongo.db.Transfer.insert_one({
            "Username": username,
            "AmountBeforeFees": round(float(money),2),
            "AmountAfterFees": round(float(money_after),2),
            "FromPhone": fromPhone,
            "ToPhone": toPhone,
            "ToNetwork": toNetwork,
            "FromNetwork": fromNetwork,
            "TransactionID": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Amount added successfully to account","SUCCESS"))

# CHECK BALANCE
class CheckBalance(Resource):
    def post(self):

        postedData = request.get_json()
        phone  = postedData["fromPhone"]
        username = postedData["username"]
        password = postedData["password"]

        retJson, error = verifyCredentials(phone, password)
        if error:
            return jsonify(retJson)

        retJson = mongo.db.Register.find({
            "Phone": phone
        },{
            "Password": 0, #projection
            "_id":0
        })[0]
        return jsonify(retJson)

# WITHDRAW MONEY
class WithdrawMoney(Resource):
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
            return jsonify(generateReturnDictionary(303, "Your balance is in negative, please TopUp with some cash", "FAILURE"))

        updateAccount(phone, balance-money)

        # Insert data into Withdrawal Collection
        mongo.db.Withdrawal.insert_one({
            "Username": username,
            "Amount": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "Transaction_Id": transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Money Withdrawn from your wallet", "SUCCESS"))

#####################################
# TODO : add interest to loan
#####################################

# TAKE LOAN
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
        updateAccount(phone, round(float(cash + money),2))
        updateDebt(phone, round(float(debt + money),2))

        # Insert data into take loan Collection
        mongo.db.Takeloan.insert_one({
            "Username": username,
            "Loan_Amount": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "TransactionID":transaction_id(),
            "DateTime": date_time()
        })
        return jsonify(generateReturnDictionary(200, "Loan Amount Added to Your Account Successfully","SUCCESS"))

# PAY LOAN
class PayLoan(Resource):
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
        return jsonify(generateReturnDictionary(200, "Loan Amount Paid Successfully","SUCCESS"))



# End Points
api.add_resource(Register, '/register')
api.add_resource(TopUp, '/topup')
api.add_resource(TransferMoney, '/transfer')
api.add_resource(CheckBalance, '/balance')
api.add_resource(WithdrawMoney,'/withdraw')
api.add_resource(TakeLoan, '/loan')
api.add_resource(PayLoan, '/pay')

if __name__ == '__main__':
    #app.run(host='0.0.0.0',port=80,debug=True)
    app.run(debug=True)
