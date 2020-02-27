#!/usr/bin/python
#############################################
# Author: Theophilus Siameh
#############################################

from functools import wraps
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import Flask, jsonify, request
from flask import render_template, flash, redirect, url_for, session
from flask_mail import Mail, Message
from flask_paginate import Pagination, get_page_args
from flask_pymongo import PyMongo
from flask_restful import Api
#from flask_restplus import Resource, Api
from itsdangerous import URLSafeTimedSerializer
# from pymongo import MongoClient
from passlib.hash import sha256_crypt
from wtforms import Form, StringField, PasswordField, validators

from Users.UserRegister import UsersRegisteration
from common.util import date_time, generateApiKeys, getNetworkName, gen_reset_password, UserExist, \
    generateReturnDictionary

##################################################
# 	                  API SECTION
##################################################
from resources.register import Registration
from resources.topup import TopUp
from resources.transfer import TransferMoney
from resources.checkbalance import CheckBalance, auth
from resources.takeloan import TakeLoan
from resources.payloan import PayLoan
from resources.withdraw import WithdrawMoney

from common.config import mongo, api, mail, app

# app = Flask(__name__)
# app.config.update(dict(
#     DEBUG=True,
#     MAIL_SERVER='smtp.googlemail.com',
#     MAIL_PORT=465,
#     MAIL_USE_TLS=False,
#     MAIL_USE_SSL=True,
#     MAIL_USERNAME='theodondre@gmail.com',
#     MAIL_PASSWORD='offpjnvauklxwivk'
# ))
#
# app.config['SECRET_KEY'] = "MobileMoney"
# # app.config["MONGO_URI"] = "mongodb://localhost:27017/MobileMoneyDB"
# app.config["MONGO_URI"] = "mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority"
# mongo = PyMongo(app)
# api   = Api(app)
# mail  = Mail(app)


#######################################################################################################################
# client = MongoClient("mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority")
# mongo = client.MobileMoneyDB
# users = db["Users"]

# mongo = pymongo.MongoClient('mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority', maxPoolSize=50, connect=False)
# db = pymongo.database.Database(mongo, 'mydatabase')
# col = pymongo.collection.Collection(db, 'mycollection')
# col_results = json.loads(dumps(col.find().limit(5).sort("time", -1)))
#######################################################################################################################
users = list(range(100))

# Check if user logged in
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

def get_users(offset=0, per_page=3):
    # mongo.db.Register.find({}).skip(offset).limit(offset + per_page)
    return users[offset: offset + per_page]

# Index
@app.route('/')
def index():
    # return jsonify({'ip': request.remote_addr}), 200
    # register = mongo.db.Register
    # list_users = register.insert_one({"Username":"Anthony"})
    return render_template('home.html')


############################################
# send email
############################################
def send_mail(subject, body, recipients):
    try:
        msg = Message(subject, sender="theodondre@gmail.com", recipients=[recipients])
        msg.body = body
        mail.send(msg)
        return 'Mail sent!'
    except Exception as e:
        return (str(e))


# def send_email(subject, recipients, html_body):
#     msg = Message(subject, recipients=recipients)
#     msg.html = html_body
#     thr = Thread(target=send_async_email, args=[msg])
#     thr.start()

# def send_password_reset_email(user_email):
#     password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
#
#     password_reset_url = url_for(
#         'reset_with_token',
#         token = password_reset_serializer.dumps(user_email, salt='password-reset-salt'),
#         _external=True)
#
#     html = render_template(
#         'email_password_reset.html',
#         password_reset_url = password_reset_url)
#
#     send_email('Password Reset Requested', user_email, html)

#######################
# Search
#######################
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.Register

        # search db
        searchResult = findByUsername.find({"$or": [
            {"Username": {'$regex': q}},
            {"Email": {'$regex': q}},
            {"Phone": {'$regex': q}}
        ]})

        return render_template('search.html', searchResult=searchResult)

    return render_template('search.html')


@app.route('/searchtop', methods=['GET', 'POST'])
def searchtop():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.TopUps

        # search db
        searchTop = findByUsername.find({"$or": [
            {"Username": {'$regex': q}},
            {"Email": {'$regex': q}},
            {"Phone": {'$regex': q}}
        ]})

        return render_template('searchtop.html', searchTop=searchTop)

    return render_template('searchtop.html')


@app.route('/searchloan', methods=['GET', 'POST'])
def searchloan():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.Takeloan

        # search db
        searchLoan = findByUsername.find({"$or": [
            {"Username": {'$regex': q}},
            {"Email": {'$regex': q}},
            {"Phone": {'$regex': q}}
        ]})

        return render_template('searchloan.html', searchLoan=searchLoan)

    return render_template('searchloan.html')


@app.route('/searchPay', methods=['GET', 'POST'])
def searchPay():
    if request.method == "POST":
        q = request.form['search']
        findByUsername = mongo.db.Payloan

        # search db
        searchPay = findByUsername.find({"$or": [
            {"Username": {'$regex': q}},
            {"Email": {'$regex': q}},
            {"Phone": {'$regex': q}}
        ]})

        return render_template('searchpay.html', searchPay=searchPay)

    return render_template('searchpay.html')


@app.route('/listusers')
def listusers():
    registeredUsers = mongo.db.Register
    listUsers = registeredUsers.find({})
    # total = listUsers.count()
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    listUser = listUsers.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("listusers.html",
                           listUser=listUser,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route('/withdraw')
def withdraw():
    withdrawHistory = mongo.db.Withdrawal
    withdrawalObject = withdrawHistory.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    withdrawalObject = withdrawalObject.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("withdrawal.html",
                           withdrawalObject=withdrawalObject,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route('/balance')
def balance():
    balanceHistory = mongo.db.Register
    balanceObject = balanceHistory.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    balanceObject = balanceObject.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("checkbalance.html",
                           balanceObject=balanceObject,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route('/topups')
def topups():
    tops = mongo.db.TopUps
    topup = tops.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    topup = topup.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("topups.html",
                           topup=topup,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route('/loan')
def loan():
    loans = mongo.db.Takeloan
    loanObject = loans.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    loanObject = loanObject.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("takeloan.html",
                           loanObject=loanObject,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route('/pay')
def pay():
    payloans = mongo.db.Payloan
    payloanObject = payloans.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    payloanObject = payloanObject.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("payloan.html",
                           payloanObject=payloanObject,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route('/transfer')
def transfer():
    transfers = mongo.db.Transfer
    transfersObject = transfers.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    transfersObject = transfersObject.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("transfer.html",
                           transfersObject=transfersObject,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


@app.route("/dashboard")
def dashboard():
    all_account = mongo.db.Register
    momo_account = all_account.find({})
    total = len(users)

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    momo_account = momo_account.skip((page - 1) * per_page).limit(per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template("dashboard.html",
                           momo_account=momo_account,
                           page=page,
                           per_page=per_page,
                           pagination=pagination)


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
    data = mongo.db.Register.find_one({"Username": "Theo.kartel"})
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
            return jsonify(generateReturnDictionary(301, 'Invalid Username/Phone', "FAILURE"))

        reg = mongo.db.Register
        existing_user = reg.find_one({"Phone": phone})
        if existing_user is None:
            # hash password
            hashed_pw = sha256_crypt.hash(str(password))
            # insert into db

            userReg = UsersRegisteration(firstname, lastname, email, phone, network, username, hashed_pw, balance=0.0,
                                         debt=0.0)
            reg.insert_one({
                "FirstName": userReg.firstname,
                "LastName": userReg.lastname,
                "Email": userReg.email,
                "Phone": userReg.phone,
                "Network": userReg.network,
                "Username": userReg.username,
                "Password": userReg.hashed_pw,
                "Balance": userReg.balance,
                "Debt": userReg.debt,
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
        username = form.username.data  # request.form['username']
        password_candidate = form.password.data  # request.form['password']

        # Get user by username
        # Get stored hash
        hashed_pw = mongo.db.Register.find_one({"Username": username})

        # Compare Passwords
        if sha256_crypt.verify(str(password_candidate), hashed_pw['Password']):
            # passed
            session['logged_in'] = True
            session['username'] = username

            flash('You are now logged in', 'success')
            return redirect(url_for('dashboard'))

        if not sha256_crypt.verify(str(password_candidate), hashed_pw['Password']):
            error = 'Invalid password'
            return render_template('login.html', error=error)
        if username is None or username == '':
            error = 'Username is required'
            return render_template('login.html', error=error)
        if password_candidate is None or password_candidate == '':
            error = 'Password is required'
            return render_template('login.html', error=error)
        if password_candidate == '' and username == '':
            error = 'Password/Username is required'
            return render_template('login.html', error=error)
    return render_template('login.html')


# Balance Form Class
class BalanceForm(Form):
    balance = StringField('Balance')
    debt = StringField('Debt')


#########################################################
# change password
#########################################################

@app.route("/change_password/", methods=['GET', 'POST'])
@is_logged_in
def change_password():
    if request.method == 'GET':  # Send the change password form
        return render_template('change_password.html')

    elif request.method == 'POST':
        # Get the post data
        username = request.form['username']  # email = request.form.get('email')
        current_password = request.form['current_password']
        new_password = request.form['password']
        confirm_new_password = request.form['confirm_password']

        # Checks
        errors = []
        if username is None or username == '':
            errors.append('Username is required')
        if current_password is None or current_password == '':
            errors.append('Current Password is required')
        if new_password is None or new_password == '':
            errors.append('New Password is required')
        if confirm_new_password is None or confirm_new_password == '':
            errors.append('Confirm New Password is required')
        if new_password != confirm_new_password:
            errors.append('New Passwords do not match')
        # current hashed password
        usernameByPassword = mongo.db.Register.find_one({"Username": username})["Password"]

        if usernameByPassword:
            if not sha256_crypt.verify(current_password, usernameByPassword):
                errors.append("Password is incorrect")
            # Query for user from database and check password
            elif len(errors) == 0:
                # if verifyPw(username, current_password):
                hashed_pw = sha256_crypt.hash(new_password)
                # update password
                mongo.db.Register.update_one({
                    "Username": username
                }, {
                    "$set": {
                        "Password": hashed_pw
                    }
                })
                # return "Password Changed"
                flash('Password Changed Successfully', 'success')
                return redirect(url_for('login'))
        else:  # No usable password
            errors.append("User has no Password")

        # Error Message
        if len(errors) > 0:
            return render_template('change_password.html', errors=errors)


###################################################
# send email
###################################################
class EmailForm(Form):
    email = StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=50)])
    # email = StringField('Email', validators=[validators.DataRequired(), Email(), Length(min=6, max=40)])


class PasswordForm(Form):
    password = PasswordField('Password', [validators.DataRequired()])


@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if request.method == 'POST' and form.validate():
        try:
            # user = User.query.filter_by(email=form.email.data).first_or_404()
            email = form.email.data
            emailFound = mongo.db.Register.find_one({"Email": email})["Email"]
        except:
            flash('There is no account with that email. You must register first.!', 'error')
            return render_template('password_reset_email.html', form=form)

        if emailFound:
            #send_password_reset_email(emailFound)
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
            # user = User.query.filter_by(email=email).first_or_404()
            emailFound = mongo.db.Register.find_one({"Email": email})["Email"]
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('login'))

        # user.password = form.password.data
        # db.session.add(user)
        # db.session.commit()

        password = form.password.data

        mongo.db.Register.update_one({
            "Username": username
        }, {
            "$set": {
                "Password": password
            }
        })

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password_with_token.html', form=form, token=token)


@app.route("/forgot_password/", methods=['GET', 'POST'])
def forgot_password():
    '''Forgot Password'''
    if request.method == 'GET':  # Send the forgot password form
        return render_template('forgot_password.html')

    elif request.method == 'POST':
        # Get the post data
        emailFound = request.form.get('email')
        username = request.form.get('username')

        if username is None or username == '':
            flash('Username is required')

        # Generate Random Pass and Set it to User object
        generated_password = gen_reset_password()
        hashed_pw = sha256_crypt.hash(generated_password)
        # update password
        mongo.db.Register.update_one({
            "Username": username
        }, {
            "$set": {
                "Password": hashed_pw
            }
        })

        # Send Reset Mail
        # message = sendmail.SendPasswordResetMail(user, generated_password)
        send_mail("Password Reset",
                  "Password Reset has been sent to your Email. \nHere is your new password : {0}".format(
                      generated_password), emailFound)
        flash('Password Reset Link has been sent to your Email.', 'success')
        return redirect(url_for('login'))
        # if message is not None:
        #    return "Password Reset Link has been sent to your Email. "
        # else:
        #    errors.append("Could Not Send Mail. Try Again Later.")

        # if len(errors) > 0:
        #    return render_template('error.html', errors=errors)


# Edit Balance
@app.route('/edit_balance/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_balance(id):
    # Create cursor
    bal = mongo.db.Register.find_one({"_id": ObjectId(id)})  # ["Password"]
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
        }, {
            "$set": {
                "Balance": round(float(balance), 2),
                "Debt": round(float(debt), 2)
            }
        }, upsert=True)

        flash('Balance/Debt Updated', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_balance.html', form=form)


# Delete Account
@app.route('/delete_account/<string:id>', methods=['POST'])
@is_logged_in
def delete_account(id):
    # Create cursor
    account = mongo.db.Register.find_one({"_id": ObjectId(id)})  # ["Password"]

    if account is None:
        flash('Account does not exist', 'failure')
    else:
        mongo.db.Register.delete_one({"_id": ObjectId(account['_id'])})

    flash('Account Deleted', 'success')
    return redirect(url_for('dashboard'))


#####################################
# TODO : add interest to loan
#####################################

# def getMonthlyPayment(loanAmount, monthlyInterateRate, numberOfYears):
#     import math
#     monthlyPayment = loanAmount * monthlyInterateRate/(1.0 - math.pow(1.0 + monthlyInterateRate,-(numberOfYears * 12)))
#     return monthlyPayment


# End Points
api.add_resource(Registration, '/momo/api/v1.0/register', endpoint = '/register')
api.add_resource(TopUp, '/momo/api/v1.0/topup', endpoint = '/topup')
api.add_resource(TransferMoney, '/momo/api/v1.0/transfer', endpoint = '/transfer')
api.add_resource(CheckBalance, '/momo/api/v1.0/balance', endpoint = '/balance')
api.add_resource(WithdrawMoney, '/momo/api/v1.0/withdraw', endpoint = '/withdraw')
api.add_resource(TakeLoan, '/momo/api/v1.0/loan', endpoint = '/loan')
api.add_resource(PayLoan, '/momo/api/v1.0/pay', endpoint = '/pay')

# api.add_resource(Registration,'/register')
# api.add_resource(TopUp, '/topup')
# api.add_resource(TransferMoney, '/transfer')
# #api.add_resource(CheckBalance, '/balance')
# api.add_resource(WithdrawMoney, '/withdraw')
# api.add_resource(TakeLoan, '/loan')
# api.add_resource(PayLoan, '/pay')

if __name__ == '__main__':
    # app.run(host='0.0.0.0',port=80,debug=True)
    app.run(debug=True)
