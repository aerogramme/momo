from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from flask_pymongo import PyMongo
from functools import wraps
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
from passlib.hash import sha256_crypt
from itsdangerous import URLSafeTimedSerializer
import bcrypt
from datetime import datetime
import json
import uuid
from flask_mail import Message
from threading import Thread

#import sendmail
import dns # required for connecting with SRV
from bson.objectid import ObjectId
from flask_paginate import Pagination, get_page_parameter,get_page_args
#from flask_dance.contrib.google import make_google_blueprint, google


#############################################
# Author: Theophilus Siameh
#############################################

app = Flask(__name__)

app.config['SECRET_KEY'] = "MobileMoney"
#app.config["MONGO_URI"] = "mongodb://localhost:27017/MobileMoneyDB"
app.config["MONGO_URI"] = "mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority"

mongo = PyMongo(app)
api = Api(app)

#client = MongoClient("mongodb+srv://mobilemoney:Abc12345@mobilemoney-q3w48.mongodb.net/MobileMoneyDB?retryWrites=true&w=majority")
#mongo = client.MobileMoneyDB
#users = db["Users"]
users = list(range(100))

#api = Api(app)

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
    # current date and time
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def transaction_id():
    return str(uuid.uuid4())

def get_users(offset=0, per_page=3):
    return users[offset: offset + per_page] #mongo.db.Register.find({}).skip(offset).limit(offset + per_page)

# Index
@app.route('/')
def index():
    #return jsonify({'ip': request.remote_addr}), 200
    #register = mongo.db.Register
    #list_users = register.insert_one({"Username":"Anthony"})
    return render_template('home.html')

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
    name = StringField('Name', [validators.DataRequired(), validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.DataRequired(), validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.DataRequired(), validators.Length(min=6, max=50)])
    phone = StringField('Phone', [validators.DataRequired(), validators.Length(min=10, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

def UserExist(username):
    userAccount = mongo.db.Register
    if userAccount.count_documents({"Username":username}) == 0:
        return False
    else:
        return True

# User Register
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        username = form.username.data
        password = form.password.data

        # request.form['password']

        reg = mongo.db.Register
        existing_user = reg.find_one({"Username": username})
        if existing_user is not None:
            hashed_pw = sha256_crypt.hash((str(password)))
            reg.insert_one({
                "Name": name,
                "Email": email,
                "Phone": phone,
                "Username": username,
                "Password": hashed_pw,
                "Balance":float(0.0),
                "Debt":float(0.0),
                "DateTimeCreated":date_time()
                })

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form = form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        if username is None:
            error = 'Username not found'
            return render_template('login.html', error = error)

        # Get user by username
        # Get stored hash
        hashed_pw = mongo.db.Register.find_one({"Username":username})[0]["Password"]

        # Compare Passwords
        if sha256_crypt.verify(password_candidate, hashed_pw):
            #passed
            session['logged_in'] = True
            session['username'] = username

            flash('You are now logged in', 'success')
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Password/Username not found'
            return render_template('login.html', error = error)
        # else:
        #     error = 'Username not found'
        #     return render_template('login.html', error=error)
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
                hashed_pw = sha256_crypt.hash(str(new_password))
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


@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if request.method == 'POST' and form.validate():
        try:
            #user = User.query.filter_by(email=form.email.data).first_or_404()
            email = form.email.data
            emailFound = mongo.db.Register.find_one({"Email":email})["Email"]
        except:
            flash('Invalid email address!', 'error')
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
    if request.method=='GET': #Send the forgot password form
        return render_template('forgot_password.html')

    elif request.method=='POST':
        #Get the post data
        emailFound = request.form.get('email')
        username = request.form.get('username')

        if username is None or username=='':
            flash('Username is required')

        #Generate Random Pass and Set it to User object
        import random
        s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        passlen = 16
        generated_password =  "".join(random.sample(s,passlen))
        print(generated_password)
        #pw_hash = bcrypt.generate_password_hash(generated_password).decode('utf-8')
        hashed_pw = sha256_crypt.hash(str(generated_password))
        # update password
        mongo.db.Register.update_one({
            "Username": username
            },{
                "$set":{
                "Password": hashed_pw
                }
            })

        #Send Reset Mail
        #message = sendmail.SendPasswordResetMail(user, generated_password)
        send_password_reset_email(emailFound)
        flash('"Password Reset Link has been sent to your Email. "', 'success')
        #return redirect(url_for('dashboard'))
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

        flash('Balance Updated', 'success')

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


class Register(Resource):
    def post(self):
        #Step 1 is to get posted data by the user
        postedData = request.get_json()
        #Get the data
        name  = postedData["name"]
        email = postedData["email"]
        phone = postedData["fromPhone"]
        username  = postedData["username"]
        password  = postedData["password"]
        network   = postedData["network"]
        #hashed_pw = sha256_crypt.encrypt((str(password))

        if UserExist(username):
            retJson = {
                'status':301,
                'msg': 'Invalid Username'

            }
            return jsonify(retJson)

        hashed_pw = sha256_crypt.hash(password)

        #Store username,pw, phone, network into the database
        mongo.db.Register.insert_one({
            "Name": name,
            "Email": email,
            "Phone": phone,
            "Username": username,
            "Password": hashed_pw,
            "Network": network,
            "Balance":float(0.0),
            "Debt":float(0.0)
        })

        retJson = {
            "status": 200,
            "msg": "You successfully signed up for the mobile money wallet"
        }
        return jsonify(retJson)

# ##########################################################
# 	API SECTION
# ##########################################################

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = mongo.db.Register.find_one({"Username":username})["Password"]

    if sha256_crypt.verify(password, hashed_pw):
        return True
    else:
        return False

def cashWithUser(username):
    cash = mongo.db.Register.find_one({
        "Username":username
    })["Balance"]
    return cash

def debtWithUser(username):
    debt = mongo.db.Register.find_one({
        "Username":username
    })["Debt"]
    return debt


def generateReturnDictionary(status, msg):
    retJson = {
        "status":status,
        "msg": msg
    }
    return retJson

def verifyCredentials(username, password):
    if not UserExist(username):
        return generateReturnDictionary(301, "Invalid Username"), True

    correct_pw = verifyPw(username, password)

    if not correct_pw:
        return generateReturnDictionary(302, "Incorrect Password"), True

    return None, False

def updateAccount(username, balance):
    mongo.db.Register.update_one({
        "Username": username
    },{
        "$set":{
            "Balance": round(float(balance),2)
        }
    })

def updateDebt(username, balance):
    mongo.db.Register.update_one({
        "Username": username
    },{
        "$set":{
            "Debt": round(float(balance),2)
        }
    })

def transactionFee(amount):
    ''' 1% Transaction Fees'''
    return amount * 0.01

class TopUp(Resource):
    def post(self):
        # get json data
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money    = postedData["amount"]
        network  = postedData["network"]
        phone    = postedData["fromPhone"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        if money <= 0:
            return jsonify(generateReturnDictionary(304, "The money amount entered must be greater than 0"))

        cash = cashWithUser(username)

        fees = transactionFee(money)
        money = money - fees # Transaction fee

        # Add transaction fee to bank account
        bank_cash = cashWithUser("BANK")
        updateAccount("BANK", round(float(bank_cash + fees),2))
        # Add remaining to user
        updateAccount(username, round(float(cash + money),2))

        # Insert data into TopUp Collection
        mongo.db.TopUps.insert_one({
            "Username": username,
            "Amount": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "TransactionID":transaction_id(),
            "DateTime": date_time()
        })

        return jsonify(generateReturnDictionary(200, "Amount Added Successfully to account"))

class TransferMoney(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        toAccount= postedData["to"]
        money    = postedData["amount"]
        network  = postedData["network"]
        fromPhone = postedData["fromPhone"]
        toPhone  = postedData["toPhone"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        #cash = cashWithUser(username)
        cash_from = cashWithUser(username)
        cash_to   = cashWithUser(toAccount)
        bank_cash = cashWithUser("BANK")

        if cash_from <= 0:
            return jsonify(generateReturnDictionary(303, "You are out of money, please Add Cash or take a loan"))

        elif money <= 2:
            return jsonify(generateReturnDictionary(304, "The amount entered must be greater than 2.00 GHS"))

        if not UserExist(toAccount):
            return jsonify(generateReturnDictionary(301, "Received username is invalid"))

        fees = transactionFee(money)
        money_after = money - fees

        updateAccount("BANK", round(float(bank_cash + fees),2))  # add fees to bank
        updateAccount(toAccount, round(float(cash_to + money_after),2)) # add to receiving account
        updateAccount(username, round(float(cash_from - money_after),2)) # deduct money from sending account

        # save to transfer collection
        mongo.db.Transfer.insert_one({
            "Username": username,
            "AmountBeforeFees": round(float(money),2),
            "AmountAfterFees": round(float(money_after),2),
            "ToAccount": toAccount,
            "Network": network,
            "FromPhone": fromPhone,
            "ToPhone": toPhone,
            "TransactionID":transaction_id(),
            "DateTime": date_time()
        })

        # retJson = {
        #     "status":200,
        #     "msg": "Amount added successfully to account"
        # }
        return jsonify(generateReturnDictionary(200, "Amount added successfully to account"))

class CheckBalance(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        retJson = mongo.db.Register.find({
            "Username": username
        },{
            "Password": 0, #projection
            "_id":0
        })[0]

        return jsonify(retJson)


class WithdrawMoney(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money    = postedData["amount"]
        network  = postedData["network"]
        phone    = postedData["fromPhone"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        # Current Balance
        balance = cashWithUser(username)

        if balance < money:
            return jsonify(generateReturnDictionary(303, "Not Enough Cash in your account"))
        elif money < 0:
            return jsonify(generateReturnDictionary(303, "You cannot withdraw negative ammount"))

        elif balance < 0:
            return jsonify(generateReturnDictionary(303, "Your balance is in negative, please TopUp"))

        updateAccount(username, balance-money)

        # Insert data into Withdrawal Collection
        mongo.db.Withdrawal.insert_one({
            "Username": username,
            "Amount": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "Transaction_Id":transaction_id(),
            "DateTime": date_time()
        })

        return jsonify(generateReturnDictionary(200,"{0} Withdrawn from your account {1}".format(money, username)))

# add interest to loan : TODO

class TakeLoan(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money    = postedData["amount"]
        network  = postedData["network"]
        phone  = postedData["fromPhone"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        debt = debtWithUser(username)
        # update accounts
        updateAccount(username, round(float(cash + money),2))
        updateDebt(username, round(float(debt + money),2))

        # Insert data into takeloan Collection
        mongo.db.Takeloan.insert_one({
            "Username": username,
            "Loan_Amount": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "TransactionID":transaction_id(),
            "DateTime": date_time()
        })

        return jsonify(generateReturnDictionary(200, "Loan Added to Your Account"))


class PayLoan(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money    = postedData["amount"]
        network  = postedData["network"]
        phone    = postedData["fromPhone"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        debt = debtWithUser(username)

        if cash < money:
            return jsonify(generateReturnDictionary(303, "Not enough cash in your account"))
        elif money > debt:
            return jsonify(generateReturnDictionary(303, "You can't overpay your loan"))
        elif debt < 0.0:
            return jsonify(generateReturnDictionary(303, "Your debt is in negative"))

        updateAccount(username, round(float(cash - money),2))
        updateDebt(username, round(float(debt - money),2))

        # Insert data into payloan Collection
        mongo.db.Payloan.insert_one({
            "Username": username,
            "AmountPaid": round(float(money),2),
            "Network": network,
            "Phone": phone,
            "TransactionID":transaction_id(),
            "DateTime": date_time()
        })

        return jsonify(generateReturnDictionary(200, "Loan Paid Successfully"))

# End Points
api.add_resource(Register, '/register')
api.add_resource(TopUp, '/topup')
api.add_resource(TransferMoney, '/transfer')
api.add_resource(CheckBalance, '/balance')
api.add_resource(WithdrawMoney,'/withdraw')
api.add_resource(TakeLoan, '/loan')
api.add_resource(PayLoan, '/pay')

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80,debug=True)
