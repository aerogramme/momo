from flask import Flask
from flask_mail import Message
from flask_mail import Mail

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

mail = Mail(app)

# app.config['MAIL_SERVER']='smtp.gmail.com'
# app.config['MAIL_PORT'] = 465
# app.config['MAIL_USERNAME'] = 'theodondre@gmail.com'
# app.config['MAIL_PASSWORD'] = ''
# app.config['MAIL_USE_SSL'] = True
# app.config['MAIL_USE_TLS'] = False

@app.route('/send-mail/',methods=['GET', 'POST'])
def send_mail():
	try:
		msg = Message("Send Mail Tutorial!",
		  			sender="theodondre@gmail.com",
		  			recipients=["theodondre@gmail.com"])
		msg.body = "Yo!\nHave you heard the good word of Python???"
		mail.send(msg)
		return 'Mail sent!'
	except Exception as e:
		return(str(e))

if __name__ == '__main__':
	app.run(debug=True)



# export MAIL_SERVER=smtp.googlemail.com
# export MAIL_PORT=587
# export MAIL_USE_TLS=1
# export MAIL_USERNAME=theodondre@gmail.com
# export MAIL_PASSWORD=


# from flask_mail import Message
#
# msg = Message('test subject', sender='theodondre@gmail.com',recipients=['theodondre@gmail.com'])
# msg.body = 'text body'
# msg.html = '<h1>HTML body</h1>'
# mail.send(msg)
#
#
# def send_email(subject, sender, recipients, text_body, html_body):
#
#     msg = Message(subject, sender=sender, recipients=recipients)
#     msg.body = text_body
#     msg.html = html_body
#     mail.send(msg)
#
#
# import jwt
# token = jwt.encode({'a': 'b'}, 'secret', algorithm='HS256')
#
# jwt.decode(token, 'secret', algorithms=['HS256'])
