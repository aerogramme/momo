from flask import Flask, render_template
from flask_basicauth import BasicAuth

app = Flask(__name__)

# If you would like to protect you entire site with basic access authentication, just set BASIC_AUTH_FORCE configuration variable to True:
# app.config['BASIC_AUTH_FORCE'] = True
app.config['BASIC_AUTH_USERNAME'] = 'john'
app.config['BASIC_AUTH_PASSWORD'] = 'doe'

basic_auth = BasicAuth(app)


@app.route('/secret')
@basic_auth.required
def secret_view():
    return "Welcome home" #render_template('templates/login.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
