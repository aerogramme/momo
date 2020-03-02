from flask import Flask
from flask_restplus import Api, Resource

#from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app, version='1.0', title='Sample API', description='A sample API', doc=True)

@api.route('/my-resource/<id>')
@api.doc(params={'id': 'An ID'})
class MyResource(Resource):
    def get(self, id):
        return {}

    @api.response(403, 'Not Authorized')
    def post(self, id):
        api.abort(403)


if __name__ == '__main__':
    app.run(debug=True)
