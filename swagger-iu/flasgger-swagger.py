# pip install flasgger
# http://127.0.0.1:5000/apidocs/

from flask import Flask, jsonify
from flasgger import Swagger


template = {
  "swagger": "2.0",
  "info": {
    "title": "My API",
    "description": "API for my data",
    "contact": {
      "responsibleOrganization": "Aerogramme",
      "responsibleDeveloper": "Theophilus Siameh",
      "email": "support@aerogramme.io",
      "url": "www.aerogramme.io",
    },
    "termsOfService": "http://aerogramme.io/privacy",
    "version": "0.0.1"
  },
  "host": "localhost:5000",  # overrides localhost:500
  "basePath": "/api",  # base bash for blueprint registration
  "schemes": [
    "http",
    "https"
  ],
  "operationId": "getmyData"
}


app = Flask(__name__)
swagger = Swagger(app, template= template)

@app.route('/colors/<palette>/')
def colors(palette):
    """
    file: colors.yml
    """
    # """Example endpoint returning a list of colors by palette
    # This is using docstrings for specifications.
    # ---
    # parameters:
    #   - name: palette
    #     in: path
    #     type: string
    #     enum: ['all', 'rgb', 'cmyk']
    #     required: true
    #     default: all
    # definitions:
    #   Palette:
    #     type: object
    #     properties:
    #       palette_name:
    #         type: array
    #         items:
    #           $ref: '#/definitions/Color'
    #   Color:
    #     type: string
    # responses:
    #   200:
    #     description: A list of colors (may be filtered by palette)
    #     schema:
    #       $ref: '#/definitions/Palette'
    #     examples:
    #       rgb: ['red', 'green', 'blue']
    # """
    all_colors = {
        'cmyk': ['cian', 'magenta', 'yellow', 'black'],
        'rgb': ['red', 'green', 'blue']
    }
    if palette == 'all':
        result = all_colors
    else:
        result = {palette: all_colors.get(palette)}

    return jsonify(result)

app.run(debug=True)


