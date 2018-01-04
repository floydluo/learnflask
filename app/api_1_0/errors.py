from flask import jsonify
from app.exceptions import ValidationError
from . import api

# there are 200, 201, good status

# 400 bad requests
# 401 unauthorized
# 403 forbidden
#
# 405 method_not_allow


# where 404 and 500 are strange
# you can also see it in app/main/errors.py


# when will these methods by called.
# 14-5 p181 API
def bad_request(message):
    response = jsonify({'error': 'bad request', 'message': message})
    response.status_code = 400
    return response


def unauthorized(message):
    response = jsonify({'error': 'unauthorized', 'message': message})
    response.status_code = 401
    return response


def forbidden(message):
    response = jsonify({'error': 'forbidden', 'message': message})
    response.status_code = 403
    return response

# such a strange thing
# error handled
@api.errorhandler(ValidationError)
def validation_error(e):
    return bad_request(e.args[0])
