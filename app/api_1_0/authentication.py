from flask import g, jsonify
from flask_httpauth import HTTPBasicAuth
from ..models import User, AnonymousUser
from . import api
# the importance of errors
from .errors import unauthorized, forbidden

# 14-6 p202 API-auth

# initialized
# this is only initialized in the blueprint package, as only used in API blueprint
auth = HTTPBasicAuth()

# decorator, just as the @login_required in the Flask_Login
@auth.verify_password
# this function just return True or False
def verify_password(email_or_token, password):
    # email and password are verified using the existing support in the User model.

    # anonymouse login is supported
    # for which the client must send a blank email field.
    if email_or_token == '':
        # the authentication callback saves the authed user in Flask's g global object
        # the view function can access it later.

        # when an anonymouse login is received, the function return True
        # and saves an instance of the AnonymousUser class used with Flask-Login
        # into g.current_user
        g.current_user = AnonymousUser()
        return True
    # 14-10 p205 new version
    # first argument can be email or token.
    # if field is blank, anonymouse user is assuemed
    # if password is blank, then the email_or_token is assuemed to be a token and validated as such
    # if both fields are nonempty, then regular email and password to auth
    # with this, token-based auth is optional
    # to give the view functions the ability to distinguish between the two auth method
    # g.token_used variable is added.

    if password == '':
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_used = True
        return g.current_user is not None


    user = User.query.filter_by(email=email_or_token).first()
    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_password(password)



# 14-7 auth error p203
@auth.error_handler
def auth_error():
    return unauthorized('Invalid credentials')

# to protect a route, the auth.login_required decorator is used.
# 14-8 api before_request handler with auth.
@api.before_request
@auth.login_required
def before_request():
    if not g.current_user.is_anonymous and not g.current_user.confirmed:
        # forbidden is in the api/errors.py
        return forbidden('Unconfirmed account')
# now the auth checks will be done automatically
# for all the routers in the blueprint.
# As an additional check, the before_request handler also rejects auth users who have not confirmed.


# 14-11 p205 token
@api.route('/token')
def get_token():
    # to prevent clients from using an old token to request a new one
    # g.token_used is checked
    if g.current_user.is_anonymous or g.token_used:
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=3600), 'expiration': 3600})
