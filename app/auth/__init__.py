from flask import Blueprint


# when you call @auth, will find you here.
# in this case, you can use @auth.

# the auth blueprint needs to ba attached in the application
# in the create_app() factory function
# also see app/__init__.py
auth = Blueprint('auth', __name__)


# this is interesting
# finding the functions in the auth/views.py
from . import views
