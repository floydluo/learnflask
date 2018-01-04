# 14-2 API blueprint constructor

from flask import Blueprint

api = Blueprint('api', __name__)

# . means __init__.py
from . import authentication, posts, users, comments, errors
# you can also see app/__init__.py to see API blueprint registration
