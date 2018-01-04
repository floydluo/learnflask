from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy

# login/  Flask_login
from flask_login import LoginManager

from flask_pagedown import PageDown
from config import config

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()

#########
# login #
#########
login_manager = LoginManager()

# can be None, 'basic', 'strong'
login_manager.session_protection = 'strong'
# sets the endpoint for the login page
# it needs to be prefixed with the blueprint name
login_manager.login_view = 'auth.login'

# flask_login requires application to set up a callback function
# that loads a user, given the identifier
# see app/models.py
# the callback function is
# load_user(user_id)


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

    # login
    login_manager.init_app(app)


    pagedown.init_app(app)

    if not app.debug and not app.testing and not app.config['SSL_DISABLE']:
        from flask_sslify import SSLify
        sslify = SSLify(app)

    # Blueprint attachment
    # main
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # auth
    from .auth import auth as auth_blueprint
    # notice the url_prefix here
    # when you url have the /auth
    # find auth. login will be registered as auth/login
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    # API blueprint registration
    # 14-3 p180
    from .api_1_0 import api as api_1_0_blueprint
    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')

    return app
