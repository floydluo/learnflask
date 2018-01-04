# adding a login form


from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField

# login and register
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    # auth/login.html
    # to see templates/auth/login

    # Length(), Email()
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    # the PasswordField class represents an <input> element with type="password"
    password = PasswordField('Password', validators=[Required()])
    # represents a checkbox
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


#####################
# register
# 8-15 p100
class RegistrationForm(Form):
    # Required the email length to be 1-64.
    email = StringField('Email', validators=[Required(), Length(1, 64),Email()])

    # Regexp is regular expression
    # contains letters, numbers, underscores and dots only.
    # 0 is the regular flag
    # error message to display the failure.
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])

    # password entered twice
    # EqualTo() make sure the two passwords are the same.
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])

    password2 = PasswordField('Confirm password', validators=[Required()])

    submit = SubmitField('Register')

    # this form also has two custom validators implemented as methods

    # with prefix validate_ followed by the name of the field.
    # the method is invoked in addition to any regularly defined validators.
    # In this case, the custom validators for email and username ensure that the values given
    # are not duplicates
    # validation error with the text of the error message as argument.
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

####################
# the template is in templates/auth/register.html
#####################
# and you also need to link the register page from login page
# see templates/auth/login.html  # link to registration
##

##########
# after a form is sent to flask, how it is handled by view functions
# see auth/views.py register()
##########


class ChangePasswordForm(Form):
    old_password = PasswordField('Old password', validators=[Required()])
    password = PasswordField('New password', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm new password', validators=[Required()])
    submit = SubmitField('Update Password')


class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Reset Password')


class PasswordResetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('New Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Reset Password')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')


class ChangeEmailForm(Form):
    email = StringField('New Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
