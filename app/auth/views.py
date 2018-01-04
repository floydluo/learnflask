from flask import render_template, redirect, request, url_for, flash

# login and logout
from flask_login import login_user, logout_user, login_required, current_user
# current_user is from flask_login

from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm,\
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm


##############
#  logging   #
##############

# this is the important on_changed_body
# when you want to login, then the flask will find this.
# can call the login() function.

# login will be register as auth/login
@auth.route('/login', methods=['GET', 'POST'])
def login():
    # view function creates a LoginForm object
    form = LoginForm()
    # you must send the form.
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):

            # login_user(): this function is interesting, imported from flask_login.
            # takes the user to login
            login_user(user, form.remember_me.data)

            # if the login form was presented to the user to prevent unauthorized access
            # to a protected URL,
            # then Flask_Login saved the original URL in the next query string argument
            # which can be accessed from teh request.args dictionary
            # if 'next' is not available, a redirect to the home page is issued instead.

            # url_for(): main.index, not main/index.
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    # form = form

    # always find the templates in app/templates

    # when it is GET, just render.
    # to see, templates/auth/login.html
    return render_template('auth/login.html', form=form)

# logout.
# you need login first.
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))




##############
#  register  #
##############

# 8-17, P103
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # generate a new user
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)

        # commit() had to be added
        # even thought the application configured automatic database commits at the end of the request
        # For, new users get assigned an id when they are committed to the database
        # because the id is needed for the confirmation token, commit() cannot be delayed.
        db.session.commit()
        token = user.generate_confirmation_token()
        # send the email to validate it.
        # 8-19 p105

        ### <!- see auth/email/comfirm ->
        send_email(user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)



################
# confirmation #
################

#### current_user must be imported from flask_login.
#### the route is protected with login_required decorator from flask_login
#### so that when the users click on the link from the confirmation email
#### they are asked to log in before thet reach this view function.
@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    # first check is the logged-in user is already confirmed
    if current_user.confirmed:
        return redirect(url_for('main.index'))

    # actual token confirmation is done entirely in the User model
    # all the view function needs to do is call the confirm() method
    # then flash a message
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    # each application can decide what unconfirmed users are allowed to do
    # before they confirm their Account
    # one possibility is to allow unconfirmed users to log in
    # but only show them a page that asks them to confirm their accounts
    # before they can gain access.
    # this step can be done using Flask's before_request hook
    # see the first view function ---> before_request()
    return redirect(url_for('main.index'))


# this one is strange

## ON the Topic of Confirmation

# Filter unconfirmed accounts in before_app_request handler
# see 8-22 p 107
@auth.before_app_request
def before_request():
    # is_authenticated must return True if the users has login credentials
    if current_user.is_authenticated:
        current_user.ping()

        # if it is not yet confirmed.
        if not current_user.confirmed and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
            # find auth.route('/unconfirmed')
            return redirect(url_for('auth.unconfirmed'))

    # before_app_request handler will intercept a request when three conditons are true:
    # 1. A user is logged in.
    # 2. The account for the user is not confirmed
    # 3. The requested endpoint (request.endpoint) is outside of the authentication blueprint and is not for static filter_by
    #    Access to the authentication routes needs to be granted.
    #    As those are the routes that will enable enable the user to confirm the account or perform account management functions.
    # if the three conditions are met, then a redirect is issued to /auth/unconfirmed route
    # that shows a page with information about account confirmation


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    # redirect the unconfirmed auth to the unconfirmed.html page
    return render_template('auth/unconfirmed.html')


# 8-23 p108
# resend account confirmation email
# the route is also protected with login_required to ensure that
# when it is accessed, the user that is making the request is known.
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)


######################
# Account Management #
######################

@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
        flash('An email with instructions to reset your password has been '
              'sent to you.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions to confirm your new email '
                  'address has been sent to you.')

            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template("auth/change_email.html", form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('Your email address has been updated.')
    else:
        flash('Invalid request.')

    # it is main.index, not main/index
    return redirect(url_for('main.index'))
