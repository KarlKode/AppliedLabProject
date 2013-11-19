from flask_wtf import Form
from wtforms import PasswordField, HiddenField, TextField, TextAreaField


class LoginForm(Form):
    user_id = TextField("name")
    password = PasswordField("password")
    next = HiddenField("next")


class CertificateCreationForm(Form):
    title = TextField("title")
    description = TextAreaField("description")


class CertificateVerifyForm(Form):
    certificate = TextAreaField("certificate")


class UserInformationForm(Form):
    firstname = TextField("firstname")
    lastname = TextField("lastname")
    email = TextField("email")
    password = PasswordField("password")


class ChangePasswordForm(Form):
    password_old = PasswordField("Current Password:")
    password_new1 = PasswordField("New Password:")
    password_new2 = PasswordField("Reenter new Password:")