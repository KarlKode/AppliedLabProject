from flask_wtf import Form
from wtforms import PasswordField, HiddenField, TextField, TextAreaField


class AdminLoginForm(Form):
    user_id = TextField("name")
    password = PasswordField("password")
    next = HiddenField("next")

