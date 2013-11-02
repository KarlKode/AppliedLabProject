from flask_wtf import Form
from wtforms import PasswordField, HiddenField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired


class LoginForm(Form):
    email = EmailField("name", validators=[DataRequired()])
    password = PasswordField("password")
    next = HiddenField("next")
