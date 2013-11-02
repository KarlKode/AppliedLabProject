from flask_wtf import Form
from wtforms import PasswordField, HiddenField, TextField
from wtforms.validators import DataRequired


class LoginForm(Form):
    user_id = TextField("name", validators=[DataRequired()])
    password = PasswordField("password")
    next = HiddenField("next")
