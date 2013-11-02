from flask import Blueprint, render_template, g, session
from werkzeug.utils import redirect
from user.forms import LoginForm
from utils import login_required

user_app = Blueprint("user_app", __name__)


@user_app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            session_id = g.rpc.credential_login(form.user_id.data, form.password.data)
            session["session_id"] = session_id
            return redirect("/")
        except Exception as e:  # TODO: Better exception handling
            print e
            pass
    return render_template("login.html", form=form)


@user_app.route("/")
@login_required
def index():
    return "User index"
