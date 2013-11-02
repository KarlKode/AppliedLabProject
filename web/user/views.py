from flask import Blueprint, render_template, g, session, url_for
from werkzeug.utils import redirect
from user.forms import LoginForm, CertificateCreationForm
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
            pass
    return render_template("login.html", form=form)


@user_app.route("/")
@login_required
def index():
    certificates = g.rpc.get_certificates(session["session_id"])
    return render_template("user_index.html", certificates=certificates)

@user_app.route("/download/<int:certificate_id>")
@login_required
def download_certificate(certificate_id):
    pass

@user_app.route("/create", methods=["GET", "POST"])
@login_required
def create_certificate():
    form = CertificateCreationForm()
    if form.validate_on_submit():
        g.rpc.create_certificate(session["session_id"], form.title.data, form.description.data)
        return redirect(url_for("user_app.index"))
    return render_template("create_certificate.html", form=form)


@user_app.route("/revoke/<int:certificate_id>")
@login_required
def revoke_certificate(certificate_id):
    pass

