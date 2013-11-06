from flask import Blueprint, render_template, g, session, url_for, Response, request
from werkzeug.utils import redirect
from user.forms import LoginForm, CertificateCreationForm, CertificateVerifyForm
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
    certificate = g.rpc.get_certificate(session["session_id"], certificate_id)
    return Response(certificate["certificate"],
                    headers={"Content-Disposition": "attachment; filename=%s.crt" % g.user_data["uid"]},
                    content_type="application/x-pem-file")

@user_app.route("/create", methods=["GET", "POST"])
@login_required
def create_certificate():
    form = CertificateCreationForm()
    if form.validate_on_submit():
        certificate = g.rpc.create_certificate_m2(session["session_id"], form.title.data, form.description.data)
        return render_template("show_created_certificate.html", certificate=certificate)
    return render_template("create_certificate.html", form=form)


@user_app.route("/verify_certificate", methods=["GET", "POST"])
@login_required
def verify_certificate():
    form = CertificateVerifyForm()
    if form.validate_on_submit():
        verification_data = g.rpc.verify_certificate(form.certificate.data)
        return render_template("verified_certificate.html", verification_data=verification_data)
    return render_template("verify_certificate.html", form=form)


@user_app.route("/revoke/<int:certificate_id>")
@login_required
def revoke_certificate(certificate_id):
    if "sure" in request.args:
        test = g.rpc.revoke_certificate(session["session_id"], certificate_id)
        # TODO: Flash message!
        return redirect(url_for("user_app.index"))
    certificate = g.rpc.get_certificate(session["session_id"], certificate_id)
    return render_template("revoke_certificate.html", certificate=certificate)

