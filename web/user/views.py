import base64
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
            response = g.rpc.credential_login(form.user_id.data, form.password.data)
            if response["_rpc_status"] == "success":
                session["session_id"] = response["data"]
                return redirect("/")
        except:
            pass
    return render_template("login.html", form=form)

@user_app.route("/")
@login_required
def index():
    r = g.rpc.get_certificates(session["session_id"])
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    certificates = r["data"]
    return render_template("user_index.html", certificates=certificates)

@user_app.route("/download/<int:certificate_id>")
@login_required
def download_certificate(certificate_id):
    r = g.rpc.get_certificate(session["session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    certificate = r["data"]
    return Response(certificate["certificate"],
                    headers={"Content-Disposition": "attachment; filename=%s.crt" % g.user_data["uid"]},
                    content_type="application/x-pem-file")

@user_app.route("/create", methods=["GET", "POST"])
@login_required
def create_certificate():
    form = CertificateCreationForm()
    if form.validate_on_submit():
        r = g.rpc.create_certificate(session["session_id"], form.title.data, form.description.data)
        if r["_rpc_status"] != "success":
            return "Internal error", 500
        certificate = r["data"]
        return Response(base64.b64decode(certificate["pkcs12"]),
                        headers={"Content-Disposition": "attachment; filename=%s.p12" % g.user_data["uid"]},
                        content_type="application/x-pkcs12")
        #return render_template("show_created_certificate.html", certificate=certificate)
    return render_template("create_certificate.html", form=form)


@user_app.route("/verify_certificate", methods=["GET", "POST"])
@login_required
def verify_certificate():
    form = CertificateVerifyForm()
    if form.validate_on_submit():
        r = g.rpc.verify_certificate(form.certificate.data)
        if r["_rpc_status"] != "success":
            return "Internal error", 500
        verification_data = r["data"]
        return render_template("verified_certificate.html", verification_data=verification_data)
    return render_template("verify_certificate.html", form=form)


@user_app.route("/revoke/<int:certificate_id>")
@login_required
def revoke_certificate(certificate_id):
    if "sure" in request.args:
        test = g.rpc.revoke_certificate(session["session_id"], certificate_id)
        # TODO: Flash message!
        return redirect(url_for("user_app.index"))
    r = g.rpc.get_certificate(session["session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    certificate = r["data"]
    return render_template("revoke_certificate.html", certificate=certificate)


@user_app.route("/data/update/<field>")
@login_required
def update_data(field):
    return "..."