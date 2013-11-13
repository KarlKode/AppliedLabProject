from flask import Blueprint, g, session, render_template, redirect, Response, url_for, request
from admin.forms import AdminLoginForm
from utils import adminlogin_required

admin_app = Blueprint("admin_app", __name__)


@admin_app.route("/")
@adminlogin_required
def index():
    certificates = g.rpc.get_certificates(session["admin_session_id"])
    return render_template("admin_index.html", certificates=certificates)


@admin_app.route("/login", methods=["GET", "POST"])
def login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        try:
            session_id = g.rpc.credential_login(form.user_id.data, form.password.data)
            session["admin_session_id"] = session_id
            return redirect("/")
        except Exception as e:  # TODO: Better exception handling
            print e.message
            pass
    return render_template("certlogin.html", form=form)

@admin_app.route("/download/<int:certificate_id>")
@adminlogin_required
def download_certificate(certificate_id):
    certificate = g.rpc.get_certificate(session["admin_session_id"], certificate_id)
    return Response(certificate["certificate"],
                    headers={"Content-Disposition": "attachment; filename=%s.crt" % g.user_data["uid"]},
                    content_type="application/x-pem-file")

@admin_app.route("/revoke/<int:certificate_id>")
@adminlogin_required
def revoke_certificate(certificate_id):
    if "sure" in request.args:
        test = g.rpc.revoke_certificate(session["admin_session_id"], certificate_id)
        # TODO: Flash message!
        return redirect(url_for("admin_app.index"))
    certificate = g.rpc.get_certificate(session["admin_session_id"], certificate_id)
    return render_template("revoke_certificate.html", certificate=certificate)

@admin_app.route("/accept/<int:update_request_id>")
@adminlogin_required
def accept_update_request(update_request_id):
    result = g.rpc.accept_update_request(session["admin_session_id"], update_request_id)
    return redirect(url_for("admin_app.index"))

@admin_app.route("/reject/<int:update_request_id>")
@adminlogin_required
def reject_update_request(update_request_id):
    result = g.rpc.reject_update_request(session["admin_session_id"], update_request_id)
    return redirect(url_for("admin_app.index"))

