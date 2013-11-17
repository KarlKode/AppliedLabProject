from flask import Blueprint, g, session, render_template, redirect, Response, url_for, request
from admin.forms import AdminLoginForm
from utils import admin_login_required

admin_app = Blueprint("admin_app", __name__)


@admin_app.route("/")
@admin_login_required
def index():
    r = g.rpc.admin_get_certificates(session["admin_session_id"])
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    return render_template("admin_index.html", certificates=r["data"])


@admin_app.route("/download/<int:certificate_id>")
@admin_login_required
def download_certificate(certificate_id):
    r = g.rpc.admin_get_certificate(session["admin_session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    certificate = r["data"]
    return Response(certificate["certificate"],
                    headers={"Content-Disposition": "attachment; filename=%s.crt" % certificate["uid"]},
                    content_type="application/x-pem-file")

@admin_app.route("/revoke/<int:certificate_id>")
@admin_login_required
def revoke_certificate(certificate_id):
    if "sure" in request.args:
        r = g.rpc.admin_revoke_certificate(session["admin_session_id"], certificate_id)
        if r["_rpc_status"] != "success":
            return "Internal error", 500
        # TODO: Flash message!
        return redirect(url_for("admin_app.index"))
    r = g.rpc.admin_get_certificate(session["admin_session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    certificate = r["data"]
    return render_template("admin_revoke_certificate.html", certificate=certificate)


@admin_app.route("/update_requests/")
@admin_login_required
def update_requests():
    return ""


@admin_app.route("/accept/<int:update_request_id>")
@admin_login_required
def accept_update_request(update_request_id):
    result = g.rpc.accept_update_request(session["admin_session_id"], update_request_id)
    return redirect(url_for("admin_app.index"))


@admin_app.route("/reject/<int:update_request_id>")
@admin_login_required
def reject_update_request(update_request_id):
    result = g.rpc.reject_update_request(session["admin_session_id"], update_request_id)
    return redirect(url_for("admin_app.index"))

