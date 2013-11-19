from flask import Blueprint, g, session, render_template, redirect, Response, url_for, request, flash
from admin.forms import AdminLoginForm
from utils import admin_login_required

admin_app = Blueprint("admin_app", __name__)


@admin_app.route("/")
@admin_login_required
def index():
    r = g.rpc.admin_get_certificates(session["admin_session_id"])
    if r["_rpc_status"] != "success":
        return "Internal error", 500

    information = g.rpc.admin_get_systeminformation(session["admin_session_id"])
    if information["_rpc_status"] != "success":
        return "Internal error", 500

    return render_template("admin_index.html", certificates=r["data"], sysinfo=information["data"])


@admin_app.route("/download/<int:certificate_id>")
@admin_login_required
def download_certificate(certificate_id):
    r = g.rpc.admin_get_certificate(session["admin_session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        flash(u'Error: ' + str(r["error"]), 'alert-danger')
        return redirect("/")

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
            flash(u'Error: ' + str(r["error"]), 'alert-danger')
            return redirect("/")
        else:
            flash(u'Certificate successful revoked', 'alert-success')

        return redirect(url_for("admin_app.index"))
    r = g.rpc.admin_get_certificate(session["admin_session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        return "Internal error", 500
    certificate = r["data"]
    return render_template("admin_revoke_certificate.html", certificate=certificate)


@admin_app.route("/update_requests/")
@admin_login_required
def update_requests():
    r = g.rpc.admin_get_update_requests(session["admin_session_id"])
    if r["_rpc_status"] != "success":
        flash(u'Error: ' + str(r["error"]), 'alert-danger')
        return redirect(url_for("admin_app.update_requests"))

    update_req = r["data"]
    return render_template("admin_update_requests.html", update_requests=update_req)


@admin_app.route("/accept/<int:update_request_id>")
@admin_login_required
def accept_update_request(update_request_id):
    result = g.rpc.admin_accept_update_request(session["admin_session_id"], update_request_id)

    if result["_rpc_status"] != "success":
        flash(u'Error: ' + str(result["error"]), 'alert-danger')
        return redirect(url_for("admin_app.update_requests"))
    else:
        flash(u'Update successful accepted!', 'alert-success')

    return redirect(url_for("admin_app.update_requests"))


@admin_app.route("/reject/<int:update_request_id>")
@admin_login_required
def reject_update_request(update_request_id):
    result = g.rpc.admin_reject_update_request(session["admin_session_id"], update_request_id)
    if result["_rpc_status"] != "success":
        flash(u'Error: ' + str(result["error"]), 'alert-danger')
        return redirect(url_for("admin_app.update_requests"))
    else:
        flash(u'Update successful rejected!', 'alert-success')


    return redirect(url_for("admin_app.update_requests"))

