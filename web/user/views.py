import base64
from flask import Blueprint, render_template, g, session, url_for, Response, request, flash
from werkzeug.utils import redirect
from user.forms import LoginForm, CertificateCreationForm, CertificateVerifyForm, UserInformationForm, ChangePasswordForm
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
                flash(u'Successfully logged in!', 'alert-success')
                return redirect("/")
            else:
                flash(u'Error: ' + str(response["error"]), 'alert-danger')
                return redirect("/")
        except Exception as e:
            flash(u'Other error: ' + str(e.message), 'alert-danger')
    return render_template("login.html", form=form)

@user_app.route("/", methods=["GET", "POST"])
@login_required
def index():
    form = UserInformationForm()

    if form.is_submitted():
        if len(form.firstname.data) > 0 and g.user_data["firstname"] != str(form.firstname.data):
            r = g.rpc.update_data(session["session_id"], "firstname", form.firstname.data)

            if r["_rpc_status"] != "success":
                flash(u'Error: ' + str(r["error"]), 'alert-danger')
                return redirect("/")
            else:
                flash(u'Updated field: firstname', 'alert-success')

        if len(form.lastname.data) > 0 and g.user_data["lastname"] != str(form.lastname.data):
            r = g.rpc.update_data(session["session_id"], "lastname", form.lastname.data)

            if r["_rpc_status"] != "success":
                flash(u'Error: ' + str(r["error"]), 'alert-danger')
                return redirect("/")
            else:
                flash(u'Updated field: lastname', 'alert-success')

        if len(form.email.data) > 0 and g.user_data["email"] != str(form.email.data):
            r = g.rpc.update_data(session["session_id"], "email", form.email.data)

            if r["_rpc_status"] != "success":
                flash(u'Error: ' + str(r["error"]), 'alert-danger')
                return redirect("/")
            else:
                flash(u'Updated field: email', 'alert-success')

        flash(u'Update was successful. Waiting for approval.. ', 'alert-success')

        form.firstname.data = ""
        form.lastname.data = ""
        form.email.data = ""

    response = g.rpc.get_certificates(session["session_id"])
    if response["_rpc_status"] != "success":
        flash(u'Error: ' + str(response["error"]), 'alert-danger')

    certificates = response["data"]
    return render_template("user_index.html", certificates=certificates, form=form)

@user_app.route("/download/<int:certificate_id>")
@login_required
def download_certificate(certificate_id):
    response = g.rpc.get_certificate(session["session_id"], certificate_id)

    if response["_rpc_status"] != "success":
        flash(u'Error: ' + str(response["error"]), 'alert-danger')
        return redirect("/")

    certificate = response["data"]
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
            flash(u'Error: ' + str(r["error"]), 'alert-danger')
            return redirect("/")

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
            flash(u'Error: ' + str(r["error"]), 'alert-danger')
            return render_template("verify_certificate.html", form=form)

        verification_data = r["data"]
        return render_template("verified_certificate.html", verification_data=verification_data)
    return render_template("verify_certificate.html", form=form)


@user_app.route("/revoke/<int:certificate_id>")
@login_required
def revoke_certificate(certificate_id):
    if "sure" in request.args:
        revoke_response = g.rpc.revoke_certificate(session["session_id"], certificate_id)
        if revoke_response["_rpc_status"] != "success":
            flash(u'Error: ' + str(revoke_response["error"]), 'alert-danger')
        else:
            flash(u'Successfully revoked certificate', 'alert-success')

        return redirect(url_for("user_app.index"))

    r = g.rpc.get_certificate(session["session_id"], certificate_id)
    if r["_rpc_status"] != "success":
        flash(u'Error: ' + str(r["error"]), 'alert-danger')

    certificate = r["data"]
    return render_template("revoke_certificate.html", certificate=certificate)


@user_app.route("/data/update/<data>")
@login_required
def update_data(data):
    print data
    pass

@user_app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.password_new1.data == form.password_new2.data:
            r = g.rpc.change_password(session["session_id"], form.password_old.data, form.password_new1.data)

            if r["_rpc_status"] != "success":
                flash(u'Error: ' + str(r["error"]), 'alert-danger')
                return render_template("change_password.html", form=form)
            else:
                flash(u'Password successful updated!', 'alert-success')
                return redirect("/")
        else:
            flash(u'New passwords do not match!', 'alert-danger')
            return render_template("change_password.html", form=form)

        return redirect("/")
    return render_template("change_password.html", form=form)

