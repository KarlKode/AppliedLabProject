from flask import Flask, g, render_template, session, redirect
import Pyro4

from admin.views import admin_app
from user.forms import LoginForm
from user.views import user_app

app = Flask(__name__)
app.config.from_pyfile("settings.py")
app.register_blueprint(user_app, url_prefix="")
app.register_blueprint(admin_app, url_prefix="/admin")


@app.before_request
def init_rpc():
    g.rpc = Pyro4.Proxy(app.config["PYRO_URI"])
    pass


@app.route("/crl")
def crl():
    r = g.rpc.get_crl()
    if r["_rpc_status"] != "success":
        return "Internal error"
    else:
        return r["data"]

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/logout")
def logout():
    if session["session_id"]:
        r = g.rpc.kill_session(session["session_id"])
        del session["session_id"]
    elif session["admin_session_id"]:
        r = g.rpc.admin_kill_session(session["admin_session_id"])
        del session["admin_session_id"]

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)