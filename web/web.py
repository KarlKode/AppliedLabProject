from flask import Flask, g, render_template
import Pyro4

from admin.views import admin_app
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

if __name__ == "__main__":
    app.run(debug=True)