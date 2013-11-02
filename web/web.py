from flask import Flask, g
import Pyro4

from admin.views import admin_app
from user.views import user_app

app = Flask(__name__)
app.config.from_pyfile("settings.py")
app.register_blueprint(user_app, url_prefix="")
app.register_blueprint(admin_app, url_prefix="/admin")


@app.before_request
def init_rpc():
    g.rpc = Pyro4.Proxy("PYRONAME:core")
    pass


@app.route("/crl")
def crl():
    return g.rpc.get_crl()

if __name__ == "__main__":
    app.run(debug=True)