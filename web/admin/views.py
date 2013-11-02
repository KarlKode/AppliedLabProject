from flask import Blueprint

admin_app = Blueprint("admin_app", __name__)


@admin_app.route("/")
def index():
    return "Admin index"