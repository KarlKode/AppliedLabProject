from functools import wraps
from flask import request, redirect, url_for, session, g


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "session_id" in session:
            try:
                r = g.rpc.validate_session(session["session_id"])
                if r["_rpc_status"] != "success":
                    # Invalid session
                    return redirect(url_for("user_app.login", next=request.url))
                g.user_data = r["data"]
                return f(*args, **kwargs)
            except:
                # TODO: Error reporting
                raise
        return redirect(url_for("user_app.login", next=request.url))
    return decorated_function


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_session_id" in session:
            try:
                g.user_data = g.rpc.admin_validate_session(session["admin_session_id"])
            except Exception as e:  # TODO: Better exception handling
                # Invalid session
                return redirect(url_for("admin_app.login", next=request.url))
            return f(*args, **kwargs)
        return redirect(url_for("admin_app.login", next=request.url))
    return decorated_function