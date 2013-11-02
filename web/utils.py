from functools import wraps
from flask import request, redirect, url_for, session, g


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if session.has_key("session_id") and g.rpc.validate_session(session["session_id"]):
                return f(*args, **kwargs)
        except Exception as e:  # TODO: Better exception handling
            print "error"
            print e
            pass
        return redirect(url_for("user_app.login", next=request.url))
    return decorated_function