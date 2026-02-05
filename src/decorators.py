from functools import wraps

from flask import redirect, session, url_for


def login_required(f):
    """Décorateur pour protéger les routes nécessitant une connexion."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)
    return decorated_function
