from functools import wraps

from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from src.services.users import add_user, get_user_password, user_exists

auth_blueprint = Blueprint("auth", __name__)


@auth_blueprint.get("/register")
def register_page():
    return render_template("register.html")


@auth_blueprint.post("/register")
def post_register():
    form = request.form.to_dict()
    username = form.get("username")
    if user_exists(username):
        print("user already exists")
        return redirect(url_for("auth.register_page"))

    password = form.get("password")
    if not password:
        return redirect(url_for("auth.register_page"))
    
    secure_password = generate_password_hash(password)
    add_user(username, secure_password)
    
    # Connecter automatiquement l'utilisateur après inscription
    session["username"] = username
    return redirect(url_for("forms.home"))


@auth_blueprint.get("/login")
def login_page():
    return render_template("login.html")


@auth_blueprint.post("/login")
def post_login():
    form = request.form.to_dict()
    username = form.get("username")
    if not user_exists(username):
        return redirect(url_for("auth.login_page"))

    secure_password = get_user_password(username)
    password = form.get("password")
    
    if not secure_password or not password:
        return redirect(url_for("auth.login_page"))
    
    if check_password_hash(secure_password, password):
        session["username"] = username
        return redirect(url_for("forms.home"))
    else:
        return redirect(url_for("auth.login_page"))


@auth_blueprint.get("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("auth.login_page"))
