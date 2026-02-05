from flask import Flask

from src.auth import auth_blueprint
from src.forms import forms_blueprint


def create_app():
    app = Flask(__name__)
    app.secret_key = 'dev-secret-key-change-in-production'
    app.register_blueprint(forms_blueprint)
    app.register_blueprint(auth_blueprint)

    return app
