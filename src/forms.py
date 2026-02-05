import ipaddress

from flask import Blueprint, render_template, request

from src.core.scan import scan
from src.decorators import login_required

forms_blueprint = Blueprint("forms", __name__)


def valid_ipv4_address(value):
    """Valide une adresse IPv4."""
    try:
        ipaddress.IPv4Address(value)
        return value
    except ipaddress.AddressValueError:
        raise ValueError(f"{value} is not a valid IPv4 address.")


def valid_port(value):
    """Valide un numéro de port."""
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"{value} is not a valid integer.")

    if not (0 <= port <= 65535):
        raise ValueError(f"{port} is not a valid port number (0-65535).")
    return port


@forms_blueprint.get("/")
@login_required
def home():
    return render_template("index.html")


@forms_blueprint.post("/scan")
@login_required
def post_scan():
    form = request.form.to_dict()
    ip_target = valid_ipv4_address(form.get("ipv4"))
    port_target = valid_port(form.get("port"))
    result = scan(ip_target, port_target)
    return render_template(
        "result.html", ipv4=ip_target, port=port_target, result=result
    )
