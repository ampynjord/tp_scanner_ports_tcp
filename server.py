import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash
from scan import validate_ip, parse_ports, scan_ports_parallel, scan_port_result

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'
DB_PATH = "db.sqlite"

# === DB ===

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def create_user(username, hashed_password):
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False

def get_user(username):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login_page", error="Connexion requise"))
        return f(*args, **kwargs)
    return decorated

# === AUTH ===

@app.get("/register")
def register_page():
    return render_template("register.html", error=request.args.get("error"))

@app.post("/register")
def post_register():
    username, password = request.form.get("username"), request.form.get("password")
    if not username or not password:
        return redirect(url_for("register_page", error="Champs requis"))
    if not create_user(username, generate_password_hash(password)):
        return redirect(url_for("register_page", error="Utilisateur deja existant"))
    session["username"] = username
    return redirect(url_for("index"))

@app.get("/login")
def login_page():
    return render_template("login.html", error=request.args.get("error"))

@app.post("/login")
def post_login():
    username, password = request.form.get("username"), request.form.get("password")
    if not username or not password:
        return redirect(url_for("login_page", error="Champs requis"))
    user = get_user(username)
    if not user:
        return redirect(url_for("login_page", error="Utilisateur inexistant"))
    if not check_password_hash(user["password"], password):
        return redirect(url_for("login_page", error="Mot de passe incorrect"))
    session["username"] = username
    return redirect(url_for("index"))

@app.get("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login_page"))

# === SCANNER ===

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@login_required
def scan_form():
    ip, port_str = request.form.get('ip'), request.form.get('port')
    print(f"Scan: {ip}:{port_str}")
    if not ip or not validate_ip(ip):
        return "Erreur: IP invalide", 400
    try:
        port = int(port_str or 0)
        if not 1 <= port <= 65535:
            return "Erreur: Port invalide", 400
    except:
        return "Erreur: Port invalide", 400
    is_open, service = scan_port_result(ip, port, detect_services=True)
    return redirect(url_for('result', ip=ip, port=port, is_open=is_open, service=service or ''))

@app.route('/result')
@login_required
def result():
    return render_template('result.html', ip=request.args.get('ip'), port=request.args.get('port'),
                          is_open=request.args.get('is_open')=='True', service=request.args.get('service') or None)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json() or {}
    ip, ports_input = data.get("ip"), data.get("ports")
    detect, workers = bool(data.get("detect", False)), int(data.get("workers", 50))
    if not ip or not validate_ip(ip):
        return jsonify({"error": "IP invalide"}), 400
    if ports_input is None:
        return jsonify({"error": "Parametre 'ports' requis"}), 400
    ports = [int(p) for p in ports_input] if isinstance(ports_input, list) else parse_ports(str(ports_input))
    if not ports:
        return jsonify({"error": "Aucun port valide"}), 400
    if len(ports) > 1:
        raw = scan_ports_parallel(ip, ports, detect_services=detect, max_workers=workers)
        results = {p: {"open": o, "service": s} for p, (o, s) in raw.items()}
    else:
        is_open, service = scan_port_result(ip, ports[0], detect_services=detect)
        results = {ports[0]: {"open": is_open, "service": service}}
    return jsonify({"ip": ip, "results": results, "summary": {
        "open": sum(1 for v in results.values() if v["open"]),
        "closed": sum(1 for v in results.values() if not v["open"])}})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
