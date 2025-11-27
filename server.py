from flask import Flask, request, jsonify, render_template, redirect, url_for
from scan import validate_ip, parse_ports, scan_ports_parallel, scan_port_result

app = Flask(__name__)


@app.route('/')
def index():
    """Route principale qui affiche le formulaire de scan"""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_form():
    """Route qui reçoit les données du formulaire et effectue le scan"""
    # Récupération des données du formulaire
    ip = request.form.get('ip')
    port_str = request.form.get('port')
    
    # Debug: print des données reçues
    print(f"Données reçues du formulaire:")
    print(f"  IP: {ip}")
    print(f"  Port: {port_str}")
    
    # Validation de l'IP
    if not ip or not validate_ip(ip):
        return "Erreur: IP invalide", 400
    
    # Validation et conversion du port
    if not port_str:
        return "Erreur: Port manquant", 400
    
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            return "Erreur: Port doit être entre 1 et 65535", 400
    except (ValueError, TypeError):
        return "Erreur: Port invalide", 400
    
    # Effectue le scan
    print(f"Lancement du scan: {ip}:{port}")
    is_open, service = scan_port_result(ip, port, detect_services=True)
    
    print(f"Résultat: {'OUVERT' if is_open else 'FERMÉ'}")
    if service:
        print(f"Service: {service}")
    
    # Redirige vers la page de résultats
    return redirect(url_for('result', ip=ip, port=port, is_open=is_open, service=service or ''))


@app.route('/result')
def result():
    """Page qui affiche les résultats du scan"""
    ip = request.args.get('ip')
    port = request.args.get('port')
    is_open = request.args.get('is_open') == 'True'
    service = request.args.get('service')
    
    return render_template('result.html', 
                         ip=ip, 
                         port=port, 
                         is_open=is_open, 
                         service=service if service else None)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Endpoint POST qui attend un JSON :
    {
      "ip": "127.0.0.1",
      "ports": "22,80" | [22,80],
      "detect": true|false,     # optionnel
      "workers": 50             # optionnel
    }
    Retourne JSON avec les résultats par port.
    """
    data = request.get_json() or {}
    ip = data.get("ip")
    ports_input = data.get("ports")
    detect = bool(data.get("detect", False))
    workers = int(data.get("workers", 50))

    if not ip or not validate_ip(ip):
        return jsonify({"error": "IP invalide ou manquante"}), 400

    if ports_input is None:
        return jsonify({"error": "Paramètre 'ports' requis"}), 400

    # Supporte une liste ou une chaîne
    if isinstance(ports_input, list):
        ports = [int(p) for p in ports_input]
    else:
        ports = parse_ports(str(ports_input))

    if not ports:
        return jsonify({"error": "Aucun port valide à scanner"}), 400

    results = {}

    if len(ports) > 1:
        raw = scan_ports_parallel(ip, ports, detect_services=detect, max_workers=workers)
        for port, (is_open, service) in raw.items():
            results[port] = {"open": is_open, "service": service}
    else:
        port = ports[0]
        is_open, service = scan_port_result(ip, port, detect_services=detect)
        results[port] = {"open": is_open, "service": service}

    summary = {
        "open": sum(1 for v in results.values() if v["open"]),
        "closed": sum(1 for v in results.values() if not v["open"]) 
    }

    return jsonify({"ip": ip, "results": results, "summary": summary})


if __name__ == '__main__':
    # Mode développement. Pour la production, utiliser gunicorn/uvicorn.
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
