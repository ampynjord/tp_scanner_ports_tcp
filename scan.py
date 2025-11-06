import socket
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def validate_ip(ip):
    """Valide une adresse IP ou un nom de domaine."""
    try:
        # Tente de valider comme une adresse IP
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # Si ce n'est pas une IP, on considère que c'est un nom de domaine
        # On vérifie juste que ce n'est pas vide
        return len(ip.strip()) > 0

def validate_port(port):
    """Valide qu'un port est dans la plage valide 1-65535."""
    return 1 <= port <= 65535

def parse_ports(port_string):
    """
    Parse une chaîne de ports et retourne une liste de ports.
    Supporte:
    - Un seul port: "80"
    - Plusieurs ports: "22,80,443"
    - Une plage de ports: "80:443"
    - Une combinaison: "22,80:85,443"
    """
    ports = []
    
    # Sépare par virgule
    parts = port_string.split(',')
    
    for part in parts:
        part = part.strip()
        
        # Vérifie si c'est une plage (contient ':')
        if ':' in part:
            try:
                start, end = part.split(':')
                start = int(start)
                end = int(end)
                
                if not validate_port(start) or not validate_port(end):
                    print(f"Erreur: Les ports doivent être entre 1 et 65535 (plage: {start}:{end})")
                    continue
                
                if start > end:
                    print(f"Erreur: Le port de début ({start}) doit être inférieur au port de fin ({end})")
                    continue
                
                ports.extend(range(start, end + 1))
            except ValueError:
                print(f"Erreur: Format de plage invalide: {part}")
        else:
            # C'est un seul port
            try:
                port = int(part)
                if not validate_port(port):
                    print(f"Erreur: Le port {port} doit être entre 1 et 65535")
                    continue
                ports.append(port)
            except ValueError:
                print(f"Erreur: Port invalide: {part}")
    
    return sorted(set(ports))  # Élimine les doublons et trie

def detect_service(ip, port, timeout=3):
    """
    Détecte automatiquement le service en récupérant et analysant la bannière.
    Utilise plusieurs techniques :
    1. Réception passive de bannière
    2. Envoi de requêtes HTTP
    3. Analyse de la réponse pour identifier le protocole
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Technique 1: Essaie de recevoir une bannière passive
            try:
                s.setblocking(False)
                import select
                ready = select.select([s], [], [], 1)
                if ready[0]:
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return analyze_banner(banner)
            except:
                pass
            
            # Technique 2: Tente différentes requêtes selon le port
            s.setblocking(True)
            
            # Pour les ports web (HTTP/HTTPS)
            if port in [80, 443, 8000, 8080, 8443]:
                return detect_http_service(s, port)
            
            # Pour SSH
            elif port == 22:
                return detect_ssh_service(s)
            
            # Pour FTP
            elif port == 21:
                return detect_ftp_service(s)
            
            # Pour SMTP
            elif port == 25 or port == 587:
                return detect_smtp_service(s)
            
            # Pour les bases de données
            elif port in [3306, 5432, 6379, 27017]:
                return detect_database_service(s, port)
            
            # Technique 3: Envoi générique et analyse de la réponse
            else:
                return detect_generic_service(s, port)
                
    except Exception as e:
        return None

def analyze_banner(banner):
    """Analyse une bannière pour identifier le service."""
    banner_lower = banner.lower()
    
    # Patterns de détection
    if 'ssh' in banner_lower:
        return banner.split('\n')[0].strip()
    elif 'ftp' in banner_lower:
        return f"FTP - {banner.split('\n')[0].strip()}"
    elif 'smtp' in banner_lower or 'esmtp' in banner_lower:
        return f"SMTP - {banner.split('\n')[0].strip()}"
    elif 'pop3' in banner_lower:
        return f"POP3 - {banner.split('\n')[0].strip()}"
    elif 'imap' in banner_lower:
        return f"IMAP - {banner.split('\n')[0].strip()}"
    elif 'http' in banner_lower:
        return "HTTP"
    elif 'mysql' in banner_lower:
        return "MySQL"
    elif 'postgresql' in banner_lower or 'postgres' in banner_lower:
        return "PostgreSQL"
    elif 'redis' in banner_lower:
        return "Redis"
    elif 'mongodb' in banner_lower or 'mongo' in banner_lower:
        return "MongoDB"
    else:
        # Retourne les premiers caractères de la bannière
        return banner[:50].strip()

def detect_http_service(s, port):
    """Détecte le service HTTP/HTTPS."""
    try:
        # Envoie une requête HTTP HEAD simple
        request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        s.send(request)
        response = s.recv(2048).decode('utf-8', errors='ignore')
        
        # Analyse la réponse
        if 'HTTP/' in response:
            lines = response.split('\n')
            status_line = lines[0].strip()
            
            # Cherche le header Server
            server = None
            for line in lines:
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
            
            if server:
                return f"HTTP - {server}"
            else:
                return f"HTTP - {status_line}"
        
        return "HTTP (supposé)" if port in [80, 8000, 8080] else "HTTPS (supposé)"
    except:
        return "HTTP (supposé)" if port in [80, 8000, 8080] else "HTTPS (supposé)"

def detect_ssh_service(s):
    """Détecte le service SSH."""
    try:
        # SSH envoie automatiquement sa bannière
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if 'SSH' in banner:
            return banner
        return "SSH"
    except:
        return "SSH (supposé)"

def detect_ftp_service(s):
    """Détecte le service FTP."""
    try:
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner:
            return f"FTP - {banner}"
        return "FTP"
    except:
        return "FTP (supposé)"

def detect_smtp_service(s):
    """Détecte le service SMTP."""
    try:
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if 'SMTP' in banner or 'ESMTP' in banner:
            return f"SMTP - {banner}"
        return "SMTP"
    except:
        return "SMTP (supposé)"

def detect_database_service(s, port):
    """Détecte les services de base de données."""
    db_map = {
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }
    
    try:
        # Certaines BDD envoient une bannière de connexion
        s.setblocking(False)
        import select
        ready = select.select([s], [], [], 0.5)
        if ready[0]:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                return f"{db_map.get(port, 'Database')} - {banner[:50]}"
        
        return f"{db_map.get(port, 'Database')} (supposé)"
    except:
        return f"{db_map.get(port, 'Database')} (supposé)"

def detect_generic_service(s, port):
    """Détection générique pour les services inconnus."""
    try:
        # Essaie d'envoyer un message générique
        s.send(b'\r\n')
        
        # Attend une réponse
        s.setblocking(False)
        import select
        ready = select.select([s], [], [], 1)
        if ready[0]:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                return analyze_banner(banner)
        
        return "Service non identifié"
    except:
        return "Service non identifié"

def scan_port(ip, port, detect_services=False):
    """
    Scanne un port unique.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(3)
            s.connect((ip, port))
            
            service_info = ""
            if detect_services:
                service = detect_service(ip, port)
                if service:
                    service_info = f" - Service: {service}"
            
            print(f"✓ Port {port} : OUVERT{service_info}")
            return True
        except (TimeoutError, ConnectionRefusedError, OSError):
            print(f"✗ Port {port} : FERMÉ")
            return False

def scan_ports_parallel(ip, ports, detect_services=False, max_workers=50):
    """
    Scanne plusieurs ports en parallèle en utilisant ThreadPoolExecutor.
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Soumet toutes les tâches
        future_to_port = {
            executor.submit(scan_port_result, ip, port, detect_services): port 
            for port in ports
        }
        
        # Récupère les résultats au fur et à mesure
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open, service = future.result()
                results[port] = (is_open, service)
            except Exception as e:
                print(f"Erreur lors du scan du port {port}: {e}")
                results[port] = (False, None)
    
    return results

def scan_port_result(ip, port, detect_services=False):
    """
    Version de scan_port qui retourne le résultat au lieu de l'afficher.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(3)
            s.connect((ip, port))
            
            service = None
            if detect_services:
                service = detect_service(ip, port)
            
            return (True, service)
        except (TimeoutError, ConnectionRefusedError, OSError):
            return (False, None)