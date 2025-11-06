"""
Tests d'intégration pour le scanner de ports TCP (sans pytest).
Exécution: python3 test_scanner_simple.py
"""

import socket
import threading
import time
from scan import (
    validate_ip, 
    validate_port, 
    parse_ports, 
    scan_port_result,
    scan_ports_parallel
)


def test_validate_ip():
    """Test des fonctions de validation d'IP."""
    print("Test: Validation d'IP...")
    
    # IPv4 valides
    assert validate_ip("192.168.1.1") == True
    assert validate_ip("127.0.0.1") == True
    assert validate_ip("8.8.8.8") == True
    
    # Noms de domaine
    assert validate_ip("google.com") == True
    assert validate_ip("example.org") == True
    
    # Invalides
    assert validate_ip("") == False
    assert validate_ip("   ") == False
    
    print("✓ Validation d'IP: OK")


def test_validate_port():
    """Test de validation de ports."""
    print("Test: Validation de ports...")
    
    # Ports valides
    assert validate_port(1) == True
    assert validate_port(80) == True
    assert validate_port(443) == True
    assert validate_port(65535) == True
    
    # Ports invalides
    assert validate_port(0) == False
    assert validate_port(-1) == False
    assert validate_port(65536) == False
    assert validate_port(100000) == False
    
    print("✓ Validation de ports: OK")


def test_parse_ports():
    """Test du parsing de ports."""
    print("Test: Parsing de ports...")
    
    # Port unique
    assert parse_ports("80") == [80]
    
    # Ports multiples
    assert parse_ports("22,80,443") == [22, 80, 443]
    
    # Plage de ports
    assert parse_ports("80:83") == [80, 81, 82, 83]
    
    # Combinaison
    result = parse_ports("22,80:82,443")
    assert result == [22, 80, 81, 82, 443]
    
    # Doublons éliminés
    assert parse_ports("80,80,80") == [80]
    
    print("✓ Parsing de ports: OK")


def test_scan_with_server():
    """Test du scan avec un serveur temporaire."""
    print("Test: Scan de ports avec serveur test...")
    
    # Crée un serveur TCP temporaire
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 0))  # Port automatique
    server_socket.listen(1)
    test_port = server_socket.getsockname()[1]
    
    print(f"  Serveur test sur le port {test_port}")
    
    # Lance le serveur dans un thread
    def accept_connections():
        server_socket.settimeout(2)
        try:
            while True:
                try:
                    conn, addr = server_socket.accept()
                    conn.close()
                except socket.timeout:
                    break
        except:
            pass
    
    thread = threading.Thread(target=accept_connections, daemon=True)
    thread.start()
    time.sleep(0.1)
    
    # Test du scan
    is_open, service = scan_port_result("127.0.0.1", test_port)
    assert is_open == True, "Le port du serveur test devrait être ouvert"
    
    # Test d'un port fermé
    is_open, service = scan_port_result("127.0.0.1", 65534)
    assert is_open == False, "Le port 65534 devrait être fermé"
    
    # Nettoyage
    server_socket.close()
    
    print("✓ Scan de ports: OK")


def test_parallel_scan():
    """Test du scan parallèle."""
    print("Test: Scan parallèle...")
    
    ports = [22, 80, 443]
    results = scan_ports_parallel("127.0.0.1", ports, detect_services=False, max_workers=3)
    
    # Vérifie que tous les ports ont été scannés
    assert len(results) == len(ports)
    
    # Vérifie le format des résultats
    for port, (is_open, service) in results.items():
        assert isinstance(is_open, bool)
    
    print("✓ Scan parallèle: OK")


def test_integration():
    """Test d'intégration complet."""
    print("Test: Workflow complet...")
    
    # Valide l'IP
    ip = "127.0.0.1"
    assert validate_ip(ip) == True
    
    # Parse les ports
    ports = parse_ports("80,443,8080")
    assert len(ports) == 3
    
    # Vérifie que tous les ports sont valides
    for port in ports:
        assert validate_port(port) == True
    
    print("✓ Workflow complet: OK")


def main():
    """Exécute tous les tests."""
    print("\n" + "="*60)
    print("Tests du Scanner de Ports TCP")
    print("="*60 + "\n")
    
    tests = [
        test_validate_ip,
        test_validate_port,
        test_parse_ports,
        test_scan_with_server,
        test_parallel_scan,
        test_integration
    ]
    
    failed = 0
    passed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__}: ÉCHEC - {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: ERREUR - {e}")
            failed += 1
        print()
    
    print("="*60)
    print(f"Résultats: {passed} réussi(s), {failed} échoué(s)")
    print("="*60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
