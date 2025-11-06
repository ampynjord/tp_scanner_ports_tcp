from scan import (
    scan_port, 
    validate_ip, 
    validate_port, 
    parse_ports, 
    scan_ports_parallel,
    scan_port_result
)
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP",
        epilog="Exemples:\n"
               "  %(prog)s -i 192.168.1.1 -p 80\n"
               "  %(prog)s -i example.com -p 22,80,443\n"
               "  %(prog)s -i 192.168.1.1 -p 80:100\n"
               "  %(prog)s -i 192.168.1.1 -p 22,80:85,443 -s\n"
               "  %(prog)s -i 192.168.1.1 -p 1:1000 -w 100",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--ip-address", required=True, help="Adresse IP ou nom de domaine cible")
    parser.add_argument("-p", "--port", required=True, help="Port(s) à scanner. Format: 80, 22,80,443, ou 80:443")
    parser.add_argument("-s", "--detect-service", action="store_true", help="Tenter de détecter le service (avancé)")
    parser.add_argument("--sequential", action="store_true", help="Forcer le mode séquentiel (par défaut: parallèle)")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Nombre de threads pour le scan parallèle (défaut: 50)")

    args = parser.parse_args()
    
    # Validation de l'IP
    if not validate_ip(args.ip_address):
        print(f"❌ Erreur: L'adresse IP '{args.ip_address}' n'est pas valide.")
        sys.exit(1)
    
    # Parse les ports
    ports = parse_ports(args.port)
    
    if not ports:
        print("❌ Erreur: Aucun port valide à scanner.")
        sys.exit(1)
    
    # Affiche les informations de scan
    print(f"\n{'='*60}")
    print(f"Scanner de ports TCP")
    print(f"{'='*60}")
    print(f"Cible: {args.ip_address}")
    print(f"Ports: {len(ports)} port(s) à scanner")
    if len(ports) <= 10:
        print(f"Liste: {', '.join(map(str, ports))}")
    else:
        print(f"Plage: {min(ports)} - {max(ports)}")
    print(f"Détection de service: {'Activée' if args.detect_service else 'Désactivée'}")
    
    # Détermine le mode: parallèle par défaut si plusieurs ports, sauf si --sequential est spécifié
    use_parallel = len(ports) > 1 and not args.sequential
    print(f"Mode: {'Parallèle' if use_parallel else 'Séquentiel'}")
    if use_parallel:
        print(f"Threads: {args.workers}")
    print(f"{'='*60}\n")
    
    # Scan des ports
    if use_parallel:
        # Mode parallèle
        print(f"🔍 Scan en parallèle avec {args.workers} threads...\n")
        results = scan_ports_parallel(args.ip_address, ports, args.detect_service, args.workers)
        
        # Affiche les résultats triés
        open_ports = []
        closed_ports = []
        
        for port in sorted(results.keys()):
            is_open, service = results[port]
            if is_open:
                service_info = f" - Service: {service}" if service else ""
                print(f"✓ Port {port} : OUVERT{service_info}")
                open_ports.append(port)
            else:
                print(f"✗ Port {port} : FERMÉ")
                closed_ports.append(port)
        
        # Résumé
        print(f"\n{'='*60}")
        print(f"Résumé: {len(open_ports)} port(s) ouvert(s), {len(closed_ports)} port(s) fermé(s)")
        if open_ports:
            print(f"Ports ouverts: {', '.join(map(str, open_ports))}")
        print(f"{'='*60}")
    else:
        # Mode séquentiel
        print("🔍 Scan en cours...\n")
        open_ports = []
        
        for port in ports:
            is_open, service = scan_port_result(args.ip_address, port, args.detect_service)
            
            if is_open:
                service_info = f" - Service: {service}" if service else ""
                print(f"✓ Port {port} : OUVERT{service_info}")
                open_ports.append(port)
            else:
                print(f"✗ Port {port} : FERMÉ")
        
        # Résumé
        print(f"\n{'='*60}")
        print(f"Résumé: {len(open_ports)} port(s) ouvert(s) sur {len(ports)}")
        if open_ports:
            print(f"Ports ouverts: {', '.join(map(str, open_ports))}")
        print(f"{'='*60}")

if __name__ == "__main__":
    main()