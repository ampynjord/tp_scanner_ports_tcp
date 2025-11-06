# Scanner de Ports TCP

Un scanner de ports TCP simple et efficace en Python avec support du scan parallèle et de la détection de services.

## Fonctionnalités

### Obligatoires ✅
- ✅ Validation de l'adresse IP
- ✅ Validation des ports (1-65535)
- ✅ Scan de plusieurs ports : `22,80,443`
- ✅ Scan d'une plage de ports : `80:443`

### Avancées ✅
- ✅ Détection de service (banner grabbing)
- ✅ Scan parallèle avec threading
- ✅ Tests d'intégration

## Installation

Aucune dépendance externe requise (utilise uniquement la bibliothèque standard Python).

```bash
git clone <votre-repo>
cd tp_scanner_ports_tcp
```

## Utilisation

### Exemples de base

**Scanner un seul port :**
```bash
python3 cli.py -i 192.168.1.1 -p 80 -s
```

**Scanner plusieurs ports :**
```bash
python3 cli.py -i example.com -p 22,80,443 -s
```

**Scanner une plage de ports :**
```bash
python3 cli.py -i 192.168.1.1 -p 80:100 -s
```

**Combinaison de ports et plages :**
```bash
python3 cli.py -i 192.168.1.1 -p 22,80:85,443 -s
```

### Options avancées

**Ajuster le nombre de threads (le mode parallèle est automatique avec plusieurs ports) :**
```bash
python3 cli.py -i 192.168.1.1 -p 1:1000 -w 100 -s
```

**Forcer le mode séquentiel :**
```bash
python3 cli.py -i 192.168.1.1 -p 22,80,443 --sequential -s
```

## Options

```
-i, --ip-address      Adresse IP ou nom de domaine cible (requis)
-p, --port            Port(s) à scanner (requis)
                      Formats : 80, 22,80,443, ou 80:443
-s, --detect-service  Activer la détection de service
--sequential          Forcer le mode séquentiel (défaut: parallèle avec plusieurs ports)
-w, --workers         Nombre de threads pour le scan parallèle (défaut: 50)
-h, --help            Afficher l'aide
```

## Tests

Exécuter les tests d'intégration :

```bash
python3 test_scanner.py
```

Si pytest est installé :
```bash
pytest test_scanner.py -v
```

## Exemple de sortie

```
============================================================
Scanner de ports TCP
============================================================
Cible: scanme.nmap.org
Ports: 3 port(s) à scanner
Liste: 22, 80, 443
Détection de service: Activée
Mode: Parallèle
============================================================

🔍 Scan en parallèle avec 50 threads...

✓ Port 22 : OUVERT - Service: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
✓ Port 80 : OUVERT - Service: HTTP - Apache/2.4.7 (Ubuntu)
✗ Port 443 : FERMÉ

============================================================
Résumé: 2 port(s) ouvert(s), 1 port(s) fermé(s)
Ports ouverts: 22, 80
============================================================
```

## Architecture

```
tp_scanner_ports_tcp/
├── cli.py                    # Interface en ligne de commande
├── scan.py                   # Logique de scan et validation
├── test_scanner.py           # Tests avec pytest
├── test_scanner_simple.py    # Tests sans dépendances
└── README.md                 # Ce fichier
```

## Fonctionnement

1. **Validation** : Vérifie que l'IP et les ports sont valides
2. **Parsing** : Analyse la chaîne de ports (supporte virgules et plages)
3. **Scan** : Tente une connexion TCP sur chaque port
4. **Détection** : Identifie automatiquement le service par banner grabbing et analyse de protocole
5. **Résultats** : Affiche un résumé des ports ouverts/fermés avec les services détectés

## Détection de Services

Le scanner utilise plusieurs techniques intelligentes pour identifier les services :

- **Banner Grabbing passif** : Écoute les bannières automatiques (SSH, FTP, SMTP)
- **Requêtes HTTP** : Envoie des requêtes HEAD pour identifier les serveurs web (Apache, Nginx, etc.)
- **Analyse de protocole** : Détecte SSH, FTP, SMTP, bases de données (MySQL, PostgreSQL, Redis, MongoDB)
- **Parsing intelligent** : Extrait les versions et informations pertinentes des réponses

Services détectés automatiquement : SSH, HTTP/HTTPS, FTP, SMTP, MySQL, PostgreSQL, Redis, MongoDB, et plus encore.

## Notes

- Le timeout par défaut est de 3 secondes par port
- Le scan parallèle est **activé automatiquement** lors du scan de plusieurs ports (pour un seul port, mode séquentiel)
- La détection de service (`-s`) utilise des techniques avancées de banner grabbing et d'analyse de protocole
- Les services détectés incluent les versions exactes (ex: OpenSSH_6.6.1p1, Apache/2.4.7)
- Utilisez `--sequential` pour forcer le mode séquentiel si nécessaire

## Avertissement

⚠️ **Utilisation légale uniquement** : N'utilisez ce scanner que sur des systèmes dont vous avez l'autorisation de tester. Le scan de ports non autorisé peut être illégal.
