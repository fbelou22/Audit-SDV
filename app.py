# Importation des modules nécessaires
from flask import Flask, render_template, request  # Pour créer l'application Flask et gérer les requêtes HTTP
import nmap  # Pour effectuer des scans de ports

# Création de l'application Flask
app = Flask(__name__)

# Initialisation du scanner de ports Nmap
nm = nmap.PortScanner()

# Définition de la route principale de l'application
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None  # Initialisation du résultat à afficher dans le template HTML
    if request.method == 'POST':  # Vérification si la requête est une requête POST
        task = request.form.get('task')  # Récupération de la tâche sélectionnée dans le formulaire
        ip_address = request.form.get('ip_address', '127.0.0.1')  # Récupération de l'adresse IP saisie, avec une valeur par défaut

        # Traitement en fonction de la tâche sélectionnée
        if task == 'port_scan' and ip_address:  # Si la tâche est un scan de ports et une adresse IP est fournie
            result = scan_ports(ip_address)
        elif task == 'vulnerability_scan':  # Si la tâche est une détection de vulnérabilités
            result = "Résultat de la détection des vulnérabilités"
        elif task == 'xss_test':  # Si la tâche est un test XSS
            url = request.form.get('url')  # Récupération de l'URL à tester
            result = test_xss(url)
        elif task == 'security_config':  # Si la tâche est une vérification de la configuration de sécurité
            result = check_security_config(ip_address)
        elif task == 'sql_injection':  # Si la tâche est un test d'injection SQL
            input_param = request.form.get('input_param')  # Récupération du paramètre d'entrée à tester
            result = test_sql_injection(input_param)
        elif task == 'sensitive_data_exposure':  # Si la tâche est un test d'exposition de données sensibles
            response = request.form.get('response')  # Récupération de la réponse HTTP à analyser
            result = test_sensitive_data_exposure(response)
        elif task == 'cookie_security':  # Si la tâche est un test de sécurité des cookies
            cookies = request.cookies  # Récupération des cookies de la requête
            result = test_cookie_security(cookies)
        elif task == 'session_management':  # Si la tâche est un test de gestion de session
            session = request.cookies  # Récupération des données de session
            result = test_session_management(session)
        elif task == 'input_validation':  # Si la tâche est un test de validation des entrées
            user_input = request.form.get('user_input')  # Récupération de l'entrée utilisateur à tester
            result = test_input_validation(user_input)

    # Rendu du template HTML avec le résultat
    return render_template('index.html', result=result)

# Fonction pour effectuer un scan de ports sur une adresse IP donnée
def scan_ports(ip):
    try:
        nm.scan(ip, '1-1024')  # Scan des ports 1 à 1024 sur l'adresse IP spécifiée
        if ip in nm.all_hosts():  # Vérification si l'adresse IP a été trouvée dans les résultats du scan
            result = nm[ip].all_tcp()  # Récupération des ports ouverts sur l'adresse IP
            return f"Ports ouverts sur {ip}: {result}"
        else:
            return f"Aucun résultat trouvé pour l'IP {ip}"
    except Exception as e:  # Gestion des erreurs potentielles
        return f"Erreur lors du scan: {str(e)}"

# Fonction pour simuler un test XSS sur une URL donnée
def test_xss(url):
    # Simulation d'un test XSS simple
    if "<script>" in url:
        return f"Possible XSS vulnerability detected at {url}"
    else:
        return f"No XSS vulnerability detected at {url}"

# Fonction pour simuler une vérification de la configuration de sécurité sur une adresse IP donnée
def check_security_config(ip):
    # Simulation d'une vérification de configuration de sécurité
    return f"Security configuration checked for {ip}: No issues found."

# Fonction pour simuler un test d'injection SQL sur un paramètre d'entrée donné
def test_sql_injection(input_param):
    # Simulation d'un test d'injection SQL
    if "'; DROP TABLE users; --" in input_param:
        return "Possible SQL injection vulnerability detected."
    else:
        return "No SQL injection vulnerability detected."

# Fonction pour simuler un test d'exposition de données sensibles sur une réponse HTTP donnée
def test_sensitive_data_exposure(response):
    # Simulation d'un test d'exposition de données sensibles
    if "password" in response:
        return "Sensitive data exposed: password found in response."
    else:
        return "No sensitive data exposure detected."

# Fonction pour simuler un test de sécurité des cookies
def test_cookie_security(cookies):
    # Simulation d'un test de sécurité des cookies
    if "session_id" in cookies and "secure" not in cookies["session_id"]:
        return "Insecure cookie detected: session_id is not marked as secure."
    else:
        return "Cookies are secure."

# Fonction pour simuler un test de gestion de session
def test_session_management(session):
    # Simulation d'un test de gestion de session
    if "user_id" in session and session["user_id"] == "admin":
        return "Session management issue detected: user_id is set to admin without proper authentication."
    else:
        return "Session management is secure."

# Fonction pour simuler un test de validation des entrées utilisateur
def test_input_validation(user_input):
    # Simulation d'un test de validation des entrées
    if "<script>" in user_input:
        return "Input validation issue detected: script tags not properly filtered."
    else:
        return "Input validation is secure."

# Point d'entrée de l'application Flask
if __name__ == '__main__':
    app.run(debug=True)  # Démarrage de l'application en mode debug
