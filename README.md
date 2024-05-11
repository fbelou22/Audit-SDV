# Audit-SDV
Audit autonome Projet d'étude

Pré requis:
Pour utiliser mon programme il faudras télécharger:
Flask (pip install -U Flask)
Python (https://www.python.org/downloads/windows/)
Nmap ( https://nmap.org/download#windows)
Afin de poursuivre je vous conseille de tout mettre dans un dossier. Une fois le CMD ouvert il vous suffiras de vous placer dans ce dossier vous pourrez le nommer à votre convenance ex:(cd path\...)
Comment lancer le programme sous CMD:
1. python -m venv env (Pour lancer un environnement virtuel)
2. env\Scripts\activate (Activer l'environement)
3. pip install -r requirements.txt
4. set FLASK_APP=app.py (Permet de sélectionné l'ensemble de l'applicatif python)
5. Flask Run (Lance Flask avec l'applicatif)
En cas de problème de version entré la commande suiavante: pip install --upgrade flask werkzeug puis reprendre l'étape 4 et 5.

1. Introduction

Le présent rapport vise à fournir une vue d'ensemble des différentes méthodes de test d'intrusion mises en œuvre dans l'application Toolbox de Test d'Intrusion. Ces méthodes couvrent divers aspects de la sécurité informatique, tels que le scan de ports, la détection de vulnérabilités, les tests XSS, les tests d'injection SQL, etc. Chaque méthode est conçue pour identifier des faiblesses potentielles dans un système informatique et contribuer à renforcer sa sécurité.

2. Méthodes de test d'intrusion

2.1. Scan de Ports

Fonction : La fonction scan_ports(ip) utilise le module Python nmap pour scanner les ports ouverts sur une adresse IP donnée.
Utilisation : Elle est utile pour détecter les services actifs et les ports ouverts sur un hôte, ce qui peut aider à identifier d'éventuelles vulnérabilités.
Paramètres : Prend en entrée l'adresse IP de l'hôte à scanner.
Résultat : Renvoie la liste des ports ouverts sur l'adresse IP spécifiée.

2.2. Détection de Vulnérabilités

Fonction : La fonction check_security_config(ip) vérifie la configuration de sécurité d'un système donné pour détecter d'éventuelles faiblesses.
Utilisation : Elle permet de repérer les configurations de sécurité non conformes ou mal paramétrées qui pourraient exposer le système à des risques.
Paramètres : Prend en entrée l'adresse IP de l'hôte à vérifier.
Résultat : Renvoie un rapport sur la configuration de sécurité de l'hôte, indiquant s'il existe des problèmes de sécurité potentiels.

2.3. Test XSS (Cross-Site Scripting)

Fonction : La fonction test_xss(url) teste une URL donnée pour détecter d'éventuelles vulnérabilités XSS.
Utilisation : Elle permet de vérifier si une application web est vulnérable aux attaques XSS en testant les entrées utilisateur.
Paramètres : Prend en entrée l'URL à tester.
Résultat : Indique s'il existe une vulnérabilité XSS potentielle dans l'URL spécifiée.

2.4. Test d'Injection SQL

Fonction : La fonction test_sql_injection(input_param) simule un test d'injection SQL en vérifiant un paramètre d'entrée donné.
Utilisation : Elle permet de détecter les vulnérabilités d'injection SQL en testant les entrées utilisateur.
Paramètres : Prend en entrée le paramètre à tester.
Résultat : Indique s'il existe une vulnérabilité d'injection SQL potentielle dans le paramètre spécifié.

2.5. Test d'Exposition de Données Sensibles

Fonction : La fonction test_sensitive_data_exposure(response) vérifie si des données sensibles sont exposées dans la réponse HTTP.
Utilisation : Elle aide à détecter les fuites d'informations sensibles dans les réponses des applications web.
Paramètres : Prend en entrée la réponse HTTP à vérifier.
Résultat : Indique s'il existe une exposition potentielle de données sensibles dans la réponse.

2.6. Test de Sécurité des Cookies

Fonction : La fonction test_cookie_security(cookies) teste la sécurité des cookies en vérifiant leur configuration.
Utilisation : Elle permet de repérer les cookies non sécurisés qui pourraient être exploités par des attaquants.
Paramètres : Prend en entrée les cookies à vérifier.
Résultat : Indique s'il existe des cookies non sécurisés dans la session.

2.7. Test de Gestion des Sessions

Fonction : La fonction test_session_management(session) vérifie la gestion des sessions en détectant les éventuelles faiblesses.
Utilisation : Elle permet de repérer les problèmes de gestion de session qui pourraient conduire à des attaques telles que le vol de session.
Paramètres : Prend en entrée les informations de session à vérifier.
Résultat : Indique s'il existe des problèmes potentiels dans la gestion des sessions.

2.8. Test de Validation des Entrées

Fonction : La fonction test_input_validation(user_input) teste la validation des entrées utilisateur en vérifiant si des données non filtrées sont acceptées.
Utilisation : Elle permet de détecter les problèmes de validation des entrées qui pourraient conduire à des attaques telles que l'injection de code.
Paramètres : Prend en entrée les données utilisateur à vérifier.
Résultat : Indique s'il existe des problèmes potentiels dans la validation des entrées utilisateur.

3. Conclusion

La mise en œuvre de ces méthodes de test d'intrusion dans l'application Toolbox de Test d'Intrusion permet d'offrir aux utilisateurs un ensemble d'outils complet pour évaluer la sécurité de leurs systèmes informatiques. Ces méthodes couvrent un large éventail de vecteurs d'attaque potentiels et aident à identifier et à corriger les vulnérabilités avant qu'elles ne soient exploitées par des attaquants. En continuant à améliorer et à étendre ces méthodes, l'application peut contribuer à renforcer la résilience et la sécurité des systèmes informatiques contre les menaces actuelles et futures.
