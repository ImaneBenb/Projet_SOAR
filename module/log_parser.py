import re

def extract_ip_authlog(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b')
    
    # Expressions régulières pour les erreurs spécifiques
    failed_password = re.compile(r"(échec|echec) d['’]authentification|Failed password", re.IGNORECASE)
    
    # Dictionnaire pour stocker les adresses IP et leur occurences
    ip_addresses_SSH = {}
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    try : 
        with open(log_content, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                match = ip_address.search(line)
                if match:
                    ip = match.group()
                    if failed_password.search(line):
                        ip_addresses_SSH[ip] = ip_addresses_SSH.get(ip, 0) + 1
       
    except FileNotFoundError:
        print(f"Fichier introuvable : {log_content}")
        
    return ip_addresses_SSH 

def extract_ip_accesslog(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b')
    
    # Expressions régulières pour les erreurs 404 et les bots
    error_404 = re.compile(r'\b404\b')   
    bot_user_agents = re.compile(r'bot|crawl|spider|slurp', re.IGNORECASE)
    
    # Dictionnaire pour stocker les adresses IP et leur occurences
    ip_addresses_HTTP = {}
    ip_addresses_HTTP_bots = {}
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    try : 
        with open(log_content, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                match = ip_address.search(line)
                if match:
                    ip = match.group()
                    if error_404.search(line):
                        ip_addresses_HTTP[ip] = ip_addresses_HTTP.get(ip, 0) + 1
                    if bot_user_agents.search(line):
                        ip_addresses_HTTP_bots[ip] = ip_addresses_HTTP_bots.get(ip, 0) + 1
       
    except FileNotFoundError:
        print(f"Fichier introuvable : {log_content}")
        
    return ip_addresses_HTTP, ip_addresses_HTTP_bots
