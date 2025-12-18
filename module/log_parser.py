import re

def extract_ip_authlog(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    
    # Expressions régulières pour les erreurs spécifiques
    failed_password = re.compile(r"echec d'authentification")
    
    # Dictionnaire pour stocker les adresses IP et leur occurences
    ip_addresses_SSH = {}
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    for line in log_content.splitlines():
        # cas des échecs d'authentification SSH
        if failed_password.search(line):
            ips = ip_address.findall(line)
            for ip in ips:
                ip_addresses_SSH[ip] = ip_addresses_SSH.get(ip, 0) + 1
    
    return {
        'failed_passwords': list(ip_addresses_SSH)
    }   

def extract_ip_accesslog(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    
    # Expressions régulières pour les erreurs 404 et les bots
    error_404 = re.compile(r'404')   
    bot_user_agents = re.compile(r'bot|crawl|spider|slurp', re.IGNORECASE)
    
    # Dictionnaire pour stocker les adresses IP et leur occurences
    ip_addresses_HTTP = {}
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    for line in log_content.splitlines():
        # cas des erreurs 404 ou des bots
        if error_404.search(line) or bot_user_agents.search(line):
            ips = ip_address.findall(line)
            for ip in ips:
                ip_addresses_HTTP[ip] = ip_addresses_HTTP.get(ip, 0) + 1
    
    return {
        'http_errors': list(ip_addresses_HTTP)
    }