import re

def extract_ip_authlog(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
    
    # Expressions régulières pour les erreurs spécifiques
    failed_password = re.compile(r'echec d’authentification')
    
    # Liste pour stocker les adresses IP 
    ip_addresses_SSH = []
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    for line in log_content.splitlines():
        # cas des échecs d'authentification SSH
        if failed_password.search(line):
            ips = ip_address.findall(line)
            ip_addresses_SSH.append(ips)
    
    return {
        'failed_passwords': list(ip_addresses_SSH)
    }   

def extract_ip_accesslog(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
    
    # Expressions régulières pour les erreurs spécifiques
    error = re.compile(r'404|bot|crawl|spider|Not Found', re.IGNORECASE)
    
    # Liste pour stocker les adresses IP 
    ip_addresses_HTTP = []
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    for line in log_content.splitlines():
        # cas des erreurs 404 ou des bots
        if error.search(line) :
            ips = ip_address.findall(line)
            ip_addresses_HTTP.append(ips)
    
    return {
        'http_errors': list(ip_addresses_HTTP)
    }