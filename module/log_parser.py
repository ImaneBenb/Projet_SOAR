import re

def extract_ip_addresses(log_content):
    
    # Expression régulière pour les adresses IP
    ip_address = re.compile(r'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
    
    # Expressions régulières pour les erreurs spécifiques
    error_404 = re.compile(r'404')
    failed_password = re.compile(r'echec d’authentification')
    
    # Expression régulière pour détécter les mots clés de bots
    bot_keywords = re.compile(r'bot|crawl|spider', re.IGNORECASE)
    
    # Sets pour stocker les adresses IP uniques
    ip_addresses_HTTP = set()
    ip_addresses_SSH = set()
    
    # Parcourir chaque ligne du contenu du log et extraire les adresses IP
    for line in log_content.splitlines():
        # cas des erreurs 404 ou des bots
        if error_404.search(line) or bot_keywords.search(line):
            ips = ip_address.findall(line)
            ip_addresses_HTTP.update(ips)
        # cas des échecs de connexion SSH
        if failed_password.search(line):
            ips = ip_address.findall(line)
            ip_addresses_SSH.update(ips)
    
    return {
        '404_errors': list(ip_addresses_HTTP),
        'failed_passwords': list(ip_addresses_SSH)
    }