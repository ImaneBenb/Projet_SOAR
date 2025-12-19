
def calculate_suspicion_score(ip_addresses_SSH, ip_addresses_HTTP, ip_addresses_HTTP_bots):
    
    suspicion_scores = {}
    
    # Rassembler toutes les IPs uniques
    all_ips = set(ip_addresses_SSH.keys()) | set(ip_addresses_HTTP.keys()) | set(ip_addresses_HTTP_bots.keys())
    
    # Définir des seuils pour chaque type d'activité suspecte
    ssh_threshold=50
    http_404_threshold=10
    bot_threshold=10
    
    for ip in all_ips:
        highly_suspect = False
        # Récupérer les occurrences pour chaque type d'activité
        ssh_failures = ip_addresses_SSH.get(ip, 0)
        http_404s = ip_addresses_HTTP.get(ip, 0)
        bot_requests = ip_addresses_HTTP_bots.get(ip, 0)
        
        # Ajouter au score basé sur les seuils
        if ssh_failures >= ssh_threshold:
            highly_suspect = True
        if http_404s >= http_404_threshold and bot_requests >= bot_threshold:
            highly_suspect = True
        
        suspicion_scores[ip] = {
            'ssh_failures': ssh_failures,
            'http_404s': http_404s,
            'bot_requests': bot_requests
        }
    
    return suspicion_scores