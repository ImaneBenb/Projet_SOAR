
def calculate_suspicion_score(ip_addresses_SSH, ip_addresses_HTTP, ip_addresses_HTTP_bots, ssh_threshold=50, http_404_threshold=10, bot_threshold=10):
    suspicion_scores = {}
    
    # Rassembler toutes les IPs uniques
    all_ips = set(ip_addresses_SSH.keys()) | set(ip_addresses_HTTP.keys()) | set(ip_addresses_HTTP_bots.keys())
    
    for ip in all_ips:
        score = 0
        ssh_failures = ip_addresses_SSH.get(ip, 0)
        http_404s = ip_addresses_HTTP.get(ip, 0)
        bot_requests = ip_addresses_HTTP_bots.get(ip, 0)
        
        # Ajouter au score basé sur les seuils
        if ssh_failures >= ssh_threshold:
            score += 2  # Poids plus élevé pour les échecs SSH
        if http_404s >= http_404_threshold:
            score += 1
        if bot_requests >= bot_threshold:
            score += 1
        
        suspicion_scores[ip] = {
            'ssh_failures': ssh_failures,
            'http_404s': http_404s,
            'bot_requests': bot_requests,
            'suspicion_score': score
        }
    
    return suspicion_scores