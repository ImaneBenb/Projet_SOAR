import os 
import csv
import matplotlib.pyplot as plt
import module.data_analyzer as data_analyzer
import module.log_parser as log_parser
import module.network_scanner as network_scanner

# Fonction pour générer le rapport de suspicion et l'histogramme
def generate_suspicion_report(suspicion_scores, scan_results, output_csv='rapport_securite.csv'):
    
    # Préparer les données pour le rapport
    report_data = []
    
    # On itère sur le dictionnaire { IP: {details} }
    for ip, details in suspicion_scores.items():
        total_score = details['activity_volume']
        
        # On reconstruit la raison lisible pour le rapport
        reasons = []
        if details['ssh_failures'] >= 50:
            reasons.append('Brute Force SSH')
        if details['bot_requests'] >= 10 and details['http_404s'] > 0:
            reasons.append('Crawler Agressif')
        
        main_reason = ' & '.join(reasons) if reasons else "Activité Suspecte"
        
        # On récupère les ports du scan
        open_ports = scan_results.get(ip, [])
        ports_str = ', '.join(map(str, open_ports)) if open_ports else 'Aucun'
        
        report_data.append({
            'IP': ip,
            'Score de Suspicion': total_score,
            'Raison Principale': main_reason,
            'Ports Ouverts': ports_str
        })
    
    # Écrire le rapport dans un fichier CSV
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP', 'Score de Suspicion', 'Raison Principale', 'Ports Ouverts']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)       
        writer.writeheader()
        for row in report_data:
            writer.writerow(row)
    
    print(f"Rapport de sécurité généré : {output_csv}")
    
    # Générer un histogramme des Top 5 IPs par score de suspicion
    top_ips = sorted(report_data, key=lambda x: x['Score de Suspicion'], reverse=True)[:5]
    ips = [entry['IP'] for entry in top_ips]
    scores = [entry['Score de Suspicion'] for entry in top_ips]
    
    plt.figure(figsize=(10, 6))
    plt.bar(ips, scores, color='red')
    plt.xlabel('Adresses IP')
    plt.ylabel('Score de Suspicion')
    plt.title('Top 5 des IPs par Score de Suspicion')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("top_5_menaces.png")
    plt.show()
    
    return report_data

def main():
    # Chemins des fichiers de logs
    authlog_path = os.path.join('log', 'auth.log')
    accesslog_path = os.path.join('log', 'access.log')
    
    # Extraire les adresses IP suspectes des logs
    ip_addresses_SSH = log_parser.extract_ip_authlog(authlog_path)
    ip_addresses_HTTP, ip_addresses_HTTP_bots = log_parser.extract_ip_accesslog(accesslog_path)
    
    # Analyser les données pour calculer les scores de suspicion
    suspicion_scores = data_analyzer.calculate_suspicion_score(
        ip_addresses_SSH, ip_addresses_HTTP, ip_addresses_HTTP_bots
    )
    
    # Scanner les ports des IPs suspectes
    suspicious_ips = list(suspicion_scores.keys())
    scan_results = network_scanner.network_scan(suspicious_ips)
    
    # Générer le rapport de suspicion et l'histogramme
    generate_suspicion_report(suspicion_scores, scan_results)
    
if __name__ == "__main__":
    main()