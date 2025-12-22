# 1. Visualisation : Générer un histogramme (bar chart) avec matplotlib des Top 5 des IPs basé sur leur score de suspicion combiné (Étape 1).
#2. Rapport Final : Exporter un fichier de synthèse (rapport_securite.csv) incluant :
#• L'IP
#• Le Score de Suspicion (total des incidents)
#• La Raison Principale (SSH Failed/404/Bot)
#• La liste des Ports Ouverts trouvés lors du scan.

import csv
import matplotlib.pyplot as plt
import module.data_analyzer as data_analyzer
import module.log_parser as log_parser
import log 

# Fonction pour générer le rapport de suspicion et l'histogramme
def generate_suspicion_report(suspicion_scores, scan_results, output_csv='rapport_securite.csv'):
    
    # Préparer les données pour le rapport
    report_data = data_analyzer.calculate_suspicion_score(suspicion_scores,log_parser.extract_ip_accesslog(log.access.log),log_parser.extract_ip_authlog(log.auth.log))
    
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
    plt.show()
    
    return report_data
