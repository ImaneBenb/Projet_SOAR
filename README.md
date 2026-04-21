# Mini-SOAR : Security Orchestration, Automation and Response

Le **Mini-SOAR** est un outil qui permet d'automatiser le processus de réponse aux incidents de cybersécurité. Elle analyse les logs bruts et prend une décision automatisée basé sur un score de suspicion.

## Objectifs du Projet
Ce projet vise à automatiser le workflow d'un analyste SOC (Security Operations Center) :
1.  **Ingestion** : Lecture des journaux système et serveur.
2.  **Analyse** : Identification des patterns d'attaque via Expressions Régulières (Regex).
3.  **Scoring** : Mettre en place une logique de seuil pour qualifier une IP de 
"suspecte" et déclencher une action de réponse.
4.  **Enrichissement** : Scan de ports (Investigation) sur les IPs identifiées.
5.  **Reporting** : Génération de rapports structurés et de visualisations de données.

## Structure du Projet
```text
.
├── main.py                 # Point d'entrée et orchestration
├── module/                 # Logique métier
│   ├── log_parser.py       # Analyse syntaxique des logs
│   ├── data_analyzer.py    # Calcul des scores de menace
│   └── network_scanner.py  # Investigation réseau (Threads)
├── log/                    # Répertoire des sources (fichiers .log)
├── rapport_securite.csv    # Rapport d'audit généré
└── top_5_menaces.png       # Dashboard visuel généré
```

Le projet est structuré en plusieurs modules :

*   **`log_parser.py`** : Moteur d'extraction. Utilise des Regex pour isoler les IPs liées aux échecs SSH (Brute Force) et aux comportements HTTP suspects (Bots, erreurs 404 en série).
*   **`data_analyzer.py`** : Cœur logique. Calcule un score de suspicion en croisant les sources. 
*   **`network_scanner.py`** : Module de réponse active. Effectue un scan de ports multithreadé (Socket) pour identifier les services exposés sur les machines attaquantes.
*   **`main.py`** : Pilote le flux de données et génère les livrables finaux.

## Livrables de Sécurité

À chaque exécution, l'outil produit :
*    **`rapport_securite.csv`** : Un inventaire détaillé (IP, Score, Raison, Ports ouverts) prêt pour une importation dans un SIEM ou un outil de gestion d'incidents.
*    **`top_5_menaces.png`** : Une visualisation graphique (Histogramme Matplotlib) identifiant immédiatement les 5 adresses IP les plus dangereuses pour l'infrastructure.

## Installation & Déploiement

### Prérequis
*   Python 3.8+
*   Bibliothèques requises : `matplotlib`

### Installation
```bash
# Cloner le dépôt
git clone https://github.com/ImaneBenb/Projet_SOAR.git
cd Projet_SOAR

# Installer les dépendances
pip install matplotlib
```

### Utilisation
Placez vos fichiers `auth.log` et `access.log` dans le répertoire `log/`, puis lancez :
```bash
python main.py
```

