# Mini-SOAR : Security Orchestrator

Un outil Python léger léger d'Orchestration et de Réponse à Incident (SOAR Light) qui permet d'automatiser la réponse à incident. Il analyse des logs, détecte des IPs suspectes, scanne leurs ports et génère un rapport visuel.

## Fonctionnalités
*   **Analyse de logs :** Parsing Regex de `auth.log` et `access.log`.
*   **Scoring :** Détection automatique des menaces via seuils.
*   **Scan Actif :** Scan de ports multithreadé sur les cibles identifiées.
*   **Reporting :** Export CSV + Graphique (`matplotlib`).

## Utilisation

1.  **Installer les dépendances :**
    ```bash
    pip install matplotlib
    ```

2.  **Lancer l'outil :**
    ```bash
    python main.py
    ```

## 📂 Structure
*   `main.py` : Le script principal.
*   `module/` : Contient `log_parser`, `data_analyzer` et `network_scanner`.
*   `log/` : Dossier contenant les fichiers logs.
*   `rapport_securite.csv` & `top_5_menaces.png` : Les résultats générés.
