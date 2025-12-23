# 🛡️ Mini-SOAR : Security Orchestrator

Un outil Python léger pour automatiser la réponse à incident. Il analyse des logs, détecte des IPs suspectes (Brute Force SSH, Bots), scanne leurs ports et génère un rapport visuel.

## ⚡ Fonctionnalités
*   **Analyse de logs :** Parsing Regex de `auth.log` et `access.log`.
*   **Scoring :** Détection automatique des menaces via seuils.
*   **Scan Actif :** Scan de ports multithreadé sur les cibles identifiées.
*   **Reporting :** Export CSV + Graphique (`matplotlib`).

## 🚀 Utilisation rapide

1.  **Installer les dépendances :**
    ```bash
    pip install matplotlib
    ```

2.  **Générer les logs de test (optionnel) :**
    ```bash
    python generate_top5_logs.py
    ```

3.  **Lancer l'outil :**
    ```bash
    python main.py
    ```

## 📂 Structure
*   `main.py` : Le script principal.
*   `module/` : Contient `log_parser`, `data_analyzer` et `network_scanner`.
*   `log/` : Dossier contenant les fichiers logs.
*   `rapport_securite.csv` & `top_5_menaces.png` : Les résultats générés.
