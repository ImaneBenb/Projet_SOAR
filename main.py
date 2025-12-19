import os
import module.log_parser as log_parser
import module.data_analyser as data_analyzer

def main():
    print("--- 🛠️  MODE DEBUG 🛠️  ---")
    
    # 1. Vérification des chemins
    log_folder = "log"
    auth_path = os.path.join(log_folder, "auth.log")
    access_path = os.path.join(log_folder, "access.log")
    
    # 2. Parsing (Extraction)
    print(f"\n[1] Parsing des fichiers...")
    
    # On vérifie ce que le parser trouve VRAIMENT
    ssh_data = log_parser.extract_ip_authlog(auth_path)
    print(f"    -> SSH Data (Brut) : {ssh_data}") 
    # Si ça affiche {}, c'est que le parser SSH ne marche pas sur ce fichier
    
    http_data, bot_data = log_parser.extract_ip_accesslog(access_path)
    print(f"    -> HTTP 404 (Brut) : {http_data}")
    print(f"    -> HTTP Bot (Brut) : {bot_data}")

    # 3. Analyse (Test des seuils)
    print(f"\n[2] Analyse...")
    
    # Appel de la fonction
    suspects = data_analyzer.calculate_suspicion_score(ssh_data, http_data, bot_data)
    
    print(f"    -> Résultat final (Suspects) : {suspects}")

    # 4. Diagnostic
    if not ssh_data and not http_data:
        print("\n❌ DIAGNOSTIC : Les dictionnaires sont vides.")
        print("   -> Vérifie tes Regex dans log_parser.py")
        print("   -> Ouvre tes fichiers logs pour voir s'ils contiennent bien des IPs et les mots clés.")
    elif len(suspects) == 0:
        print("\n⚠️  DIAGNOSTIC : Des données ont été trouvées, mais aucune ne dépasse les seuils.")
        print("   -> Essaie de baisser les seuils dans data_analyzer.py (ex: ssh=1, bot=1).")
    else:
        print(f"\n✅ SUCCÈS : {len(suspects)} suspects trouvés.")

if __name__ == "__main__":
    main()