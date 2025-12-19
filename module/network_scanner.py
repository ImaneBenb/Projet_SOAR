
import socket
import threading

# Fonction pour scanner un port spécifique
def scan_port(ip, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    except Exception as e:
        pass
   
# Fonction pour scanner une liste de ports sur une IP donnée    
def scan_ip_ports(ip, port_range):
    open_ports = []
    threads = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return open_ports

# Fonction principale pour scanner une liste d'IPs suspectes
def network_scan(suspicious_ips):
    port_range = range(20, 24)  # Example critical ports: 20-23
    port_range = list(port_range) + [80, 443, 3389]  # Adding common ports
    scan_results = {}
    for ip in suspicious_ips:
        open_ports = scan_ip_ports(ip, port_range)
        if open_ports:
            scan_results[ip] = open_ports
    return scan_results
