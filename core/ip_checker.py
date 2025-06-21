import requests
from datetime import datetime

#MAPEAMENTO DE IDS DE CATEGORIA PARA NOMES
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}

def check_ip_reputation(api_key, ip_address, max_age_in_days=90):
    """COnsulta a API do AbuseIPDB para obter a reputação de um endereço IP."""
    print(f'\[INFO] Consultando o IP: {ip_address}...')

    params = {'ipAddress': ip_address, 'maxAgeInDays': max_age_in_days, 'verbose': True}
    headers = {'Accept': 'application/json', 'Key': api_key}

    try: 
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        response.raise_for_status()
        return response.json().get('data', {})
    except requests.exceptions.HTTPError as http_error:
        print(f'[ERRO HTTP] {http_error}')
        if response.status_code == 422:
            print(f"[ERRO] O IP '{ip_address}' parece ser inválido")
    except requests.exceptions.RequestException as req_error:
        print(f'[ERRO DE CONEXÃO] {req_error}')
    return None

def display_ip_report(report_data):
    """Exibe o relatorio de reuputação do IP de forma legivel."""
    if not report_data:
        print("\n[INFO] Não foram encontrados dados para o IP especificado")
        return
    
    print("\n--- Relatório de Inteligencia de Ameaças ---")
    print(f"  Endereço IP: {report_data.get('ipAddress')}")
    print(f"  Pais: {report_data.get('countryName', 'N/A')} ({report_data.get('countryCode', 'N/A')})")
    print(f"  Provedor (ISP): {report_data.get('isp', 'N/A')}")
    print(f"  Dominio: {report_data.get('domain', 'N/A')}")
    print(f"  É de um IP Público?: {'Sim' if report_data.get('isPublic') else 'Não'}")
    print(f"  É Whitelisted? {'Sim' if report_data.get('isWhitelisted') else 'Não'}")

    # Pontuação do abuso 
    abuse_score = report_data.get('abuseConfidenceScore', 0)
    print (f"\n >> Pontuação de Abuso: {abuse_score}% <<")
    if abuse_score > 75:
        print("  >> NÍVEL DE RISCO: ALTO <<")
    elif abuse_score > 25:
        print(" >> NÍVEL DE RISCO: MODERADO <<")
    else:
        print(" >> NÍVEL DE RISCO: BAIXO << ")
    
    print (f"\n Total de Relatórios de Abuso: {report_data.get('totalReports', 0)}")

    # Exibe os ultimos relatorios detalhados
    recent_reports = report_data.get('reports', [])
    if recent_reports:
        print("\n---Ultimos 5 Relatórios Detalhados ---")
        for i, report in enumerate(recent_reports[:5]):
            try:
                reported_at = datetime.strptime(report['reportedAt'], "%Y-%m-%dT%H:%M:%S%z")
                print(f"\n  Relatório #{i+1}")
                print(f"    Data: {reported_at.strftime('%d/%m/%Y %H:%M:%S')}")
                print(f"    Comentário: \"{report['comment']}\"")

                category_ids = report.get('categories', [])
                category_names = [ABUSEIPDB_CATEGORIES.get(cat_id, f"Desconhecida ({cat_id})") for cat_id in category_ids]
                print(f"    Categorias: {category_names}")
            except (KeyError, ValueError) as e:
                print(f"    [AVISO] Não foi possivel processar um relatório detalhado: {e}")
        print("\n-------------------------------------------")
    else: 
        print("\n-------------------------------------------")