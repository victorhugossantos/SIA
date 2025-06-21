import requests
import time

def check_url_reputation(api_key, url_to_check):
    """Consulta a API do VirusTotal para obter a reputação de uma URL"""

    print(f"\n[INFO] Consultando a URL: {url_to_check}...")

    submit_url='https://www.virustotal.com/api/v3/urls'
    headers= {'x-apikey': api_key}
    payload = {'url': url_to_check}

    try: 
        response = requests.post(submit_url, headers=headers, data=payload)
        response.raise_for_status()
        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            print('[ERRO] Não foi possivel obter o ID d análise da URL.')
            return None
        
        print('[INFO] Análise solicitada. Aguardando o relatório final...')
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        time.sleep(15)

        report_response = requests.get(analysis_url, headers=headers)
        report_response.raise_for_status()
        return report_response.json().get('data', {}).get('attributes', {})
    
    except requests.exceptions.HTTPError as http_error:
        print(f'[ERRO HTTP] {http_error}')
    except requests.exceptions.RequestException as req_error:
        print(f"[ERRO DE CONEXÃO] {req_error}")
    return None

def display_url_report(report_data):
    """Exibe o relatório de reputação da URL de forma legível."""
    if not report_data or 'results' not in report_data:
        print('\n[INFO] Não foram encontrados dados para a URL especificada.')
        return
    
    print("\n --- Relatório de Reputação de URL ---")
    stats = report_data.get('stats', {})
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    total_engines = sum(stats.values())

    print(f"  URL Analisada: {report_data.get('url')}")
    print(f"\n >> Detecções: {malicious + suspicious} / {total_engines} <<")

    if malicious > 0:
        print(" >> NÍVEL DE RISCO: ALTO (Malicioso) << ")
    elif suspicious > 0:
        print(" >> NÍVEL DE RISCO: MODERADO (Suspito) << ")
    else:
        print (" >> NÍVEL DE RISCO: BAIXO (Limpo) <<")
    
    if malicious > 0 or suspicious > 0:
        print("\n Motores que dectaram a ameaça:")
        results = report_data.get('results', {})
        for engine, result in results.item():
            if result.get('category') not in ['harmless', 'undetected']:
                print(f"    - {engine}: {result.get('result', 'N/A')} ({result.get('category')})")
    print("---------------------------------------")

# --- funções de Verificação de Hash ---

def check_hash_reputation(api_key, file_hash):
        """Consulta a API do VirusTotal para obter a reputação de um hash de um arquivo."""
        print(f"\n[INFO] Consultando o Hash: {file_hash}...")

        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey' : api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 404:
                return None # Hash não encontrado no VirtusTotal
            response.raise_for_status()
            return response.json().get('data', {}).get('attributes', {})
        except requests.exceptions.HTTPError as http_err:
            print(f"[ERRO HTTP] {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"[ERRO DE CONEXÃO] {req_err}")
        return None
    
def display_hash_report(report_data):
        """Exibe o relátorio de reputação do hash de forma legível"""
        if not report_data:
            print("\n[INFO] Este hash não foi entrando na base de dados do VirusTotal.")
            return
        print ("\n --- Relatório de Reputação de Hash ---")
        stats = report_data.get('last_analysis_stats', {})
        malicious = report_data.get('malicious', 0)
        suspicious = report_data.get('suspicious', 0)
        total_engines = sum(stats.values())

        print(f"  Hash (SHA256): {report_data.get('sha256')}")
        print(f"  Nome Principal: {report_data.get('meaningful_name', 'N/A')}")
        print(f"\n  >> Detecções: {malicious + suspicious} / {total_engines}") 

        if malicious > 0:
            print("  >> NÍVEL DE RISCO: ALTO (Malicioso)")
        elif suspicious > 0:
            print("  >> NÍVEL DE RISCO: MODERADO (Suspeito) << ")
        else: 
            print(" >> NÍVEL DE RISCO: BAIXO (Limpo) << ")
        
        # Exibe os nome dado ao malware pelos morotes de antivurus

        if malicious > 0 or suspicious > 0:
            print("\n Nomes de Ameaça Identificados: ")
            results = report_data.get('last_analysis_results', {})
            detected_names = set()
            for engine, result in results.items():
                if result.get('result'):
                    detected_names.add(result.get('result'))
            
            for name in list(detected_names)[:5]: # mostra até os 5 nomes diferente
                print(f"    - {name}")
print("----------------------------------------")

# --- Função de Verificação de Dominio

def check_domain_reputation(api_key, domain):
    """Consulta a API do VirusToal para obter a reputação de um dominio."""
    print(f"\n[INFO] Consultando o Domínio: {domain}...")

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': api_key}

    try: 
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return None # Dominio não entrando no virustotal
        response.raise_for_status()
        return response.json().get('data', {}).get('attributes', {})
    except requests.exceptions.HTTPError as http_err:
        print(f"[ERRO HTTP] {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"[ERRO DE CONEXÃO] {req_err}")
    return None

def display_domain_report(report_data):
    """Exibe o relatório de reputação do dominio de forma legivel"""
    if not report_data:
        print("\n[INFO] Este domonio não i encontrado na base de dados do VirusTotal.")
        return
    print("\n--- Relatório de Reputação de Domínio ---")
    stats = report_data.get('last_analysis_stats, {}')
    if not stats:
        stats = {}
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    total_engines = sum(stats.values())

    print(f"  Domínio Analisado: {report_data.get('id')}")
    print(f"  Reputação (VirusTotal): {report_data.get('reputation')}")
    print(f"\n  >> Detecções: {malicious + suspicious} / {total_engines} <<")

    if malicious > 0:
        print("  >> NÍVEL DE RISCO: ALTO (Malicioso)")
    elif suspicious > 0:
        print("  >> NÍVEL DE RISCO: MODERADO (Suspeito) << ")
    else: 
        print(" >> NÍVEL DE RISCO: BAIXO (Limpo) << ")

    #Exibe as categorais atribuidas ao domínio
    categories = report_data.get('categories', {})
    if categories:
        print("\n Categorais Indentificadas: ")
        for source, category in categories.items():
            print(f"    - {source}: {category}")
    print("-------------------------------------------")
