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
        print(f"[ERRO DE OCNEXAO] {req_error}")
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
            
