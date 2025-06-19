import requests
import json
import argparse
import sys
from datetime import datetime
import configparser

ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check'

def check_ip_reputation(api_key, ip_address, max_age_in_days=90):

    print(f"[INFO] Consultando o IP: {ip_address}...")

    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': max_age_in_days,
        'vebose': True # Pede uma resposta mais detalhada

    }

    headers = {
        'Accept': 'Application/json',
        'Key': api_key
    }

    try: 
        response = requests.get(url=ABUSEIPDB_API_URL, headers=headers, params=params)
        response.raise_for_status()

        # Decodifica a resposta JSON
        decoded_response = response.json()
        return decoded_response.get('data', {})
    
    except requests.exceptions.HTTPError as http_error:
        print(f"[ERRO HTTP] Ocorreu um erro ao consultar a API: {http_error}")
        if response.status_code == 401:
            print(f"[ERRO] A chave da API é invalida ou não foi autorizada. Verifique a chave de API")
        elif response.status_code ==  429:
            print(f"[ERRO] Limite de requisições da API excedido. Tente novamente mais tarde.")
        elif response.status_code == 422:
            print(f"[ERRO] O IP '{ip_address}' parece ser invalido.")
        else: 
            print(f"[ERRO] Detalhes: {response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"[ERRO DE CONEXÃO] Não foi possivel conectar à API: {req_err}")
    except json.JSONDecodeError:
        print(f"[ERRO] Não foi possivel decodificar a resposta da API")
    
    return None

def display_report(report_data):
    """Exibe o relátorio de reputaçao do IP de forma legivel"""

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
            reported_at = datetime.strptime(report['reportedAt'], "%Y-%m-%dT%H:%M:%S%z")
            print(f"\n  Relatório #{i+1}")
            print(f"    Data: {report_data.strftime('%d/%m/%Y %H:%M:%S')}")
            print(f"    Comentário: \"{report['comment']}\"")
            print(f"    Categorias: {[cat['name'] for cat in report.get('categories', [])]}")
        print("\n-------------------------------------------")

def main():
    """
    Função princiopal que gerencia a entrada interativa do usuario e o fluxo do script
    """

    config = configparser.ConfigParser()
    config.read('config.ini')
    API_KEY = config['API']['KEY']

    if not API_KEY or API_KEY == "SUA_CHAVE_API_AQUI":
        print("[AVISO] Você precisa conigurar sua chave no arquivo config.ini")
        sys.exit(1)

    print("--- Plataforma de Inteligência de Ameaças (v0.1) ---")
    print("Bem-vindo! Digite um endereço IP para verificar sua reputação.")

    while True:
        ip_address = input("\nDigite o IP(ou 'sair' para fechar): ").strip()

        if not ip_address:
            continue

        if ip_address.lower() in ['sair', 'exit', 'quit']:
            print("[INFO] Encerrando o programa. Até logo!")
            break
        
        # Chama a função principal de verificação
        report = check_ip_reputation(API_KEY, ip_address)

        if report:
            display_report(report)

if __name__ == "__main__":
    main()
        

        