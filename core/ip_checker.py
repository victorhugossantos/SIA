import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table

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
    """Exibe o relatorio de reputação do IP de forma legivel."""
    if not report_data:
        print("\n[INFO] Não foram encontrados dados para o IP especificado")
        return
    
    console = Console()

    table = Table(title=f"\n[bold blue]Relatório de Reputação de IP: {report_data.get('ipAddress')}[/bold blue]", show_header=True, header_style="bold magenta")
    table.add_column("Propriedade", style='cyan')
    table.add_column("Valor", style='white')

    table.add_row("País", f"{report_data.get('countryName', 'N/A')} ({report_data.get('countryCode', 'N/A')})")
    table.add_row("Provedor (ISP)", report_data.get('isp', 'N/A'))
    table.add_row("Domínio", report_data.get('domain', 'N/A') or 'N/A')
    table.add_row("Total de Relatórios", str(report_data.get('totalReports', 0)))

    # Pontuação do abuso 
    abuse_score = report_data.get('abuseConfidenceScore', 0)
    print (f"\n >> Pontuação de Abuso: {abuse_score}% <<")
    if abuse_score > 75:
        score_style, risk_level = "bold red", "[bold red]ALTO[/bold red]"
    elif abuse_score > 25:
        score_style, risk_level = "bold yellow", "[bold yellow]MODERADO[/bold yellow]"
    else:
        score_style, risk_level = "bold green", "[bold green]BAIXO[/bold green]"
    
    table.add_row("Pontuação de Abuso", f"[{score_style}]{abuse_score}%[/]")
    table.add_row("Nível de Risco", risk_level)

    console.print(table)

    # Exibe os ultimos relatorios detalhados
    recent_reports = report_data.get('reports', [])
    if recent_reports:
       details_table = Table(title="[bold blue] Últimos Relatórios Detalhados [/bold blue]", show_header=True, header_style="bold magenta")
       details_table.add_column("Data", style='cyan')
       details_table.add_column("Comentário", style='white')
       details_table.add_column("Categorias", style="yellow")

       for report in recent_reports[:5]:
            reported_at = datetime.strptime(report['reportedAt'], "%Y-%m-%dT%H:%M:%S%z").strftime('%d/%m/%Y %H:%M:%S')
            comment = report.get('comment', '')
            category_ids = report.get('categories', [])
            category_names = ", ".join([ABUSEIPDB_CATEGORIES.get(cat_id, f"ID {cat_id}") for cat_id in category_ids])
            details_table.add_row(reported_at, comment, category_names)
    
    console.print(details_table)
