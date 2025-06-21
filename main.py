import sys
from core import config_manager, ip_checker, virustotal_checker

def main_menu(api_keys):
    """Exibe o menu principal e gerencia o fluxo da aplicação"""

    while True:
        print("\n--- Plataforma de Inteligencia de Ameaças ---")
        print("\nSelecione uma opção: ")
        print("  1. Verificar Reputação de IP")
        print("  2. Verificar Reputação de URL")
        print("  3. Verificar Reputação de Hash de Arquivo")
        print("  4. Sair")

        escolha = input("Opção: ").strip()

        if escolha == '1':
            ip_address = input("\nDigite o IP para verificar: ").strip()
            if ip_address:
                report = ip_checker.check_ip_reputation(api_keys['abuseipdb'], ip_address)
                if report:
                    ip_checker.display_ip_report(report)
        elif escolha == '2':
            url_to_check = input("\nDigite a URL completa para verificar: ").strip()
            if url_to_check:
                report = virustotal_checker.check_url_reputation(api_keys['virustotal'], url_to_check)
                if report:
                    virustotal_checker.display_url_report(report)
        elif escolha == '3':
            hash_to_check = input("\nInsira o Hash (MD5, SHA1 ou SHA256) para verificar: ").strip()
            report = virustotal_checker.check_hash_reputation(api_keys['virustotal'], hash_to_check)
            virustotal_checker.display_hash_report(report)
        elif escolha == '4':
            print("[INFO] Encerrando o programa. Até logo!")
            break

        else: 
            print("[AVISO] Opção inválida, Por favor, escolha uma das opções do menu acima.")

def main():
    """Função principal"""
    api_keys = config_manager.load_api_keys()
    if not api_keys:
        sys.exit(1)

    main_menu(api_keys)

if __name__ == "__main__":
    main()

