import sys
import core.config_manager as config_manager
import core.ip_checker as ip_checker
import core.url_checker as url_checker

def main_menu(api_keys):
    """Exibe o menu principal e gerencia o fluxo da aplicação"""

    while True:
        print("\n--- Plataforma de Inteligencia de Ameaças ---")
        print("\nSelecione uma opção: ")
        print("  1. Verificar Reputação de IP")
        print("  2. Verificar Reputação de URL")
        print("  3. Sair")

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
                report = url_checker.check_url_reputation(api_keys['virustotal'], url_to_check)
                if report:
                    url_checker.display_url_report(report)
        elif escolha == '3':
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

