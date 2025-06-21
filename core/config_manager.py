import configparser
import sys

def load_api_keys():
    config = configparser.ConfigParser()
    try: 
        if not config.read('config.ini'):
            raise FileNotFoundError
        
        abuseipdb_key = config['API']['ABUSEIPDB_KEY']
        virustotal_key = config['API']['VIRUSTOTAL_KEY']

        return {
            'abuseipdb': abuseipdb_key,
            'virustotal': virustotal_key
        }
    
    except (KeyError, FileNotFoundError):
        print("[ERRO] Arquivo 'config.ini' não encontrado ou mal configurado.")
        print("Certifique-se que o arquivo existe e contpé as seguintes chaves sob a seção [API]: ")
        print("ABUSEIPDB_KEY = SUA_CHAVE_AQUI")
        print("VIRUSTOTAL_KEY = SUA_CHAVE_AQUI")
        return None