# SIA: Sistema de Inteligência e Ameaças
Uma ferramente de linha de comando, construída em Python, para agregar e analisar dados de itenligência de ameaças cibernéticas(Threat Intelligence) de forma rápida e eficiente.

## 🚀 Sobre o Projeto

O __SIA__ (Sistema de Inteligência e Análise) foi criada para centralizar a verificação de reputação de indicadores de compromentimento (IOCs), como endereços IP e URLs. Em vez de consultar manualmente múltiplos serviços, O SIA automatiza esse processo diretamente do seu terminal, focernencando relátorios claros e concisos para auxiliar na tomada de decisões de segurança.

#### Fonte de Dados Atuais
* __AbuseIPDB__: Para análise de reputação de endereços IP.
* __VirusTotal__: Para análise de reputação de URLs.

## 🌟Principais Funcionalidades

* __Análise de IP:__ Obtém a pontuação de abuso, geolocalização, provedor(ISP) e relátorios de atividade maliciosa.

* __Análise de URL:__ Verifica se a URL em dezenas de motores de antivírus e serviços de blocklist.

* __Inteface Interativa:__ Um menu simples e intuitov para guiar o usuário.

* __Estrutura Modular:__ Código organizada e pronto para ser expandido com novas fontes de inteligência.

* __Configuração Segura:__ Gestao de chaves de API através de um arquivo de configuração externo, evitando a exposição de segredos no código.

## ⚙️ Instalação e Uso
Siga estes passos para configurar e executar o projeto no seu ambiente local.

#### Pré-requisitos
* Python 3.8 ou superior.
* Chaves de API para serviços [AbuseIPDB](https://www.abuseipdb.com/) e [VirusTotal](https://www.virustotal.com/)

#### Passos de Instalação

1. Clone o repositório:

```bash
git clone https://github.com/victorhugossantos/SIA 
cd SIA
```
2. Cire e ative um ambiente virtual:

```bash
# Para macOS/Linux
python3 -m venv .venv
source .venv/bin/activate

# Para Windows
python -m venv .venv
.\.venv\Scripts\activate
```

3. Instale as dependências: 
```bash
pip install -r requirements.txt
```

4. Configure as suas chaves de API:
* No diretório principal, crie uma cópia do arquivo ``config.ini.example`` renomeia-a para ``config.ini``

* Abre o arquivo ``config.ini`` e insira as suas chaves de API nos campos correspondentes.

```ini 
[API]
ABUSEIPDB_KEY = SUA_CHAVE_DO_ABUSEIPDB_AQUI
VIRUSTOTAL_KEY = SUA_CHAVE_DO_VIRUSTOTAL_AQUI
``` 

#### Execute a Aplicação
Com tudo configurado, execute o script principal:
```bash
python main.py
```

## 🤝 Como Contribuir
Contribuições são o que tornam a comunidade de código aberto um lugar incrível para aprender inspirar e criar. Qualquer construibuição que você fizer será __muito bem-vinda.__

1. Faça um *Fork* do Projeto.
2. Crie a sua *Feature Branch* (``git checkout -b feature/FuncionabilidadeIncrivel``)
3. Faça o *Commit* das suas alterações (``git commit -m 'Adiciona alguma FuncionabilidadeIncrivel'``).
4. Faça o *Push* para a *Branch*(``git push origin feature/FuncionabilidadeIncrivel``);
5. Abra um *Pull Request*

## 📜 Licença
Distruibuido sob a Licença MIT. veja ``LICENSE.txt`` para mais informações.

__Desenvolvido por Victor Hugo Santos__
