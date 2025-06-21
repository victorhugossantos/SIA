
# SIA: Sistema de Inteligência e Ameaças
Uma ferramenta de linha de comando, construída em Python, para agregar e analisar dados de inteligência de ameaças cibernéticas (Threat Intelligence) de forma rápida e eficiente.

## 🚀 Sobre o Projeto

O __SIA__ (Sistema de Inteligência e Análise) foi criado para centralizar a verificação de reputação de indicadores de comprometimento (IOCs), como endereços IP e URLs. Em vez de consultar manualmente múltiplos serviços, o SIA automatiza esse processo diretamente do seu terminal, fornecendo relatórios claros e concisos para auxiliar na tomada de decisões de segurança.

#### Fontes de Dados Atuais
* __AbuseIPDB__: Para análise de reputação de endereços IP.
* __VirusTotal__: Para análise de reputação de URLs.

## 🌟 Principais Funcionalidades

* __Análise de IP:__ Obtém a pontuação de abuso, geolocalização, provedor (ISP) e relatórios de atividade maliciosa.

* __Análise de URL:__ Verifica se a URL consta em dezenas de motores de antivírus e serviços de blocklist.

* __Interface Interativa:__ Um menu simples e intuitivo para guiar o usuário.

* __Estrutura Modular:__ Código organizado e pronto para ser expandido com novas fontes de inteligência.

* __Configuração Segura:__ Gestão de chaves de API através de um arquivo de configuração externo, evitando a exposição de segredos no código.

## ⚙️ Instalação e Uso
Siga estes passos para configurar e executar o projeto no seu ambiente local.

#### Pré-requisitos
* Python 3.8 ou superior.
* Chaves de API para os serviços [AbuseIPDB](https://www.abuseipdb.com/) e [VirusTotal](https://www.virustotal.com/)

#### Passos de Instalação

1. Clone o repositório:

```bash
git clone https://github.com/victorhugossantos/SIA 
cd SIA
```
2. Crie e ative um ambiente virtual:

```bash
# Para macOS/Linux
python3 -m venv .venv
source .venv/bin/activate

# Para Windows
python -m venv .venv
.\.venv\Scriptsctivate
```

3. Instale as dependências: 
```bash
pip install -r requirements.txt
```

4. Configure as suas chaves de API:
* No diretório principal, crie uma cópia do arquivo ``config.ini.example`` e renomeie-a para ``config.ini``

* Abra o arquivo ``config.ini`` e insira as suas chaves de API nos campos correspondentes.

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
Contribuições são o que tornam a comunidade de código aberto um lugar incrível para aprender, se inspirar e criar. Qualquer contribuição que você fizer será __muito bem-vinda.__

1. Faça um *Fork* do projeto.
2. Crie a sua *Feature Branch* (``git checkout -b feature/FuncionalidadeIncrivel``)
3. Faça o *Commit* das suas alterações (``git commit -m 'Adiciona alguma FuncionalidadeIncrivel'``).
4. Faça o *Push* para a *Branch* (``git push origin feature/FuncionalidadeIncrivel``);
5. Abra um *Pull Request*.

## 📜 Licença
Distribuído sob a Licença MIT. Veja ``LICENSE.txt`` para mais informações.

__Desenvolvido por Victor Hugo Santos__
