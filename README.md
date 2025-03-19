# NetgateX - Ferramenta de Segurança de Redes

![NetgateX Logo](logo.png)

## Descrição

NetgateX é uma ferramenta educacional de segurança de redes desenvolvida para fins de pesquisa e testes éticos. Esta ferramenta permite monitorar, analisar e testar a segurança de redes WiFi, detectando possíveis vulnerabilidades.

## Recursos

- **Análise de Tráfego**: Capture e analise pacotes em tempo real
- **Detecção de Dispositivos**: Identifique dispositivos conectados à rede
- **Evil Twin**: Configure ataques de AP falso para testar a conscientização de segurança
- **Man-in-the-Middle**: Intercepte e analise o tráfego entre dispositivos
- **Interface Gráfica**: Dashboard intuitivo para gerenciar todas as operações
- **Gerenciamento WiFi**: Configure e gerencie interfaces de rede sem fio
- **Compatibilidade com Windows**: Suporte para execução em Windows 10/11 (com BOAS limitações)

## Compatibilidade com Sistemas Operacionais

O NetgateX foi projetado para funcionar em múltiplos sistemas operacionais:

### Linux (Funcionalidade Completa)
- Suporte completo a todas as funcionalidades
- Recomendado Kali Linux, ParrotOS ou Ubuntu
- Controle total de interfaces WiFi, incluindo modo monitor

### Windows 10/11 (Funcionalidade Limitada)
- Suporte à maioria das funcionalidades de análise passiva
- Escaneamento de redes WiFi
- Detecção de dispositivos
- Análise básica de tráfego
- Limitações no modo monitor e alguns ataques

## Requisitos

### Requisitos Gerais
- Python 3.8+ (3.10 recomendado)
- Adaptador WiFi compatível
- Dependências listadas em `requirements.txt`

### Requisitos Específicos para Windows
- Execução como Administrador
- Python instalado da página oficial python.org (recomendado)
- Microsoft Visual C++ Build Tools (para algumas dependências)

## Instalação

### Linux
```bash
git clone https://github.com/mairinkdev/netgatex.git
cd netgatex
pip install -r requirements.txt
```

### Windows
```
git clone https://github.com/mairinkdev/netgatex.git
cd netgatex
pip install -r requirements.txt
```

Para desenvolvedores no Windows: Se encontrar problemas com a biblioteca netifaces ou outras dependências nativas, use:
```
pip install pipwin
pipwin install netifaces
```

## Uso

### Linux
```bash
sudo python netgatex.py
```

### Windows
Abra o PowerShell ou CMD como Administrador:
```
python netgatex.py
```

Para modo CLI apenas (sem interface gráfica):
```
python netgatex.py --cli
```

## Comandos Disponíveis (Modo CLI)

- `interfaces` - Lista interfaces WiFi disponíveis
- `scan` - Escaneia redes WiFi próximas
- `monitor start` - Inicia monitoramento de tráfego
- `mitm start` - Inicia ataque Man-in-the-Middle (requer privilégios)
- `eviltwin start` - Inicia ataque Evil Twin (funcionalidade limitada no Windows)
- `help` - Mostra todos os comandos disponíveis

## Estrutura do Projeto

```
netgatex/
├── src/
│   ├── core/
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   └── wifi_manager.py
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── evil_twin.py
│   │   └── mitm.py
│   ├── monitoring/
│   │   ├── __init__.py
│   │   └── traffic_analyzer.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py
│   └── ui/
│       ├── __init__.py
│       └── dashboard.py
├── web/
│   ├── templates/
│   └── static/
├── logs/
├── netgatex.py
└── requirements.txt
```

## Limitações conhecidas no Windows

- Modo monitor não é nativamente suportado no Windows (simulado em algumas funções)
- Ataques Evil Twin têm funcionalidade limitada
- Ataques MITM podem precisar de adaptadores WiFi externos específicos
- Injeção de pacotes tem suporte limitado sem drivers especializados

## Resolução de Problemas

### Windows
- Certifique-se de executar como Administrador
- Para problemas com pacotes missing, instale o Microsoft C++ Build Tools
- Se o PySimpleGUI solicitar licença, use o modo CLI com `--cli`

### Linux
- Certifique-se de executar com sudo
- Verifique se seu adaptador WiFi suporta modo monitor

## Aviso Legal

Esta ferramenta é fornecida apenas para fins educacionais e de pesquisa. O uso indevido desta ferramenta para atacar alvos sem permissão explícita é ilegal e antiético. O autor não se responsabiliza por qualquer uso indevido deste software.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para mais detalhes. 