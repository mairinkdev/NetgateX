#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetgateX - Ferramenta Avançada para Teste de Segurança em Redes WiFi
Autor: Equipe NetgateX
Versão: 1.0.0
"""

import sys
import os
import time
import argparse
from colorama import init, Fore, Style

# Inicializa o colorama
init(autoreset=True)

# Garante que estamos importando módulos do diretório correto
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importa os módulos internos
try:
    from src.core.scanner import NetworkScanner
    from src.core.wifi_manager import WiFiManager
    from src.monitoring.traffic_analyzer import TrafficAnalyzer
    from src.attacks.deauth import DeauthAttack
    from src.attacks.evil_twin import EvilTwin
    from src.attacks.mitm import MITMAttack
    from src.ui.dashboard import Dashboard
    from src.utils.logger import Logger
    from src.utils.helpers import check_dependencies, is_root
except ImportError as e:
    print(f"{Fore.RED}Erro ao importar módulos: {e}")
    print(f"{Fore.YELLOW}Certifique-se de instalar todas as dependências com 'pip install -r requirements.txt'")
    sys.exit(1)

def print_banner():
    """Exibe o banner de inicialização da ferramenta."""
    banner = f"""
{Fore.CYAN}███╗   ██╗███████╗████████╗ ██████╗  █████╗ ████████╗███████╗██╗  ██╗
{Fore.CYAN}████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
{Fore.CYAN}██╔██╗ ██║█████╗     ██║   ██║  ███╗███████║   ██║   █████╗   ╚███╔╝ 
{Fore.CYAN}██║╚██╗██║██╔══╝     ██║   ██║   ██║██╔══██║   ██║   ██╔══╝   ██╔██╗ 
{Fore.CYAN}██║ ╚████║███████╗   ██║   ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
{Fore.CYAN}╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Fore.WHITE}==========================================================================
{Fore.GREEN}                    Ferramenta de Teste de Segurança WiFi
{Fore.YELLOW}                                Versão 1.0.0
{Fore.RED}                                   @MAIRINKDEV 🦈
{Fore.WHITE}==========================================================================
    """
    print(banner)

def setup_argument_parser():
    """Configura e analisa os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(description='NetgateX - Ferramenta Avançada para Teste de Segurança em Redes WiFi')
    
    parser.add_argument('-i', '--interface', help='Interface de rede WiFi a ser utilizada')
    parser.add_argument('-m', '--modo', choices=['scan', 'monitor', 'attack', 'analyze', 'report'], help='Modo de operação')
    parser.add_argument('-t', '--target', help='BSSID/MAC alvo para ataques')
    parser.add_argument('-c', '--channel', type=int, help='Canal de rede WiFi')
    parser.add_argument('-g', '--gui', action='store_true', help='Iniciar com interface gráfica')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verboso (mais informações)')
    
    return parser.parse_args()

def check_environment():
    """Verifica se o ambiente está corretamente configurado."""
    # Verifica se está rodando como root/admin
    if not is_root():
        print(f"{Fore.RED}[ERRO] Este programa precisa ser executado como administrador/root.")
        print(f"{Fore.YELLOW}Por favor, execute novamente com privilégios administrativos.")
        sys.exit(1)
    
    # Verifica dependências
    if not check_dependencies():
        print(f"{Fore.RED}[ERRO] Algumas dependências estão faltando.")
        print(f"{Fore.YELLOW}Execute 'pip install -r requirements.txt' para instalar.")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[+] Ambiente verificado e pronto para execução.")

def main():
    """Função principal do programa."""
    print_banner()
    args = setup_argument_parser()
    
    # Verificar ambiente
    try:
        check_environment()
    except Exception as e:
        print(f"{Fore.RED}[ERRO] Falha ao verificar o ambiente: {e}")
        sys.exit(1)
    
    # Inicializar o logger
    logger = Logger(verbose=args.verbose)
    logger.info("Inicializando NetgateX...")
    
    try:
        # Se o modo GUI for selecionado, iniciar a interface gráfica
        if args.gui:
            logger.info("Iniciando interface gráfica...")
            dashboard = Dashboard()
            dashboard.start()
            return
        
        # Caso contrário, seguir com o modo de linha de comando
        if args.modo == 'scan':
            logger.info("Iniciando escaneamento de redes...")
            scanner = NetworkScanner(interface=args.interface)
            scanner.start_scan()
        
        elif args.modo == 'monitor':
            logger.info("Iniciando modo de monitoramento...")
            analyzer = TrafficAnalyzer(interface=args.interface, channel=args.channel)
            analyzer.start_monitoring()
        
        elif args.modo == 'attack':
            if not args.target:
                logger.error("É necessário especificar um alvo (-t/--target) para o modo de ataque.")
                sys.exit(1)
            
            logger.info(f"Iniciando ataque contra {args.target}...")
            # Implementar seleção de tipo de ataque aqui
            
        elif args.modo == 'analyze':
            logger.info("Iniciando análise de vulnerabilidades...")
            # Implementar análise de vulnerabilidades
            
        elif args.modo == 'report':
            logger.info("Gerando relatório...")
            # Implementar geração de relatório
            
        else:
            logger.warning("Nenhum modo selecionado. Use -h para ver as opções disponíveis.")
            
    except KeyboardInterrupt:
        logger.info("\nOperação interrompida pelo usuário. Encerrando...")
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
    finally:
        logger.info("Encerrando NetgateX...")

if __name__ == "__main__":
    main() 