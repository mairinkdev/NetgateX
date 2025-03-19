#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de logging para a ferramenta NetgateX.
"""

import os
import logging
import datetime
from colorama import Fore, Style

class Logger:
    """Classe para gerenciar logs da aplicação."""
    
    def __init__(self, log_dir="logs", verbose=False):
        """
        Inicializa o logger.
        
        Args:
            log_dir (str): Diretório onde os logs serão salvos.
            verbose (bool): Se True, exibe logs mais detalhados.
        """
        self.verbose = verbose
        
        # Cria o diretório de logs se não existir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Define o nome do arquivo com a data atual
        date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_dir, f"netgatex_{date_str}.log")
        
        # Configura o logger
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("NetgateX")
        
        # Desabilita a saída para o console do logging padrão
        # pois usaremos nossa própria implementação colorida
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                self.logger.removeHandler(handler)
    
    def debug(self, message):
        """Log de mensagens de debug."""
        self.logger.debug(message)
        if self.verbose:
            print(f"{Fore.BLUE}[DEBUG] {message}{Style.RESET_ALL}")
    
    def info(self, message):
        """Log de mensagens de informação."""
        self.logger.info(message)
        print(f"{Fore.GREEN}[INFO] {message}{Style.RESET_ALL}")
    
    def warning(self, message):
        """Log de mensagens de aviso."""
        self.logger.warning(message)
        print(f"{Fore.YELLOW}[AVISO] {message}{Style.RESET_ALL}")
    
    def error(self, message):
        """Log de mensagens de erro."""
        self.logger.error(message)
        print(f"{Fore.RED}[ERRO] {message}{Style.RESET_ALL}")
    
    def critical(self, message):
        """Log de mensagens críticas."""
        self.logger.critical(message)
        print(f"{Fore.RED}{Style.BRIGHT}[CRÍTICO] {message}{Style.RESET_ALL}")

    def packet(self, message):
        """Log específico para pacotes capturados."""
        if self.verbose:
            self.logger.debug(f"PACKET: {message}")
            print(f"{Fore.CYAN}[PACOTE] {message}{Style.RESET_ALL}")
    
    def attack(self, message):
        """Log específico para ataques."""
        self.logger.info(f"ATTACK: {message}")
        print(f"{Fore.MAGENTA}[ATAQUE] {message}{Style.RESET_ALL}")
    
    def success(self, message):
        """Log para operações bem-sucedidas."""
        self.logger.info(f"SUCCESS: {message}")
        print(f"{Fore.GREEN}{Style.BRIGHT}[SUCESSO] {message}{Style.RESET_ALL}")
    
    def vuln(self, message):
        """Log para vulnerabilidades encontradas."""
        self.logger.warning(f"VULNERABILITY: {message}")
        print(f"{Fore.RED}{Style.BRIGHT}[VULNERABILIDADE] {message}{Style.RESET_ALL}") 