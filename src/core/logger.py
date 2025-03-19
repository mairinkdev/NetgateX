#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo Logger para NetgateX

Este módulo fornece capacidades de logging para toda a aplicação.
"""

import os
import logging
import datetime
from logging.handlers import RotatingFileHandler
import colorama

# Inicializa colorama para saída colorida em Windows
colorama.init()

class Logger:
    """
    Classe que lida com todas as necessidades de logging da aplicação.
    Suporta logging para arquivos e console com saída colorida.
    """
    
    # Constantes para cores ANSI
    COLORS = {
        "DEBUG": colorama.Fore.CYAN,
        "INFO": colorama.Fore.GREEN,
        "WARNING": colorama.Fore.YELLOW,
        "ERROR": colorama.Fore.RED,
        "CRITICAL": colorama.Fore.MAGENTA + colorama.Style.BRIGHT,
        "SUCCESS": colorama.Fore.LIGHTGREEN_EX + colorama.Style.BRIGHT  # Adicionado para mensagens de sucesso
    }
    
    def __init__(self, log_level="INFO", log_to_console=True, log_to_file=True):
        """
        Inicializa o logger.
        
        Args:
            log_level (str): Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_to_console (bool): Se True, loga para o console
            log_to_file (bool): Se True, loga para um arquivo
        """
        # Configura o diretório de logs se ele não existir
        self.log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Configura o nome do arquivo de log com timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.log_dir, f"netgatex_{timestamp}.log")
        
        # Configura o logger
        self.logger = logging.getLogger("NetgateX")
        self.logger.setLevel(getattr(logging, log_level))
        
        # Impede duplicação de logs
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Formatos de log para arquivo e console
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        
        # Handler para arquivo
        if log_to_file:
            file_handler = RotatingFileHandler(
                self.log_file, 
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        
        # Handler para console
        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(console_formatter)
            console_handler.setLevel(getattr(logging, log_level))
            self.logger.addHandler(console_handler)
            
            # Adiciona manipulador personalizado para cores
            self._add_coloring_to_handler(console_handler)
    
    def _add_coloring_to_handler(self, handler):
        """
        Adiciona cores ao handler de console.
        
        Args:
            handler: O handler para adicionar cores
        """
        original_emit = handler.emit
        
        def new_emit(record):
            # Adiciona cores ao registro antes de emitir
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{colorama.Style.RESET_ALL}"
                record.msg = f"{self.COLORS[levelname]}{record.msg}{colorama.Style.RESET_ALL}"
            original_emit(record)
            
        handler.emit = new_emit
    
    def debug(self, message):
        """Loga uma mensagem de nível DEBUG."""
        self.logger.debug(message)
    
    def info(self, message):
        """Loga uma mensagem de nível INFO."""
        self.logger.info(message)
    
    def warning(self, message):
        """Loga uma mensagem de nível WARNING."""
        self.logger.warning(message)
    
    def error(self, message):
        """Loga uma mensagem de nível ERROR."""
        self.logger.error(message)
    
    def critical(self, message):
        """Loga uma mensagem de nível CRITICAL."""
        self.logger.critical(message)
        
    def success(self, message):
        """Loga uma mensagem de sucesso (usa o nível INFO com formatação especial)."""
        # Usa INFO internamente já que SUCCESS não é um nível padrão do logging
        self.logger.info(f"SUCCESS: {message}")
        
        # Imprime com formatação especial no console se estiver capturando logs do console
        print(f"{self.COLORS['SUCCESS']}SUCCESS: {message}{colorama.Style.RESET_ALL}")
        
    def attack(self, message):
        """Loga uma mensagem relacionada a ataques (usa o nível WARNING com formatação especial)."""
        # Usa WARNING internamente
        self.logger.warning(f"ATTACK: {message}")
        
        # Imprime com formatação especial no console
        print(f"{colorama.Fore.RED + colorama.Style.BRIGHT}ATTACK: {message}{colorama.Style.RESET_ALL}")

    def get_log_file_path(self):
        """Retorna o caminho do arquivo de log atual."""
        return self.log_file 