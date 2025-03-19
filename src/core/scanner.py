#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para escaneamento de redes WiFi.
"""

import os
import time
import threading
import platform
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from tabulate import tabulate

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.utils.helpers import enable_monitor_mode, disable_monitor_mode, validate_mac_address
from src.utils.logger import Logger

class NetworkScanner:
    """Classe para escaneamento de redes WiFi."""
    
    def __init__(self, interface=None, timeout=30, channel_hopping=True, logger=None):
        """
        Inicializa o scanner de redes.
        
        Args:
            interface (str): Interface de rede WiFi a ser utilizada.
            timeout (int): Tempo máximo de escaneamento em segundos.
            channel_hopping (bool): Se True, alterna entre canais durante o escaneamento.
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.interface = interface
        self.timeout = timeout
        self.channel_hopping = channel_hopping
        self.logger = logger if logger else Logger(verbose=True)
        self.running = False
        self.networks = {}  # Dicionário para armazenar redes encontradas
        self.original_interface_name = interface
        self.clients = {}  # Mapeia BSSIDs para lista de clientes
        self.hidden_ssids = []  # Lista de BSSIDs com SSIDs ocultos
        
    def _channel_hopper(self):
        """
        Alterna entre os canais de WiFi durante o escaneamento.
        Esta função é executada em uma thread separada.
        """
        # Canais WiFi padrão: 1 a 14
        channels = range(1, 15)
        
        self.logger.debug("Iniciando channel hopping...")
        
        while self.running:
            for channel in channels:
                if not self.running:
                    break
                
                try:
                    if platform.system() == "Linux":
                        os.system(f"iwconfig {self.interface} channel {channel} > /dev/null 2>&1")
                    elif platform.system() == "Darwin":  # macOS
                        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                        os.system(f"{airport_path} {self.interface} --channel={channel} > /dev/null 2>&1")
                    
                    self.logger.debug(f"Alterado para canal {channel}")
                    time.sleep(0.5)  # Espera meio segundo em cada canal
                except Exception as e:
                    self.logger.error(f"Erro ao alterar canal: {e}")
    
    def _packet_handler(self, packet):
        """
        Processa os pacotes capturados.
        
        Args:
            packet (Packet): Pacote capturado pelo scapy.
        """
        # Verifica se é um pacote Beacon (para encontrar APs)
        if packet.haslayer(Dot11Beacon):
            # Extrai o BSSID (endereço MAC do AP)
            bssid = packet[Dot11].addr2
            
            # Se já analisamos este AP, podemos ignorar este pacote
            if bssid in self.networks:
                return
            
            # Extrai capacidades/informações do AP
            stats = packet[Dot11Beacon].network_stats()
            
            # Verifica se o SSID está oculto
            if stats.get("ssid") == "":
                stats["ssid"] = "<Oculto>"
                self.hidden_ssids.append(bssid)
            
            # Armazena as informações do AP
            self.networks[bssid] = {
                "ssid": stats.get("ssid", "<Desconhecido>"),
                "channel": stats.get("channel", 0),
                "encryption": stats.get("crypto", ""),
                "signal": self._get_signal_strength(packet),
                "beacon": packet,
                "clients": []
            }
            
            # Exibe informações sobre a rede encontrada
            self.logger.info(f"Nova rede encontrada: {self.networks[bssid]['ssid']} ({bssid}) - Canal: {self.networks[bssid]['channel']} - Criptografia: {self.networks[bssid]['encryption']}")
        
        # Verifica pacotes de dados para encontrar clientes conectados
        elif packet.haslayer(Dot11) and packet.type == 2:  # Pacotes de dados
            # Extrai endereços de origem e destino
            src = packet[Dot11].addr2
            dst = packet[Dot11].addr1
            
            # Se o pacote é de uma estação para um AP que conhecemos
            if dst in self.networks and src not in self.networks[dst]["clients"]:
                self.networks[dst]["clients"].append(src)
                self.logger.debug(f"Cliente {src} conectado à rede {self.networks[dst]['ssid']} ({dst})")
                
            # Se o pacote é de um AP que conhecemos para uma estação
            elif src in self.networks and dst not in self.networks[src]["clients"] and dst != "ff:ff:ff:ff:ff:ff":
                self.networks[src]["clients"].append(dst)
                self.logger.debug(f"Cliente {dst} conectado à rede {self.networks[src]['ssid']} ({src})")
    
    def _get_signal_strength(self, packet):
        """
        Obtém a força do sinal de um pacote.
        
        Args:
            packet (Packet): Pacote capturado pelo scapy.
            
        Returns:
            int: Força do sinal em dBm ou None se não disponível.
        """
        if packet.haslayer(RadioTap):
            return packet[RadioTap].dBm_AntSignal
        return None
    
    def start_scan(self):
        """
        Inicia o escaneamento de redes WiFi.
        
        Returns:
            dict: Dicionário com as redes encontradas.
        """
        if not self.interface:
            self.logger.error("Interface de rede não especificada.")
            return {}
        
        # Habilita o modo monitor
        self.logger.info(f"Habilitando modo monitor na interface {self.interface}...")
        success, monitor_interface = enable_monitor_mode(self.interface)
        
        if not success:
            self.logger.error(f"Falha ao habilitar modo monitor: {monitor_interface}")
            return {}
        
        self.interface = monitor_interface
        self.logger.success(f"Modo monitor habilitado na interface {self.interface}")
        
        try:
            # Inicia a thread de channel hopping
            self.running = True
            if self.channel_hopping:
                hopper_thread = threading.Thread(target=self._channel_hopper)
                hopper_thread.daemon = True
                hopper_thread.start()
            
            # Inicia o escaneamento
            self.logger.info(f"Iniciando escaneamento por {self.timeout} segundos...")
            sniff(iface=self.interface, prn=self._packet_handler, timeout=self.timeout, store=False)
            
            # Finaliza o escaneamento
            self.running = False
            if self.channel_hopping:
                hopper_thread.join(2)  # Aguarda a thread finalizar (com timeout)
            
            # Exibe resultados
            self.print_results()
            
            return self.networks
            
        except KeyboardInterrupt:
            self.logger.info("Escaneamento interrompido pelo usuário.")
        except Exception as e:
            self.logger.error(f"Erro durante o escaneamento: {e}")
        finally:
            self.running = False
            
            # Restaura o modo gerenciado
            self.logger.info("Desabilitando modo monitor...")
            disable_monitor_mode(self.interface)
            self.interface = self.original_interface_name
            
            return self.networks
    
    def print_results(self):
        """Exibe os resultados do escaneamento no formato de tabela."""
        if not self.networks:
            self.logger.warning("Nenhuma rede encontrada.")
            return
        
        # Prepara dados para a tabela
        table_data = []
        for bssid, info in self.networks.items():
            # Determina se a rede tem o SSID escondido
            ssid = info["ssid"]
            if bssid in self.hidden_ssids:
                ssid = "<Oculto>"
            
            # Formata a força do sinal
            signal = info["signal"] if info["signal"] is not None else "N/A"
            if signal != "N/A":
                signal = f"{signal} dBm"
            
            # Conta o número de clientes
            client_count = len(info["clients"])
            
            # Adiciona linha à tabela
            table_data.append([
                bssid, 
                ssid, 
                info["channel"],
                info["encryption"],
                signal,
                client_count
            ])
        
        # Ordena por força de sinal (do mais forte para o mais fraco)
        table_data.sort(key=lambda x: x[4] if x[4] != "N/A" else -100, reverse=True)
        
        # Imprime a tabela
        headers = ["BSSID", "SSID", "Canal", "Criptografia", "Sinal", "Clientes"]
        print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Estatísticas finais
        self.logger.info(f"Total de redes encontradas: {len(self.networks)}")
        self.logger.info(f"Redes com SSID oculto: {len(self.hidden_ssids)}")
        
        # Informações detalhadas sobre clientes conectados
        client_info = False
        for bssid, info in self.networks.items():
            if info["clients"]:
                if not client_info:
                    print("\nClientes conectados:")
                    client_info = True
                
                print(f"\nRede: {info['ssid']} ({bssid})")
                for client in info["clients"]:
                    print(f"  • Cliente: {client}")
                    
    def get_network_details(self, target_bssid):
        """
        Obtém detalhes específicos de uma rede.
        
        Args:
            target_bssid (str): BSSID da rede alvo.
            
        Returns:
            dict: Detalhes da rede ou None se não encontrada.
        """
        if not validate_mac_address(target_bssid):
            self.logger.error(f"BSSID inválido: {target_bssid}")
            return None
            
        if target_bssid in self.networks:
            return self.networks[target_bssid]
        else:
            self.logger.error(f"Rede com BSSID {target_bssid} não encontrada.")
            return None 