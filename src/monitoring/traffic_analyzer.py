#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para análise de tráfego de rede.
Permite monitorar pacotes e detectar atividades suspeitas.
"""

import os
import sys
import time
import threading
import platform
import subprocess
import re
import collections
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set, Deque

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Elt, Dot11Auth, Dot11Deauth

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
try:
    from src.core.logger import Logger
    from src.utils.helpers import enable_monitor_mode, disable_monitor_mode
except ImportError:
    # Caso esteja sendo executado diretamente
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from core.logger import Logger
    from utils.helpers import enable_monitor_mode, disable_monitor_mode

class TrafficAnalyzer:
    """Classe para análise de tráfego de rede."""
    
    def __init__(self, interface=None, channel=1, monitor_mode=True, logger=None):
        """
        Inicializa o analisador de tráfego.
        
        Args:
            interface (str): Interface de rede a ser utilizada.
            channel (int): Canal WiFi para monitorar.
            monitor_mode (bool): Se True, coloca a interface em modo monitor.
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.interface = interface
        self.channel = channel
        self.monitor_mode = monitor_mode
        self.logger = logger if logger else Logger(verbose=True)
        
        # Estado de execução
        self.running = False
        self.original_interface = interface
        self.monitor_interface = None
        
        # Threads
        self.capture_thread = None
        self.channel_hopping_thread = None
        
        # Estatísticas e dados coletados
        self.packet_count = 0
        self.start_time = 0
        self.networks = {}
        self.clients = {}
        self.deauth_attacks = {}
        self.packets_per_second = 0
        self.last_packets = collections.deque(maxlen=10)  # Para calcular média de pacotes por segundo
        
        # Detecta o sistema operacional
        self.os_type = platform.system().lower()
        
        # Verifica compatibilidade com Windows
        if self.os_type == "windows":
            self.logger.warning("Windows tem suporte limitado para análise de tráfego WiFi.")
            if self.monitor_mode:
                self.logger.warning("Modo monitor pode não funcionar corretamente no Windows.")
                self.logger.info("Realizando captura em modo normal (sem monitor mode).")
                self.monitor_mode = False
    
    def _setup_monitor_mode(self):
        """
        Configura a interface para o modo monitor.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if not self.monitor_mode:
            self.logger.info("Modo monitor não solicitado. Usando interface em modo normal.")
            self.monitor_interface = self.interface
            return True
            
        if self.os_type == "windows":
            self.logger.warning("O modo monitor não é facilmente habilitado no Windows.")
            self.logger.info("Para análise profunda no Windows, considere usar adapatadores WiFi externos compatíveis.")
            self.monitor_interface = self.interface
            return True
        
        try:
            self.logger.info(f"Configurando interface {self.interface} para modo monitor...")
            
            # Ativa o modo monitor
            success = enable_monitor_mode(self.interface)
            
            if success:
                # Em alguns sistemas, o nome da interface pode mudar ao ativar o modo monitor
                # Tenta determinar o novo nome da interface
                if self.os_type == "linux":
                    # Aguarda um momento para a interface ser configurada
                    time.sleep(2)
                    
                    # Verifica se a interface original ainda existe
                    result = subprocess.run("iwconfig", shell=True, capture_output=True, text=True)
                    output = result.stdout
                    
                    # Procura por interfaces em modo monitor
                    monitor_interfaces = re.findall(r"(\w+).*Mode:Monitor", output)
                    
                    if monitor_interfaces:
                        # Verifica se a interface original está em modo monitor
                        if self.interface in monitor_interfaces:
                            self.monitor_interface = self.interface
                        # Ou se existe uma interface com nome similar (ex: wlan0mon)
                        elif any(self.interface in iface for iface in monitor_interfaces):
                            for iface in monitor_interfaces:
                                if self.interface in iface:
                                    self.monitor_interface = iface
                                    break
                        # Caso contrário, usa a primeira interface em modo monitor
                        else:
                            self.monitor_interface = monitor_interfaces[0]
                    else:
                        # Se não encontrou nenhuma interface em modo monitor, usa a original
                        self.monitor_interface = self.interface
                else:
                    # Em outros sistemas, assume que o nome da interface não muda
                    self.monitor_interface = self.interface
                
                self.logger.success(f"Modo monitor ativado na interface {self.monitor_interface}")
                return True
            else:
                self.logger.error("Falha ao ativar o modo monitor. Tentando capturar em modo normal.")
                self.monitor_interface = self.interface
                self.monitor_mode = False
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao configurar modo monitor: {e}")
            self.monitor_interface = self.interface
            self.monitor_mode = False
            return False
    
    def _set_channel(self, channel=None):
        """
        Define o canal da interface WiFi.
        
        Args:
            channel (int): Canal a ser definido. Se None, usa o canal definido na inicialização.
            
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if channel is None:
            channel = self.channel
            
        if self.os_type == "windows":
            self.logger.debug(f"Configuração de canal não suportada diretamente no Windows.")
            return False
            
        try:
            self.logger.debug(f"Configurando interface {self.monitor_interface} para canal {channel}...")
            
            # Usa o comando iwconfig para definir o canal
            if self.os_type == "linux":
                result = subprocess.run(
                    f"iwconfig {self.monitor_interface} channel {channel}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                if result.returncode == 0:
                    self.logger.debug(f"Canal alterado para {channel}")
                    return True
                else:
                    error_msg = result.stderr.decode('utf-8', errors='ignore')
                    self.logger.debug(f"Erro ao alterar canal: {error_msg}")
                    return False
            elif self.os_type == "darwin":  # macOS
                # No macOS, o comando é diferente
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                result = subprocess.run(
                    f"{airport_path} --channel={channel}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                if result.returncode == 0:
                    self.logger.debug(f"Canal alterado para {channel}")
                    return True
                else:
                    error_msg = result.stderr.decode('utf-8', errors='ignore')
                    self.logger.debug(f"Erro ao alterar canal: {error_msg}")
                    return False
            
            return False
                
        except Exception as e:
            self.logger.debug(f"Erro ao definir canal: {e}")
            return False
    
    def _channel_hopper(self):
        """Thread para alternar entre canais WiFi."""
        if self.os_type == "windows":
            self.logger.debug("Channel hopping não suportado diretamente no Windows.")
            return
            
        channels = [1, 6, 11]  # Canais mais comuns
        extended_channels = list(range(1, 14))  # Para uma varredura mais completa
        
        try:
            while self.running:
                for channel in extended_channels:
                    if not self.running:
                        break
                        
                    success = self._set_channel(channel)
                    if success:
                        self.channel = channel
                    
                    # Permanece em cada canal por alguns segundos
                    time.sleep(5)
        except Exception as e:
            self.logger.error(f"Erro na thread de channel hopping: {e}")
    
    def _packet_processor(self, packet):
        """
        Processa pacotes capturados.
        
        Args:
            packet: Pacote Scapy capturado.
        """
        try:
            self.packet_count += 1
            
            # Atualiza estatísticas de pacotes por segundo
            current_time = time.time()
            self.last_packets.append(current_time)
            
            if len(self.last_packets) >= 2:
                time_diff = self.last_packets[-1] - self.last_packets[0]
                if time_diff > 0:
                    self.packets_per_second = len(self.last_packets) / time_diff
            
            # Processamento específico para pacotes 802.11 (WiFi)
            if packet.haslayer(Dot11):
                self._process_dot11_packet(packet)
                
        except Exception as e:
            self.logger.debug(f"Erro ao processar pacote: {e}")
    
    def _process_dot11_packet(self, packet):
        """
        Processa pacotes 802.11 (WiFi).
        
        Args:
            packet: Pacote Scapy Dot11.
        """
        try:
            # Extrai informações básicas do pacote
            if not hasattr(packet, 'addr2') or not packet.addr2:
                return
                
            mac_src = packet.addr2.lower()
            
            # Detecta Beacons (anúncios de redes)
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self._process_beacon(packet)
                
            # Detecta Probe Requests (dispositivos procurando redes)
            elif packet.haslayer(Dot11ProbeReq):
                self._process_probe_request(packet)
                
            # Detecta pacotes de autenticação
            elif packet.haslayer(Dot11Auth):
                self._process_auth(packet)
                
            # Detecta pacotes de desautenticação (possíveis ataques)
            elif packet.haslayer(Dot11Deauth):
                self._process_deauth(packet)
                
        except Exception as e:
            self.logger.debug(f"Erro ao processar pacote Dot11: {e}")
    
    def _process_beacon(self, packet):
        """
        Processa beacons e probe responses para identificar redes.
        
        Args:
            packet: Pacote Scapy Dot11Beacon ou Dot11ProbeResp.
        """
        try:
            # Extrai informações da rede
            if not hasattr(packet, 'addr2') or not packet.addr2:
                return
                
            bssid = packet.addr2.lower()
            
            # Extrai o SSID
            ssid = None
            encryption = set()
            channel = None
            
            # Identifica elementos do pacote
            if packet.haslayer(Dot11Elt):
                # Percorre elementos para encontrar SSID e outros dados
                current = packet[Dot11Elt]
                while current:
                    # ID 0 é o SSID
                    if current.ID == 0:
                        ssid = current.info.decode('utf-8', errors='ignore')
                    # ID 3 é o canal
                    elif current.ID == 3 and len(current.info) > 0:
                        channel = ord(current.info)
                    
                    current = current.payload if hasattr(current, 'payload') else None
            
            # Detecta tipo de criptografia
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                              "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            
            if 'privacy' in cap:
                encryption.add('WEP/WPA/WPA2')
            if 'WPA2' in cap:
                encryption.add('WPA2')
            if 'WPA' in cap:
                encryption.add('WPA')
            
            # Se não detectou nenhuma criptografia, é uma rede aberta
            if not encryption:
                encryption.add('OPEN')
            
            # Calcula a força do sinal (RSSI)
            signal_strength = None
            if hasattr(packet, 'dBm_AntSignal'):
                signal_strength = packet.dBm_AntSignal
            
            # Atualiza ou adiciona a rede na lista
            if bssid not in self.networks:
                self.networks[bssid] = {
                    'ssid': ssid if ssid else '<hidden>',
                    'bssid': bssid,
                    'channel': channel,
                    'encryption': list(encryption),
                    'signal': signal_strength,
                    'clients': set(),
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'beacons': 1
                }
                
                # Registra apenas quando encontra uma nova rede
                if ssid:
                    self.logger.info(f"Nova rede encontrada: {ssid} ({bssid}) - Canal {channel} - {', '.join(encryption)}")
                else:
                    self.logger.info(f"Nova rede oculta encontrada: {bssid} - Canal {channel} - {', '.join(encryption)}")
            else:
                # Atualiza informações da rede
                network = self.networks[bssid]
                network['last_seen'] = datetime.now()
                network['beacons'] += 1
                
                # Atualiza SSID se for revelado
                if ssid and network['ssid'] == '<hidden>':
                    network['ssid'] = ssid
                    self.logger.info(f"SSID revelado para rede {bssid}: {ssid}")
                    
                # Atualiza canal se ainda não foi detectado
                if channel and not network['channel']:
                    network['channel'] = channel
                    
                # Atualiza força do sinal
                if signal_strength:
                    network['signal'] = signal_strength
                
                # Adiciona tipos de criptografia detectados
                if encryption:
                    for enc in encryption:
                        if enc not in network['encryption']:
                            network['encryption'].append(enc)
                
        except Exception as e:
            self.logger.debug(f"Erro ao processar beacon: {e}")
    
    def _process_probe_request(self, packet):
        """
        Processa probe requests para identificar dispositivos.
        
        Args:
            packet: Pacote Scapy Dot11ProbeReq.
        """
        try:
            # Extrai informações do dispositivo
            if not hasattr(packet, 'addr2') or not packet.addr2:
                return
                
            client_mac = packet.addr2.lower()
            
            # Extrai o SSID que o dispositivo está procurando
            ssid = None
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            # Calcula a força do sinal (RSSI)
            signal_strength = None
            if hasattr(packet, 'dBm_AntSignal'):
                signal_strength = packet.dBm_AntSignal
            
            # Atualiza ou adiciona o cliente na lista
            if client_mac not in self.clients:
                self.clients[client_mac] = {
                    'mac': client_mac,
                    'probed_ssids': set([ssid]) if ssid else set(),
                    'associated_bssid': None,
                    'signal': signal_strength,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'packets': 1
                }
                
                # Registra apenas quando encontra um novo dispositivo
                self.logger.debug(f"Novo dispositivo encontrado: {client_mac}" + 
                            (f" procurando por '{ssid}'" if ssid else ""))
            else:
                # Atualiza informações do cliente
                client = self.clients[client_mac]
                client['last_seen'] = datetime.now()
                client['packets'] += 1
                
                # Adiciona SSID à lista se ainda não estiver presente
                if ssid and ssid not in client['probed_ssids']:
                    client['probed_ssids'].add(ssid)
                    
                # Atualiza força do sinal
                if signal_strength:
                    client['signal'] = signal_strength
                
        except Exception as e:
            self.logger.debug(f"Erro ao processar probe request: {e}")
    
    def _process_auth(self, packet):
        """
        Processa pacotes de autenticação.
        
        Args:
            packet: Pacote Scapy Dot11Auth.
        """
        try:
            # Extrai informações
            if not hasattr(packet, 'addr1') or not packet.addr1 or not hasattr(packet, 'addr2') or not packet.addr2:
                return
                
            client_mac = packet.addr1.lower()
            bssid = packet.addr2.lower()
            
            # Se o cliente já está na lista, atualiza sua rede associada
            if client_mac in self.clients:
                client = self.clients[client_mac]
                client['last_seen'] = datetime.now()
                client['packets'] += 1
                
                # Se estiver se autenticando a uma rede, registra a associação
                client['associated_bssid'] = bssid
                
                # Adiciona o cliente à lista de clientes da rede
                if bssid in self.networks:
                    self.networks[bssid]['clients'].add(client_mac)
                    
                    # Registra a associação
                    self.logger.info(f"Dispositivo {client_mac} autenticando na rede {self.networks[bssid]['ssid']} ({bssid})")
                
        except Exception as e:
            self.logger.debug(f"Erro ao processar autenticação: {e}")
    
    def _process_deauth(self, packet):
        """
        Processa pacotes de desautenticação para detectar ataques.
        
        Args:
            packet: Pacote Scapy Dot11Deauth.
        """
        try:
            # Extrai informações
            if not hasattr(packet, 'addr1') or not packet.addr1 or not hasattr(packet, 'addr2') or not packet.addr2:
                return
                
            # addr1 é o destinatário, addr2 é o remetente
            dst = packet.addr1.lower()
            src = packet.addr2.lower()
            
            # Cria uma chave única para o par de endereços
            deauth_key = f"{src}-{dst}"
            
            # Atualiza ou adiciona o evento de desautenticação na lista
            if deauth_key not in self.deauth_attacks:
                self.deauth_attacks[deauth_key] = {
                    'src': src,
                    'dst': dst,
                    'count': 1,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                }
                
                # Procura informações sobre a rede e o cliente
                network_name = None
                client_name = None
                
                for bssid, network in self.networks.items():
                    if bssid == src:
                        network_name = network['ssid']
                        break
                
                # Registra apenas o primeiro pacote de desautenticação
                if dst == "ff:ff:ff:ff:ff:ff":
                    # Desautenticação broadcast (possivelmente um ataque)
                    self.logger.warning(f"Possível ataque de desautenticação broadcast detectado de {src}" +
                                  (f" ({network_name})" if network_name else ""))
                else:
                    # Desautenticação direcionada
                    self.logger.debug(f"Pacote de desautenticação: {src} -> {dst}")
            else:
                # Atualiza a contagem e timestamp
                deauth = self.deauth_attacks[deauth_key]
                deauth['count'] += 1
                deauth['last_seen'] = datetime.now()
                
                # Registra possíveis ataques quando a contagem é alta
                if deauth['count'] == 10:
                    self.logger.warning(f"Possível ataque de desautenticação em andamento: {src} -> {dst} ({deauth['count']} pacotes)")
                elif deauth['count'] == 100:
                    self.logger.warning(f"Ataque de desautenticação confirmado: {src} -> {dst} ({deauth['count']} pacotes)")
                
        except Exception as e:
            self.logger.debug(f"Erro ao processar desautenticação: {e}")
    
    def _restore_interface(self):
        """Restaura a interface para o modo gerenciado."""
        if not self.monitor_mode:
            return
            
        if self.os_type == "windows":
            self.logger.debug("Restauração da interface não é necessária no Windows.")
            return
            
        try:
            self.logger.info(f"Restaurando interface {self.monitor_interface} para modo gerenciado...")
            
            # Desativa o modo monitor
            if self.monitor_interface and self.monitor_interface != self.original_interface:
                success = disable_monitor_mode(self.monitor_interface)
                if not success:
                    disable_monitor_mode(self.original_interface)
            else:
                disable_monitor_mode(self.original_interface)
                
            self.logger.success("Interface restaurada com sucesso.")
            
        except Exception as e:
            self.logger.error(f"Erro ao restaurar interface: {e}")
    
    def start_capture(self, channel_hopping=False):
        """
        Inicia a captura de pacotes.
        
        Args:
            channel_hopping (bool): Se True, alterna entre os canais automaticamente.
            
        Returns:
            bool: True se a captura foi iniciada com sucesso, False caso contrário.
        """
        if self.running:
            self.logger.warning("A captura já está em execução.")
            return False
            
        try:
            # Configura a interface para o modo monitor se necessário
            monitor_setup = self._setup_monitor_mode()
            
            # Define o canal se não estiver usando channel hopping
            if not channel_hopping and monitor_setup and self.channel:
                self._set_channel(self.channel)
            
            # Inicia a captura
            self.running = True
            self.start_time = time.time()
            
            # Inicia a thread de captura
            self.logger.info(f"Iniciando captura de pacotes na interface {self.monitor_interface}...")
            
            self.capture_thread = threading.Thread(
                target=self._capture_packets
            )
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Inicia a thread de channel hopping se solicitado
            if channel_hopping and self.monitor_mode and self.os_type != "windows":
                self.logger.info("Iniciando channel hopping...")
                self.channel_hopping_thread = threading.Thread(
                    target=self._channel_hopper
                )
                self.channel_hopping_thread.daemon = True
                self.channel_hopping_thread.start()
            
            self.logger.success("Captura iniciada com sucesso.")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar captura: {e}")
            self.running = False
            self._restore_interface()
            return False
    
    def _capture_packets(self):
        """Thread principal de captura de pacotes."""
        try:
            self.logger.debug(f"Iniciando sniffing na interface {self.monitor_interface}...")
            
            # Configura filtros de captura de acordo com o sistema operacional
            if self.os_type == "windows":
                # No Windows, usar filtros mais básicos
                sniff(
                    iface=self.monitor_interface,
                    prn=self._packet_processor,
                    store=False
                )
            else:
                # No Linux, podemos usar filtros mais avançados
                if self.monitor_mode:
                    # Modo monitor
                    sniff(
                        iface=self.monitor_interface,
                        prn=self._packet_processor,
                        store=False
                    )
                else:
                    # Modo normal
                    sniff(
                        iface=self.monitor_interface,
                        prn=self._packet_processor,
                        filter="type mgt subtype beacon or type mgt subtype probe-req or type mgt subtype probe-resp or type mgt subtype deauth",
                        store=False
                    )
                
        except Exception as e:
            self.logger.error(f"Erro na thread de captura: {e}")
            self.running = False
    
    def stop_capture(self):
        """
        Para a captura de pacotes.
        
        Returns:
            bool: True se a captura foi parada com sucesso, False caso contrário.
        """
        if not self.running:
            self.logger.warning("A captura não está em execução.")
            return False
            
        try:
            self.logger.info("Parando captura de pacotes...")
            self.running = False
            
            # Aguarda as threads terminarem (com timeout)
            if self.capture_thread and self.capture_thread.is_alive():
                # Não podemos fazer join na thread de captura, pois o sniff não pode ser interrompido facilmente
                self.logger.info("Aguardando a thread de captura finalizar...")
                
            if self.channel_hopping_thread and self.channel_hopping_thread.is_alive():
                self.channel_hopping_thread.join(timeout=2)
            
            # Restaura a interface
            self._restore_interface()
            
            # Calcula o tempo total de captura
            total_time = time.time() - self.start_time
            
            # Exibe resumo
            self.logger.success(f"Captura finalizada. {self.packet_count} pacotes capturados em {total_time:.2f} segundos.")
            self.logger.info(f"Redes encontradas: {len(self.networks)}, Dispositivos: {len(self.clients)}")
            
            if self.deauth_attacks:
                self.logger.warning(f"Possíveis ataques de desautenticação detectados: {len(self.deauth_attacks)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao parar captura: {e}")
            return False
    
    def get_networks(self):
        """
        Obtém a lista de redes encontradas.
        
        Returns:
            list: Lista de redes encontradas.
        """
        networks = []
        for bssid, data in self.networks.items():
            # Converte o conjunto de clientes para lista
            data_copy = dict(data)
            data_copy['clients'] = list(data['clients'])
            # Adiciona à lista, criando uma cópia para não modificar o original
            networks.append(data_copy)
        return networks
    
    def get_clients(self):
        """
        Obtém a lista de clientes encontrados.
        
        Returns:
            list: Lista de clientes encontrados.
        """
        clients = []
        for mac, data in self.clients.items():
            # Converte o conjunto de SSIDs para lista
            data_copy = dict(data)
            data_copy['probed_ssids'] = list(data['probed_ssids'])
            # Adiciona à lista
            clients.append(data_copy)
        return clients
    
    def get_deauth_attacks(self):
        """
        Obtém a lista de ataques de desautenticação detectados.
        
        Returns:
            list: Lista de ataques de desautenticação.
        """
        return list(self.deauth_attacks.values())
    
    def get_stats(self):
        """
        Obtém estatísticas da captura.
        
        Returns:
            dict: Estatísticas da captura.
        """
        total_time = time.time() - self.start_time if self.running else 0
        return {
            'running': self.running,
            'packet_count': self.packet_count,
            'time': total_time,
            'packets_per_second': self.packets_per_second,
            'networks_count': len(self.networks),
            'clients_count': len(self.clients),
            'deauth_attacks_count': len(self.deauth_attacks),
            'current_channel': self.channel
        } 