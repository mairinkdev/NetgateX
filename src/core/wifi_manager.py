#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para gerenciamento de interfaces WiFi.
"""

import os
import sys
import time
import platform
import subprocess
import pywifi
from pywifi import const
import netifaces
import re

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
try:
    from src.utils.logger import Logger
    from src.utils.helpers import enable_monitor_mode, disable_monitor_mode, get_wifi_interfaces
except ImportError:
    # Caso esteja sendo executado diretamente
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from utils.logger import Logger
    from utils.helpers import enable_monitor_mode, disable_monitor_mode, get_wifi_interfaces

class WiFiManager:
    """Classe para gerenciar interfaces WiFi."""
    
    def __init__(self, logger=None):
        """
        Inicializa o gerenciador WiFi.
        
        Args:
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.logger = logger if logger else Logger(verbose=False)
        self.wifi = pywifi.PyWiFi()
        self.interfaces = {}  # Nome da interface -> objeto da interface
        self.monitor_interfaces = {}  # Nome da interface -> estado (True = monitor ativo)
        self.os_type = platform.system().lower()
        
        # Detecta interfaces disponíveis
        self._initialize_interfaces()
    
    def _initialize_interfaces(self):
        """Inicializa as interfaces WiFi disponíveis."""
        try:
            for iface in self.wifi.interfaces():
                self.interfaces[iface.name()] = iface
                self.monitor_interfaces[iface.name()] = False
                self.logger.debug(f"Interface WiFi detectada: {iface.name()}")
        except Exception as e:
            self.logger.error(f"Erro ao detectar interfaces WiFi: {e}")
            
            # Método alternativo para Windows se PyWiFi falhar
            if self.os_type == 'windows':
                try:
                    # Usar netsh para listar adaptadores no Windows
                    output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                    interface_name = None
                    for line in output.split('\n'):
                        if "Nome" in line or "Name" in line:
                            interface_name = line.split(':')[1].strip()
                            self.interfaces[interface_name] = None  # Não temos o objeto PyWiFi, mas podemos registrar o nome
                            self.monitor_interfaces[interface_name] = False
                            self.logger.debug(f"Interface WiFi detectada via netsh: {interface_name}")
                except Exception as e2:
                    self.logger.error(f"Erro ao detectar interfaces WiFi via netsh: {e2}")
    
    def refresh_interfaces(self):
        """Atualiza a lista de interfaces WiFi disponíveis."""
        self.interfaces.clear()
        self.monitor_interfaces.clear()
        self._initialize_interfaces()
        return self.get_interfaces()
    
    def get_interfaces(self):
        """
        Obtém a lista de interfaces WiFi disponíveis.
        
        Returns:
            list: Lista de nomes de interfaces WiFi.
        """
        if not self.interfaces and self.os_type == 'windows':
            # Método alternativo para Windows
            try:
                output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                interface_name = None
                for line in output.split('\n'):
                    if "Nome" in line or "Name" in line:
                        interface_name = line.split(':')[1].strip()
                        self.interfaces[interface_name] = None
                        self.monitor_interfaces[interface_name] = False
            except Exception as e:
                self.logger.error(f"Erro ao listar interfaces WiFi no Windows: {e}")
                
        return list(self.interfaces.keys())
    
    def get_interface_status(self, interface_name):
        """
        Obtém o status de uma interface WiFi.
        
        Args:
            interface_name (str): Nome da interface.
            
        Returns:
            dict: Dicionário com informações da interface ou None se não encontrada.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return None
        
        try:
            # Usa PyWiFi se possível
            if self.interfaces[interface_name]:
                iface = self.interfaces[interface_name]
                status_map = {
                    const.IFACE_DISCONNECTED: "Desconectado",
                    const.IFACE_SCANNING: "Escaneando",
                    const.IFACE_INACTIVE: "Inativo",
                    const.IFACE_CONNECTING: "Conectando",
                    const.IFACE_CONNECTED: "Conectado"
                }
                
                status = iface.status()
                
                result = {
                    "name": iface.name(),
                    "status": status_map.get(status, "Desconhecido"),
                    "status_code": status,
                    "is_monitor": self.monitor_interfaces.get(interface_name, False)
                }
            else:
                # Método alternativo para Windows
                result = {
                    "name": interface_name,
                    "status": "Desconhecido",
                    "status_code": -1,
                    "is_monitor": self.monitor_interfaces.get(interface_name, False)
                }
                
                # Tenta obter status no Windows via netsh
                if self.os_type == 'windows':
                    try:
                        output = subprocess.check_output(f"netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                        in_section = False
                        for line in output.split('\n'):
                            if interface_name in line:
                                in_section = True
                            elif in_section and "Estado" in line or "State" in line:
                                status_text = line.split(':')[1].strip()
                                result["status"] = status_text
                                if "conectado" in status_text.lower() or "connected" in status_text.lower():
                                    result["status_code"] = const.IFACE_CONNECTED
                                else:
                                    result["status_code"] = const.IFACE_DISCONNECTED
                    except Exception as e:
                        self.logger.error(f"Erro ao obter status via netsh: {e}")
            
            # Tenta obter endereço MAC e IP
            try:
                if interface_name in netifaces.interfaces():
                    if netifaces.AF_LINK in netifaces.ifaddresses(interface_name):
                        result["mac"] = netifaces.ifaddresses(interface_name)[netifaces.AF_LINK][0]['addr']
                    if netifaces.AF_INET in netifaces.ifaddresses(interface_name):
                        result["ip"] = netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr']
            except Exception as e:
                self.logger.error(f"Erro ao obter MAC/IP via netifaces: {e}")
                
                # Método alternativo para Windows
                if self.os_type == 'windows':
                    try:
                        # Obtém MAC via getmac
                        mac_output = subprocess.check_output(f"getmac /v /fo csv", shell=True).decode('utf-8', errors='ignore')
                        for line in mac_output.split('\n'):
                            if interface_name in line:
                                parts = line.split(',')
                                if len(parts) >= 2:
                                    result["mac"] = parts[1].strip(' "')
                        
                        # Obtém IP via ipconfig
                        ip_output = subprocess.check_output(f"ipconfig /all", shell=True).decode('utf-8', errors='ignore')
                        in_section = False
                        for line in ip_output.split('\n'):
                            if interface_name in line:
                                in_section = True
                            elif in_section and "IPv4" in line:
                                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                                if match:
                                    result["ip"] = match.group(1)
                    except Exception as e:
                        self.logger.error(f"Erro ao obter MAC/IP via comandos Windows: {e}")
            
            return result
        except Exception as e:
            self.logger.error(f"Erro ao obter status da interface {interface_name}: {e}")
            return None
    
    def get_connected_network(self, interface_name):
        """
        Obtém informações sobre a rede WiFi conectada.
        
        Args:
            interface_name (str): Nome da interface.
            
        Returns:
            dict: Informações da rede conectada ou None se não estiver conectado.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return None
        
        try:
            # Verifica se está conectado usando PyWiFi
            iface = self.interfaces[interface_name]
            if iface and iface.status() != const.IFACE_CONNECTED:
                # Método alternativo para Windows
                if self.os_type == 'windows':
                    try:
                        output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                        network_info = {}
                        in_section = False
                        
                        for line in output.split('\n'):
                            if interface_name in line:
                                in_section = True
                            elif in_section:
                                if "SSID" in line and "BSSID" not in line:
                                    network_info["ssid"] = line.split(':')[1].strip()
                                elif "BSSID" in line:
                                    network_info["bssid"] = line.split(':')[1].strip()
                                elif "Signal" in line:
                                    network_info["signal"] = line.split(':')[1].strip()
                                elif "Channel" in line:
                                    network_info["channel"] = line.split(':')[1].strip()
                                elif "Autenticação" in line or "Authentication" in line:
                                    network_info["security"] = line.split(':')[1].strip()
                                    
                        # Se encontrou SSID, considera conectado
                        if "ssid" in network_info:
                            return network_info
                        return None
                    except Exception as e:
                        self.logger.error(f"Erro ao obter rede conectada via netsh: {e}")
                return None
            
            network_info = {}
            
            # No Windows e Linux podemos tentar obter o SSID via comandos
            if self.os_type == "windows":
                try:
                    cmd_output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                    for line in cmd_output.split('\n'):
                        if "SSID" in line and "BSSID" not in line:
                            network_info["ssid"] = line.split(':')[1].strip()
                        elif "BSSID" in line:
                            network_info["bssid"] = line.split(':')[1].strip()
                        elif "Signal" in line:
                            network_info["signal"] = line.split(':')[1].strip()
                        elif "Channel" in line:
                            network_info["channel"] = line.split(':')[1].strip()
                except Exception as e:
                    self.logger.error(f"Erro ao obter rede via netsh: {e}")
            elif self.os_type == "linux":
                try:
                    cmd_output = subprocess.check_output(f"iwconfig {interface_name}", shell=True).decode('utf-8', errors='ignore')
                    for line in cmd_output.split('\n'):
                        if "ESSID:" in line:
                            network_info["ssid"] = line.split('ESSID:')[1].strip().strip('"')
                        elif "Frequency:" in line:
                            network_info["frequency"] = line.split('Frequency:')[1].split(' ')[0].strip()
                            if "Channel" in line:
                                network_info["channel"] = line.split('Channel')[1].split(')')[0].strip()
                        elif "Access Point:" in line:
                            network_info["bssid"] = line.split('Access Point:')[1].strip()
                        elif "Signal level=" in line:
                            network_info["signal"] = line.split('Signal level=')[1].split(' ')[0].strip()
                except Exception as e:
                    self.logger.error(f"Erro ao obter rede via iwconfig: {e}")
            
            return network_info
        except Exception as e:
            self.logger.error(f"Erro ao obter informações da rede conectada: {e}")
            return None
    
    def scan_networks(self, interface_name):
        """
        Escaneia redes WiFi disponíveis.
        
        Args:
            interface_name (str): Nome da interface.
            
        Returns:
            list: Lista de redes encontradas ou None se ocorrer erro.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return None
        
        try:
            # Tenta usar PyWiFi para escanear
            iface = self.interfaces[interface_name]
            
            # Não podemos escanear no modo monitor
            if self.monitor_interfaces.get(interface_name, False):
                self.logger.error(f"Interface {interface_name} está em modo monitor. Desative o modo monitor antes de escanear.")
                return None
            
            self.logger.info(f"Escaneando redes com interface {interface_name}...")
            
            networks = []
            
            # Se temos um objeto PyWiFi, usa ele para escanear
            if iface:
                # Inicia o escaneamento
                iface.scan()
                time.sleep(2)  # Espera o escaneamento completar
                
                # Obtém os resultados
                scan_results = iface.scan_results()
                self.logger.info(f"Encontradas {len(scan_results)} redes.")
                
                # Converte para um formato mais amigável
                for result in scan_results:
                    network = {
                        "ssid": result.ssid,
                        "bssid": result.bssid,
                        "signal": result.signal,
                        "frequency": result.freq,
                        "channel": self._frequency_to_channel(result.freq),
                    }
                    
                    # Determina segurança
                    auth_algs = result.akm
                    cipher = result.cipher
                    security = ""
                    
                    if auth_algs:
                        if const.AKM_TYPE_WPA in auth_algs or const.AKM_TYPE_WPA2 in auth_algs:
                            security = "WPA/WPA2"
                        elif const.AKM_TYPE_WPA2PSK in auth_algs:
                            security = "WPA2-PSK"
                        elif const.AKM_TYPE_WPAPSK in auth_algs:
                            security = "WPA-PSK"
                        else:
                            security = "Desconhecido"
                    else:
                        security = "Aberto"
                    
                    network["security"] = security
                    networks.append(network)
            
            # Método alternativo para Windows se PyWiFi falhar ou não tivermos o objeto
            if not networks and self.os_type == "windows":
                try:
                    cmd_output = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True).decode('utf-8', errors='ignore')
                    current_network = {}
                    
                    for line in cmd_output.split('\n'):
                        line = line.strip()
                        if "SSID" in line and "BSSID" not in line and ":" in line:
                            # Novo SSID encontrado
                            if current_network and "ssid" in current_network:
                                networks.append(current_network)
                            current_network = {"ssid": line.split(':', 1)[1].strip().strip('"')}
                        elif "BSSID" in line and ":" in line:
                            current_network["bssid"] = line.split(':', 1)[1].strip()
                        elif "Signal" in line and ":" in line:
                            signal_str = line.split(':', 1)[1].strip().replace('%', '')
                            try:
                                # Converte porcentagem para dBm aproximado
                                signal_pct = int(signal_str)
                                # Fórmula aproximada: -100dBm = 0%, -50dBm = 100%
                                signal_dbm = -100 + signal_pct / 2
                                current_network["signal"] = int(signal_dbm)
                            except:
                                current_network["signal"] = signal_str
                        elif "Channel" in line and ":" in line:
                            current_network["channel"] = line.split(':', 1)[1].strip()
                        elif ("Authentication" in line or "Autenticação" in line) and ":" in line:
                            current_network["security"] = line.split(':', 1)[1].strip()
                    
                    # Adiciona o último network
                    if current_network and "ssid" in current_network:
                        networks.append(current_network)
                        
                    self.logger.info(f"Encontradas {len(networks)} redes via netsh.")
                except Exception as e:
                    self.logger.error(f"Erro ao escanear redes via netsh: {e}")
            
            return networks
        except Exception as e:
            self.logger.error(f"Erro ao escanear redes: {e}")
            return None
    
    def _frequency_to_channel(self, frequency):
        """
        Converte frequência WiFi para número de canal.
        
        Args:
            frequency (int): Frequência em MHz.
            
        Returns:
            int: Número do canal.
        """
        if frequency >= 2412 and frequency <= 2484:
            if frequency == 2484:  # Canal 14 é um caso especial
                return 14
            return int((frequency - 2412) / 5) + 1
        elif frequency >= 5170 and frequency <= 5825:
            return int((frequency - 5170) / 5) + 34
        else:
            return 0
    
    def enable_monitor_mode(self, interface_name):
        """
        Habilita o modo monitor em uma interface WiFi.
        
        Args:
            interface_name (str): Nome da interface.
            
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return False
        
        try:
            # Já está em modo monitor?
            if self.monitor_interfaces.get(interface_name, False):
                self.logger.warning(f"Interface {interface_name} já está em modo monitor.")
                return True
            
            # Verificação de sistema operacional
            if self.os_type == "windows":
                self.logger.warning("O modo monitor tem suporte limitado no Windows. Usando alternativa.")
                
                # No Windows, não podemos habilitar modo monitor nativamente
                # Mas podemos fingir que estamos no modo monitor para testes
                self.monitor_interfaces[interface_name] = True
                self.logger.warning("ATENÇÃO: No Windows, o modo monitor é simulado e tem funcionalidade limitada.")
                self.logger.info(f"Modo monitor simulado habilitado na interface {interface_name}.")
                return True
            else:
                # Habilita modo monitor usando o helper
                success, monitor_interface = enable_monitor_mode(interface_name)
                
                if success:
                    self.monitor_interfaces[interface_name] = True
                    self.logger.success(f"Modo monitor habilitado na interface {interface_name}.")
                    return True
                else:
                    self.logger.error(f"Falha ao habilitar modo monitor: {monitor_interface}")
                    return False
                
        except Exception as e:
            self.logger.error(f"Erro ao habilitar modo monitor: {e}")
            return False
    
    def disable_monitor_mode(self, interface_name):
        """
        Desabilita o modo monitor em uma interface WiFi.
        
        Args:
            interface_name (str): Nome da interface.
            
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return False
        
        try:
            # Não está em modo monitor?
            if not self.monitor_interfaces.get(interface_name, False):
                self.logger.warning(f"Interface {interface_name} não está em modo monitor.")
                return True
            
            # Verificação de sistema operacional
            if self.os_type == "windows":
                # No Windows, apenas desativa o flag do modo monitor simulado
                self.monitor_interfaces[interface_name] = False
                self.logger.info(f"Modo monitor simulado desabilitado na interface {interface_name}.")
                return True
            else:
                # Desabilita modo monitor usando o helper
                success = disable_monitor_mode(interface_name)
                
                if success:
                    self.monitor_interfaces[interface_name] = False
                    self.logger.success(f"Modo monitor desabilitado na interface {interface_name}.")
                    return True
                else:
                    self.logger.error(f"Falha ao desabilitar modo monitor na interface {interface_name}.")
                    return False
                
        except Exception as e:
            self.logger.error(f"Erro ao desabilitar modo monitor: {e}")
            return False
    
    def connect_to_network(self, interface_name, ssid, password=None, timeout=10):
        """
        Conecta a uma rede WiFi.
        
        Args:
            interface_name (str): Nome da interface.
            ssid (str): SSID da rede alvo.
            password (str): Senha da rede (None para redes abertas).
            timeout (int): Tempo limite para conexão em segundos.
            
        Returns:
            bool: True se conectado com sucesso, False caso contrário.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return False
        
        try:
            # Interface em modo monitor?
            if self.monitor_interfaces.get(interface_name, False):
                self.logger.error(f"Interface {interface_name} está em modo monitor. Desative antes de conectar.")
                return False
            
            # Se temos um objeto PyWiFi, usa ele para conectar
            iface = self.interfaces[interface_name]
            if iface:
                # Desconecta de qualquer rede atual
                iface.disconnect()
                time.sleep(1)
                
                # Cria perfil para a rede
                profile = pywifi.Profile()
                profile.ssid = ssid
                if password:
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm.append(const.AKM_TYPE_WPA2PSK)
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                else:
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm.append(const.AKM_TYPE_NONE)
                    profile.cipher = const.CIPHER_TYPE_NONE
                
                # Remove perfis existentes
                iface.remove_all_network_profiles()
                
                # Adiciona e conecta ao novo perfil
                profile_added = iface.add_network_profile(profile)
                iface.connect(profile_added)
                
                # Aguarda a conexão
                start_time = time.time()
                while time.time() - start_time < timeout:
                    if iface.status() == const.IFACE_CONNECTED:
                        self.logger.success(f"Conectado à rede {ssid}.")
                        return True
                    time.sleep(1)
                
                self.logger.error(f"Falha ao conectar à rede {ssid}. Tempo limite excedido.")
                return False
            
            # Método alternativo para Windows
            elif self.os_type == "windows":
                try:
                    # Cria um perfil XML temporário
                    profile_name = f"NetgateX_{ssid}"
                    profile_path = os.path.join(os.environ.get('TEMP', '.'), f"{profile_name}.xml")
                    
                    # Conteúdo do perfil XML
                    profile_content = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            {"<authEncryption><authentication>open</authentication><encryption>none</encryption></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>" + password + "</keyMaterial></sharedKey>" if password else "<authEncryption><authentication>open</authentication><encryption>none</encryption></authEncryption>"}
        </security>
    </MSM>
</WLANProfile>"""
                    
                    # Escreve o perfil em um arquivo temporário
                    with open(profile_path, 'w') as f:
                        f.write(profile_content)
                    
                    # Adiciona o perfil
                    subprocess.check_output(f'netsh wlan add profile filename="{profile_path}"', shell=True)
                    
                    # Conecta à rede
                    subprocess.check_output(f'netsh wlan connect name="{ssid}"', shell=True)
                    
                    # Espera a conexão
                    self.logger.info(f"Tentando conectar à rede {ssid}...")
                    start_time = time.time()
                    connected = False
                    
                    while time.time() - start_time < timeout:
                        # Verifica se está conectado
                        output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                        if ssid in output and ("conectado" in output.lower() or "connected" in output.lower()):
                            connected = True
                            break
                        time.sleep(1)
                    
                    # Limpa o arquivo temporário
                    try:
                        os.remove(profile_path)
                    except:
                        pass
                    
                    if connected:
                        self.logger.success(f"Conectado à rede {ssid}.")
                        return True
                    else:
                        self.logger.error(f"Falha ao conectar à rede {ssid}. Tempo limite excedido.")
                        return False
                except Exception as e:
                    self.logger.error(f"Erro ao conectar à rede {ssid} via netsh: {e}")
                    return False
            
            self.logger.error(f"Não foi possível conectar à rede {ssid}. Método não disponível.")
            return False
                
        except Exception as e:
            self.logger.error(f"Erro ao conectar à rede {ssid}: {e}")
            return False
    
    def disconnect(self, interface_name):
        """
        Desconecta de uma rede WiFi.
        
        Args:
            interface_name (str): Nome da interface.
            
        Returns:
            bool: True se desconectado com sucesso, False caso contrário.
        """
        if interface_name not in self.interfaces:
            self.logger.error(f"Interface {interface_name} não encontrada.")
            return False
        
        try:
            # Se temos um objeto PyWiFi, usa ele para desconectar
            iface = self.interfaces[interface_name]
            if iface:
                iface.disconnect()
                self.logger.info(f"Desconectado da rede atual na interface {interface_name}.")
                return True
            
            # Método alternativo para Windows
            elif self.os_type == "windows":
                try:
                    subprocess.check_output(f'netsh wlan disconnect', shell=True)
                    self.logger.info(f"Desconectado da rede atual via netsh.")
                    return True
                except Exception as e:
                    self.logger.error(f"Erro ao desconectar via netsh: {e}")
                    return False
            
            return False
        except Exception as e:
            self.logger.error(f"Erro ao desconectar da rede: {e}")
            return False 