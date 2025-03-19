#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Funções auxiliares para a ferramenta NetgateX.
"""

import os
import sys
import platform
import subprocess
import importlib
import re
import netifaces
import psutil
import socket
import time
import ctypes
import random
from typing import List, Dict, Tuple, Union, Optional

def is_root():
    """
    Verifica se o programa está sendo executado com privilégios de administrador/root.
    
    Returns:
        bool: True se estiver rodando como admin/root, False caso contrário.
    """
    if platform.system() == "Windows":
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0

def check_dependencies():
    """
    Verifica se todas as dependências necessárias estão instaladas.
    
    Returns:
        bool: True se todas as dependências estão instaladas, False caso contrário.
    """
    required_modules = [
        'scapy', 'flask', 'rich', 'psutil', 'pywifi', 'netifaces',
        'pyshark', 'requests', 'colorama', 'cryptography', 'pycryptodomex'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            importlib.import_module(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Módulos ausentes: {', '.join(missing_modules)}")
        return False
    
    # Verifica dependências externas
    external_deps = {
        'Linux': ['aircrack-ng', 'iwconfig', 'tcpdump'],
        'Windows': [],  # No Windows, não temos dependências externas diretas
        'Darwin': ['airport', 'tcpdump']
    }
    
    os_name = platform.system()
    if os_name in external_deps:
        for program in external_deps[os_name]:
            if not is_program_installed(program):
                print(f"Programa externo ausente: {program}")
                return False
    
    return True

def is_program_installed(program):
    """
    Verifica se um programa externo está instalado no sistema.
    
    Args:
        program (str): Nome do programa a ser verificado.
        
    Returns:
        bool: True se o programa estiver instalado, False caso contrário.
    """
    if platform.system() == "Windows":
        try:
            subprocess.run(['where', program], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        try:
            subprocess.run(['which', program], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False

def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Obtém uma lista de interfaces de rede disponíveis no sistema.
    
    Returns:
        List[Dict[str, str]]: Lista de dicionários contendo informações sobre as interfaces.
    """
    interfaces = []
    os_type = platform.system().lower()
    
    try:
        if os_type == "windows":
            # No Windows, usa ipconfig
            result = subprocess.run("ipconfig /all", shell=True, capture_output=True, text=True)
            output = result.stdout
            
            # Divide a saída por adaptador
            adapters = re.split(r"(?:\r)?\n(?:\r)?\n", output)
            
            for adapter in adapters:
                if not adapter.strip():
                    continue
                
                # Extrai o nome da interface
                name_match = re.search(r"^(.*?)(?:adapter|adaptador) (.*?):", adapter, re.IGNORECASE | re.MULTILINE)
                if not name_match:
                    continue
                
                adapter_name = name_match.group(2).strip()
                
                # Verifica se é uma interface física
                if "Loopback" in adapter_name or "Pseudo" in adapter_name:
                    continue
                
                # Extrai o endereço MAC
                mac_match = re.search(r"(?:Physical Address|Endereço Físico).*?: (.*?)(?:\r)?\n", adapter, re.IGNORECASE)
                mac = mac_match.group(1).strip().replace("-", ":").lower() if mac_match else None
                
                # Extrai o endereço IPv4
                ip_match = re.search(r"IPv4 Address.*?: (.*?)(?:\(.*?\))?(?:\r)?\n", adapter, re.IGNORECASE)
                if not ip_match:
                    ip_match = re.search(r"Endereço IPv4.*?: (.*?)(?:\(.*?\))?(?:\r)?\n", adapter, re.IGNORECASE)
                ip = ip_match.group(1).strip() if ip_match else None
                
                # Determina se é uma interface WiFi
                is_wifi = "wireless" in adapter.lower() or "wi-fi" in adapter.lower() or "sem fio" in adapter.lower()
                
                # Só adiciona interfaces que têm MAC
                if mac:
                    interfaces.append({
                        "name": adapter_name,
                        "mac": mac,
                        "ip": ip,
                        "is_wifi": is_wifi
                    })
                    
        else:
            # No Linux/Unix, usa netifaces
            for iface in netifaces.interfaces():
                # Pula interfaces que não são físicas
                if iface == 'lo' or iface.startswith('veth') or iface.startswith('br-') or iface.startswith('docker'):
                    continue
                
                addrs = netifaces.ifaddresses(iface)
                
                # Obtém MAC
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr')
                
                # Obtém IP
                ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr')
                
                # Determina se é uma interface WiFi
                is_wifi = False
                try:
                    # No Linux, verifica se a interface está na pasta /sys/class/net/*/wireless
                    if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                        is_wifi = True
                    else:
                        # Também pode verificar com iw
                        result = subprocess.run(f"iw dev {iface} info", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        is_wifi = result.returncode == 0
                except:
                    pass
                
                interfaces.append({
                    "name": iface,
                    "mac": mac,
                    "ip": ip,
                    "is_wifi": is_wifi
                })
    
    except Exception as e:
        print(f"Erro ao obter interfaces de rede: {e}")
    
    return interfaces

def get_wifi_interfaces() -> List[Dict[str, str]]:
    """
    Obtém uma lista de interfaces WiFi disponíveis no sistema.
    
    Returns:
        List[Dict[str, str]]: Lista de dicionários contendo informações sobre as interfaces WiFi.
    """
    all_interfaces = get_network_interfaces()
    wifi_interfaces = [iface for iface in all_interfaces if iface.get("is_wifi", False)]
    
    # Se não encontrou nenhuma interface WiFi usando o método anterior, tenta métodos alternativos
    if not wifi_interfaces:
        os_type = platform.system().lower()
        
        if os_type == "windows":
            # No Windows, usa netsh
            try:
                result = subprocess.run("netsh wlan show interfaces", shell=True, capture_output=True, text=True)
                output = result.stdout
                
                if "There is no wireless interface on the system" not in output and "Não há interface sem fio no sistema" not in output:
                    # Extrai os nomes das interfaces
                    name_matches = re.finditer(r"(?:Name|Nome)\s+:\s+(.*?)(?:\r)?\n", output, re.IGNORECASE)
                    
                    for match in name_matches:
                        adapter_name = match.group(1).strip()
                        
                        # Procura esta interface na lista de todas as interfaces
                        for iface in all_interfaces:
                            if adapter_name.lower() in iface["name"].lower():
                                iface["is_wifi"] = True
                                wifi_interfaces.append(iface)
                                break
                        else:
                            # Se não encontrou, adiciona como uma nova interface
                            wifi_interfaces.append({
                                "name": adapter_name,
                                "mac": None,
                                "ip": None,
                                "is_wifi": True
                            })
            except Exception as e:
                print(f"Erro ao obter interfaces WiFi via netsh: {e}")
                
        elif os_type == "linux":
            # No Linux, tenta outro método
            try:
                result = subprocess.run("iw dev", shell=True, capture_output=True, text=True)
                output = result.stdout
                
                # Extrai nomes de interfaces
                for line in output.splitlines():
                    if "Interface" in line:
                        iface_name = line.split("Interface")[1].strip()
                        for iface in all_interfaces:
                            if iface_name == iface["name"]:
                                iface["is_wifi"] = True
                                wifi_interfaces.append(iface)
                                break
                        else:
                            # Se não encontrou, adiciona como uma nova interface
                            wifi_interfaces.append({
                                "name": iface_name,
                                "mac": None,
                                "ip": None,
                                "is_wifi": True
                            })
            except Exception as e:
                print(f"Erro ao obter interfaces WiFi via iw: {e}")
    
    return wifi_interfaces

def enable_monitor_mode(interface: str) -> bool:
    """
    Coloca uma interface WiFi em modo monitor.
    
    Args:
        interface (str): Nome da interface.
        
    Returns:
        bool: True se bem-sucedido, False caso contrário.
    """
    os_type = platform.system().lower()
    
    if os_type == "windows":
        print("AVISO: O modo monitor no Windows requer adaptadores WiFi específicos e drivers compatíveis.")
        print("       Esta funcionalidade pode não estar disponível em todas as configurações.")
        
        try:
            # No Windows, o modo monitor é limitado e depende do driver
            # Algumas possibilidades incluem o uso de ferramentas como Npcap ou WinPcap
            # Esta é uma implementação simplificada que pode não funcionar em todos os sistemas
            
            # Verifica se o Npcap está instalado
            npcap_check = subprocess.run("where wpcap.dll", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if npcap_check.returncode != 0:
                print("Erro: Npcap/WinPcap não encontrado. Instale-o para usar o modo monitor.")
                return False
            
            # Algumas interfaces podem suportar modo monitor via netsh
            try:
                # Tenta desativar e reativar a interface
                subprocess.run(f"netsh interface set interface name=\"{interface}\" admin=disabled", shell=True, check=True)
                time.sleep(1)
                subprocess.run(f"netsh interface set interface name=\"{interface}\" admin=enabled", shell=True, check=True)
                
                print(f"Interface {interface} reiniciada. Verifique se o modo monitor está disponível.")
                return True
            except Exception as e:
                print(f"Erro ao configurar interface: {e}")
                return False
                
        except Exception as e:
            print(f"Erro ao habilitar modo monitor no Windows: {e}")
            return False
    else:
        # No Linux
        try:
            # Verifica se airmon-ng está disponível
            airmon_check = subprocess.run("which airmon-ng", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if airmon_check.returncode == 0:
                # Método usando airmon-ng
                subprocess.run(f"airmon-ng check kill", shell=True)
                result = subprocess.run(f"airmon-ng start {interface}", shell=True, capture_output=True, text=True)
                
                # Verifica se a interface foi criada com sucesso
                output = result.stdout
                monitor_interface = interface
                
                # Tenta extrair o nome da interface monitor (normalmente wlan0mon ou similar)
                match = re.search(r"(mon\d+|wlan\d+mon)", output)
                if match:
                    monitor_interface = match.group(0)
                else:
                    monitor_interface = f"{interface}mon"
                
                # Verifica se a interface existe
                if monitor_interface in netifaces.interfaces():
                    print(f"Modo monitor habilitado. Interface: {monitor_interface}")
                    return True
                else:
                    print(f"Não foi possível encontrar a interface monitor: {monitor_interface}")
                    
                    # Tenta verificar se a interface original está em modo monitor
                    iwconfig_check = subprocess.run(f"iwconfig {interface}", shell=True, capture_output=True, text=True)
                    if "Mode:Monitor" in iwconfig_check.stdout:
                        print(f"Interface {interface} está em modo monitor.")
                        return True
                        
                    return False
            else:
                # Método alternativo usando iw e ip
                # Desativa a interface
                subprocess.run(f"ip link set {interface} down", shell=True, check=True)
                
                # Define o modo monitor
                try:
                    subprocess.run(f"iw dev {interface} set type monitor", shell=True, check=True)
                except:
                    # Alguns drivers não suportam mudança direta de modo
                    # Tenta um método alternativo
                    subprocess.run(f"iw dev {interface} set monitor control", shell=True)
                
                # Ativa a interface
                subprocess.run(f"ip link set {interface} up", shell=True, check=True)
                
                # Verifica se o modo foi alterado
                iwconfig_check = subprocess.run(f"iwconfig {interface}", shell=True, capture_output=True, text=True)
                if "Mode:Monitor" in iwconfig_check.stdout:
                    print(f"Interface {interface} colocada em modo monitor com sucesso.")
                    return True
                else:
                    print(f"Falha ao colocar {interface} em modo monitor.")
                    return False
                
        except Exception as e:
            print(f"Erro ao habilitar modo monitor: {e}")
            return False

def disable_monitor_mode(interface: str) -> bool:
    """
    Desativa o modo monitor em uma interface WiFi.
    
    Args:
        interface (str): Nome da interface.
        
    Returns:
        bool: True se bem-sucedido, False caso contrário.
    """
    os_type = platform.system().lower()
    
    if os_type == "windows":
        try:
            # No Windows, simplesmente reinicia a interface
            subprocess.run(f"netsh interface set interface name=\"{interface}\" admin=disabled", shell=True, check=True)
            time.sleep(1)
            subprocess.run(f"netsh interface set interface name=\"{interface}\" admin=enabled", shell=True, check=True)
            print(f"Interface {interface} reiniciada.")
            return True
        except Exception as e:
            print(f"Erro ao desativar modo monitor no Windows: {e}")
            return False
    else:
        # No Linux
        try:
            # Verifica se airmon-ng está disponível
            airmon_check = subprocess.run("which airmon-ng", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if airmon_check.returncode == 0 and (interface.endswith("mon") or "mon" in interface):
                # Se a interface termina com "mon", provavelmente foi criada pelo airmon-ng
                original_interface = interface.replace("mon", "")
                subprocess.run(f"airmon-ng stop {interface}", shell=True, check=True)
                
                # Verifica se a interface original está disponível
                if original_interface in netifaces.interfaces():
                    subprocess.run(f"ip link set {original_interface} up", shell=True)
                    print(f"Modo monitor desativado. Interface original: {original_interface}")
                    return True
                else:
                    print(f"Interface original não encontrada: {original_interface}")
                    return False
            else:
                # Método alternativo usando iw e ip
                # Desativa a interface
                subprocess.run(f"ip link set {interface} down", shell=True, check=True)
                
                # Define o modo managed
                subprocess.run(f"iw dev {interface} set type managed", shell=True, check=True)
                
                # Ativa a interface
                subprocess.run(f"ip link set {interface} up", shell=True, check=True)
                
                # Verifica se o modo foi alterado
                iwconfig_check = subprocess.run(f"iwconfig {interface}", shell=True, capture_output=True, text=True)
                if "Mode:Managed" in iwconfig_check.stdout:
                    print(f"Interface {interface} retornada para modo gerenciado com sucesso.")
                    # Reinicia o NetworkManager para restabelecer a conexão
                    try:
                        subprocess.run("systemctl restart NetworkManager", shell=True)
                    except:
                        pass
                    return True
                else:
                    print(f"Falha ao retornar {interface} para modo gerenciado.")
                    return False
                
        except Exception as e:
            print(f"Erro ao desativar modo monitor: {e}")
            return False

def validate_mac_address(mac):
    """
    Valida um endereço MAC.
    
    Args:
        mac (str): Endereço MAC a ser validado.
        
    Returns:
        bool: True se for um endereço MAC válido, False caso contrário.
    """
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def generate_random_mac() -> str:
    """
    Gera um endereço MAC aleatório.
    
    Returns:
        str: Endereço MAC aleatório.
    """
    # Primeiro byte deve ter o bit menos significativo do primeiro octeto = 0 (unicast)
    # e o segundo bit menos significativo do primeiro octeto = 0 (globally unique)
    first_byte = random.randint(0, 254) & 0xFC
    
    # Os outros 5 bytes são aleatórios
    other_bytes = [random.randint(0, 255) for _ in range(5)]
    
    # Junta os bytes e formata como MAC
    mac_bytes = [first_byte] + other_bytes
    mac = ':'.join([f"{b:02x}" for b in mac_bytes])
    
    return mac

def kill_conflicting_processes():
    """
    Mata processos que podem entrar em conflito com as operações da ferramenta.
    
    Returns:
        bool: True se bem-sucedido, False caso contrário.
    """
    conflicting_processes = [
        'NetworkManager', 'wpa_supplicant', 'dhclient', 'avahi-daemon',
        'dhcpcd', 'hostapd', 'airodump-ng', 'aireplay-ng', 'airmon-ng'
    ]
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name']
            for conflict in conflicting_processes:
                if conflict.lower() in proc_name.lower():
                    try:
                        psutil.Process(proc.info['pid']).terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        return False
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return True

def is_admin() -> bool:
    """
    Verifica se o programa está sendo executado com privilégios de administrador.
    
    Returns:
        bool: True se estiver rodando como administrador, False caso contrário.
    """
    try:
        if platform.system().lower() == "windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception as e:
                print(f"Erro ao verificar privilégios de administrador no Windows: {e}")
                return False
        else:
            return os.geteuid() == 0
    except Exception:
        # Em caso de erro, retornamos False para ser seguro
        return False

def get_ip_address(interface: Optional[str] = None) -> str:
    """
    Obtém o endereço IP principal do sistema ou de uma interface específica.
    
    Args:
        interface (str, optional): Nome da interface. Se None, retorna o IP principal.
        
    Returns:
        str: Endereço IP ou string vazia se não encontrado.
    """
    try:
        if interface:
            # Obtém o IP de uma interface específica
            if platform.system().lower() == "windows":
                # No Windows, usa ipconfig
                result = subprocess.run("ipconfig", shell=True, capture_output=True, text=True)
                output = result.stdout
                
                # Procura pela interface especificada
                # Considerando tanto o formato em português quanto em inglês
                interfaces = re.split(r"(?:\r)?\n(?:\r)?\n", output)
                for section in interfaces:
                    if interface in section:
                        # Extrai o IP
                        ip_match = re.search(r"IPv4.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                        if not ip_match:
                            ip_match = re.search(r"Endereço IPv4.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                        if ip_match:
                            return ip_match.group(1).strip()
                return ""
            else:
                # No Linux/Unix
                if interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        return addrs[netifaces.AF_INET][0]['addr']
                return ""
        else:
            # Obtém o IP principal (usado para conexão externa)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
    except Exception:
        # Método alternativo
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception:
            return ""

def get_mac_address(interface: str) -> str:
    """
    Obtém o endereço MAC de uma interface.
    
    Args:
        interface (str): Nome da interface.
        
    Returns:
        str: Endereço MAC ou string vazia se não encontrado.
    """
    try:
        if platform.system().lower() == "windows":
            # No Windows, usa getmac
            result = subprocess.run("getmac /v /NH /FO CSV", shell=True, capture_output=True, text=True)
            output = result.stdout
            
            # Procura pela interface especificada
            lines = output.strip().split('\n')
            for line in lines:
                parts = line.strip('"').split('","')
                if interface in parts[0]:
                    mac = parts[2].replace('-', ':').lower()
                    return mac
                    
            return ""
        else:
            # No Linux/Unix
            if interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_LINK in addrs:
                    return addrs[netifaces.AF_LINK][0]['addr']
            return ""
    except Exception:
        return ""

def check_port_in_use(port: int) -> bool:
    """
    Verifica se uma porta está em uso.
    
    Args:
        port (int): Número da porta a verificar.
        
    Returns:
        bool: True se a porta estiver em uso, False caso contrário.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except Exception:
        return False

def find_available_port(start_port: int = 8000, end_port: int = 9000) -> Optional[int]:
    """
    Encontra uma porta disponível dentro de um intervalo.
    
    Args:
        start_port (int): Início do intervalo de portas.
        end_port (int): Fim do intervalo de portas.
        
    Returns:
        int: Porta disponível ou None se não encontrar.
    """
    for port in range(start_port, end_port):
        if not check_port_in_use(port):
            return port
    return None

def kill_process_by_port(port: int) -> bool:
    """
    Mata o processo que está usando uma determinada porta.
    
    Args:
        port (int): Porta usada pelo processo.
        
    Returns:
        bool: True se bem-sucedido, False caso contrário.
    """
    try:
        if platform.system().lower() == "windows":
            # No Windows, usa netstat para encontrar o PID
            result = subprocess.run(f"netstat -ano | findstr :{port}", shell=True, capture_output=True, text=True)
            output = result.stdout
            
            if not output:
                print(f"Nenhum processo encontrado usando a porta {port}")
                return False
                
            # Extrai o PID
            lines = output.strip().split('\n')
            pids = set()
            for line in lines:
                if f":{port}" in line:
                    cols = line.strip().split()
                    if len(cols) >= 5:
                        pids.add(cols[-1])
            
            if not pids:
                print(f"Não foi possível determinar o PID para a porta {port}")
                return False
                
            # Mata os processos
            for pid in pids:
                try:
                    subprocess.run(f"taskkill /F /PID {pid}", shell=True, check=True)
                    print(f"Processo com PID {pid} encerrado")
                except:
                    print(f"Falha ao encerrar processo com PID {pid}")
                    
            return True
            
        else:
            # No Linux, usa lsof para encontrar o PID
            result = subprocess.run(f"lsof -i:{port} -t", shell=True, capture_output=True, text=True)
            output = result.stdout.strip()
            
            if not output:
                print(f"Nenhum processo encontrado usando a porta {port}")
                return False
            
            # Mata os processos
            pids = output.split('\n')
            for pid in pids:
                try:
                    subprocess.run(f"kill -9 {pid}", shell=True, check=True)
                    print(f"Processo com PID {pid} encerrado")
                except:
                    print(f"Falha ao encerrar processo com PID {pid}")
                    
            return True
            
    except Exception as e:
        print(f"Erro ao matar processo por porta: {e}")
        return False

def is_ip_address(value: str) -> bool:
    """
    Verifica se uma string é um endereço IP válido.
    
    Args:
        value (str): String a ser verificada.
        
    Returns:
        bool: True se for um IP válido, False caso contrário.
    """
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False

def get_process_status(pid: int) -> Optional[Dict]:
    """
    Obtém o status de um processo pelo PID.
    
    Args:
        pid (int): PID do processo.
        
    Returns:
        Dict: Dicionário com informações do processo ou None se não encontrado.
    """
    try:
        process = psutil.Process(pid)
        return {
            'pid': pid,
            'name': process.name(),
            'status': process.status(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'create_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(process.create_time()))
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except Exception:
        return None
        
# Funções específicas para o Windows

def get_windows_network_status() -> Dict:
    """
    Obtém informações sobre o status da rede no Windows.
    
    Returns:
        Dict: Dicionário com informações sobre o status da rede.
    """
    if platform.system().lower() != "windows":
        return {"error": "Função disponível apenas para Windows"}
        
    try:
        result = {}
        
        # Obtém informações da conexão atual
        netsh_result = subprocess.run("netsh wlan show interfaces", shell=True, capture_output=True, text=True)
        netsh_output = netsh_result.stdout
        
        # Extrai informações
        ssid_match = re.search(r"SSID\s+:\s+(.*?)(?:\r)?\n", netsh_output)
        if not ssid_match:
            ssid_match = re.search(r"SSID\s+:\s+(.*?)(?:\r)?\n", netsh_output)
        
        if ssid_match:
            result["ssid"] = ssid_match.group(1).strip()
            
            # Extrai outras informações
            bssid_match = re.search(r"BSSID\s+:\s+(.*?)(?:\r)?\n", netsh_output)
            if bssid_match:
                result["bssid"] = bssid_match.group(1).strip()
                
            signal_match = re.search(r"Signal\s+:\s+(.*?)(?:\r)?\n", netsh_output)
            if not signal_match:
                signal_match = re.search(r"Sinal\s+:\s+(.*?)(?:\r)?\n", netsh_output)
                
            if signal_match:
                result["signal"] = signal_match.group(1).strip()
                
            channel_match = re.search(r"Channel\s+:\s+(.*?)(?:\r)?\n", netsh_output)
            if not channel_match:
                channel_match = re.search(r"Canal\s+:\s+(.*?)(?:\r)?\n", netsh_output)
                
            if channel_match:
                result["channel"] = channel_match.group(1).strip()
                
            radio_match = re.search(r"Radio type\s+:\s+(.*?)(?:\r)?\n", netsh_output)
            if not radio_match:
                radio_match = re.search(r"Tipo de rádio\s+:\s+(.*?)(?:\r)?\n", netsh_output)
                
            if radio_match:
                result["radio_type"] = radio_match.group(1).strip()
            
            # Obtém informações de IP da interface conectada
            adapter_match = re.search(r"(?:Name|Nome)\s+:\s+(.*?)(?:\r)?\n", netsh_output)
            if adapter_match:
                adapter_name = adapter_match.group(1).strip()
                result["interface"] = adapter_name
                
                # Obtém o IP da interface
                ipconfig_result = subprocess.run("ipconfig", shell=True, capture_output=True, text=True)
                ipconfig_output = ipconfig_result.stdout
                
                # Divide a saída por adaptador
                sections = re.split(r"(?:\r)?\n(?:\r)?\n", ipconfig_output)
                for section in sections:
                    if adapter_name in section:
                        ip_match = re.search(r"IPv4.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                        if not ip_match:
                            ip_match = re.search(r"Endereço IPv4.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                        
                        if ip_match:
                            result["ip"] = ip_match.group(1).strip()
                            
                        mask_match = re.search(r"Subnet Mask.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                        if not mask_match:
                            mask_match = re.search(r"Máscara de Sub-rede.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                            
                        if mask_match:
                            result["subnet_mask"] = mask_match.group(1).strip()
                            
                        gateway_match = re.search(r"Default Gateway.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                        if not gateway_match:
                            gateway_match = re.search(r"Gateway Padrão.*?:\s+(\d+\.\d+\.\d+\.\d+)", section)
                            
                        if gateway_match:
                            result["gateway"] = gateway_match.group(1).strip()
                            
                        break
        else:
            # Nenhuma rede WiFi conectada
            result["status"] = "Desconectado"
            
        return result
        
    except Exception as e:
        return {"error": str(e)}

def windows_scan_networks() -> List[Dict]:
    """
    Escaneia redes WiFi disponíveis no Windows.
    
    Returns:
        List[Dict]: Lista de redes WiFi disponíveis.
    """
    if platform.system().lower() != "windows":
        return [{"error": "Função disponível apenas para Windows"}]
        
    try:
        # Executa o comando para escanear redes
        result = subprocess.run("netsh wlan show networks mode=bssid", shell=True, capture_output=True, text=True)
        output = result.stdout
        
        # Divide a saída por rede
        networks = []
        sections = re.split(r"SSID \d+ :", output)[1:]
        
        for section in sections:
            network = {}
            
            # Extrai o SSID
            ssid_match = re.search(r"(?:Name|Nome)\s+:\s+(.*?)(?:\r)?\n", section)
            if ssid_match:
                network["ssid"] = ssid_match.group(1).strip()
                
                # Extrai outros detalhes
                auth_match = re.search(r"Authentication\s+:\s+(.*?)(?:\r)?\n", section)
                if not auth_match:
                    auth_match = re.search(r"Autenticação\s+:\s+(.*?)(?:\r)?\n", section)
                    
                if auth_match:
                    network["auth"] = auth_match.group(1).strip()
                
                encr_match = re.search(r"Encryption\s+:\s+(.*?)(?:\r)?\n", section)
                if not encr_match:
                    encr_match = re.search(r"Criptografia\s+:\s+(.*?)(?:\r)?\n", section)
                    
                if encr_match:
                    network["encryption"] = encr_match.group(1).strip()
                
                # Extrai informações de BSSID (MAC do AP)
                bssids = []
                bssid_sections = re.findall(r"BSSID \d+\s+:\s+(.*?)(?:\r)?\n(?:.*?Signal\s+:\s+(\d+)%)?", section, re.DOTALL)
                
                if bssid_sections:
                    for bssid_match in bssid_sections:
                        if len(bssid_match) >= 1:
                            bssid_info = {
                                "bssid": bssid_match[0].strip()
                            }
                            
                            if len(bssid_match) >= 2 and bssid_match[1]:
                                bssid_info["signal"] = int(bssid_match[1].strip())
                                
                            bssids.append(bssid_info)
                    
                    network["bssids"] = bssids
                    
                    # Usa o sinal do primeiro BSSID como sinal da rede
                    if bssids and "signal" in bssids[0]:
                        network["signal"] = bssids[0]["signal"]
                
                networks.append(network)
        
        return networks
        
    except Exception as e:
        return [{"error": str(e)}]

def check_windows_prerequisites() -> Dict[str, bool]:
    """
    Verifica os pré-requisitos específicos do Windows.
    
    Returns:
        Dict[str, bool]: Dicionário com o status dos pré-requisitos.
    """
    results = {
        "is_admin": is_admin(),
        "wlan_service": False,
        "hosted_network_support": False,
    }
    
    # Verifica se o serviço WLAN AutoConfig está em execução
    try:
        output = subprocess.run(
            "sc query \"Wlansvc\"", 
            shell=True,
            capture_output=True,
            text=True
        )
        
        results["wlan_service"] = "RUNNING" in output.stdout
    except Exception:
        pass
    
    # Verifica suporte a hosted network
    try:
        output = subprocess.run(
            "netsh wlan show drivers", 
            shell=True,
            capture_output=True,
            text=True
        )
        
        results["hosted_network_support"] = "Hosted network supported  : Yes" in output.stdout or "Suporte a rede hospedada  : Sim" in output.stdout
    except Exception:
        pass
    
    return results 