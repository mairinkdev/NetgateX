#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetgateX - Ferramenta de Segurança de Redes

Arquivo principal que inicializa a aplicação NetgateX.
"""

import os
import sys
import time
import signal
import argparse
import platform
import ctypes
import threading
from datetime import datetime

# Verifica se está sendo executado como root/administrador
if os.name == 'posix' and os.geteuid() != 0:
    print("Este programa precisa ser executado como root. Use 'sudo python netgatex.py'")
    sys.exit(1)
elif os.name == 'nt':
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("Este programa precisa ser executado como administrador.")
            sys.exit(1)
    except Exception as e:
        print(f"Erro ao verificar privilégios de administrador: {e}")
        print("Continuando sem verificação de privilégios...")

# Adiciona o diretório raiz ao path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Imports internos
from src.core.logger import Logger
from src.core.wifi_manager import WiFiManager
# Importação condicional da interface gráfica
ENABLE_GUI = '--no-gui' not in sys.argv
try:
    from src.ui.dashboard import Dashboard
    DASHBOARD_AVAILABLE = True
except ImportError as e:
    print(f"Interface gráfica não disponível: {e}")
    print("Executando em modo CLI.")
    DASHBOARD_AVAILABLE = False
    ENABLE_GUI = False

from src.monitoring.traffic_analyzer import TrafficAnalyzer
from src.attacks.evil_twin import EvilTwin
from src.attacks.mitm import MITMAttack
from src.utils.helpers import is_admin

def signal_handler(sig, frame):
    """Manipulador de sinais para saída limpa."""
    print("\n[*] Encerrando NetgateX...")
    # Limpar recursos e sair
    sys.exit(0)

def setup_directories():
    """Configura os diretórios necessários."""
    required_dirs = [
        'logs',
        'web/templates',
        'web/static'
    ]
    
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)

def check_os_compatibility():
    """Verifica a compatibilidade do sistema operacional."""
    current_os = platform.system().lower()
    
    if current_os == 'linux':
        print("[+] Sistema operacional Linux detectado, compatibilidade completa.")
        return True
    elif current_os == 'windows':
        print("[!] Sistema operacional Windows detectado. Algumas funcionalidades podem ser limitadas.")
        return True
    else:
        print(f"[!] Sistema operacional {current_os} pode não ser totalmente compatível.")
        return False

def parse_arguments():
    """Analisa os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(description='NetgateX - Ferramenta de Segurança de Redes')
    parser.add_argument('--no-gui', action='store_true', help='Executar sem interface gráfica')
    parser.add_argument('--cli', action='store_true', help='Executar em modo linha de comando')
    parser.add_argument('--interface', type=str, help='Interface de rede a ser usada')
    parser.add_argument('--debug', action='store_true', help='Ativar modo de depuração')
    
    return parser.parse_args()

class NetgateX:
    """Classe principal da aplicação NetgateX."""
    
    def __init__(self, cli_mode=False, interface=None, debug=False):
        """
        Inicializa a aplicação NetgateX.
        
        Args:
            cli_mode (bool): Se True, executa em modo de linha de comando.
            interface (str): Interface WiFi a ser usada.
            debug (bool): Se True, ativa o modo de depuração.
        """
        self.cli_mode = cli_mode
        self.interface = interface
        self.logger = Logger(log_level="DEBUG" if debug else "INFO")
        self.wifi_manager = None
        self.dashboard = None
        self.running = False
        
        # Verifica se está sendo executado como root/admin
        if not self._check_privileges():
            self.logger.error("É necessário executar como administrador/root para acessar as interfaces de rede.")
            if platform.system().lower() == "windows":
                self.logger.info("Execute o prompt de comando/PowerShell como administrador e tente novamente.")
            else:
                self.logger.info("Execute com 'sudo python netgatex.py' e tente novamente.")
            sys.exit(1)
            
        # Configura o manipulador de sinais
        self._setup_signal_handler()
        
        # Inicializa os componentes
        self._initialize_components()
    
    def _check_privileges(self):
        """
        Verifica se a aplicação está sendo executada com privilégios de administrador.
        
        Returns:
            bool: True se tem privilégios, False caso contrário.
        """
        try:
            return is_admin()
        except Exception as e:
            self.logger.error(f"Erro ao verificar privilégios: {e}")
            # Em caso de erro, continua mesmo assim, mas pode falhar mais tarde
            return True
    
    def _setup_signal_handler(self):
        """Configura o manipulador de sinais para encerramento adequado."""
        def signal_handler(sig, frame):
            self.logger.info("Sinal de interrupção recebido. Encerrando...")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
    
    def _initialize_components(self):
        """Inicializa os componentes principais da aplicação."""
        self.logger.info(f"Inicializando NetgateX em modo {'CLI' if self.cli_mode else 'GUI'}...")
        
        try:
            # Inicializa o gerenciador WiFi
            self.wifi_manager = WiFiManager(logger=self.logger)
            
            if self.interface:
                # Verifica se a interface especificada existe
                if self.interface not in self.wifi_manager.get_interfaces():
                    self.logger.error(f"Interface {self.interface} não encontrada.")
                    available_interfaces = self.wifi_manager.get_interfaces()
                    if available_interfaces:
                        self.logger.info(f"Interfaces disponíveis: {', '.join(available_interfaces)}")
                    sys.exit(1)
                self.logger.info(f"Usando interface: {self.interface}")
            
            # Em modo GUI, inicializa o dashboard se disponível
            if not self.cli_mode and ENABLE_GUI and DASHBOARD_AVAILABLE:
                try:
                    self.dashboard = Dashboard(
                        logger=self.logger, 
                        wifi_manager=self.wifi_manager
                    )
                    self.logger.success("Dashboard inicializado com sucesso.")
                except Exception as dashboard_error:
                    self.logger.error(f"Erro ao inicializar o Dashboard: {dashboard_error}")
                    self.logger.info("Alternando para modo CLI...")
                    self.cli_mode = True
            
            self.logger.success("Componentes inicializados com sucesso.")
            
        except Exception as e:
            self.logger.error(f"Erro ao inicializar componentes: {e}")
            sys.exit(1)
    
    def start(self):
        """Inicia a aplicação."""
        if self.running:
            return
            
        self.running = True
        
        try:
            if self.cli_mode:
                self._start_cli_mode()
            else:
                self._start_gui_mode()
        except Exception as e:
            self.logger.error(f"Erro ao iniciar NetgateX: {e}")
            self.stop()
    
    def _start_gui_mode(self):
        """Inicia a aplicação em modo GUI."""
        try:
            self.logger.info("Iniciando interface gráfica...")
            if self.dashboard:
                self.dashboard.start()
            else:
                self.logger.error("Dashboard não inicializado.")
        except Exception as e:
            self.logger.error(f"Erro ao iniciar interface gráfica: {e}")
    
    def _start_cli_mode(self):
        """Inicia a aplicação em modo CLI."""
        self.logger.info("Modo CLI ativado.")
        self.logger.info("Digite 'help' para ver os comandos disponíveis.")
        
        # Implementação do loop de CLI
        while self.running:
            try:
                cmd = input("\nNetgateX> ").strip().lower()
                self._process_cli_command(cmd)
            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                self.logger.error(f"Erro ao processar comando: {e}")
    
    def _process_cli_command(self, cmd):
        """
        Processa um comando do CLI.
        
        Args:
            cmd (str): Comando a ser processado.
        """
        if cmd == "exit" or cmd == "quit" or cmd == "q":
            self.stop()
            return
            
        elif cmd == "help" or cmd == "h" or cmd == "?":
            print("\nComandos disponíveis:")
            print("  interfaces       - Lista as interfaces WiFi disponíveis")
            print("  scan             - Escaneia redes WiFi próximas")
            print("  monitor start    - Inicia monitoramento de tráfego")
            print("  monitor stop     - Para monitoramento de tráfego")
            print("  mitm start       - Inicia ataque Man-in-the-Middle")
            print("  mitm stop        - Para ataque Man-in-the-Middle")
            print("  eviltwin start   - Inicia ataque Evil Twin")
            print("  eviltwin stop    - Para ataque Evil Twin")
            print("  help, h, ?       - Mostra esta ajuda")
            print("  exit, quit, q    - Sai do programa")
            
        elif cmd == "interfaces":
            interfaces = self.wifi_manager.get_interfaces()
            print("\nInterfaces WiFi disponíveis:")
            for i, iface in enumerate(interfaces, 1):
                status = self.wifi_manager.get_interface_status(iface) or {}
                connected = self.wifi_manager.get_connected_network(iface)
                mac_info = f" - {status.get('mac', 'MAC desconhecido')}" if status.get('mac') else ""
                network_info = f" (Conectado a: {connected['ssid']})" if connected else ""
                print(f"  {i}. {iface}{mac_info}{network_info}")
            
        elif cmd == "scan":
            if not self.interface:
                self.interface = self._select_interface()
                if not self.interface:
                    return
                
            self.logger.info(f"Escaneando redes com interface {self.interface}...")
            networks = self.wifi_manager.scan_networks(self.interface)
            
            if networks:
                print("\nRedes WiFi encontradas:")
                for i, network in enumerate(networks, 1):
                    security = network.get('security', 'Desconhecido')
                    channel = network.get('channel', 'N/A')
                    signal = network.get('signal', 0)
                    print(f"  {i}. {network['ssid']} - Canal: {channel}, Sinal: {signal}%, Segurança: {security}")
            else:
                self.logger.warning("Nenhuma rede encontrada.")
                
        elif cmd.startswith("monitor"):
            parts = cmd.split()
            if len(parts) < 2:
                self.logger.error("Uso: monitor start|stop")
                return
                
            if parts[1] == "start":
                if not self.interface:
                    self.interface = self._select_interface()
                    if not self.interface:
                        return
                
                self.logger.info(f"Iniciando monitoramento na interface {self.interface}...")
                monitor = TrafficAnalyzer(
                    interface=self.interface,
                    logger=self.logger
                )
                
                try:
                    monitor.start_capture()
                    self.logger.info("Pressione Ctrl+C para parar o monitoramento.")
                    while True:
                        try:
                            time.sleep(1)
                        except KeyboardInterrupt:
                            break
                finally:
                    monitor.stop_capture()
                    self.logger.info("Monitoramento finalizado.")
                    
            elif parts[1] == "stop":
                self.logger.info("Comando não implementado. Use Ctrl+C para parar o monitoramento em execução.")
                
        elif cmd.startswith("mitm"):
            parts = cmd.split()
            if len(parts) < 2:
                self.logger.error("Uso: mitm start|stop")
                return
                
            if parts[1] == "start":
                if not self.interface:
                    self.interface = self._select_interface()
                    if not self.interface:
                        return
                
                # Obtém o gateway automaticamente
                gateway = None
                target = None
                
                # Pergunta se quer um alvo específico ou toda a rede
                target_mode = input("Atacar um alvo específico? (s/N): ").strip().lower()
                if target_mode == "s" or target_mode == "sim":
                    target = input("Digite o IP do alvo: ").strip()
                
                self.logger.info(f"Iniciando ataque MITM na interface {self.interface}...")
                mitm = MITMAttack(
                    interface=self.interface,
                    gateway=gateway,
                    target=target,
                    logger=self.logger
                )
                
                try:
                    mitm.start_attack()
                    self.logger.info("Pressione Ctrl+C para parar o ataque.")
                    while True:
                        try:
                            time.sleep(1)
                        except KeyboardInterrupt:
                            break
                finally:
                    mitm.stop_attack()
                    self.logger.info("Ataque MITM finalizado.")
                    
            elif parts[1] == "stop":
                self.logger.info("Comando não implementado. Use Ctrl+C para parar o ataque em execução.")
                
        elif cmd.startswith("eviltwin"):
            parts = cmd.split()
            if len(parts) < 2:
                self.logger.error("Uso: eviltwin start|stop")
                return
                
            if parts[1] == "start":
                if not self.interface:
                    self.interface = self._select_interface()
                    if not self.interface:
                        return
                
                # Obtém informações para o ataque
                target_ssid = input("Digite o SSID alvo: ").strip()
                if not target_ssid:
                    self.logger.error("SSID alvo é necessário.")
                    return
                    
                # BSSID é opcional
                target_bssid = input("Digite o BSSID alvo (opcional): ").strip()
                if not target_bssid:
                    target_bssid = None
                    
                channel = input("Digite o canal (padrão: 1): ").strip()
                if not channel:
                    channel = 1
                else:
                    try:
                        channel = int(channel)
                    except ValueError:
                        self.logger.error("Canal deve ser um número.")
                        return
                
                self.logger.info(f"Iniciando ataque Evil Twin contra '{target_ssid}' na interface {self.interface}...")
                eviltwin = EvilTwin(
                    interface=self.interface,
                    target_ssid=target_ssid,
                    target_bssid=target_bssid,
                    channel=channel,
                    logger=self.logger
                )
                
                try:
                    eviltwin.start_attack()
                    self.logger.info("Pressione Ctrl+C para parar o ataque.")
                    while True:
                        try:
                            time.sleep(1)
                        except KeyboardInterrupt:
                            break
                finally:
                    eviltwin.stop_attack()
                    self.logger.info("Ataque Evil Twin finalizado.")
                    
            elif parts[1] == "stop":
                self.logger.info("Comando não implementado. Use Ctrl+C para parar o ataque em execução.")
                
        else:
            self.logger.error(f"Comando desconhecido: {cmd}")
            self.logger.info("Digite 'help' para ver os comandos disponíveis.")
    
    def _select_interface(self):
        """
        Permite ao usuário selecionar uma interface WiFi.
        
        Returns:
            str: Nome da interface selecionada ou None se cancelada.
        """
        interfaces = self.wifi_manager.get_interfaces()
        
        if not interfaces:
            self.logger.error("Nenhuma interface WiFi detectada.")
            return None
            
        print("\nInterfaces WiFi disponíveis:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
            
        while True:
            try:
                choice = input("\nSelecione uma interface (número ou nome): ").strip()
                
                # Verifica se o usuário digitou um número
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(interfaces):
                        return interfaces[idx]
                    else:
                        self.logger.error("Número inválido.")
                except ValueError:
                    # Não é um número, verifica se é um nome de interface válido
                    if choice in interfaces:
                        return choice
                    else:
                        self.logger.error("Interface não encontrada.")
                        
            except KeyboardInterrupt:
                return None
    
    def stop(self):
        """Para a aplicação."""
        if not self.running:
            return
            
        self.logger.info("Encerrando NetgateX...")
        self.running = False
        
        # Encerra o dashboard se estiver em execução
        if self.dashboard:
            self.dashboard.close()
            
        self.logger.success("NetgateX encerrado.")

def main():
    """Função principal que inicia a aplicação."""
    print("""
    ███╗   ██╗███████╗████████╗ ██████╗  █████╗ ████████╗███████╗██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
    ██╔██╗ ██║█████╗     ██║   ██║  ███╗███████║   ██║   █████╗   ╚███╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ██║   ██║██╔══██║   ██║   ██╔══╝   ██╔██╗ 
    ██║ ╚████║███████╗   ██║   ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                                                                
    """)
    print("[*] Inicializando NetgateX v1.0.0...")
    print("[*] @MAIRINKDEV 🦈")
    
    # Configura o manipulador de sinais
    signal.signal(signal.SIGINT, signal_handler)
    
    # Analisa argumentos
    args = parse_arguments()
    
    # Configura os diretórios
    setup_directories()
    
    # Verifica compatibilidade do sistema operacional
    if not check_os_compatibility():
        response = input("Deseja continuar mesmo assim? (s/n): ").lower()
        if response != 's':
            sys.exit(1)
    
    # Inicializa o logger
    log_level = "DEBUG" if args.debug else "INFO"
    logger = Logger(log_level=log_level)
    logger.info("NetgateX iniciado")
    
    # Inicializa o gerenciador de WiFi
    wifi_manager = WiFiManager(logger=logger)
    interfaces = wifi_manager.get_interfaces()
    
    if not interfaces:
        logger.error("Nenhuma interface WiFi encontrada!")
        print("[!] Nenhuma interface WiFi encontrada!")
        sys.exit(1)
    
    # Seleciona a interface
    if args.interface and args.interface in interfaces:
        interface = args.interface
    else:
        interface = interfaces[0]
        logger.info(f"Usando interface padrão: {interface}")
    
    # Decide o modo de execução
    use_cli = args.no_gui or not DASHBOARD_AVAILABLE
    
    # Se não estiver no modo GUI, exibir informações básicas
    if use_cli:
        print(f"[+] Interfaces disponíveis: {', '.join(interfaces)}")
        print(f"[+] Interface selecionada: {interface}")
        print("[*] Inicialização em modo CLI completa.")
        
        # Inicializa a aplicação em modo CLI
        app = NetgateX(
            cli_mode=True,
            interface=interface,
            debug=args.debug
        )
        app.start()
    else:
        # Inicializa a aplicação em modo GUI
        app = NetgateX(
            cli_mode=False,
            interface=interface,
            debug=args.debug
        )
        app.start()
    
    logger.info("NetgateX encerrado")

if __name__ == "__main__":
    main() 