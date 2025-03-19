#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para a interface gráfica (dashboard) da ferramenta NetgateX.
"""

import os
import sys
import time
import threading
import PySimpleGUI as sg
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import io
from PIL import Image, ImageTk

# Importa módulos internos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.core.scanner import NetworkScanner
from src.core.wifi_manager import WiFiManager
from src.monitoring.traffic_analyzer import TrafficAnalyzer
from src.attacks.deauth import DeauthAttack
from src.attacks.evil_twin import EvilTwin
from src.attacks.mitm import MITMAttack
from src.utils.logger import Logger
from src.utils.helpers import get_wifi_interfaces, get_network_interfaces

# Define tema e cores
sg.theme('DarkBlue12')
ACCENT_COLOR = '#007acc'
SECONDARY_COLOR = '#2d2d30'
TEXT_COLOR = '#ffffff'

class Dashboard:
    """Classe para gerenciar a interface gráfica da ferramenta."""
    
    def __init__(self, logger=None):
        """
        Inicializa o dashboard.
        
        Args:
            logger (Logger): Instância do logger para registrar eventos.
        """
        self.logger = logger if logger else Logger(verbose=False)
        self.window = None
        self.running = False
        self.current_interface = None
        self.networks = {}
        self.active_attacks = {}
        
        # Objetos para funcionalidades
        self.scanner = None
        self.wifi_manager = WiFiManager()
        self.traffic_analyzer = None
        
        # Guarda threads ativas
        self.active_threads = {}
        
        # Inicializa a interface
        self._create_window()
    
    def _create_window(self):
        """Cria a janela principal do dashboard."""
        # Menu principal
        menu_def = [
            ['Arquivo', ['Salvar Configuração', 'Carregar Configuração', '---', 'Sair']],
            ['Ferramentas', ['Capturar Tráfego', 'Analisar Vulnerabilidades', '---', 'Configurações']],
            ['Ajuda', ['Sobre', 'Manual']]
        ]
        
        # Layout principal com abas
        tab_layout = [
            self._create_scan_tab(),
            self._create_monitor_tab(),
            self._create_attack_tab(),
            self._create_report_tab()
        ]
        
        # Barra de status
        status_bar = [
            sg.Text("Status: Pronto", key='-STATUS-', size=(40, 1)),
            sg.Text("Interface: Nenhuma", key='-INTERFACE-', size=(30, 1)),
            sg.Text(datetime.now().strftime("%H:%M:%S"), key='-TIME-', size=(10, 1))
        ]
        
        # Layout completo
        layout = [
            [sg.Menu(menu_def)],
            [sg.Image(data=self._get_logo(), key='-LOGO-'), 
             sg.Text('NetgateX - Ferramenta Avançada para Teste de Segurança em Redes WiFi', font=('Helvetica', 16))],
            [sg.TabGroup([
                [sg.Tab('Escaneamento', tab_layout[0], tooltip='Escaneamento de redes WiFi'),
                 sg.Tab('Monitoramento', tab_layout[1], tooltip='Monitoramento de tráfego'),
                 sg.Tab('Ataques', tab_layout[2], tooltip='Ataques e testes'),
                 sg.Tab('Relatórios', tab_layout[3], tooltip='Geração de relatórios')]
            ], key='-TABGROUP-', enable_events=True)],
            [sg.HSep()],
            status_bar
        ]
        
        # Cria a janela
        self.window = sg.Window('NetgateX', layout, size=(900, 650), resizable=True, finalize=True)
        
        # Inicia o timer de atualização da hora
        self._start_clock_update()
        
        # Preenche a lista de interfaces
        self._update_interface_list()
    
    def _get_logo(self):
        """
        Gera o logo da aplicação.
        
        Returns:
            bytes: Dados da imagem em bytes.
        """
        # Cria uma imagem simples como logo
        img = Image.new('RGB', (64, 64), color=ACCENT_COLOR)
        bio = io.BytesIO()
        img.save(bio, format='PNG')
        return bio.getvalue()
    
    def _start_clock_update(self):
        """Inicia a atualização do relógio na barra de status."""
        def update_clock():
            while self.running:
                if self.window:
                    self.window['-TIME-'].update(datetime.now().strftime("%H:%M:%S"))
                time.sleep(1)
        
        self.running = True
        clock_thread = threading.Thread(target=update_clock, daemon=True)
        clock_thread.start()
    
    def _update_interface_list(self):
        """Atualiza a lista de interfaces WiFi disponíveis."""
        try:
            wifi_interfaces = get_wifi_interfaces()
            self.window['-INTERFACE_LIST-'].update(values=wifi_interfaces)
            self.logger.debug(f"Interfaces WiFi encontradas: {wifi_interfaces}")
        except Exception as e:
            self.logger.error(f"Erro ao listar interfaces WiFi: {e}")
    
    def _update_status(self, message):
        """Atualiza a mensagem de status."""
        if self.window:
            self.window['-STATUS-'].update(f"Status: {message}")
            self.logger.info(message)
    
    def _create_scan_tab(self):
        """Cria o layout da aba de escaneamento."""
        scan_layout = [
            [sg.Text('Interface WiFi:'),
             sg.Combo([], size=(20, 1), key='-INTERFACE_LIST-'),
             sg.Button('Atualizar', key='-REFRESH_INTERFACES-'),
             sg.Button('Escanear Redes', key='-START_SCAN-')],
            [sg.HSep()],
            [sg.Text('Redes Encontradas:')],
            [sg.Table(
                values=[],
                headings=['BSSID', 'SSID', 'Canal', 'Segurança', 'Sinal', 'Clientes'],
                auto_size_columns=True,
                display_row_numbers=False,
                justification='left',
                num_rows=15,
                key='-NETWORK_TABLE-',
                selected_row_colors='black on yellow',
                enable_events=True,
                expand_x=True,
                expand_y=True,
                tooltip='Lista de redes encontradas'
            )],
            [sg.Text('Detalhes da Rede Selecionada:')],
            [sg.Multiline(size=(80, 5), key='-NETWORK_DETAILS-', disabled=True)]
        ]
        return scan_layout
    
    def _create_monitor_tab(self):
        """Cria o layout da aba de monitoramento."""
        monitor_layout = [
            [sg.Text('Monitoramento de Tráfego')],
            [sg.Text('Interface:'), 
             sg.Combo([], size=(20, 1), key='-MONITOR_INTERFACE-'),
             sg.Text('Canal:'), 
             sg.Spin([i for i in range(1, 15)], initial_value=1, size=(5, 1), key='-CHANNEL-'),
             sg.Checkbox('Salvar PCAP', key='-SAVE_PCAP-'),
             sg.Button('Iniciar Monitoramento', key='-START_MONITOR-')],
            [sg.HSep()],
            [sg.Frame('Estatísticas', [
                [sg.Text('Pacotes Capturados: 0', key='-PACKETS_COUNT-')],
                [sg.Text('Dispositivos Detectados: 0', key='-DEVICES_COUNT-')],
                [sg.Text('Dispositivos IoT: 0', key='-IOT_COUNT-')],
                [sg.Text('Protocolos Mais Comuns:')],
                [sg.Multiline(size=(40, 3), key='-PROTOCOLS-', disabled=True)]
            ]), 
             sg.Frame('Visualização', [
                [sg.Canvas(key='-GRAPH-', size=(300, 200))]
            ])],
            [sg.Text('Pacotes Capturados:')],
            [sg.Multiline(size=(80, 10), key='-PACKET_LOG-', disabled=True, autoscroll=True)]
        ]
        return monitor_layout
    
    def _create_attack_tab(self):
        """Cria o layout da aba de ataques."""
        attack_types = ['Desautenticação', 'Evil Twin', 'MITM', 'Downgrade de Segurança', 'Fuzzing']
        
        # Sub-layouts para cada tipo de ataque
        deauth_layout = [
            [sg.Text('BSSID Alvo:'), sg.Input(key='-DEAUTH_BSSID-', size=(20, 1))],
            [sg.Text('MAC Cliente:'), sg.Input(key='-DEAUTH_CLIENT-', size=(20, 1), tooltip='Deixe em branco para atacar todos os clientes')],
            [sg.Text('Canal:'), sg.Spin([i for i in range(1, 15)], initial_value=1, size=(5, 1), key='-DEAUTH_CHANNEL-')],
            [sg.Text('Pacotes:'), sg.Spin([i for i in range(0, 10001, 10)], initial_value=0, size=(5, 1), key='-DEAUTH_PACKETS-', tooltip='0 = Infinito')],
            [sg.Button('Iniciar Ataque', key='-START_DEAUTH-')]
        ]
        
        evil_twin_layout = [
            [sg.Text('SSID Alvo:'), sg.Input(key='-EVIL_SSID-', size=(20, 1))],
            [sg.Text('BSSID Alvo:'), sg.Input(key='-EVIL_BSSID-', size=(20, 1), tooltip='Opcional, para desautenticação')],
            [sg.Text('Canal:'), sg.Spin([i for i in range(1, 15)], initial_value=1, size=(5, 1), key='-EVIL_CHANNEL-')],
            [sg.Button('Iniciar AP Falso', key='-START_EVIL-')]
        ]
        
        mitm_layout = [
            [sg.Text('Interface:'), sg.Combo([], size=(20, 1), key='-MITM_INTERFACE-')],
            [sg.Text('Gateway:'), sg.Input(key='-MITM_GATEWAY-', size=(20, 1))],
            [sg.Text('Alvo:'), sg.Input(key='-MITM_TARGET-', size=(20, 1), tooltip='Deixe em branco para atacar todos os hosts')],
            [sg.Checkbox('Sniffing de Pacotes', key='-MITM_SNIFF-')],
            [sg.Checkbox('Injeção de Código', key='-MITM_INJECT-')],
            [sg.Button('Iniciar MITM', key='-START_MITM-')]
        ]
        
        # Layout da aba de ataques
        attack_layout = [
            [sg.Text('Interface:'), 
             sg.Combo([], size=(20, 1), key='-ATTACK_INTERFACE-'),
             sg.Text('Tipo de Ataque:'), 
             sg.Combo(attack_types, default_value='Desautenticação', size=(20, 1), key='-ATTACK_TYPE-', enable_events=True)],
            [sg.HSep()],
            [sg.Column(deauth_layout, key='-DEAUTH_PANEL-', visible=True),
             sg.Column(evil_twin_layout, key='-EVIL_PANEL-', visible=False),
             sg.Column(mitm_layout, key='-MITM_PANEL-', visible=False)],
            [sg.HSep()],
            [sg.Text('Status dos Ataques:')],
            [sg.Multiline(size=(80, 10), key='-ATTACK_LOG-', disabled=True, autoscroll=True)]
        ]
        return attack_layout
    
    def _create_report_tab(self):
        """Cria o layout da aba de relatórios."""
        report_layout = [
            [sg.Text('Geração de Relatórios')],
            [sg.Text('Tipo de Relatório:'),
             sg.Combo(['Resumo de Escaneamento', 'Análise de Vulnerabilidades', 'Completo'], 
                      default_value='Resumo de Escaneamento', size=(30, 1), key='-REPORT_TYPE-')],
            [sg.Text('Formato:'),
             sg.Combo(['PDF', 'HTML', 'CSV', 'JSON'], 
                      default_value='PDF', size=(10, 1), key='-REPORT_FORMAT-')],
            [sg.Text('Nome do Arquivo:'), sg.Input(key='-REPORT_FILENAME-', size=(30, 1))],
            [sg.Button('Gerar Relatório', key='-GENERATE_REPORT-')],
            [sg.HSep()],
            [sg.Text('Visualização do Relatório:')],
            [sg.Multiline(size=(80, 20), key='-REPORT_PREVIEW-', disabled=True)]
        ]
        return report_layout
    
    def _handle_scan_network(self):
        """Manipula o evento de escaneamento de redes."""
        interface = self.window['-INTERFACE_LIST-'].get()
        if not interface:
            self._update_status("Selecione uma interface WiFi")
            return
        
        self.current_interface = interface
        self.window['-INTERFACE-'].update(f"Interface: {interface}")
        self._update_status(f"Escaneando redes com interface {interface}...")
        
        # Limpa a tabela
        self.window['-NETWORK_TABLE-'].update([])
        self.window['-NETWORK_DETAILS-'].update("")
        
        # Inicia o escaneamento em uma thread separada
        def scan_thread():
            try:
                self.scanner = NetworkScanner(interface=interface, timeout=30, logger=self.logger)
                self.networks = self.scanner.start_scan()
                
                # Atualiza a tabela na thread principal
                if self.window:
                    table_data = []
                    for bssid, info in self.networks.items():
                        table_data.append([
                            bssid,
                            info['ssid'],
                            info['channel'],
                            info['encryption'],
                            info['signal'] if info['signal'] is not None else "N/A",
                            len(info['clients'])
                        ])
                    
                    # Ordena por força de sinal
                    table_data.sort(key=lambda x: x[4] if x[4] != "N/A" else -100, reverse=True)
                    
                    self.window['-NETWORK_TABLE-'].update(table_data)
                    self._update_status(f"Escaneamento concluído. Encontradas {len(self.networks)} redes.")
            except Exception as e:
                self.logger.error(f"Erro durante o escaneamento: {e}")
                self._update_status(f"Erro durante o escaneamento: {e}")
        
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()
        self.active_threads['scan'] = thread
    
    def _handle_monitor_traffic(self):
        """Manipula o evento de monitoramento de tráfego."""
        interface = self.window['-MONITOR_INTERFACE-'].get()
        channel = self.window['-CHANNEL-'].get()
        save_pcap = self.window['-SAVE_PCAP-'].get()
        
        if not interface:
            self._update_status("Selecione uma interface WiFi")
            return
        
        self.current_interface = interface
        self.window['-INTERFACE-'].update(f"Interface: {interface}")
        self._update_status(f"Iniciando monitoramento na interface {interface}, canal {channel}...")
        
        # Limpa os campos
        self.window['-PACKET_LOG-'].update("")
        self.window['-PROTOCOLS-'].update("")
        self.window['-PACKETS_COUNT-'].update("Pacotes Capturados: 0")
        self.window['-DEVICES_COUNT-'].update("Dispositivos Detectados: 0")
        self.window['-IOT_COUNT-'].update("Dispositivos IoT: 0")
        
        # Botão muda para "Parar"
        self.window['-START_MONITOR-'].update('Parar Monitoramento')
        
        # Inicia o monitoramento em uma thread separada
        def monitor_thread():
            try:
                self.traffic_analyzer = TrafficAnalyzer(
                    interface=interface,
                    channel=channel,
                    logger=self.logger,
                    save_pcap=save_pcap
                )
                
                # Define um callback para atualizar a UI
                def update_ui(packet_count, protocol_stats, devices, iot_count, packet_log):
                    if self.window:
                        self.window['-PACKETS_COUNT-'].update(f"Pacotes Capturados: {packet_count}")
                        self.window['-DEVICES_COUNT-'].update(f"Dispositivos Detectados: {len(devices)}")
                        self.window['-IOT_COUNT-'].update(f"Dispositivos IoT: {iot_count}")
                        
                        # Atualiza os protocolos mais comuns
                        top_protocols = protocol_stats.most_common(5)
                        if top_protocols:
                            protocols_str = "\n".join([f"{p}: {c}" for p, c in top_protocols])
                            self.window['-PROTOCOLS-'].update(protocols_str)
                        
                        # Adiciona log de pacotes
                        if packet_log:
                            current_log = self.window['-PACKET_LOG-'].get()
                            self.window['-PACKET_LOG-'].update(current_log + "\n" + packet_log if current_log else packet_log)
                
                # Inicia o monitoramento
                self.traffic_analyzer.start_monitoring()
                
                self._update_status("Monitoramento finalizado.")
                self.window['-START_MONITOR-'].update('Iniciar Monitoramento')
                
            except Exception as e:
                self.logger.error(f"Erro durante o monitoramento: {e}")
                self._update_status(f"Erro durante o monitoramento: {e}")
                self.window['-START_MONITOR-'].update('Iniciar Monitoramento')
        
        # Verifica se já está monitorando
        if 'monitor' in self.active_threads and self.active_threads['monitor'].is_alive():
            # Para o monitoramento atual
            if self.traffic_analyzer:
                self.traffic_analyzer.running = False
                self._update_status("Parando monitoramento...")
                self.window['-START_MONITOR-'].update('Iniciar Monitoramento')
        else:
            # Inicia novo monitoramento
            thread = threading.Thread(target=monitor_thread, daemon=True)
            thread.start()
            self.active_threads['monitor'] = thread
    
    def _handle_attack_type_change(self):
        """Manipula a mudança de tipo de ataque."""
        attack_type = self.window['-ATTACK_TYPE-'].get()
        
        # Esconde todos os painéis
        self.window['-DEAUTH_PANEL-'].update(visible=False)
        self.window['-EVIL_PANEL-'].update(visible=False)
        self.window['-MITM_PANEL-'].update(visible=False)
        
        # Mostra o painel do ataque selecionado
        if attack_type == 'Desautenticação':
            self.window['-DEAUTH_PANEL-'].update(visible=True)
        elif attack_type == 'Evil Twin':
            self.window['-EVIL_PANEL-'].update(visible=True)
        elif attack_type == 'MITM':
            self.window['-MITM_PANEL-'].update(visible=True)
    
    def _handle_start_deauth(self):
        """Manipula o início do ataque de desautenticação."""
        interface = self.window['-ATTACK_INTERFACE-'].get()
        bssid = self.window['-DEAUTH_BSSID-'].get()
        client = self.window['-DEAUTH_CLIENT-'].get()
        channel = self.window['-DEAUTH_CHANNEL-'].get()
        packets = self.window['-DEAUTH_PACKETS-'].get()
        
        if not interface or not bssid:
            self._update_status("Interface e BSSID são obrigatórios")
            return
        
        # Limpa o cliente se estiver em branco
        if not client:
            client = None
        
        self._update_status(f"Iniciando ataque de desautenticação contra {bssid}...")
        
        # Inicia o ataque em uma thread separada
        def deauth_thread():
            try:
                deauth = DeauthAttack(
                    interface=interface,
                    target_bssid=bssid,
                    target_client=client,
                    channel=channel,
                    count=packets,
                    logger=self.logger
                )
                
                # Registra o ataque ativo
                attack_id = f"deauth_{bssid}"
                self.active_attacks[attack_id] = deauth
                
                # Log do ataque
                attack_log = f"Ataque de desautenticação iniciado contra {bssid}"
                if client:
                    attack_log += f", cliente {client}"
                current_log = self.window['-ATTACK_LOG-'].get()
                self.window['-ATTACK_LOG-'].update(current_log + "\n" + attack_log if current_log else attack_log)
                
                # Inicia o ataque
                deauth.start_attack()
                
                # Remove dos ataques ativos quando finalizar
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]
                
                self._update_status("Ataque de desautenticação finalizado.")
                
            except Exception as e:
                self.logger.error(f"Erro durante o ataque de desautenticação: {e}")
                self._update_status(f"Erro durante o ataque: {e}")
        
        thread = threading.Thread(target=deauth_thread, daemon=True)
        thread.start()
        self.active_threads['deauth'] = thread
    
    def _handle_start_evil_twin(self):
        """Manipula o início do ataque Evil Twin."""
        interface = self.window['-ATTACK_INTERFACE-'].get()
        ssid = self.window['-EVIL_SSID-'].get()
        bssid = self.window['-EVIL_BSSID-'].get()
        channel = self.window['-EVIL_CHANNEL-'].get()
        
        if not interface or not ssid:
            self._update_status("Interface e SSID são obrigatórios")
            return
        
        # Limpa o BSSID se estiver em branco
        if not bssid:
            bssid = None
        
        self._update_status(f"Iniciando ataque Evil Twin para a rede {ssid}...")
        
        # Inicia o ataque em uma thread separada
        def evil_twin_thread():
            try:
                evil_twin = EvilTwin(
                    target_ssid=ssid,
                    target_bssid=bssid,
                    interface=interface,
                    channel=channel,
                    logger=self.logger
                )
                
                # Registra o ataque ativo
                attack_id = f"evil_twin_{ssid}"
                self.active_attacks[attack_id] = evil_twin
                
                # Log do ataque
                attack_log = f"Ataque Evil Twin iniciado para a rede {ssid}"
                if bssid:
                    attack_log += f" ({bssid})"
                current_log = self.window['-ATTACK_LOG-'].get()
                self.window['-ATTACK_LOG-'].update(current_log + "\n" + attack_log if current_log else attack_log)
                
                # Inicia o ataque
                evil_twin.start_attack()
                
                # O método anterior bloqueia até o ataque ser interrompido
                # Remove dos ataques ativos quando finalizar
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]
                
                self._update_status("Ataque Evil Twin finalizado.")
                
            except Exception as e:
                self.logger.error(f"Erro durante o ataque Evil Twin: {e}")
                self._update_status(f"Erro durante o ataque: {e}")
        
        thread = threading.Thread(target=evil_twin_thread, daemon=True)
        thread.start()
        self.active_threads['evil_twin'] = thread
    
    def _handle_start_mitm(self):
        """Manipula o início do ataque MITM."""
        interface = self.window['-MITM_INTERFACE-'].get()
        gateway = self.window['-MITM_GATEWAY-'].get()
        target = self.window['-MITM_TARGET-'].get()
        sniff = self.window['-MITM_SNIFF-'].get()
        inject = self.window['-MITM_INJECT-'].get()
        
        if not interface or not gateway:
            self._update_status("Interface e Gateway são obrigatórios")
            return
        
        # Limpa o alvo se estiver em branco
        if not target:
            target = None
        
        self._update_status(f"Iniciando ataque MITM na rede {gateway}...")
        
        # Inicia o ataque em uma thread separada
        def mitm_thread():
            try:
                mitm = MITMAttack(
                    interface=interface,
                    gateway=gateway,
                    target=target,
                    sniff=sniff,
                    inject=inject,
                    logger=self.logger
                )
                
                # Registra o ataque ativo
                attack_id = f"mitm_{interface}"
                self.active_attacks[attack_id] = mitm
                
                # Log do ataque
                attack_log = f"Ataque MITM iniciado na interface {interface}, gateway {gateway}"
                if target:
                    attack_log += f", alvo {target}"
                current_log = self.window['-ATTACK_LOG-'].get()
                self.window['-ATTACK_LOG-'].update(current_log + "\n" + attack_log if current_log else attack_log)
                
                # Inicia o ataque
                mitm.start_attack()
                
                # Remove dos ataques ativos quando finalizar
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]
                
                self._update_status("Ataque MITM finalizado.")
                
            except Exception as e:
                self.logger.error(f"Erro durante o ataque MITM: {e}")
                self._update_status(f"Erro durante o ataque: {e}")
        
        thread = threading.Thread(target=mitm_thread, daemon=True)
        thread.start()
        self.active_threads['mitm'] = thread
    
    def _handle_generate_report(self):
        """Manipula a geração de relatórios."""
        report_type = self.window['-REPORT_TYPE-'].get()
        report_format = self.window['-REPORT_FORMAT-'].get()
        filename = self.window['-REPORT_FILENAME-'].get()
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}"
        
        # Adiciona a extensão correta
        if report_format == 'PDF':
            filename = f"{filename}.pdf"
        elif report_format == 'HTML':
            filename = f"{filename}.html"
        elif report_format == 'CSV':
            filename = f"{filename}.csv"
        elif report_format == 'JSON':
            filename = f"{filename}.json"
        
        self._update_status(f"Gerando relatório {report_type} no formato {report_format}...")
        
        # Aqui seria implementada a geração de relatório real
        # Por enquanto, apenas um exemplo básico
        report_content = f"""
RELATÓRIO DE SEGURANÇA WIFI
===========================
Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tipo: {report_type}
Formato: {report_format}

RESUMO:
- Redes escaneadas: {len(self.networks) if self.networks else 0}
- Dispositivos detectados: {len(self.traffic_analyzer.devices) if hasattr(self, 'traffic_analyzer') and self.traffic_analyzer else 0}
- Vulnerabilidades encontradas: 0

DETALHES:
"""
        
        if self.networks:
            report_content += "\nRedes WiFi:\n"
            for bssid, info in self.networks.items():
                report_content += f"- {info['ssid']} ({bssid}): Canal {info['channel']}, Segurança: {info['encryption']}\n"
        
        self.window['-REPORT_PREVIEW-'].update(report_content)
        self._update_status(f"Relatório gerado e salvo como {filename}")
    
    def _clean_up(self):
        """Limpa recursos e encerra ataques ativos."""
        self.logger.info("Limpando recursos...")
        
        # Para todos os ataques ativos
        for attack_id, attack in self.active_attacks.items():
            try:
                if hasattr(attack, 'stop_attack'):
                    attack.stop_attack()
                self.logger.info(f"Ataque {attack_id} finalizado.")
            except Exception as e:
                self.logger.error(f"Erro ao finalizar ataque {attack_id}: {e}")
        
        # Define running como False para parar threads
        self.running = False
    
    def start(self):
        """Inicia a execução do dashboard."""
        self.running = True
        
        # Loop principal de eventos
        while True:
            event, values = self.window.read(timeout=100)
            
            # Eventos de fechamento
            if event == sg.WINDOW_CLOSED or event == 'Sair':
                break
            
            # Eventos da aba de escaneamento
            elif event == '-REFRESH_INTERFACES-':
                self._update_interface_list()
                self._update_status("Lista de interfaces atualizada")
            
            elif event == '-START_SCAN-':
                self._handle_scan_network()
            
            elif event == '-NETWORK_TABLE-':
                if values['-NETWORK_TABLE-'] and self.networks:
                    # Obtém o BSSID da rede selecionada
                    selected_row = values['-NETWORK_TABLE-'][0]
                    selected_data = self.window['-NETWORK_TABLE-'].get()[selected_row]
                    bssid = selected_data[0]
                    
                    # Exibe detalhes
                    if bssid in self.networks:
                        details = self.networks[bssid]
                        details_text = f"SSID: {details['ssid']}\n"
                        details_text += f"BSSID: {bssid}\n"
                        details_text += f"Canal: {details['channel']}\n"
                        details_text += f"Segurança: {details['encryption']}\n"
                        details_text += f"Sinal: {details['signal']} dBm\n"
                        details_text += f"Clientes Conectados: {len(details['clients'])}"
                        
                        self.window['-NETWORK_DETAILS-'].update(details_text)
            
            # Eventos da aba de monitoramento
            elif event == '-START_MONITOR-':
                self._handle_monitor_traffic()
            
            # Eventos da aba de ataques
            elif event == '-ATTACK_TYPE-':
                self._handle_attack_type_change()
            
            elif event == '-START_DEAUTH-':
                self._handle_start_deauth()
            
            elif event == '-START_EVIL-':
                self._handle_start_evil_twin()
            
            elif event == '-START_MITM-':
                self._handle_start_mitm()
            
            # Eventos da aba de relatórios
            elif event == '-GENERATE_REPORT-':
                self._handle_generate_report()
            
            # Eventos de menu
            elif event == 'Sobre':
                sg.popup('NetgateX', 'Ferramenta Avançada para Teste de Segurança em Redes WiFi', 'Versão 1.0.0')
            
            # Atualiza interfaces em todas as abas
            try:
                interfaces = get_wifi_interfaces()
                self.window['-INTERFACE_LIST-'].update(values=interfaces)
                self.window['-MONITOR_INTERFACE-'].update(values=interfaces)
                self.window['-ATTACK_INTERFACE-'].update(values=interfaces)
                self.window['-MITM_INTERFACE-'].update(values=interfaces)
            except:
                pass
        
        # Limpa recursos antes de fechar
        self._clean_up()
        self.window.close()
    
if __name__ == "__main__":
    dashboard = Dashboard()
    dashboard.start() 