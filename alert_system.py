import json
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import threading
import queue
import time

class AlertSystem:
    """
    Sistema de alertas que notifica sobre vulnerabilidades críticas encontradas
    em smart contracts através de múltiplos canais (webhook, email, etc.).
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Inicializa o sistema de alertas.
        
        Args:
            config: Configuração dos canais de alerta
        """
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(__name__)
        
        # Fila de alertas para processamento assíncrono
        self.alert_queue = queue.Queue()
        self.is_running = False
        self.worker_thread = None
        
        # Estatísticas
        self.stats = {
            'alerts_sent': 0,
            'webhook_alerts': 0,
            'email_alerts': 0,
            'failed_alerts': 0,
            'last_alert_time': None
        }
        
        # Filtros de severidade
        self.severity_levels = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Retorna configuração padrão do sistema de alertas.
        
        Returns:
            Dict com configuração padrão
        """
        return {
            'webhook': {
                'enabled': False,
                'url': '',
                'timeout': 30,
                'retry_attempts': 3,
                'retry_delay': 5
            },
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_email': '',
                'to_emails': [],
                'use_tls': True
            },
            'slack': {
                'enabled': False,
                'webhook_url': '',
                'channel': '#security-alerts',
                'username': 'Ethereum Auditor Bot'
            },
            'discord': {
                'enabled': False,
                'webhook_url': ''
            },
            'filters': {
                'min_severity': 'high',  # Apenas high e critical por padrão
                'max_alerts_per_contract': 10,
                'cooldown_minutes': 5  # Evita spam de alertas
            }
        }
    
    def start(self) -> bool:
        """
        Inicia o sistema de alertas.
        
        Returns:
            bool: True se iniciado com sucesso
        """
        if self.is_running:
            self.logger.warning("Sistema de alertas já está em execução")
            return False
        
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._alert_worker, daemon=True)
        self.worker_thread.start()
        
        self.logger.info("Sistema de alertas iniciado")
        return True
    
    def stop(self) -> None:
        """
        Para o sistema de alertas.
        """
        if not self.is_running:
            return
        
        self.logger.info("Parando sistema de alertas...")
        self.is_running = False
        
        # Adiciona item especial para sinalizar parada
        self.alert_queue.put(None)
        
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=10)
        
        self.logger.info("Sistema de alertas parado")
    
    def _alert_worker(self) -> None:
        """
        Worker thread que processa a fila de alertas.
        """
        self.logger.info("Worker de alertas iniciado")
        
        while self.is_running:
            try:
                # Pega próximo alerta da fila (bloqueia até ter um)
                alert_data = self.alert_queue.get(timeout=1)
                
                # Sinal para parar
                if alert_data is None:
                    break
                
                self._process_alert(alert_data)
                self.alert_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Erro no worker de alertas: {e}")
        
        self.logger.info("Worker de alertas finalizado")
    
    def _process_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Processa um alerta individual.
        
        Args:
            alert_data: Dados do alerta
        """
        try:
            # Verifica filtros
            if not self._should_send_alert(alert_data):
                return
            
            # Envia para todos os canais habilitados
            success_count = 0
            total_channels = 0
            
            if self.config['webhook']['enabled']:
                total_channels += 1
                if self._send_webhook_alert(alert_data):
                    success_count += 1
                    self.stats['webhook_alerts'] += 1
            
            if self.config['email']['enabled']:
                total_channels += 1
                if self._send_email_alert(alert_data):
                    success_count += 1
                    self.stats['email_alerts'] += 1
            
            if self.config['slack']['enabled']:
                total_channels += 1
                if self._send_slack_alert(alert_data):
                    success_count += 1
            
            if self.config['discord']['enabled']:
                total_channels += 1
                if self._send_discord_alert(alert_data):
                    success_count += 1
            
            # Atualiza estatísticas
            if success_count > 0:
                self.stats['alerts_sent'] += 1
                self.stats['last_alert_time'] = datetime.utcnow()
                
                self.logger.info(f"Alerta enviado com sucesso para {success_count}/{total_channels} canais")
            else:
                self.stats['failed_alerts'] += 1
                self.logger.error("Falha ao enviar alerta para todos os canais")
                
        except Exception as e:
            self.logger.error(f"Erro ao processar alerta: {e}")
            self.stats['failed_alerts'] += 1
    
    def _should_send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Verifica se um alerta deve ser enviado baseado nos filtros.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            bool: True se deve enviar o alerta
        """
        try:
            # Verifica severidade mínima
            min_severity = self.config['filters']['min_severity']
            alert_severity = alert_data.get('severity', 'info')
            
            min_level = self.severity_levels.get(min_severity, 4)
            alert_level = self.severity_levels.get(alert_severity, 4)
            
            if alert_level > min_level:
                return False
            
            # Outros filtros podem ser adicionados aqui
            # Por exemplo: cooldown, limite por contrato, etc.
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar filtros de alerta: {e}")
            return False
    
    def _send_webhook_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Envia alerta via webhook.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            bool: True se enviado com sucesso
        """
        webhook_config = self.config['webhook']
        
        if not webhook_config.get('url'):
            self.logger.error("URL do webhook não configurada")
            return False
        
        try:
            payload = {
                'timestamp': datetime.utcnow().isoformat(),
                'alert_type': 'smart_contract_vulnerability',
                'contract_address': alert_data.get('contract_address'),
                'severity': alert_data.get('severity'),
                'vulnerability_count': alert_data.get('vulnerability_count', 0),
                'risk_level': alert_data.get('risk_level'),
                'vulnerabilities': alert_data.get('vulnerabilities', []),
                'report_url': alert_data.get('report_url'),
                'message': self._format_alert_message(alert_data)
            }
            
            for attempt in range(webhook_config.get('retry_attempts', 3)):
                try:
                    response = requests.post(
                        webhook_config['url'],
                        json=payload,
                        timeout=webhook_config.get('timeout', 30),
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 200:
                        self.logger.info("Alerta webhook enviado com sucesso")
                        return True
                    else:
                        self.logger.warning(f"Webhook retornou status {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Tentativa {attempt + 1} de webhook falhou: {e}")
                    
                    if attempt < webhook_config.get('retry_attempts', 3) - 1:
                        time.sleep(webhook_config.get('retry_delay', 5))
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar webhook: {e}")
            return False
    
    def _send_email_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Envia alerta via email.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            bool: True se enviado com sucesso
        """
        email_config = self.config['email']
        
        if not email_config.get('to_emails'):
            self.logger.error("Lista de emails de destino não configurada")
            return False
        
        try:
            # Cria mensagem
            msg = MIMEMultipart()
            msg['From'] = email_config.get('from_email', email_config.get('username'))
            msg['To'] = ', '.join(email_config['to_emails'])
            msg['Subject'] = f"🚨 Alerta de Segurança - Contrato {alert_data.get('contract_address', 'Unknown')}"
            
            # Corpo do email
            body = self._format_email_body(alert_data)
            msg.attach(MIMEText(body, 'html'))
            
            # Envia email
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            
            if email_config.get('use_tls', True):
                server.starttls()
            
            if email_config.get('username') and email_config.get('password'):
                server.login(email_config['username'], email_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info("Alerta email enviado com sucesso")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar email: {e}")
            return False
    
    def _send_slack_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Envia alerta para Slack.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            bool: True se enviado com sucesso
        """
        slack_config = self.config['slack']
        
        if not slack_config.get('webhook_url'):
            self.logger.error("URL do webhook Slack não configurada")
            return False
        
        try:
            # Emoji baseado na severidade
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢',
                'info': '🔵'
            }.get(alert_data.get('severity', 'info'), '⚫')
            
            payload = {
                'channel': slack_config.get('channel', '#security-alerts'),
                'username': slack_config.get('username', 'Ethereum Auditor Bot'),
                'icon_emoji': ':warning:',
                'attachments': [{
                    'color': self._get_slack_color(alert_data.get('severity', 'info')),
                    'title': f"{severity_emoji} Vulnerabilidade Detectada em Smart Contract",
                    'fields': [
                        {
                            'title': 'Contrato',
                            'value': f"`{alert_data.get('contract_address', 'Unknown')}`",
                            'short': True
                        },
                        {
                            'title': 'Severidade',
                            'value': alert_data.get('severity', 'Unknown').upper(),
                            'short': True
                        },
                        {
                            'title': 'Nível de Risco',
                            'value': alert_data.get('risk_level', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Vulnerabilidades',
                            'value': str(alert_data.get('vulnerability_count', 0)),
                            'short': True
                        }
                    ],
                    'footer': 'Ethereum Smart Contract Auditor',
                    'ts': int(datetime.utcnow().timestamp())
                }]
            }
            
            response = requests.post(
                slack_config['webhook_url'],
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Alerta Slack enviado com sucesso")
                return True
            else:
                self.logger.error(f"Slack retornou status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao enviar alerta Slack: {e}")
            return False
    
    def _send_discord_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Envia alerta para Discord.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            bool: True se enviado com sucesso
        """
        discord_config = self.config['discord']
        
        if not discord_config.get('webhook_url'):
            self.logger.error("URL do webhook Discord não configurada")
            return False
        
        try:
            severity_color = {
                'critical': 0xFF0000,  # Vermelho
                'high': 0xFF8C00,      # Laranja
                'medium': 0xFFD700,    # Dourado
                'low': 0x00FF00,       # Verde
                'info': 0x0000FF       # Azul
            }.get(alert_data.get('severity', 'info'), 0x808080)
            
            payload = {
                'embeds': [{
                    'title': '🚨 Vulnerabilidade Detectada em Smart Contract',
                    'color': severity_color,
                    'fields': [
                        {
                            'name': 'Contrato',
                            'value': f"`{alert_data.get('contract_address', 'Unknown')}`",
                            'inline': True
                        },
                        {
                            'name': 'Severidade',
                            'value': alert_data.get('severity', 'Unknown').upper(),
                            'inline': True
                        },
                        {
                            'name': 'Nível de Risco',
                            'value': alert_data.get('risk_level', 'Unknown'),
                            'inline': True
                        },
                        {
                            'name': 'Total de Vulnerabilidades',
                            'value': str(alert_data.get('vulnerability_count', 0)),
                            'inline': True
                        }
                    ],
                    'footer': {
                        'text': 'Ethereum Smart Contract Auditor'
                    },
                    'timestamp': datetime.utcnow().isoformat()
                }]
            }
            
            response = requests.post(
                discord_config['webhook_url'],
                json=payload,
                timeout=30
            )
            
            if response.status_code == 204:  # Discord retorna 204 para sucesso
                self.logger.info("Alerta Discord enviado com sucesso")
                return True
            else:
                self.logger.error(f"Discord retornou status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erro ao enviar alerta Discord: {e}")
            return False
    
    def _get_slack_color(self, severity: str) -> str:
        """
        Retorna cor para Slack baseada na severidade.
        
        Args:
            severity: Nível de severidade
            
        Returns:
            Cor em formato hex
        """
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': '#FFD700',
            'low': 'good',
            'info': '#0000FF'
        }
        return colors.get(severity, '#808080')
    
    def _format_alert_message(self, alert_data: Dict[str, Any]) -> str:
        """
        Formata mensagem de alerta.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            Mensagem formatada
        """
        contract_address = alert_data.get('contract_address', 'Unknown')
        severity = alert_data.get('severity', 'Unknown').upper()
        risk_level = alert_data.get('risk_level', 'Unknown')
        vuln_count = alert_data.get('vulnerability_count', 0)
        
        message = f"🚨 ALERTA DE SEGURANÇA 🚨\n\n"
        message += f"Contrato: {contract_address}\n"
        message += f"Severidade: {severity}\n"
        message += f"Nível de Risco: {risk_level}\n"
        message += f"Vulnerabilidades Encontradas: {vuln_count}\n"
        message += f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        
        return message
    
    def _format_email_body(self, alert_data: Dict[str, Any]) -> str:
        """
        Formata corpo do email de alerta.
        
        Args:
            alert_data: Dados do alerta
            
        Returns:
            HTML do corpo do email
        """
        contract_address = alert_data.get('contract_address', 'Unknown')
        severity = alert_data.get('severity', 'Unknown').upper()
        risk_level = alert_data.get('risk_level', 'Unknown')
        vuln_count = alert_data.get('vulnerability_count', 0)
        vulnerabilities = alert_data.get('vulnerabilities', [])
        
        html = f"""
        <html>
        <body>
            <h2 style="color: red;">🚨 Alerta de Segurança - Smart Contract</h2>
            
            <h3>Informações Gerais</h3>
            <ul>
                <li><strong>Contrato:</strong> <code>{contract_address}</code></li>
                <li><strong>Severidade:</strong> <span style="color: red;">{severity}</span></li>
                <li><strong>Nível de Risco:</strong> {risk_level}</li>
                <li><strong>Total de Vulnerabilidades:</strong> {vuln_count}</li>
                <li><strong>Timestamp:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
            </ul>
            
            <h3>Vulnerabilidades Críticas</h3>
            <ul>
        """
        
        for vuln in vulnerabilities[:5]:  # Mostra apenas as 5 primeiras
            if vuln.get('severity') in ['critical', 'high']:
                html += f"<li><strong>{vuln.get('title', 'Vulnerabilidade')}</strong> - {vuln.get('severity', 'Unknown').upper()}</li>"
        
        html += """
            </ul>
            
            <p><em>Este é um alerta automático gerado pelo Agente Auditor de Smart Contracts Ethereum.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def send_alert(self, analysis_result: Dict[str, Any], contract_info: Dict[str, Any]) -> None:
        """
        Envia alerta baseado no resultado da análise.
        
        Args:
            analysis_result: Resultado da análise de segurança
            contract_info: Informações do contrato
        """
        try:
            risk_assessment = analysis_result.get('risk_assessment', {})
            vulnerabilities = analysis_result.get('vulnerabilities', [])
            
            # Verifica se há vulnerabilidades que justifiquem alerta
            critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
            high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
            
            if not critical_vulns and not high_vulns:
                return  # Não envia alerta para vulnerabilidades menores
            
            # Determina severidade do alerta
            alert_severity = 'critical' if critical_vulns else 'high'
            
            alert_data = {
                'contract_address': analysis_result.get('contract_address'),
                'severity': alert_severity,
                'risk_level': risk_assessment.get('risk_level', 'Unknown'),
                'vulnerability_count': len(vulnerabilities),
                'critical_count': len(critical_vulns),
                'high_count': len(high_vulns),
                'vulnerabilities': vulnerabilities,
                'analysis_id': analysis_result.get('analysis_id'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Adiciona à fila de processamento
            self.alert_queue.put(alert_data)
            
            self.logger.info(f"Alerta adicionado à fila para contrato {alert_data['contract_address']}")
            
        except Exception as e:
            self.logger.error(f"Erro ao preparar alerta: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do sistema de alertas.
        
        Returns:
            Dict com estatísticas
        """
        stats = self.stats.copy()
        stats['is_running'] = self.is_running
        stats['queue_size'] = self.alert_queue.qsize()
        return stats

