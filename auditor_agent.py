import os
import logging
import threading
import queue
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable
import json

from src.models.contract import db, Contract, Audit, Vulnerability
from src.auditor.monitor.blockchain_monitor import BlockchainMonitor
from src.auditor.retriever.code_retriever import CodeRetriever
from src.auditor.analyzer.security_analyzer import SecurityAnalyzer
from src.auditor.reporter.report_generator import ReportGenerator
from src.auditor.alerter.alert_system import AlertSystem

class EthereumAuditorAgent:
    """
    Agente principal que coordena todo o processo de auditoria de smart contracts.
    Integra monitoramento, recuperação de código, análise, relatórios e alertas.
    """
    
    def __init__(self, config: Dict[str, Any], flask_app=None):
        """
        Inicializa o agente auditor.
        
        Args:
            config: Configuração do agente
            flask_app: Instância da aplicação Flask para contexto de banco de dados
        """
        self.config = config
        self.flask_app = flask_app
        self.logger = logging.getLogger(__name__)
        
        # Estado do agente
        self.is_running = False
        self.start_time = None
        
        # Fila de processamento de contratos
        self.contract_queue = queue.Queue()
        self.processing_threads = []
        self.max_concurrent_audits = config.get('max_concurrent_audits', 3)
        
        # Componentes do agente
        self.blockchain_monitor = None
        self.code_retriever = None
        self.security_analyzer = None
        self.report_generator = None
        self.alert_system = None
        
        # Estatísticas
        self.stats = {
            'contracts_detected': 0,
            'contracts_processed': 0,
            'contracts_failed': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'reports_generated': 0,
            'alerts_sent': 0,
            'uptime_seconds': 0
        }
        
        # Inicializa componentes
        self._initialize_components()
    
    def _initialize_components(self) -> None:
        """
        Inicializa todos os componentes do agente.
        """
        try:
            # Monitor de blockchain
            web3_url = self.config.get('web3_provider_url', 'wss://mainnet.infura.io/ws/v3/YOUR_PROJECT_ID')
            self.blockchain_monitor = BlockchainMonitor(web3_url, self._on_new_contract_detected)
            
            # Recuperador de código
            etherscan_api_key = self.config.get('etherscan_api_key', '')
            self.code_retriever = CodeRetriever(etherscan_api_key)
            
            # Analisador de segurança
            analyzer_config = self.config.get('analyzer', {})
            self.security_analyzer = SecurityAnalyzer(analyzer_config)
            
            # Gerador de relatórios
            reports_dir = self.config.get('reports_dir', 'reports')
            self.report_generator = ReportGenerator(reports_dir)
            
            # Sistema de alertas
            alert_config = self.config.get('alerts', {})
            self.alert_system = AlertSystem(alert_config)
            
            self.logger.info("Componentes do agente inicializados com sucesso")
            
        except Exception as e:
            self.logger.error(f"Erro ao inicializar componentes: {e}")
            raise
    
    def _on_new_contract_detected(self, contract_info: Dict[str, Any]) -> None:
        """
        Callback chamado quando um novo contrato é detectado.
        
        Args:
            contract_info: Informações do contrato detectado
        """
        try:
            self.logger.info(f"Novo contrato detectado: {contract_info.get('address')}")
            
            # Adiciona à fila de processamento
            self.contract_queue.put(contract_info)
            self.stats['contracts_detected'] += 1
            
        except Exception as e:
            self.logger.error(f"Erro ao processar contrato detectado: {e}")
    
    def _contract_processor_worker(self, worker_id: int) -> None:
        """
        Worker thread que processa contratos da fila.
        
        Args:
            worker_id: ID do worker
        """
        self.logger.info(f"Worker {worker_id} iniciado")
        
        while self.is_running:
            try:
                # Pega próximo contrato da fila (timeout para permitir parada)
                contract_info = self.contract_queue.get(timeout=1)
                
                if contract_info is None:  # Sinal para parar
                    break
                
                self.logger.info(f"Worker {worker_id} processando contrato {contract_info.get('address')}")
                
                # Processa o contrato
                success = self._process_contract(contract_info)
                
                if success:
                    self.stats['contracts_processed'] += 1
                else:
                    self.stats['contracts_failed'] += 1
                
                self.contract_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Erro no worker {worker_id}: {e}")
                self.stats['contracts_failed'] += 1
        
        self.logger.info(f"Worker {worker_id} finalizado")
    
    def _process_contract(self, contract_info: Dict[str, Any]) -> bool:
        """
        Processa um contrato completo: recupera código, analisa, gera relatório e envia alertas.
        
        Args:
            contract_info: Informações do contrato
            
        Returns:
            bool: True se processado com sucesso
        """
        contract_address = contract_info.get('address')
        
        if not contract_address:
            self.logger.error("Endereço do contrato não fornecido")
            return False
        
        try:
            with self.flask_app.app_context() if self.flask_app else self._dummy_context():
                # 1. Verifica se contrato já existe no banco
                existing_contract = Contract.query.filter_by(address=contract_address).first()
                
                if existing_contract and existing_contract.audit_status == 'completed':
                    self.logger.info(f"Contrato {contract_address} já foi auditado")
                    return True
                
                # 2. Cria ou atualiza registro do contrato
                if not existing_contract:
                    contract_record = Contract(
                        address=contract_address,
                        transaction_hash=contract_info.get('transaction_hash', ''),
                        block_number=contract_info.get('block_number', 0),
                        creator_address=contract_info.get('creator_address', ''),
                        audit_status='pending'
                    )
                    db.session.add(contract_record)
                else:
                    contract_record = existing_contract
                    contract_record.audit_status = 'in_progress'
                
                db.session.commit()
                
                # 3. Recupera código do contrato
                self.logger.info(f"Recuperando código do contrato {contract_address}")
                complete_contract_info = self.code_retriever.retrieve_complete_contract_info(contract_address)
                
                # Atualiza registro com informações recuperadas
                if complete_contract_info.get('is_verified'):
                    contract_record.is_verified = True
                    contract_record.verification_date = datetime.utcnow()
                    contract_record.source_code = complete_contract_info.get('source_code')
                    contract_record.abi = complete_contract_info.get('abi')
                    
                    metadata = complete_contract_info.get('metadata', {})
                    contract_record.name = metadata.get('contract_name')
                    contract_record.compiler_version = metadata.get('compiler_version')
                    contract_record.optimization_enabled = metadata.get('optimization_used', False)
                    contract_record.runs = metadata.get('runs', 0)
                
                contract_record.bytecode = complete_contract_info.get('bytecode')
                db.session.commit()
                
                # 4. Executa análise de segurança (apenas se tiver código-fonte)
                if complete_contract_info.get('source_code'):
                    self.logger.info(f"Executando análise de segurança do contrato {contract_address}")
                    analysis_result = self.security_analyzer.analyze_contract(complete_contract_info)
                    
                    # 5. Salva resultado da análise no banco
                    audit_record = Audit(
                        contract_id=contract_record.id,
                        audit_type='comprehensive',
                        tool_name='multi-tool',
                        status=analysis_result.get('status', 'failed'),
                        started_at=analysis_result.get('started_at'),
                        completed_at=analysis_result.get('completed_at'),
                        duration_seconds=analysis_result.get('duration_seconds'),
                        raw_output=json.dumps(analysis_result, default=str)
                    )
                    
                    # Estatísticas de vulnerabilidades
                    vulnerabilities = analysis_result.get('vulnerabilities', [])
                    risk_assessment = analysis_result.get('risk_assessment', {})
                    severity_counts = risk_assessment.get('severity_counts', {})
                    
                    audit_record.vulnerabilities_found = len(vulnerabilities)
                    audit_record.critical_count = severity_counts.get('critical', 0)
                    audit_record.high_count = severity_counts.get('high', 0)
                    audit_record.medium_count = severity_counts.get('medium', 0)
                    audit_record.low_count = severity_counts.get('low', 0)
                    audit_record.info_count = severity_counts.get('info', 0)
                    
                    db.session.add(audit_record)
                    db.session.commit()
                    
                    # Salva vulnerabilidades individuais
                    for vuln_data in vulnerabilities:
                        vulnerability = Vulnerability(
                            audit_id=audit_record.id,
                            title=vuln_data.get('title', ''),
                            description=vuln_data.get('description', ''),
                            severity=vuln_data.get('severity', 'info'),
                            category=vuln_data.get('category', ''),
                            file_path=vuln_data.get('file_path', ''),
                            line_number=vuln_data.get('line_number'),
                            function_name=vuln_data.get('function_name', ''),
                            code_snippet=vuln_data.get('code_snippet', ''),
                            impact=vuln_data.get('impact', ''),
                            recommendation=vuln_data.get('recommendation', ''),
                            confidence=vuln_data.get('confidence', 'medium')
                        )
                        db.session.add(vulnerability)
                    
                    db.session.commit()
                    
                    # 6. Gera relatórios
                    self.logger.info(f"Gerando relatórios para contrato {contract_address}")
                    reports = self.report_generator.generate_all_formats(analysis_result, complete_contract_info)
                    
                    # Atualiza caminho do relatório principal
                    if reports.get('pdf'):
                        audit_record.report_path = reports['pdf']
                        db.session.commit()
                    
                    self.stats['reports_generated'] += 1
                    
                    # 7. Envia alertas se necessário
                    if severity_counts.get('critical', 0) > 0 or severity_counts.get('high', 0) > 0:
                        self.logger.info(f"Enviando alertas para contrato {contract_address}")
                        self.alert_system.send_alert(analysis_result, complete_contract_info)
                        self.stats['alerts_sent'] += 1
                    
                    # Atualiza estatísticas
                    self.stats['total_vulnerabilities'] += len(vulnerabilities)
                    self.stats['critical_vulnerabilities'] += severity_counts.get('critical', 0)
                    self.stats['high_vulnerabilities'] += severity_counts.get('high', 0)
                    
                    contract_record.audit_status = 'completed'
                    contract_record.last_audit_date = datetime.utcnow()
                    
                else:
                    # Contrato não verificado - marca como concluído mas sem análise
                    contract_record.audit_status = 'completed'
                    self.logger.info(f"Contrato {contract_address} não verificado - pulando análise")
                
                db.session.commit()
                
                self.logger.info(f"Processamento do contrato {contract_address} concluído com sucesso")
                return True
                
        except Exception as e:
            self.logger.error(f"Erro ao processar contrato {contract_address}: {e}")
            
            # Marca contrato como falhou
            try:
                with self.flask_app.app_context() if self.flask_app else self._dummy_context():
                    contract_record = Contract.query.filter_by(address=contract_address).first()
                    if contract_record:
                        contract_record.audit_status = 'failed'
                        db.session.commit()
            except:
                pass
            
            return False
    
    def _dummy_context(self):
        """
        Context manager dummy para quando não há Flask app.
        """
        class DummyContext:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        return DummyContext()
    
    def start(self) -> bool:
        """
        Inicia o agente auditor.
        
        Returns:
            bool: True se iniciado com sucesso
        """
        if self.is_running:
            self.logger.warning("Agente já está em execução")
            return False
        
        try:
            self.logger.info("Iniciando Agente Auditor de Smart Contracts Ethereum...")
            
            # Inicia sistema de alertas
            if not self.alert_system.start():
                self.logger.error("Falha ao iniciar sistema de alertas")
                return False
            
            # Inicia workers de processamento
            self.is_running = True
            self.start_time = datetime.utcnow()
            
            for i in range(self.max_concurrent_audits):
                worker_thread = threading.Thread(
                    target=self._contract_processor_worker,
                    args=(i,),
                    daemon=True
                )
                worker_thread.start()
                self.processing_threads.append(worker_thread)
            
            # Inicia monitor de blockchain
            if not self.blockchain_monitor.start():
                self.logger.error("Falha ao iniciar monitor de blockchain")
                self.stop()
                return False
            
            self.logger.info("Agente Auditor iniciado com sucesso!")
            self.logger.info(f"Monitorando contratos na rede Ethereum...")
            self.logger.info(f"Workers de processamento: {self.max_concurrent_audits}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar agente: {e}")
            self.stop()
            return False
    
    def stop(self) -> None:
        """
        Para o agente auditor.
        """
        if not self.is_running:
            return
        
        self.logger.info("Parando Agente Auditor...")
        
        # Para monitor de blockchain
        if self.blockchain_monitor:
            self.blockchain_monitor.stop()
        
        # Para workers
        self.is_running = False
        
        # Adiciona sinais de parada na fila
        for _ in range(len(self.processing_threads)):
            self.contract_queue.put(None)
        
        # Aguarda workers terminarem
        for thread in self.processing_threads:
            if thread.is_alive():
                thread.join(timeout=10)
        
        # Para sistema de alertas
        if self.alert_system:
            self.alert_system.stop()
        
        # Limpa recursos
        if self.security_analyzer:
            self.security_analyzer.cleanup()
        
        self.logger.info("Agente Auditor parado")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Retorna status atual do agente.
        
        Returns:
            Dict com informações de status
        """
        status = {
            'is_running': self.is_running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'uptime_seconds': (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0,
            'queue_size': self.contract_queue.qsize(),
            'active_workers': len([t for t in self.processing_threads if t.is_alive()]),
            'stats': self.stats.copy()
        }
        
        # Adiciona estatísticas dos componentes
        if self.blockchain_monitor:
            status['blockchain_monitor'] = self.blockchain_monitor.get_stats()
        
        if self.code_retriever:
            status['code_retriever'] = self.code_retriever.get_stats()
        
        if self.security_analyzer:
            status['security_analyzer'] = self.security_analyzer.get_stats()
        
        if self.alert_system:
            status['alert_system'] = self.alert_system.get_stats()
        
        return status
    
    def process_single_contract(self, contract_address: str) -> Dict[str, Any]:
        """
        Processa um único contrato manualmente (útil para testes).
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Dict com resultado do processamento
        """
        contract_info = {
            'address': contract_address,
            'transaction_hash': '',
            'block_number': 0,
            'creator_address': '',
            'timestamp': datetime.utcnow()
        }
        
        success = self._process_contract(contract_info)
        
        return {
            'success': success,
            'contract_address': contract_address,
            'processed_at': datetime.utcnow().isoformat()
        }


def create_default_config() -> Dict[str, Any]:
    """
    Cria configuração padrão para o agente auditor.
    
    Returns:
        Dict com configuração padrão
    """
    return {
        'web3_provider_url': 'wss://mainnet.infura.io/ws/v3/YOUR_PROJECT_ID',
        'etherscan_api_key': 'YOUR_ETHERSCAN_API_KEY',
        'max_concurrent_audits': 3,
        'reports_dir': 'reports',
        'analyzer': {
            'slither': {
                'enabled': True,
                'timeout': 300
            },
            'custom_patterns': {
                'enabled': True,
                'timeout': 60
            }
        },
        'alerts': {
            'webhook': {
                'enabled': False,
                'url': ''
            },
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'to_emails': []
            },
            'filters': {
                'min_severity': 'high'
            }
        }
    }

