import asyncio
import logging
from web3 import Web3
try:
    from web3.middleware import geth_poa_middleware
except ImportError:
    # Fallback para versões mais recentes do web3
    try:
        from web3.middleware.proof_of_authority import geth_poa_middleware
    except ImportError:
        geth_poa_middleware = None
import threading
import time
from datetime import datetime
from typing import Callable, Optional, Dict, Any
import json

class BlockchainMonitor:
    """
    Monitor de blockchain que detecta novos contratos implantados na rede Ethereum.
    Utiliza WebSocket para monitoramento em tempo real.
    """
    
    def __init__(self, web3_provider_url: str, callback: Callable[[Dict[str, Any]], None]):
        """
        Inicializa o monitor de blockchain.
        
        Args:
            web3_provider_url: URL do provedor Web3 (WebSocket recomendado)
            callback: Função callback para processar novos contratos detectados
        """
        self.web3_provider_url = web3_provider_url
        self.callback = callback
        self.w3 = None
        self.is_running = False
        self.monitor_thread = None
        self.last_processed_block = 0
        
        # Configuração de logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Estatísticas
        self.stats = {
            'blocks_processed': 0,
            'contracts_detected': 0,
            'start_time': None,
            'last_block_time': None
        }
    
    def connect(self) -> bool:
        """
        Conecta ao provedor Web3.
        
        Returns:
            bool: True se conectado com sucesso, False caso contrário
        """
        try:
            if self.web3_provider_url.startswith('ws'):
                from web3 import WebsocketProvider
                provider = WebsocketProvider(self.web3_provider_url)
            else:
                from web3 import HTTPProvider
                provider = HTTPProvider(self.web3_provider_url)
            
            self.w3 = Web3(provider)
            
            # Adiciona middleware para redes PoA se necessário e disponível
            if geth_poa_middleware and hasattr(self.w3.eth, 'get_block'):
                try:
                    block = self.w3.eth.get_block('latest')
                    if 'difficulty' not in block or block['difficulty'] == 0:
                        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                except:
                    pass
            
            # Testa a conexão
            latest_block = self.w3.eth.block_number
            self.last_processed_block = latest_block
            
            self.logger.info(f"Conectado ao Ethereum. Último bloco: {latest_block}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao conectar ao Web3: {e}")
            return False
    
    def is_contract_creation(self, transaction: Dict[str, Any]) -> bool:
        """
        Verifica se uma transação é de criação de contrato.
        
        Args:
            transaction: Dados da transação
            
        Returns:
            bool: True se for criação de contrato
        """
        return transaction.get('to') is None and transaction.get('input', '0x') != '0x'
    
    def extract_contract_info(self, transaction: Dict[str, Any], receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extrai informações do contrato de uma transação de criação.
        
        Args:
            transaction: Dados da transação
            receipt: Recibo da transação
            
        Returns:
            Dict com informações do contrato ou None se não for válido
        """
        try:
            if receipt.get('status') != 1:  # Transação falhou
                return None
            
            contract_address = receipt.get('contractAddress')
            if not contract_address:
                return None
            
            return {
                'address': contract_address,
                'transaction_hash': transaction['hash'].hex(),
                'block_number': transaction['blockNumber'],
                'creator_address': transaction['from'],
                'gas_used': receipt.get('gasUsed', 0),
                'gas_price': transaction.get('gasPrice', 0),
                'bytecode': transaction.get('input', ''),
                'timestamp': datetime.utcnow(),
                'block_hash': transaction.get('blockHash', '').hex() if transaction.get('blockHash') else ''
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao extrair informações do contrato: {e}")
            return None
    
    def process_block(self, block_number: int) -> None:
        """
        Processa um bloco específico em busca de contratos.
        
        Args:
            block_number: Número do bloco a processar
        """
        try:
            block = self.w3.eth.get_block(block_number, full_transactions=True)
            self.stats['blocks_processed'] += 1
            self.stats['last_block_time'] = datetime.utcnow()
            
            contracts_in_block = 0
            
            for transaction in block.transactions:
                if self.is_contract_creation(transaction):
                    try:
                        receipt = self.w3.eth.get_transaction_receipt(transaction.hash)
                        contract_info = self.extract_contract_info(transaction, receipt)
                        
                        if contract_info:
                            contracts_in_block += 1
                            self.stats['contracts_detected'] += 1
                            
                            self.logger.info(f"Novo contrato detectado: {contract_info['address']} no bloco {block_number}")
                            
                            # Chama o callback para processar o contrato
                            try:
                                self.callback(contract_info)
                            except Exception as e:
                                self.logger.error(f"Erro no callback para contrato {contract_info['address']}: {e}")
                    
                    except Exception as e:
                        self.logger.error(f"Erro ao processar transação {transaction.hash.hex()}: {e}")
            
            if contracts_in_block > 0:
                self.logger.info(f"Bloco {block_number}: {contracts_in_block} contratos detectados")
                
        except Exception as e:
            self.logger.error(f"Erro ao processar bloco {block_number}: {e}")
    
    def monitor_loop(self) -> None:
        """
        Loop principal de monitoramento.
        """
        self.logger.info("Iniciando monitoramento de blockchain...")
        self.stats['start_time'] = datetime.utcnow()
        
        while self.is_running:
            try:
                current_block = self.w3.eth.block_number
                
                # Processa blocos perdidos
                while self.last_processed_block < current_block and self.is_running:
                    self.last_processed_block += 1
                    self.process_block(self.last_processed_block)
                
                # Aguarda novos blocos
                time.sleep(2)  # Verifica a cada 2 segundos
                
            except Exception as e:
                self.logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(5)  # Aguarda antes de tentar novamente
    
    def start(self) -> bool:
        """
        Inicia o monitoramento em uma thread separada.
        
        Returns:
            bool: True se iniciado com sucesso
        """
        if self.is_running:
            self.logger.warning("Monitor já está em execução")
            return False
        
        if not self.w3:
            if not self.connect():
                return False
        
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Monitor de blockchain iniciado")
        return True
    
    def stop(self) -> None:
        """
        Para o monitoramento.
        """
        if not self.is_running:
            return
        
        self.logger.info("Parando monitor de blockchain...")
        self.is_running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)
        
        self.logger.info("Monitor de blockchain parado")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do monitor.
        
        Returns:
            Dict com estatísticas
        """
        stats = self.stats.copy()
        if stats['start_time']:
            stats['uptime_seconds'] = (datetime.utcnow() - stats['start_time']).total_seconds()
        stats['is_running'] = self.is_running
        stats['last_processed_block'] = self.last_processed_block
        return stats


class EtherscanMonitor:
    """
    Monitor alternativo que usa a API do Etherscan para detectar novos contratos verificados.
    Útil como backup ou para redes onde WebSocket não está disponível.
    """
    
    def __init__(self, api_key: str, callback: Callable[[Dict[str, Any]], None], check_interval: int = 60):
        """
        Inicializa o monitor do Etherscan.
        
        Args:
            api_key: Chave da API do Etherscan
            callback: Função callback para processar novos contratos
            check_interval: Intervalo de verificação em segundos
        """
        self.api_key = api_key
        self.callback = callback
        self.check_interval = check_interval
        self.is_running = False
        self.monitor_thread = None
        self.last_check_time = datetime.utcnow()
        
        self.logger = logging.getLogger(__name__)
        
        # Base URL da API do Etherscan
        self.base_url = "https://api.etherscan.io/api"
    
    def get_recent_verified_contracts(self) -> list:
        """
        Obtém contratos verificados recentemente do Etherscan.
        
        Returns:
            Lista de contratos verificados
        """
        import requests
        
        try:
            params = {
                'module': 'contract',
                'action': 'getcontractcreation',
                'apikey': self.api_key
            }
            
            response = requests.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if data.get('status') == '1':
                return data.get('result', [])
            else:
                self.logger.error(f"Erro na API do Etherscan: {data.get('message', 'Erro desconhecido')}")
                return []
                
        except Exception as e:
            self.logger.error(f"Erro ao consultar Etherscan: {e}")
            return []
    
    def monitor_loop(self) -> None:
        """
        Loop de monitoramento do Etherscan.
        """
        self.logger.info("Iniciando monitoramento via Etherscan...")
        
        while self.is_running:
            try:
                contracts = self.get_recent_verified_contracts()
                
                for contract_data in contracts:
                    # Processa apenas contratos novos
                    contract_info = {
                        'address': contract_data.get('contractAddress'),
                        'transaction_hash': contract_data.get('txHash'),
                        'creator_address': contract_data.get('contractCreator'),
                        'timestamp': datetime.utcnow(),
                        'source': 'etherscan'
                    }
                    
                    try:
                        self.callback(contract_info)
                    except Exception as e:
                        self.logger.error(f"Erro no callback: {e}")
                
                self.last_check_time = datetime.utcnow()
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Erro no loop do Etherscan: {e}")
                time.sleep(30)
    
    def start(self) -> bool:
        """
        Inicia o monitoramento.
        
        Returns:
            bool: True se iniciado com sucesso
        """
        if self.is_running:
            return False
        
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        return True
    
    def stop(self) -> None:
        """
        Para o monitoramento.
        """
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)

