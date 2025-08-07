import requests
import json
import time
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import os
import tempfile

class CodeRetriever:
    """
    Recuperador de código-fonte e bytecode de smart contracts.
    Integra com APIs de exploradores de blockchain como Etherscan.
    """
    
    def __init__(self, etherscan_api_key: str, cache_dir: Optional[str] = None):
        """
        Inicializa o recuperador de código.
        
        Args:
            etherscan_api_key: Chave da API do Etherscan
            cache_dir: Diretório para cache de códigos (opcional)
        """
        self.etherscan_api_key = etherscan_api_key
        self.cache_dir = cache_dir or tempfile.mkdtemp(prefix='contract_cache_')
        self.logger = logging.getLogger(__name__)
        
        # URLs das APIs
        self.etherscan_base_url = "https://api.etherscan.io/api"
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.2  # 5 requests per second max
        
        # Estatísticas
        self.stats = {
            'contracts_retrieved': 0,
            'verified_contracts': 0,
            'unverified_contracts': 0,
            'cache_hits': 0,
            'api_errors': 0
        }
        
        # Cria diretório de cache se não existir
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _rate_limit(self) -> None:
        """
        Implementa rate limiting para evitar sobrecarga da API.
        """
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_etherscan_request(self, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Faz uma requisição para a API do Etherscan com rate limiting.
        
        Args:
            params: Parâmetros da requisição
            
        Returns:
            Resposta da API ou None em caso de erro
        """
        self._rate_limit()
        
        try:
            params['apikey'] = self.etherscan_api_key
            response = requests.get(self.etherscan_base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == '1':
                return data.get('result')
            elif data.get('status') == '0':
                message = data.get('message', 'Erro desconhecido')
                if 'not verified' in message.lower():
                    self.logger.debug(f"Contrato não verificado: {message}")
                    return None
                else:
                    self.logger.error(f"Erro na API do Etherscan: {message}")
                    self.stats['api_errors'] += 1
                    return None
            else:
                self.logger.error(f"Resposta inesperada da API: {data}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erro de rede ao consultar Etherscan: {e}")
            self.stats['api_errors'] += 1
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Erro ao decodificar resposta JSON: {e}")
            self.stats['api_errors'] += 1
            return None
        except Exception as e:
            self.logger.error(f"Erro inesperado na requisição: {e}")
            self.stats['api_errors'] += 1
            return None
    
    def get_contract_source_code(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """
        Obtém o código-fonte verificado de um contrato.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Dict com informações do código-fonte ou None se não verificado
        """
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': contract_address
        }
        
        result = self._make_etherscan_request(params)
        
        if result and len(result) > 0:
            contract_data = result[0]
            
            # Verifica se o contrato está verificado
            if contract_data.get('SourceCode'):
                self.stats['verified_contracts'] += 1
                
                return {
                    'source_code': contract_data.get('SourceCode', ''),
                    'abi': contract_data.get('ABI', ''),
                    'contract_name': contract_data.get('ContractName', ''),
                    'compiler_version': contract_data.get('CompilerVersion', ''),
                    'optimization_used': contract_data.get('OptimizationUsed', '0') == '1',
                    'runs': int(contract_data.get('Runs', '0')),
                    'constructor_arguments': contract_data.get('ConstructorArguments', ''),
                    'evm_version': contract_data.get('EVMVersion', ''),
                    'library': contract_data.get('Library', ''),
                    'license_type': contract_data.get('LicenseType', ''),
                    'proxy': contract_data.get('Proxy', '0') == '1',
                    'implementation': contract_data.get('Implementation', ''),
                    'swarm_source': contract_data.get('SwarmSource', '')
                }
            else:
                self.stats['unverified_contracts'] += 1
                return None
        
        return None
    
    def get_contract_bytecode(self, contract_address: str) -> Optional[str]:
        """
        Obtém o bytecode de um contrato.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Bytecode do contrato ou None em caso de erro
        """
        params = {
            'module': 'proxy',
            'action': 'eth_getCode',
            'address': contract_address,
            'tag': 'latest'
        }
        
        result = self._make_etherscan_request(params)
        
        if result and result != '0x':
            return result
        
        return None
    
    def get_contract_abi(self, contract_address: str) -> Optional[str]:
        """
        Obtém a ABI de um contrato verificado.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            ABI do contrato em formato JSON string ou None
        """
        params = {
            'module': 'contract',
            'action': 'getabi',
            'address': contract_address
        }
        
        result = self._make_etherscan_request(params)
        
        if result and result != 'Contract source code not verified':
            return result
        
        return None
    
    def get_contract_creation_info(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """
        Obtém informações sobre a criação do contrato.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Dict com informações de criação ou None
        """
        params = {
            'module': 'contract',
            'action': 'getcontractcreation',
            'contractaddresses': contract_address
        }
        
        result = self._make_etherscan_request(params)
        
        if result and len(result) > 0:
            creation_data = result[0]
            return {
                'creator_address': creation_data.get('contractCreator', ''),
                'creation_tx_hash': creation_data.get('txHash', '')
            }
        
        return None
    
    def retrieve_complete_contract_info(self, contract_address: str) -> Dict[str, Any]:
        """
        Recupera todas as informações disponíveis de um contrato.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Dict com todas as informações do contrato
        """
        self.logger.info(f"Recuperando informações do contrato: {contract_address}")
        
        contract_info = {
            'address': contract_address,
            'retrieved_at': datetime.utcnow(),
            'is_verified': False,
            'has_source_code': False,
            'has_bytecode': False,
            'source_code': None,
            'bytecode': None,
            'abi': None,
            'metadata': {}
        }
        
        try:
            # Tenta obter código-fonte (apenas para contratos verificados)
            source_info = self.get_contract_source_code(contract_address)
            if source_info:
                contract_info['is_verified'] = True
                contract_info['has_source_code'] = True
                contract_info['source_code'] = source_info['source_code']
                contract_info['abi'] = source_info['abi']
                contract_info['metadata'] = {
                    'contract_name': source_info['contract_name'],
                    'compiler_version': source_info['compiler_version'],
                    'optimization_used': source_info['optimization_used'],
                    'runs': source_info['runs'],
                    'evm_version': source_info['evm_version'],
                    'license_type': source_info['license_type'],
                    'is_proxy': source_info['proxy']
                }
            
            # Sempre tenta obter bytecode
            bytecode = self.get_contract_bytecode(contract_address)
            if bytecode:
                contract_info['has_bytecode'] = True
                contract_info['bytecode'] = bytecode
            
            # Se não tem código-fonte, tenta obter ABI separadamente
            if not contract_info['abi']:
                abi = self.get_contract_abi(contract_address)
                if abi:
                    contract_info['abi'] = abi
            
            # Obtém informações de criação
            creation_info = self.get_contract_creation_info(contract_address)
            if creation_info:
                contract_info['metadata'].update(creation_info)
            
            self.stats['contracts_retrieved'] += 1
            
            self.logger.info(f"Contrato {contract_address}: verificado={contract_info['is_verified']}, "
                           f"código-fonte={contract_info['has_source_code']}, "
                           f"bytecode={contract_info['has_bytecode']}")
            
        except Exception as e:
            self.logger.error(f"Erro ao recuperar informações do contrato {contract_address}: {e}")
        
        return contract_info
    
    def save_contract_to_cache(self, contract_info: Dict[str, Any]) -> str:
        """
        Salva informações do contrato no cache local.
        
        Args:
            contract_info: Informações do contrato
            
        Returns:
            Caminho do arquivo salvo
        """
        contract_address = contract_info['address']
        cache_file = os.path.join(self.cache_dir, f"{contract_address}.json")
        
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(contract_info, f, indent=2, default=str)
            
            self.logger.debug(f"Contrato {contract_address} salvo no cache: {cache_file}")
            return cache_file
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar contrato no cache: {e}")
            return ""
    
    def load_contract_from_cache(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """
        Carrega informações do contrato do cache local.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Informações do contrato ou None se não encontrado
        """
        cache_file = os.path.join(self.cache_dir, f"{contract_address}.json")
        
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    contract_info = json.load(f)
                
                self.stats['cache_hits'] += 1
                self.logger.debug(f"Contrato {contract_address} carregado do cache")
                return contract_info
                
            except Exception as e:
                self.logger.error(f"Erro ao carregar contrato do cache: {e}")
        
        return None
    
    def save_source_code_to_file(self, contract_address: str, source_code: str) -> str:
        """
        Salva o código-fonte de um contrato em arquivo .sol.
        
        Args:
            contract_address: Endereço do contrato
            source_code: Código-fonte do contrato
            
        Returns:
            Caminho do arquivo salvo
        """
        filename = f"{contract_address}.sol"
        filepath = os.path.join(self.cache_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(source_code)
            
            self.logger.debug(f"Código-fonte salvo: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar código-fonte: {e}")
            return ""
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do recuperador.
        
        Returns:
            Dict com estatísticas
        """
        return self.stats.copy()
    
    def clear_cache(self) -> None:
        """
        Limpa o cache de contratos.
        """
        try:
            import shutil
            if os.path.exists(self.cache_dir):
                shutil.rmtree(self.cache_dir)
                os.makedirs(self.cache_dir, exist_ok=True)
                self.logger.info("Cache limpo com sucesso")
        except Exception as e:
            self.logger.error(f"Erro ao limpar cache: {e}")


class MultiSourceRetriever:
    """
    Recuperador que utiliza múltiplas fontes para obter informações de contratos.
    Combina Etherscan, Sourcify e outras fontes quando disponíveis.
    """
    
    def __init__(self, etherscan_api_key: str):
        """
        Inicializa o recuperador multi-fonte.
        
        Args:
            etherscan_api_key: Chave da API do Etherscan
        """
        self.etherscan_retriever = CodeRetriever(etherscan_api_key)
        self.logger = logging.getLogger(__name__)
    
    def retrieve_contract(self, contract_address: str) -> Dict[str, Any]:
        """
        Recupera informações do contrato usando múltiplas fontes.
        
        Args:
            contract_address: Endereço do contrato
            
        Returns:
            Dict com informações consolidadas do contrato
        """
        # Por enquanto, usa apenas Etherscan
        # Pode ser expandido para incluir Sourcify, GitHub, etc.
        return self.etherscan_retriever.retrieve_complete_contract_info(contract_address)

