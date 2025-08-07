import os
import json
import subprocess
import tempfile
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import hashlib

class SecurityAnalyzer:
    """
    Analisador de segurança que executa múltiplas ferramentas de auditoria
    em smart contracts para detectar vulnerabilidades.
    """
    
    def __init__(self, tools_config: Optional[Dict[str, Any]] = None):
        """
        Inicializa o analisador de segurança.
        
        Args:
            tools_config: Configuração das ferramentas de análise
        """
        self.logger = logging.getLogger(__name__)
        self.tools_config = tools_config or self._get_default_tools_config()
        
        # Diretório temporário para análises
        self.temp_dir = tempfile.mkdtemp(prefix='security_analysis_')
        
        # Estatísticas
        self.stats = {
            'analyses_performed': 0,
            'vulnerabilities_found': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'info_vulnerabilities': 0
        }
    
    def _get_default_tools_config(self) -> Dict[str, Any]:
        """
        Retorna configuração padrão das ferramentas de análise.
        
        Returns:
            Dict com configuração das ferramentas
        """
        return {
            'slither': {
                'enabled': True,
                'command': 'slither',
                'timeout': 300,  # 5 minutos
                'args': ['--json', '-']
            },
            'mythril': {
                'enabled': False,  # Desabilitado por padrão (requer instalação)
                'command': 'myth',
                'timeout': 600,  # 10 minutos
                'args': ['analyze', '--execution-timeout', '300']
            },
            'custom_patterns': {
                'enabled': True,
                'timeout': 60
            }
        }
    
    def _create_temp_contract_file(self, source_code: str, contract_name: str = "Contract") -> str:
        """
        Cria um arquivo temporário com o código-fonte do contrato.
        
        Args:
            source_code: Código-fonte do contrato
            contract_name: Nome do contrato
            
        Returns:
            Caminho do arquivo temporário
        """
        # Gera hash do código para nome único
        code_hash = hashlib.md5(source_code.encode()).hexdigest()[:8]
        filename = f"{contract_name}_{code_hash}.sol"
        filepath = os.path.join(self.temp_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(source_code)
            return filepath
        except Exception as e:
            self.logger.error(f"Erro ao criar arquivo temporário: {e}")
            return ""
    
    def _run_slither_analysis(self, contract_file: str) -> Dict[str, Any]:
        """
        Executa análise com Slither.
        
        Args:
            contract_file: Caminho do arquivo do contrato
            
        Returns:
            Dict com resultados da análise
        """
        if not self.tools_config['slither']['enabled']:
            return {'enabled': False}
        
        try:
            cmd = [self.tools_config['slither']['command']] + \
                  self.tools_config['slither']['args'] + [contract_file]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.tools_config['slither']['timeout'],
                cwd=os.path.dirname(contract_file)
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    slither_output = json.loads(result.stdout)
                    return {
                        'success': True,
                        'raw_output': slither_output,
                        'vulnerabilities': self._parse_slither_output(slither_output)
                    }
                except json.JSONDecodeError:
                    return {
                        'success': False,
                        'error': 'Erro ao decodificar saída JSON do Slither',
                        'raw_stderr': result.stderr
                    }
            else:
                return {
                    'success': False,
                    'error': f'Slither falhou com código {result.returncode}',
                    'raw_stderr': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout na execução do Slither'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Slither não encontrado. Instale com: pip install slither-analyzer'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro inesperado no Slither: {str(e)}'
            }
    
    def _parse_slither_output(self, slither_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parseia a saída do Slither para formato padronizado.
        
        Args:
            slither_output: Saída bruta do Slither
            
        Returns:
            Lista de vulnerabilidades padronizadas
        """
        vulnerabilities = []
        
        try:
            results = slither_output.get('results', {})
            detectors = results.get('detectors', [])
            
            for detector in detectors:
                vulnerability = {
                    'tool': 'slither',
                    'title': detector.get('check', 'Vulnerabilidade detectada'),
                    'description': detector.get('description', ''),
                    'severity': self._map_slither_severity(detector.get('impact', 'Low')),
                    'confidence': detector.get('confidence', 'Medium').lower(),
                    'category': detector.get('check', ''),
                    'elements': detector.get('elements', []),
                    'markdown': detector.get('markdown', ''),
                    'first_markdown_element': detector.get('first_markdown_element', ''),
                    'id': detector.get('id', ''),
                    'additional_fields': detector.get('additional_fields', {})
                }
                
                # Extrai informações de localização
                if vulnerability['elements']:
                    first_element = vulnerability['elements'][0]
                    vulnerability.update({
                        'file_path': first_element.get('source_mapping', {}).get('filename_relative', ''),
                        'line_number': first_element.get('source_mapping', {}).get('lines', [0])[0] if first_element.get('source_mapping', {}).get('lines') else 0,
                        'function_name': first_element.get('name', ''),
                        'code_snippet': first_element.get('source_mapping', {}).get('content', '')
                    })
                
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            self.logger.error(f"Erro ao parsear saída do Slither: {e}")
        
        return vulnerabilities
    
    def _map_slither_severity(self, slither_impact: str) -> str:
        """
        Mapeia severidade do Slither para padrão interno.
        
        Args:
            slither_impact: Impacto reportado pelo Slither
            
        Returns:
            Severidade padronizada
        """
        mapping = {
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Informational': 'info',
            'Optimization': 'info'
        }
        return mapping.get(slither_impact, 'low')
    
    def _run_custom_pattern_analysis(self, source_code: str) -> Dict[str, Any]:
        """
        Executa análise baseada em padrões customizados.
        
        Args:
            source_code: Código-fonte do contrato
            
        Returns:
            Dict com resultados da análise
        """
        if not self.tools_config['custom_patterns']['enabled']:
            return {'enabled': False}
        
        vulnerabilities = []
        
        # Padrões de vulnerabilidades conhecidas
        patterns = {
            'reentrancy': {
                'pattern': r'\.call\s*\(\s*[^)]*\)\s*;?\s*(?!.*require\s*\()',
                'severity': 'high',
                'title': 'Possível Vulnerabilidade de Reentrância',
                'description': 'Uso de call() sem verificação adequada pode permitir ataques de reentrância'
            },
            'unchecked_call': {
                'pattern': r'\.call\s*\([^)]*\)\s*;(?!\s*require)',
                'severity': 'medium',
                'title': 'Chamada Externa Não Verificada',
                'description': 'Resultado de call() não é verificado, pode falhar silenciosamente'
            },
            'tx_origin': {
                'pattern': r'tx\.origin',
                'severity': 'high',
                'title': 'Uso de tx.origin',
                'description': 'tx.origin pode ser explorado em ataques de phishing'
            },
            'block_timestamp': {
                'pattern': r'block\.timestamp|now',
                'severity': 'medium',
                'title': 'Dependência de Timestamp',
                'description': 'Dependência de block.timestamp pode ser manipulada por mineradores'
            },
            'selfdestruct': {
                'pattern': r'selfdestruct\s*\(',
                'severity': 'critical',
                'title': 'Uso de selfdestruct',
                'description': 'Função selfdestruct pode destruir o contrato permanentemente'
            },
            'delegatecall': {
                'pattern': r'\.delegatecall\s*\(',
                'severity': 'high',
                'title': 'Uso de delegatecall',
                'description': 'delegatecall pode ser perigoso se usado com entrada não confiável'
            },
            'random_weakness': {
                'pattern': r'block\.(?:difficulty|timestamp|number|coinbase|gaslimit).*random|keccak256\s*\(\s*abi\.encodePacked\s*\(\s*block\.',
                'severity': 'medium',
                'title': 'Geração de Aleatoriedade Fraca',
                'description': 'Uso de propriedades do bloco para aleatoriedade é previsível'
            },
            'uninitialized_storage': {
                'pattern': r'struct\s+\w+\s*\{[^}]*\}\s*\w+\s*;(?!\s*=)',
                'severity': 'medium',
                'title': 'Possível Variável de Storage Não Inicializada',
                'description': 'Variáveis de storage não inicializadas podem apontar para slots inesperados'
            }
        }
        
        try:
            lines = source_code.split('\n')
            
            for pattern_name, pattern_info in patterns.items():
                pattern = re.compile(pattern_info['pattern'], re.IGNORECASE | re.MULTILINE)
                
                for line_num, line in enumerate(lines, 1):
                    matches = pattern.finditer(line)
                    
                    for match in matches:
                        vulnerability = {
                            'tool': 'custom_patterns',
                            'title': pattern_info['title'],
                            'description': pattern_info['description'],
                            'severity': pattern_info['severity'],
                            'confidence': 'medium',
                            'category': pattern_name,
                            'line_number': line_num,
                            'code_snippet': line.strip(),
                            'match_text': match.group(),
                            'match_start': match.start(),
                            'match_end': match.end()
                        }
                        vulnerabilities.append(vulnerability)
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Erro na análise de padrões: {str(e)}'
            }
    
    def _consolidate_vulnerabilities(self, analysis_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolida vulnerabilidades de múltiplas ferramentas, removendo duplicatas.
        
        Args:
            analysis_results: Lista de resultados de análise
            
        Returns:
            Lista consolidada de vulnerabilidades
        """
        all_vulnerabilities = []
        
        for result in analysis_results:
            if result.get('success') and 'vulnerabilities' in result:
                all_vulnerabilities.extend(result['vulnerabilities'])
        
        # Remove duplicatas baseadas em título, linha e severidade
        unique_vulnerabilities = []
        seen = set()
        
        for vuln in all_vulnerabilities:
            key = (
                vuln.get('title', ''),
                vuln.get('line_number', 0),
                vuln.get('severity', ''),
                vuln.get('category', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        # Ordena por severidade (crítico -> info)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        unique_vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
        
        return unique_vulnerabilities
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calcula pontuação de risco baseada nas vulnerabilidades encontradas.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Dict com pontuação e estatísticas de risco
        """
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        total_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
                total_score += severity_weights[severity]
        
        # Normaliza a pontuação (0-100)
        max_possible_score = len(vulnerabilities) * 10  # Assumindo todas críticas
        normalized_score = min(100, (total_score / max(max_possible_score, 1)) * 100) if max_possible_score > 0 else 0
        
        # Determina nível de risco
        if normalized_score >= 80 or severity_counts['critical'] > 0:
            risk_level = 'CRITICAL'
        elif normalized_score >= 60 or severity_counts['high'] > 2:
            risk_level = 'HIGH'
        elif normalized_score >= 40 or severity_counts['medium'] > 3:
            risk_level = 'MEDIUM'
        elif normalized_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'total_score': total_score,
            'normalized_score': round(normalized_score, 2),
            'risk_level': risk_level,
            'severity_counts': severity_counts,
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    def analyze_contract(self, contract_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa análise completa de segurança em um contrato.
        
        Args:
            contract_info: Informações do contrato incluindo código-fonte
            
        Returns:
            Dict com resultados completos da análise
        """
        analysis_start = datetime.utcnow()
        contract_address = contract_info.get('address', 'unknown')
        
        self.logger.info(f"Iniciando análise de segurança do contrato: {contract_address}")
        
        analysis_result = {
            'contract_address': contract_address,
            'analysis_id': hashlib.md5(f"{contract_address}_{analysis_start}".encode()).hexdigest(),
            'started_at': analysis_start,
            'status': 'running',
            'tools_used': [],
            'vulnerabilities': [],
            'risk_assessment': {},
            'raw_results': {},
            'errors': []
        }
        
        try:
            source_code = contract_info.get('source_code')
            if not source_code:
                analysis_result.update({
                    'status': 'failed',
                    'error': 'Código-fonte não disponível para análise'
                })
                return analysis_result
            
            # Cria arquivo temporário com o código
            contract_name = contract_info.get('metadata', {}).get('contract_name', 'Contract')
            contract_file = self._create_temp_contract_file(source_code, contract_name)
            
            if not contract_file:
                analysis_result.update({
                    'status': 'failed',
                    'error': 'Erro ao criar arquivo temporário'
                })
                return analysis_result
            
            analysis_results = []
            
            # Executa Slither
            if self.tools_config['slither']['enabled']:
                self.logger.info("Executando análise com Slither...")
                slither_result = self._run_slither_analysis(contract_file)
                analysis_results.append(slither_result)
                analysis_result['tools_used'].append('slither')
                analysis_result['raw_results']['slither'] = slither_result
                
                if not slither_result.get('success'):
                    analysis_result['errors'].append(f"Slither: {slither_result.get('error', 'Erro desconhecido')}")
            
            # Executa análise de padrões customizados
            if self.tools_config['custom_patterns']['enabled']:
                self.logger.info("Executando análise de padrões customizados...")
                patterns_result = self._run_custom_pattern_analysis(source_code)
                analysis_results.append(patterns_result)
                analysis_result['tools_used'].append('custom_patterns')
                analysis_result['raw_results']['custom_patterns'] = patterns_result
                
                if not patterns_result.get('success'):
                    analysis_result['errors'].append(f"Padrões customizados: {patterns_result.get('error', 'Erro desconhecido')}")
            
            # Consolida vulnerabilidades
            vulnerabilities = self._consolidate_vulnerabilities(analysis_results)
            analysis_result['vulnerabilities'] = vulnerabilities
            
            # Calcula avaliação de risco
            risk_assessment = self._calculate_risk_score(vulnerabilities)
            analysis_result['risk_assessment'] = risk_assessment
            
            # Atualiza estatísticas
            self.stats['analyses_performed'] += 1
            self.stats['vulnerabilities_found'] += len(vulnerabilities)
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                self.stats[f'{severity}_vulnerabilities'] += risk_assessment['severity_counts'][severity]
            
            analysis_result.update({
                'status': 'completed',
                'completed_at': datetime.utcnow(),
                'duration_seconds': (datetime.utcnow() - analysis_start).total_seconds()
            })
            
            self.logger.info(f"Análise concluída para {contract_address}: "
                           f"{len(vulnerabilities)} vulnerabilidades encontradas, "
                           f"risco {risk_assessment['risk_level']}")
            
        except Exception as e:
            self.logger.error(f"Erro durante análise do contrato {contract_address}: {e}")
            analysis_result.update({
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.utcnow()
            })
        
        finally:
            # Limpa arquivos temporários
            try:
                if 'contract_file' in locals() and os.path.exists(contract_file):
                    os.remove(contract_file)
            except:
                pass
        
        return analysis_result
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do analisador.
        
        Returns:
            Dict com estatísticas
        """
        return self.stats.copy()
    
    def cleanup(self) -> None:
        """
        Limpa recursos e arquivos temporários.
        """
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            self.logger.error(f"Erro ao limpar diretório temporário: {e}")


class VulnerabilityClassifier:
    """
    Classificador de vulnerabilidades que categoriza e prioriza achados de segurança.
    """
    
    @staticmethod
    def classify_vulnerability(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifica uma vulnerabilidade com informações adicionais.
        
        Args:
            vulnerability: Dados da vulnerabilidade
            
        Returns:
            Vulnerabilidade classificada com metadados adicionais
        """
        classified = vulnerability.copy()
        
        # Adiciona categoria OWASP se aplicável
        owasp_mapping = {
            'reentrancy': 'A1 - Injection',
            'unchecked_call': 'A2 - Broken Authentication',
            'tx_origin': 'A3 - Sensitive Data Exposure',
            'delegatecall': 'A4 - XML External Entities (XXE)',
            'selfdestruct': 'A5 - Broken Access Control'
        }
        
        category = vulnerability.get('category', '')
        if category in owasp_mapping:
            classified['owasp_category'] = owasp_mapping[category]
        
        # Adiciona recomendações específicas
        recommendations = {
            'reentrancy': 'Implemente o padrão Checks-Effects-Interactions ou use ReentrancyGuard',
            'unchecked_call': 'Sempre verifique o valor de retorno de call() ou use transfer()',
            'tx_origin': 'Use msg.sender em vez de tx.origin para verificações de autorização',
            'block_timestamp': 'Evite dependência crítica de timestamps ou use oráculos externos',
            'selfdestruct': 'Considere remover selfdestruct ou adicionar controles de acesso rigorosos',
            'delegatecall': 'Valide cuidadosamente a entrada e considere usar call() quando apropriado'
        }
        
        if category in recommendations:
            classified['recommendation'] = recommendations[category]
        
        return classified

