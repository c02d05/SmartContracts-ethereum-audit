from flask import Blueprint, jsonify, request
from src.models.contract import db, Contract, Audit, Vulnerability
from src.auditor.auditor_agent import EthereumAuditorAgent, create_default_config
from datetime import datetime, timedelta
import json
import os

auditor_bp = Blueprint('auditor', __name__)

# Instância global do agente (será inicializada no main.py)
auditor_agent = None

def init_auditor_agent(flask_app):
    """
    Inicializa o agente auditor com a aplicação Flask.
    
    Args:
        flask_app: Instância da aplicação Flask
    """
    global auditor_agent
    
    # Carrega configuração
    config = create_default_config()
    
    # Sobrescreve com variáveis de ambiente se disponíveis
    config['web3_provider_url'] = os.getenv('WEB3_PROVIDER_URL', config['web3_provider_url'])
    config['etherscan_api_key'] = os.getenv('ETHERSCAN_API_KEY', config['etherscan_api_key'])
    
    # Cria instância do agente
    auditor_agent = EthereumAuditorAgent(config, flask_app)

@auditor_bp.route('/status', methods=['GET'])
def get_status():
    """
    Retorna status atual do agente auditor.
    """
    try:
        if not auditor_agent:
            return jsonify({
                'error': 'Agente auditor não inicializado',
                'is_running': False
            }), 503
        
        status = auditor_agent.get_status()
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/start', methods=['POST'])
def start_agent():
    """
    Inicia o agente auditor.
    """
    try:
        if not auditor_agent:
            return jsonify({'error': 'Agente auditor não inicializado'}), 503
        
        if auditor_agent.is_running:
            return jsonify({
                'message': 'Agente já está em execução',
                'is_running': True
            })
        
        success = auditor_agent.start()
        
        if success:
            return jsonify({
                'message': 'Agente auditor iniciado com sucesso',
                'is_running': True
            })
        else:
            return jsonify({
                'error': 'Falha ao iniciar agente auditor',
                'is_running': False
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/stop', methods=['POST'])
def stop_agent():
    """
    Para o agente auditor.
    """
    try:
        if not auditor_agent:
            return jsonify({'error': 'Agente auditor não inicializado'}), 503
        
        auditor_agent.stop()
        
        return jsonify({
            'message': 'Agente auditor parado com sucesso',
            'is_running': False
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/contracts', methods=['GET'])
def get_contracts():
    """
    Lista contratos auditados com paginação e filtros.
    """
    try:
        # Parâmetros de consulta
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        status = request.args.get('status')  # pending, in_progress, completed, failed
        risk_level = request.args.get('risk_level')  # critical, high, medium, low, minimal
        has_vulnerabilities = request.args.get('has_vulnerabilities', type=bool)
        
        # Query base
        query = Contract.query
        
        # Aplica filtros
        if status:
            query = query.filter(Contract.audit_status == status)
        
        if has_vulnerabilities is not None:
            if has_vulnerabilities:
                query = query.join(Audit).join(Vulnerability)
            else:
                query = query.outerjoin(Audit).outerjoin(Vulnerability).filter(Vulnerability.id.is_(None))
        
        # Ordena por data de criação (mais recentes primeiro)
        query = query.order_by(Contract.created_at.desc())
        
        # Paginação
        contracts = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Serializa resultados
        result = {
            'contracts': [contract.to_dict() for contract in contracts.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': contracts.total,
                'pages': contracts.pages,
                'has_next': contracts.has_next,
                'has_prev': contracts.has_prev
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/contracts/<contract_address>', methods=['GET'])
def get_contract_details(contract_address):
    """
    Retorna detalhes de um contrato específico.
    """
    try:
        contract = Contract.query.filter_by(address=contract_address).first()
        
        if not contract:
            return jsonify({'error': 'Contrato não encontrado'}), 404
        
        # Inclui auditorias e vulnerabilidades
        contract_data = contract.to_dict()
        
        # Adiciona auditorias
        audits = []
        for audit in contract.audits:
            audit_data = audit.to_dict()
            
            # Adiciona vulnerabilidades da auditoria
            vulnerabilities = [vuln.to_dict() for vuln in audit.vulnerabilities]
            audit_data['vulnerabilities'] = vulnerabilities
            
            audits.append(audit_data)
        
        contract_data['audits'] = audits
        
        return jsonify(contract_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/contracts/<contract_address>/audit', methods=['POST'])
def audit_contract_manually(contract_address):
    """
    Executa auditoria manual de um contrato específico.
    """
    try:
        if not auditor_agent:
            return jsonify({'error': 'Agente auditor não inicializado'}), 503
        
        # Valida endereço do contrato
        if not contract_address or len(contract_address) != 42 or not contract_address.startswith('0x'):
            return jsonify({'error': 'Endereço de contrato inválido'}), 400
        
        # Executa auditoria
        result = auditor_agent.process_single_contract(contract_address)
        
        if result['success']:
            return jsonify({
                'message': 'Auditoria executada com sucesso',
                'contract_address': contract_address,
                'processed_at': result['processed_at']
            })
        else:
            return jsonify({
                'error': 'Falha na auditoria do contrato',
                'contract_address': contract_address
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """
    Lista vulnerabilidades encontradas com filtros.
    """
    try:
        # Parâmetros de consulta
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        severity = request.args.get('severity')
        category = request.args.get('category')
        contract_address = request.args.get('contract_address')
        
        # Query base
        query = Vulnerability.query.join(Audit).join(Contract)
        
        # Aplica filtros
        if severity:
            query = query.filter(Vulnerability.severity == severity)
        
        if category:
            query = query.filter(Vulnerability.category == category)
        
        if contract_address:
            query = query.filter(Contract.address == contract_address)
        
        # Ordena por severidade e data
        severity_order = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
        
        query = query.order_by(
            db.case(severity_order, value=Vulnerability.severity),
            Vulnerability.created_at.desc()
        )
        
        # Paginação
        vulnerabilities = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Serializa resultados
        result = {
            'vulnerabilities': [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': vulnerabilities.total,
                'pages': vulnerabilities.pages,
                'has_next': vulnerabilities.has_next,
                'has_prev': vulnerabilities.has_prev
            }
        }
        
        for vuln in vulnerabilities.items:
            vuln_data = vuln.to_dict()
            # Adiciona informações do contrato
            vuln_data['contract_address'] = vuln.audit.contract.address
            vuln_data['contract_name'] = vuln.audit.contract.name
            result['vulnerabilities'].append(vuln_data)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """
    Retorna estatísticas gerais do sistema.
    """
    try:
        # Estatísticas de contratos
        total_contracts = Contract.query.count()
        verified_contracts = Contract.query.filter_by(is_verified=True).count()
        audited_contracts = Contract.query.filter_by(audit_status='completed').count()
        
        # Estatísticas de vulnerabilidades
        total_vulnerabilities = Vulnerability.query.count()
        critical_vulnerabilities = Vulnerability.query.filter_by(severity='critical').count()
        high_vulnerabilities = Vulnerability.query.filter_by(severity='high').count()
        medium_vulnerabilities = Vulnerability.query.filter_by(severity='medium').count()
        low_vulnerabilities = Vulnerability.query.filter_by(severity='low').count()
        info_vulnerabilities = Vulnerability.query.filter_by(severity='info').count()
        
        # Estatísticas por categoria
        vulnerability_categories = db.session.query(
            Vulnerability.category,
            db.func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.category).all()
        
        # Contratos auditados por dia (últimos 30 dias)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        daily_audits = db.session.query(
            db.func.date(Contract.last_audit_date).label('date'),
            db.func.count(Contract.id).label('count')
        ).filter(
            Contract.last_audit_date >= thirty_days_ago,
            Contract.audit_status == 'completed'
        ).group_by(db.func.date(Contract.last_audit_date)).all()
        
        # Estatísticas do agente (se estiver rodando)
        agent_stats = {}
        if auditor_agent:
            agent_stats = auditor_agent.get_status().get('stats', {})
        
        result = {
            'contracts': {
                'total': total_contracts,
                'verified': verified_contracts,
                'audited': audited_contracts,
                'verification_rate': (verified_contracts / total_contracts * 100) if total_contracts > 0 else 0
            },
            'vulnerabilities': {
                'total': total_vulnerabilities,
                'by_severity': {
                    'critical': critical_vulnerabilities,
                    'high': high_vulnerabilities,
                    'medium': medium_vulnerabilities,
                    'low': low_vulnerabilities,
                    'info': info_vulnerabilities
                },
                'by_category': [
                    {'category': cat, 'count': count} 
                    for cat, count in vulnerability_categories
                ]
            },
            'daily_audits': [
                {'date': str(date), 'count': count}
                for date, count in daily_audits
            ],
            'agent': agent_stats
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/reports/<contract_address>', methods=['GET'])
def get_contract_reports(contract_address):
    """
    Lista relatórios disponíveis para um contrato.
    """
    try:
        contract = Contract.query.filter_by(address=contract_address).first()
        
        if not contract:
            return jsonify({'error': 'Contrato não encontrado'}), 404
        
        reports = []
        
        for audit in contract.audits:
            if audit.report_path and os.path.exists(audit.report_path):
                report_info = {
                    'audit_id': audit.id,
                    'report_path': audit.report_path,
                    'created_at': audit.completed_at.isoformat() if audit.completed_at else None,
                    'tool_name': audit.tool_name,
                    'vulnerabilities_found': audit.vulnerabilities_found
                }
                reports.append(report_info)
        
        return jsonify({
            'contract_address': contract_address,
            'reports': reports
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auditor_bp.route('/health', methods=['GET'])
def health_check():
    """
    Endpoint de health check.
    """
    try:
        # Verifica conexão com banco de dados
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        
        # Verifica status do agente
        agent_running = auditor_agent.is_running if auditor_agent else False
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'agent_running': agent_running,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

