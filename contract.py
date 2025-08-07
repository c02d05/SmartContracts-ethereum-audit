from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class Contract(db.Model):
    __tablename__ = 'contracts'
    
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(42), unique=True, nullable=False, index=True)
    transaction_hash = db.Column(db.String(66), nullable=False)
    block_number = db.Column(db.Integer, nullable=False)
    creator_address = db.Column(db.String(42), nullable=False)
    
    # Metadados do contrato
    name = db.Column(db.String(255))
    compiler_version = db.Column(db.String(50))
    optimization_enabled = db.Column(db.Boolean, default=False)
    runs = db.Column(db.Integer)
    
    # Status de verificação
    is_verified = db.Column(db.Boolean, default=False)
    verification_date = db.Column(db.DateTime)
    
    # Código
    source_code = db.Column(db.Text)
    bytecode = db.Column(db.Text)
    abi = db.Column(db.Text)  # JSON string
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Status de auditoria
    audit_status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, failed
    last_audit_date = db.Column(db.DateTime)
    
    # Relacionamentos
    audits = db.relationship('Audit', backref='contract', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Contract {self.address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'address': self.address,
            'transaction_hash': self.transaction_hash,
            'block_number': self.block_number,
            'creator_address': self.creator_address,
            'name': self.name,
            'compiler_version': self.compiler_version,
            'optimization_enabled': self.optimization_enabled,
            'runs': self.runs,
            'is_verified': self.is_verified,
            'verification_date': self.verification_date.isoformat() if self.verification_date else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'audit_status': self.audit_status,
            'last_audit_date': self.last_audit_date.isoformat() if self.last_audit_date else None,
            'has_source_code': bool(self.source_code),
            'audit_count': len(self.audits)
        }

class Audit(db.Model):
    __tablename__ = 'audits'
    
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contracts.id'), nullable=False)
    
    # Informações da auditoria
    audit_type = db.Column(db.String(50), nullable=False)  # static, dynamic, formal
    tool_name = db.Column(db.String(100), nullable=False)
    tool_version = db.Column(db.String(50))
    
    # Status e timing
    status = db.Column(db.String(20), default='running')  # running, completed, failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    
    # Resultados
    vulnerabilities_found = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    
    # Dados brutos e relatório
    raw_output = db.Column(db.Text)  # JSON string com saída bruta da ferramenta
    report_path = db.Column(db.String(500))  # Caminho para o relatório gerado
    
    # Relacionamentos
    vulnerabilities = db.relationship('Vulnerability', backref='audit', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Audit {self.id} - {self.tool_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'contract_id': self.contract_id,
            'audit_type': self.audit_type,
            'tool_name': self.tool_name,
            'tool_version': self.tool_version,
            'status': self.status,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'vulnerabilities_found': self.vulnerabilities_found,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'report_path': self.report_path
        }

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audits.id'), nullable=False)
    
    # Classificação da vulnerabilidade
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    category = db.Column(db.String(100))  # reentrancy, overflow, etc.
    
    # Localização no código
    file_path = db.Column(db.String(500))
    line_number = db.Column(db.Integer)
    function_name = db.Column(db.String(255))
    code_snippet = db.Column(db.Text)
    
    # Detalhes técnicos
    impact = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON string com links/referências
    
    # Metadados
    confidence = db.Column(db.String(20))  # high, medium, low
    false_positive = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Vulnerability {self.title} - {self.severity}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'audit_id': self.audit_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'function_name': self.function_name,
            'code_snippet': self.code_snippet,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'references': json.loads(self.references) if self.references else [],
            'confidence': self.confidence,
            'false_positive': self.false_positive,
            'created_at': self.created_at.isoformat()
        }

