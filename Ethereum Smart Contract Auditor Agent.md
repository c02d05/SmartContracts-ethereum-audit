# Ethereum Smart Contract Auditor Agent

Um agente auditor automatizado de alta precisão para smart contracts da rede Ethereum que executa auditoria em tempo real para cada novo contrato verificado na rede, garantindo segurança em nível profundo.

## 🚀 Características Principais

### Auditoria Automatizada e Precisa
- **Monitoramento em Tempo Real**: Detecta automaticamente novos contratos verificados na rede Ethereum
- **Análise Multi-Ferramenta**: Integra Slither, análise de padrões customizados e verificações de segurança avançadas
- **Detecção Cirúrgica**: Identifica vulnerabilidades com alta precisão, minimizando falsos positivos
- **Classificação de Risco**: Sistema avançado de classificação de vulnerabilidades (Critical, High, Medium, Low, Info)

### Sistema de Alertas Inteligente
- **Notificações Multi-Canal**: Webhook, Email, Slack, Discord
- **Filtros Configuráveis**: Alertas baseados em severidade e tipo de vulnerabilidade
- **Prevenção de Spam**: Sistema de cooldown e limites por contrato
- **Alertas em Tempo Real**: Notificação imediata para vulnerabilidades críticas

### Interface de Monitoramento Avançada
- **Dashboard em Tempo Real**: Visualização completa do status do agente e estatísticas
- **Gestão de Contratos**: Lista e detalhes de todos os contratos auditados
- **Análise de Vulnerabilidades**: Visualização detalhada de todas as vulnerabilidades encontradas
- **Relatórios Profissionais**: Geração automática de relatórios em PDF e JSON

### Arquitetura Robusta
- **Processamento Paralelo**: Múltiplos workers para auditoria simultânea de contratos
- **Recuperação de Falhas**: Sistema resiliente com tratamento de erros e retry automático
- **Armazenamento Persistente**: Banco de dados SQLite com histórico completo de auditorias
- **API RESTful**: Interface completa para integração com outros sistemas

## 🏗️ Arquitetura do Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                    Ethereum Auditor Agent                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Blockchain      │  │ Code Retriever  │  │ Security        │  │
│  │ Monitor         │  │                 │  │ Analyzer        │  │
│  │                 │  │ • Etherscan API │  │                 │  │
│  │ • Web3 Provider │  │ • Source Code   │  │ • Slither       │  │
│  │ • Event Filter  │  │ • ABI & Bytecode│  │ • Custom Rules  │  │
│  │ • New Contracts │  │ • Metadata      │  │ • Pattern Match │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│           │                     │                     │         │
│           └─────────────────────┼─────────────────────┘         │
│                                 │                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Report          │  │ Alert System    │  │ Database        │  │
│  │ Generator       │  │                 │  │                 │  │
│  │                 │  │ • Webhook       │  │ • Contracts     │  │
│  │ • PDF Reports   │  │ • Email         │  │ • Audits        │  │
│  │ • JSON Export   │  │ • Slack/Discord │  │ • Vulnerabilities│ │
│  │ • Statistics    │  │ • Filters       │  │ • History       │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────────┐
│                     Web Dashboard                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Agent Status    │  │ Contract List   │  │ Vulnerability   │  │
│  │                 │  │                 │  │ Analysis        │  │
│  │ • Start/Stop    │  │ • Search/Filter │  │                 │  │
│  │ • Statistics    │  │ • Audit Status  │  │ • Severity View │  │
│  │ • Queue Status  │  │ • Details       │  │ • Reports       │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Pré-requisitos

### Sistema
- Python 3.11+
- Node.js 20+
- SQLite 3
- Git

### APIs Necessárias
- **Etherscan API Key**: Para recuperação de código-fonte dos contratos
- **Web3 Provider**: Infura, Alchemy ou nó Ethereum próprio

### Ferramentas de Auditoria
- **Slither**: Ferramenta de análise estática da Trail of Bits
- **Solc**: Compilador Solidity

## 🚀 Instalação e Configuração

### 1. Clone o Repositório
```bash
git clone <repository-url>
cd ethereum-auditor-agent
```

### 2. Configuração do Backend
```bash
# Ative o ambiente virtual
source venv/bin/activate

# Instale as dependências
pip install -r requirements.txt

# Instale o Slither
pip install slither-analyzer

# Configure as variáveis de ambiente
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

### 3. Configuração do Frontend
```bash
cd ../ethereum-auditor-dashboard

# Instale as dependências
pnpm install

# Configure a URL da API se necessário
# Edite src/App.jsx se a API não estiver em localhost:5000
```

### 4. Configuração das Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto backend:

```env
# Configurações da Blockchain
WEB3_PROVIDER_URL=wss://mainnet.infura.io/ws/v3/YOUR_PROJECT_ID
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_API_KEY

# Configurações do Banco de Dados
DATABASE_URL=sqlite:///database/app.db

# Configurações de Alertas
WEBHOOK_URL=https://your-webhook-url.com/alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK

# Configurações de Email
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAILS=admin@yourcompany.com,security@yourcompany.com

# Configurações do Agente
MAX_CONCURRENT_AUDITS=3
MIN_ALERT_SEVERITY=high
```

## 🎯 Uso

### Iniciando o Sistema

#### Backend (API e Agente)
```bash
cd ethereum-auditor-agent
source venv/bin/activate
python src/main.py
```

#### Frontend (Dashboard)
```bash
cd ethereum-auditor-dashboard
pnpm run dev --host
```

### Acessando o Dashboard
- **URL**: http://localhost:5174
- **API**: http://localhost:5000/api/auditor

### Controlando o Agente

#### Via Dashboard Web
1. Acesse o dashboard
2. Use os botões "Iniciar" e "Parar" no painel de status
3. Monitore estatísticas em tempo real

#### Via API
```bash
# Iniciar o agente
curl -X POST http://localhost:5000/api/auditor/start

# Parar o agente
curl -X POST http://localhost:5000/api/auditor/stop

# Verificar status
curl http://localhost:5000/api/auditor/status

# Auditar contrato específico
curl -X POST http://localhost:5000/api/auditor/contracts/0x1234.../audit
```

## 🔧 Configuração Avançada

### Configuração de Alertas

#### Webhook
```json
{
  "webhook": {
    "enabled": true,
    "url": "https://your-webhook-url.com/alerts",
    "timeout": 30,
    "retry_attempts": 3,
    "retry_delay": 5
  }
}
```

#### Email
```json
{
  "email": {
    "enabled": true,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "auditor@yourcompany.com",
    "to_emails": ["admin@yourcompany.com", "security@yourcompany.com"],
    "use_tls": true
  }
}
```

#### Filtros de Alerta
```json
{
  "filters": {
    "min_severity": "high",
    "max_alerts_per_contract": 10,
    "cooldown_minutes": 5
  }
}
```

### Configuração do Analisador

#### Slither
```json
{
  "slither": {
    "enabled": true,
    "timeout": 300,
    "detectors": [
      "reentrancy-eth",
      "reentrancy-no-eth",
      "uninitialized-state",
      "uninitialized-storage",
      "arbitrary-send",
      "controlled-delegatecall",
      "weak-prng",
      "suicidal",
      "assembly",
      "assert-state-change",
      "boolean-equal",
      "deprecated-standards"
    ]
  }
}
```

#### Padrões Customizados
```json
{
  "custom_patterns": {
    "enabled": true,
    "timeout": 60,
    "patterns": [
      {
        "name": "Hardcoded Address",
        "pattern": "0x[a-fA-F0-9]{40}",
        "severity": "medium",
        "description": "Endereço hardcoded encontrado"
      },
      {
        "name": "Unsafe Math",
        "pattern": "\\+\\+|\\-\\-|\\*|/(?!\\*)",
        "severity": "low",
        "description": "Operação matemática sem SafeMath"
      }
    ]
  }
}
```

## 📊 API Reference

### Endpoints Principais

#### Status e Controle
- `GET /api/auditor/status` - Status do agente
- `POST /api/auditor/start` - Iniciar agente
- `POST /api/auditor/stop` - Parar agente
- `GET /api/auditor/health` - Health check

#### Contratos
- `GET /api/auditor/contracts` - Listar contratos
- `GET /api/auditor/contracts/{address}` - Detalhes do contrato
- `POST /api/auditor/contracts/{address}/audit` - Auditar contrato

#### Vulnerabilidades
- `GET /api/auditor/vulnerabilities` - Listar vulnerabilidades
- `GET /api/auditor/statistics` - Estatísticas gerais

#### Relatórios
- `GET /api/auditor/reports/{address}` - Relatórios do contrato

### Exemplos de Resposta

#### Status do Agente
```json
{
  "is_running": true,
  "start_time": "2025-08-07T18:30:00.000Z",
  "uptime_seconds": 3600,
  "queue_size": 5,
  "active_workers": 3,
  "stats": {
    "contracts_detected": 150,
    "contracts_processed": 145,
    "contracts_failed": 2,
    "total_vulnerabilities": 89,
    "critical_vulnerabilities": 5,
    "high_vulnerabilities": 12,
    "reports_generated": 145,
    "alerts_sent": 17
  }
}
```

#### Detalhes do Contrato
```json
{
  "id": 1,
  "address": "0x1234567890123456789012345678901234567890",
  "name": "MyToken",
  "is_verified": true,
  "audit_status": "completed",
  "last_audit_date": "2025-08-07T18:45:00.000Z",
  "audits": [
    {
      "id": 1,
      "audit_type": "comprehensive",
      "status": "completed",
      "vulnerabilities_found": 3,
      "critical_count": 0,
      "high_count": 1,
      "medium_count": 2,
      "vulnerabilities": [
        {
          "title": "Reentrancy Vulnerability",
          "severity": "high",
          "category": "reentrancy",
          "description": "Potential reentrancy attack in withdraw function",
          "line_number": 45,
          "function_name": "withdraw",
          "impact": "Funds can be drained from contract",
          "recommendation": "Use ReentrancyGuard or checks-effects-interactions pattern"
        }
      ]
    }
  ]
}
```

## 🔍 Tipos de Vulnerabilidades Detectadas

### Críticas (Critical)
- **Reentrancy Attacks**: Vulnerabilidades de reentrada que podem drenar fundos
- **Integer Overflow/Underflow**: Problemas de overflow sem SafeMath
- **Unprotected Selfdestruct**: Função selfdestruct sem proteção adequada
- **Arbitrary Code Execution**: Execução de código arbitrário via delegatecall

### Altas (High)
- **Access Control Issues**: Problemas de controle de acesso
- **Uninitialized Storage Pointers**: Ponteiros de storage não inicializados
- **Weak Randomness**: Uso de fontes de aleatoriedade fracas
- **Unchecked External Calls**: Chamadas externas sem verificação

### Médias (Medium)
- **Deprecated Functions**: Uso de funções depreciadas
- **Gas Limit Issues**: Problemas relacionados ao limite de gas
- **Timestamp Dependence**: Dependência de timestamp para lógica crítica
- **Hardcoded Values**: Valores hardcoded que deveriam ser configuráveis

### Baixas (Low)
- **Code Style Issues**: Problemas de estilo de código
- **Unused Variables**: Variáveis não utilizadas
- **Missing Events**: Eventos ausentes para operações importantes
- **Optimization Opportunities**: Oportunidades de otimização de gas

### Informativas (Info)
- **Best Practices**: Recomendações de melhores práticas
- **Documentation**: Sugestões de documentação
- **Code Quality**: Melhorias de qualidade do código

## 📈 Monitoramento e Métricas

### Métricas do Sistema
- **Contratos Detectados**: Total de novos contratos identificados
- **Taxa de Processamento**: Contratos processados por hora
- **Taxa de Sucesso**: Percentual de auditorias bem-sucedidas
- **Tempo Médio de Auditoria**: Tempo médio para completar uma auditoria

### Métricas de Segurança
- **Vulnerabilidades por Severidade**: Distribuição de vulnerabilidades encontradas
- **Contratos de Alto Risco**: Contratos com vulnerabilidades críticas ou altas
- **Taxa de Detecção**: Eficácia na detecção de vulnerabilidades conhecidas
- **Falsos Positivos**: Taxa de falsos positivos reportados

### Alertas e Notificações
- **Alertas Enviados**: Total de alertas disparados
- **Canais de Notificação**: Distribuição por canal (email, webhook, etc.)
- **Tempo de Resposta**: Tempo entre detecção e notificação
- **Taxa de Entrega**: Sucesso na entrega de alertas

## 🛠️ Desenvolvimento e Contribuição

### Estrutura do Projeto
```
ethereum-auditor-agent/
├── src/
│   ├── auditor/
│   │   ├── monitor/          # Monitoramento da blockchain
│   │   ├── retriever/        # Recuperação de código
│   │   ├── analyzer/         # Análise de segurança
│   │   ├── reporter/         # Geração de relatórios
│   │   ├── alerter/          # Sistema de alertas
│   │   └── auditor_agent.py  # Agente principal
│   ├── models/               # Modelos de dados
│   ├── routes/               # Rotas da API
│   └── main.py              # Aplicação Flask
├── reports/                  # Relatórios gerados
├── database/                 # Banco de dados SQLite
└── requirements.txt          # Dependências Python

ethereum-auditor-dashboard/
├── src/
│   ├── components/           # Componentes React
│   ├── hooks/               # Hooks customizados
│   ├── lib/                 # Utilitários
│   └── App.jsx              # Aplicação principal
├── public/                  # Arquivos estáticos
└── package.json             # Dependências Node.js
```

### Adicionando Novos Detectores

#### 1. Detector Slither Customizado
```python
# src/auditor/analyzer/custom_detectors/my_detector.py
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class MyCustomDetector(AbstractDetector):
    ARGUMENT = 'my-detector'
    HELP = 'Detect my custom vulnerability'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        # Implementar lógica de detecção
        return results
```

#### 2. Padrão de Análise Customizado
```python
# src/auditor/analyzer/patterns/my_pattern.py
import re
from typing import List, Dict, Any

def detect_my_pattern(source_code: str) -> List[Dict[str, Any]]:
    """
    Detecta padrão customizado no código-fonte.
    """
    vulnerabilities = []
    pattern = r'my_vulnerable_pattern'
    
    for match in re.finditer(pattern, source_code, re.MULTILINE):
        vulnerabilities.append({
            'title': 'My Custom Vulnerability',
            'severity': 'medium',
            'line_number': source_code[:match.start()].count('\n') + 1,
            'description': 'Description of the vulnerability',
            'recommendation': 'How to fix it'
        })
    
    return vulnerabilities
```

### Executando Testes
```bash
# Testes do backend
cd ethereum-auditor-agent
python -m pytest tests/

# Testes do frontend
cd ethereum-auditor-dashboard
pnpm test
```

## 🚨 Segurança e Limitações

### Considerações de Segurança
- **API Keys**: Mantenha as chaves de API seguras e use variáveis de ambiente
- **Webhook URLs**: Use HTTPS para webhooks e valide assinaturas quando possível
- **Acesso à Rede**: Configure firewalls adequadamente para proteger o sistema
- **Logs**: Monitore logs para atividades suspeitas

### Limitações Conhecidas
- **Rate Limits**: Sujeito aos limites de rate da Etherscan API
- **Contratos Não Verificados**: Não pode auditar contratos sem código-fonte verificado
- **Falsos Positivos**: Algumas detecções podem gerar falsos positivos
- **Recursos**: Requer recursos computacionais significativos para análise

### Recomendações de Produção
- **Backup**: Configure backup regular do banco de dados
- **Monitoramento**: Implemente monitoramento de saúde do sistema
- **Escalabilidade**: Use múltiplas instâncias para alta disponibilidade
- **Logs**: Configure rotação de logs e armazenamento adequado

## 📞 Suporte e Documentação

### Documentação Adicional
- [Guia de Instalação Detalhado](docs/installation.md)
- [Referência da API](docs/api-reference.md)
- [Guia de Configuração](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)

### Suporte
- **Issues**: Reporte bugs e solicite features via GitHub Issues
- **Discussões**: Participe das discussões na comunidade
- **Email**: suporte@ethereum-auditor.com

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙏 Agradecimentos

- **Trail of Bits** pela ferramenta Slither
- **OpenZeppelin** pelas bibliotecas de segurança
- **Ethereum Foundation** pela infraestrutura da rede
- **Comunidade de Segurança** pelas pesquisas e descobertas

---

**Desenvolvido por Manus AI** - Agente Auditor de Smart Contracts Ethereum de Alta Precisão

