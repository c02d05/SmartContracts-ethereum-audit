import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  BarChart3, 
  FileText, 
  Settings,
  Play,
  Square,
  RefreshCw,
  Search,
  Filter
} from 'lucide-react'
import { Button } from '@/components/ui/button.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert.jsx'
import { Progress } from '@/components/ui/progress.jsx'
import './App.css'

// API base URL - ajuste conforme necessário
const API_BASE_URL = '/api/auditor'

// Hook para fazer chamadas à API
function useApi() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const apiCall = async (endpoint, options = {}) => {
    setLoading(true)
    setError(null)
    
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        ...options
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const data = await response.json()
      return data
    } catch (err) {
      setError(err.message)
      throw err
    } finally {
      setLoading(false)
    }
  }

  return { apiCall, loading, error }
}

// Componente de Status do Agente
function AgentStatus() {
  const [status, setStatus] = useState(null)
  const { apiCall, loading, error } = useApi()

  const fetchStatus = async () => {
    try {
      const data = await apiCall('/status')
      setStatus(data)
    } catch (err) {
      console.error('Erro ao buscar status:', err)
    }
  }

  const startAgent = async () => {
    try {
      await apiCall('/start', { method: 'POST' })
      await fetchStatus()
    } catch (err) {
      console.error('Erro ao iniciar agente:', err)
    }
  }

  const stopAgent = async () => {
    try {
      await apiCall('/stop', { method: 'POST' })
      await fetchStatus()
    } catch (err) {
      console.error('Erro ao parar agente:', err)
    }
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 5000) // Atualiza a cada 5 segundos
    return () => clearInterval(interval)
  }, [])

  if (loading && !status) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Status do Agente
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center p-4">
            <RefreshCw className="h-6 w-6 animate-spin" />
          </div>
        </CardContent>
      </Card>
    )
  }

  const isRunning = status?.is_running || false
  const uptime = status?.uptime_seconds || 0
  const queueSize = status?.queue_size || 0

  const formatUptime = (seconds) => {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return `${hours}h ${minutes}m`
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Status do Agente
          <Badge variant={isRunning ? "default" : "secondary"} className="ml-auto">
            {isRunning ? "Ativo" : "Inativo"}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Estado:</span>
          <div className="flex items-center gap-2">
            {isRunning ? (
              <CheckCircle className="h-4 w-4 text-green-500" />
            ) : (
              <XCircle className="h-4 w-4 text-red-500" />
            )}
            <span className="text-sm font-medium">
              {isRunning ? "Em execução" : "Parado"}
            </span>
          </div>
        </div>

        {isRunning && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Tempo ativo:</span>
              <span className="text-sm font-medium">{formatUptime(uptime)}</span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Fila de processamento:</span>
              <Badge variant="outline">{queueSize} contratos</Badge>
            </div>
          </>
        )}

        <div className="flex gap-2">
          <Button 
            onClick={startAgent} 
            disabled={isRunning || loading}
            size="sm"
            className="flex-1"
          >
            <Play className="h-4 w-4 mr-2" />
            Iniciar
          </Button>
          <Button 
            onClick={stopAgent} 
            disabled={!isRunning || loading}
            variant="outline"
            size="sm"
            className="flex-1"
          >
            <Square className="h-4 w-4 mr-2" />
            Parar
          </Button>
          <Button 
            onClick={fetchStatus} 
            disabled={loading}
            variant="ghost"
            size="sm"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Erro</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  )
}

// Componente de Estatísticas
function Statistics() {
  const [stats, setStats] = useState(null)
  const { apiCall, loading } = useApi()

  const fetchStats = async () => {
    try {
      const data = await apiCall('/statistics')
      setStats(data)
    } catch (err) {
      console.error('Erro ao buscar estatísticas:', err)
    }
  }

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 30000) // Atualiza a cada 30 segundos
    return () => clearInterval(interval)
  }, [])

  if (loading && !stats) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                <div className="h-8 bg-gray-200 rounded w-1/2"></div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  const contracts = stats?.contracts || {}
  const vulnerabilities = stats?.vulnerabilities || {}

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total de Contratos</CardTitle>
          <FileText className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{contracts.total || 0}</div>
          <p className="text-xs text-muted-foreground">
            {contracts.verified || 0} verificados ({(contracts.verification_rate || 0).toFixed(1)}%)
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Contratos Auditados</CardTitle>
          <CheckCircle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{contracts.audited || 0}</div>
          <p className="text-xs text-muted-foreground">
            Processados com sucesso
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Vulnerabilidades</CardTitle>
          <AlertTriangle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{vulnerabilities.total || 0}</div>
          <p className="text-xs text-muted-foreground">
            {(vulnerabilities.by_severity?.critical || 0)} críticas, {(vulnerabilities.by_severity?.high || 0)} altas
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Taxa de Risco</CardTitle>
          <BarChart3 className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">
            {contracts.total > 0 ? 
              ((vulnerabilities.total || 0) / contracts.total * 100).toFixed(1) : 0}%
          </div>
          <p className="text-xs text-muted-foreground">
            Vulnerabilidades por contrato
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

// Componente de Lista de Contratos
function ContractsList() {
  const [contracts, setContracts] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const { apiCall } = useApi()

  const fetchContracts = async () => {
    try {
      setLoading(true)
      const data = await apiCall('/contracts?per_page=50')
      setContracts(data.contracts || [])
    } catch (err) {
      console.error('Erro ao buscar contratos:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchContracts()
  }, [])

  const filteredContracts = contracts.filter(contract => {
    const matchesSearch = contract.address.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (contract.name && contract.name.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesStatus = statusFilter === 'all' || contract.audit_status === statusFilter
    return matchesSearch && matchesStatus
  })

  const getStatusBadge = (status) => {
    const variants = {
      'pending': 'secondary',
      'in_progress': 'default',
      'completed': 'default',
      'failed': 'destructive'
    }
    
    const labels = {
      'pending': 'Pendente',
      'in_progress': 'Em Progresso',
      'completed': 'Concluído',
      'failed': 'Falhou'
    }

    return (
      <Badge variant={variants[status] || 'secondary'}>
        {labels[status] || status}
      </Badge>
    )
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A'
    return new Date(dateString).toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Contratos Auditados</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center p-8">
            <RefreshCw className="h-6 w-6 animate-spin" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Contratos Auditados</CardTitle>
        <CardDescription>
          Lista de smart contracts processados pelo agente auditor
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex gap-4 mb-4">
          <div className="flex-1">
            <Input
              placeholder="Buscar por endereço ou nome..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-input bg-background rounded-md text-sm"
          >
            <option value="all">Todos os status</option>
            <option value="pending">Pendente</option>
            <option value="in_progress">Em Progresso</option>
            <option value="completed">Concluído</option>
            <option value="failed">Falhou</option>
          </select>
        </div>

        <div className="space-y-4">
          {filteredContracts.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              Nenhum contrato encontrado
            </div>
          ) : (
            filteredContracts.map((contract) => (
              <div key={contract.id} className="border rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <code className="text-sm bg-muted px-2 py-1 rounded">
                      {contract.address}
                    </code>
                    {contract.name && (
                      <span className="text-sm font-medium">{contract.name}</span>
                    )}
                  </div>
                  {getStatusBadge(contract.audit_status)}
                </div>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-muted-foreground">
                  <div>
                    <span className="font-medium">Bloco:</span> {contract.block_number}
                  </div>
                  <div>
                    <span className="font-medium">Verificado:</span> {contract.is_verified ? 'Sim' : 'Não'}
                  </div>
                  <div>
                    <span className="font-medium">Auditorias:</span> {contract.audit_count}
                  </div>
                  <div>
                    <span className="font-medium">Última auditoria:</span> {formatDate(contract.last_audit_date)}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  )
}

// Componente principal do Dashboard
function Dashboard() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Monitoramento em tempo real do Agente Auditor de Smart Contracts Ethereum
        </p>
      </div>

      <AgentStatus />
      <Statistics />
      <ContractsList />
    </div>
  )
}

// Componente de Layout Principal
function Layout({ children }) {
  const location = useLocation()

  const navigation = [
    { name: 'Dashboard', href: '/', icon: Activity },
    { name: 'Contratos', href: '/contracts', icon: FileText },
    { name: 'Vulnerabilidades', href: '/vulnerabilities', icon: AlertTriangle },
    { name: 'Relatórios', href: '/reports', icon: BarChart3 },
    { name: 'Configurações', href: '/settings', icon: Settings },
  ]

  return (
    <div className="min-h-screen bg-background">
      <div className="border-b">
        <div className="flex h-16 items-center px-4">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6" />
            <span className="font-semibold">Ethereum Auditor</span>
          </div>
          <nav className="flex items-center space-x-4 lg:space-x-6 mx-6">
            {navigation.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.href
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center gap-2 text-sm font-medium transition-colors hover:text-primary ${
                    isActive ? 'text-primary' : 'text-muted-foreground'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {item.name}
                </Link>
              )
            })}
          </nav>
        </div>
      </div>
      <div className="container mx-auto py-6">
        {children}
      </div>
    </div>
  )
}

// Componente principal da aplicação
function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/contracts" element={<div>Página de Contratos (em desenvolvimento)</div>} />
          <Route path="/vulnerabilities" element={<div>Página de Vulnerabilidades (em desenvolvimento)</div>} />
          <Route path="/reports" element={<div>Página de Relatórios (em desenvolvimento)</div>} />
          <Route path="/settings" element={<div>Página de Configurações (em desenvolvimento)</div>} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App

