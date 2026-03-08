/**
 * Alerts List Page
 */

import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '@/lib/api'
import { useWebSocket } from '@/hooks/useWebSocket'
import type { AlertFilters, Alert } from '@/types'
import { Search, Filter, Eye, ArrowUpDown, AlertTriangle, CheckSquare, Square, CheckCircle, XCircle, Wifi, WifiOff, Brain, Loader2, Plus, X } from 'lucide-react'
import type { AIAnalysisResult } from '@/lib/api'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

const statusColors = {
  pending: 'bg-gray-100 text-gray-800',
  analyzing: 'bg-blue-100 text-blue-800',
  triaged: 'bg-purple-100 text-purple-800',
  in_progress: 'bg-yellow-100 text-yellow-800',
  resolved: 'bg-green-100 text-green-800',
  closed: 'bg-gray-100 text-gray-800',
  false_positive: 'bg-red-100 text-red-800',
}

export const Alerts: React.FC = () => {
  const [filters, setFilters] = useState<AlertFilters>({
    page: 1,
    page_size: 20,
    sort_by: 'created_at',
    sort_order: 'desc',
  })

  const [searchTerm, setSearchTerm] = useState('')
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [analyzingAlert, setAnalyzingAlert] = useState<string | null>(null)
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResult | null>(null)
  const [showAnalysisModal, setShowAnalysisModal] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showFilterModal, setShowFilterModal] = useState(false)
  const [activeFilters, setActiveFilters] = useState<AlertFilters>({})
  const [newAlert, setNewAlert] = useState({
    title: '',
    description: '',
    severity: 'medium',
    type: 'other',
    source_ip: '',
    destination_ip: '',
    source_port: '',
    destination_port: '',
    protocol: '',
  })
  const queryClient = useQueryClient()

  // Fetch alerts
  const { data, isLoading } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => api.alerts.getAlerts(filters),
  })

  // WebSocket connection for real-time updates
  const { isConnected } = useWebSocket({
    onMessage: (message) => {
      if (message.type === 'alerts_update') {
        // Invalidate alerts query to trigger refresh
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
      } else if (message.type === 'alert_created' && message.data) {
        // New alert created - invalidate to show it
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
      }
    },
    onConnect: () => {
      // WebSocket connected - debug only
    },
    onDisconnect: () => {
      // WebSocket disconnected - debug only
    },
  })

  // Bulk update mutation
  const bulkUpdateMutation = useMutation({
    mutationFn: ({ alertIds, status }: { alertIds: string[]; status: string }) => {
      if (status === 'resolved') {
        return api.alerts.bulkAction(alertIds, 'close')
      }
      throw new Error(`Unsupported bulk action: ${status}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      setSelectedAlerts(new Set())
    },
  })

  // AI Analysis mutation
  const analyzeMutation = useMutation({
    mutationFn: async (alert: Alert) => {
      setAnalyzingAlert(alert.alert_id)
      const result = await api.ai.analyzeAlert({
        id: alert.alert_id,
        title: alert.title,
        description: alert.description,
        severity: alert.severity,
        type: alert.alert_type,
        source: alert.source_ip,
        target: alert.destination_ip,
      })
      return result
    },
    onSuccess: (result) => {
      setAiAnalysis(result)
      setShowAnalysisModal(true)
      setAnalyzingAlert(null)
    },
    onError: (error: any) => {
      console.error('AI analysis failed:', error)
      // Extract error message from response if available
      let errorMsg = 'AI分析失败，请检查配置'
      if (error?.response?.data?.error) {
        errorMsg = `AI分析失败: ${error.response.data.error}`
      } else if (error?.message) {
        errorMsg = `AI分析失败: ${error.message}`
      }
      alert(errorMsg)
      setAnalyzingAlert(null)
    },
  })

  const handleAIAnalyze = (alert: Alert) => {
    analyzeMutation.mutate(alert)
  }

  // Create alert mutation
  const createAlertMutation = useMutation({
    mutationFn: async (alertData: typeof newAlert) =>
      api.alerts.createAlert({
        title: alertData.title,
        description: alertData.description,
        severity: alertData.severity as Alert['severity'],
        alert_type: alertData.type as Alert['alert_type'],
        source_ip: alertData.source_ip || undefined,
        destination_ip: alertData.destination_ip || undefined,
        metadata: {
          source_port: alertData.source_port || undefined,
          destination_port: alertData.destination_port || undefined,
          protocol: alertData.protocol || undefined,
          source: 'web_dashboard',
        },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      setShowCreateModal(false)
      setNewAlert({
        title: '',
        description: '',
        severity: 'medium',
        type: 'other',
        source_ip: '',
        destination_ip: '',
        source_port: '',
        destination_port: '',
        protocol: '',
      })
      alert('告警创建成功！')
    },
    onError: (error) => {
      console.error('Failed to create alert:', error)
      alert('创建失败，请重试')
    },
  })

  const handleCreateAlert = () => {
    if (!newAlert.title.trim()) {
      alert('请输入告警标题')
      return
    }
    createAlertMutation.mutate(newAlert)
  }

  const alerts = data?.data || []
  const total = data?.total || 0
  const totalPages = data?.total_pages || 0

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setFilters({ ...filters, search: searchTerm, page: 1 })
  }

  const applyAlertFilters = (newFilters: Partial<AlertFilters>) => {
    const combined = { ...activeFilters, ...newFilters }
    setActiveFilters(combined)
    setFilters({ ...filters, ...combined, page: 1 })
    setShowFilterModal(false)
  }

  const clearAlertFilters = () => {
    setActiveFilters({})
    setFilters({
      page: 1,
      page_size: 20,
      sort_by: 'created_at',
      sort_order: 'desc',
    })
    setShowFilterModal(false)
  }

  const handleSelectAll = () => {
    if (selectedAlerts.size === alerts.length) {
      setSelectedAlerts(new Set())
    } else {
      setSelectedAlerts(new Set(alerts.map((a: Alert) => a.alert_id)))
    }
  }

  const handleSelectAlert = (alertId: string) => {
    const newSelected = new Set(selectedAlerts)
    if (newSelected.has(alertId)) {
      newSelected.delete(alertId)
    } else {
      newSelected.add(alertId)
    }
    setSelectedAlerts(newSelected)
  }

  const handleBulkAction = (status: string) => {
    if (status !== 'resolved') {
      alert('当前仅支持批量关闭/标记 resolved')
      return
    }
    if (window.confirm(`Update ${selectedAlerts.size} alerts to ${status}?`)) {
      bulkUpdateMutation.mutate({
        alertIds: Array.from(selectedAlerts),
        status,
      })
    }
  }

  const handleSort = (field: string) => {
    if (filters.sort_by === field) {
      setFilters({
        ...filters,
        sort_order: filters.sort_order === 'asc' ? 'desc' : 'asc',
      })
    } else {
      setFilters({
        ...filters,
        sort_by: field,
        sort_order: 'desc',
      })
    }
  }

  const handlePageChange = (newPage: number) => {
    setFilters({ ...filters, page: newPage })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
          <p className="text-sm text-gray-600 mt-1">
            Total: {total.toLocaleString()} alerts
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Connection Status */}
          <div className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-300 rounded-lg">
            {isConnected ? (
              <>
                <Wifi className="w-4 h-4 text-green-600" />
                <span className="text-sm font-medium text-gray-700">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-gray-400" />
                <span className="text-sm font-medium text-gray-500">Offline</span>
              </>
            )}
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn btn-primary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Create Alert
          </button>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="card">
        <div className="card-body">
          <div className="flex flex-col md:flex-row gap-4">
            {/* Search */}
            <form onSubmit={handleSearch} className="flex-1 flex gap-2">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search alerts by ID, title, or IP..."
                  className="input pl-10"
                />
              </div>
              <button type="submit" className="btn btn-primary">
                Search
              </button>
            </form>

            {/* Filters */}
            <button
              onClick={() => setShowFilterModal(true)}
              className="btn btn-outline flex items-center gap-2"
            >
              <Filter className="w-4 h-4" />
              Filters
              {Object.keys(activeFilters).length > 0 && (
                <span className="ml-1 px-2 py-0.5 bg-primary-600 text-white text-xs rounded-full">
                  {Object.keys(activeFilters).length}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Bulk Action Bar */}
      {selectedAlerts.size > 0 && (
        <div className="card bg-blue-50 border-blue-200">
          <div className="card-body flex items-center justify-between">
            <span className="text-sm font-medium text-gray-900">
              {selectedAlerts.size} alert{selectedAlerts.size > 1 ? 's' : ''} selected
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => handleBulkAction('resolved')}
                className="btn btn-success btn-sm flex items-center gap-1"
                disabled={bulkUpdateMutation.isPending}
              >
                <CheckCircle className="w-4 h-4" />
                Mark Resolved
              </button>
              <button
                onClick={() => handleBulkAction('false_positive')}
                className="btn btn-outline btn-sm text-danger-600 border-danger-300 hover:bg-danger-50 flex items-center gap-1"
                disabled={bulkUpdateMutation.isPending}
              >
                <XCircle className="w-4 h-4" />
                False Positive
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Alerts Table */}
      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="spinner"></div>
            </div>
          ) : alerts.length === 0 ? (
            <div className="text-center py-12">
              <AlertTriangle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600">No alerts found</p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th className="w-12">
                    <button
                      onClick={handleSelectAll}
                      className="p-2 hover:bg-gray-100 rounded"
                      title={selectedAlerts.size === alerts.length ? 'Deselect All' : 'Select All'}
                    >
                      {selectedAlerts.size === alerts.length && alerts.length > 0 ? (
                        <CheckSquare className="w-5 h-5 text-gray-600" />
                      ) : (
                        <Square className="w-5 h-5 text-gray-400" />
                      )}
                    </button>
                  </th>
                  <th
                    className="cursor-pointer hover:bg-gray-100"
                    onClick={() => handleSort('alert_id')}
                  >
                    <div className="flex items-center gap-2">
                      ID
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </th>
                  <th
                    className="cursor-pointer hover:bg-gray-100"
                    onClick={() => handleSort('title')}
                  >
                    <div className="flex items-center gap-2">
                      Title
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Type</th>
                  <th
                    className="cursor-pointer hover:bg-gray-100"
                    onClick={() => handleSort('created_at')}
                  >
                    <div className="flex items-center gap-2">
                      Created
                      <ArrowUpDown className="w-4 h-4" />
                    </div>
                  </th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert: Alert) => (
                  <tr key={alert.alert_id} className={selectedAlerts.has(alert.alert_id) ? 'bg-blue-50' : ''}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedAlerts.has(alert.alert_id)}
                        onChange={() => handleSelectAlert(alert.alert_id)}
                        className="w-4 h-4 cursor-pointer"
                      />
                    </td>
                    <td className="font-mono text-sm">{alert.alert_id}</td>
                    <td>
                      <div className="max-w-xs truncate" title={alert.title}>
                        {alert.title}
                      </div>
                    </td>
                    <td>
                      <span className={severityColors[alert.severity as keyof typeof severityColors]}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${statusColors[alert.status as keyof typeof statusColors]}`}>
                        {alert.status.replace('_', ' ').toUpperCase()}
                      </span>
                    </td>
                    <td className="capitalize">{alert.alert_type.replace('_', ' ')}</td>
                    <td className="text-sm text-gray-600">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/alerts/${alert.alert_id}`}
                          className="text-primary-600 hover:text-primary-700"
                          title="View Details"
                        >
                          <Eye className="w-5 h-5" />
                        </Link>
                        <button
                          onClick={() => handleAIAnalyze(alert)}
                          disabled={analyzingAlert === alert.alert_id}
                          className="text-purple-600 hover:text-purple-700 disabled:opacity-50 disabled:cursor-not-allowed"
                          title="AI Analysis (智谱AI)"
                        >
                          {analyzingAlert === alert.alert_id ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                          ) : (
                            <Brain className="w-5 h-5" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="card-footer flex items-center justify-between">
            <div className="text-sm text-gray-600">
              Page {filters.page} of {totalPages} ({total.toLocaleString()} total)
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => handlePageChange(filters.page! - 1)}
                disabled={filters.page === 1}
                className="btn btn-outline disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => handlePageChange(filters.page! + 1)}
                disabled={filters.page === totalPages}
                className="btn btn-outline disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* AI Analysis Modal */}
      {showAnalysisModal && aiAnalysis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col mx-4">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                  <Brain className="w-5 h-5 text-purple-600" />
                  AI Analysis Report (智谱AI分析报告)
                </h2>
                <p className="text-sm text-gray-500 mt-1">
                  Powered by {aiAnalysis.model} • Used {aiAnalysis.usage?.total_tokens || 0} tokens
                </p>
              </div>
              <button
                onClick={() => {
                  setShowAnalysisModal(false)
                  setAiAnalysis(null)
                }}
                className="text-gray-400 hover:text-gray-500"
              >
                ✕
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-6">
              {aiAnalysis.error ? (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <p className="text-red-800">{aiAnalysis.error}</p>
                  {aiAnalysis.raw_content && (
                    <details className="mt-2">
                      <summary className="text-sm text-red-600 cursor-pointer">Raw Response</summary>
                      <pre className="mt-2 text-xs text-red-700 overflow-auto">
                        {aiAnalysis.raw_content}
                      </pre>
                    </details>
                  )}
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Risk Score */}
                  <div className="bg-gray-50 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-gray-900">Risk Assessment (风险评估)</h3>
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <p className="text-sm text-gray-600">Confidence (置信度)</p>
                          <p className="text-2xl font-bold text-purple-600">{aiAnalysis.analysis.confidence}%</p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-gray-600">Risk Score (风险评分)</p>
                          <p className="text-3xl font-bold" style={{
                            color: aiAnalysis.analysis.risk_score >= 90 ? '#dc2626' :
                                   aiAnalysis.analysis.risk_score >= 70 ? '#f97316' :
                                   aiAnalysis.analysis.risk_score >= 40 ? '#eab308' :
                                   aiAnalysis.analysis.risk_score >= 20 ? '#84cc16' : '#6b7280'
                          }}>
                            {aiAnalysis.analysis.risk_score}/100
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-3">
                      <div
                        className="h-3 rounded-full transition-all"
                        style={{
                          width: `${aiAnalysis.analysis.risk_score}%`,
                          backgroundColor: aiAnalysis.analysis.risk_score >= 90 ? '#dc2626' :
                                         aiAnalysis.analysis.risk_score >= 70 ? '#f97316' :
                                         aiAnalysis.analysis.risk_score >= 40 ? '#eab308' :
                                         aiAnalysis.analysis.risk_score >= 20 ? '#84cc16' : '#6b7280'
                        }}
                      ></div>
                    </div>
                    <div className="flex items-center gap-2 mt-3">
                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                        aiAnalysis.analysis.risk_level === 'critical' ? 'bg-red-100 text-red-800' :
                        aiAnalysis.analysis.risk_level === 'high' ? 'bg-orange-100 text-orange-800' :
                        aiAnalysis.analysis.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        aiAnalysis.analysis.risk_level === 'low' ? 'bg-green-100 text-green-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {aiAnalysis.analysis.risk_level.toUpperCase()}
                      </span>
                      <span className="text-sm text-gray-600">Priority: {aiAnalysis.analysis.priority.toUpperCase()}</span>
                    </div>
                  </div>

                  {/* Summary */}
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                    <h4 className="font-semibold text-blue-900 mb-2">Summary (摘要)</h4>
                    <p className="text-blue-800">{aiAnalysis.analysis.summary}</p>
                  </div>

                  {/* Analysis */}
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-3">Detailed Analysis (详细分析)</h4>
                    <div className="bg-gray-50 rounded-lg p-4 whitespace-pre-wrap text-sm text-gray-700">
                      {aiAnalysis.analysis.analysis}
                    </div>
                  </div>

                  {/* Threat Indicators */}
                  {aiAnalysis.analysis.threat_indicators && aiAnalysis.analysis.threat_indicators.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-3">Threat Indicators (威胁指标)</h4>
                      <div className="flex flex-wrap gap-2">
                        {aiAnalysis.analysis.threat_indicators.map((indicator, idx) => (
                          <span key={idx} className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm">
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommended Actions */}
                  {aiAnalysis.analysis.recommended_actions && aiAnalysis.analysis.recommended_actions.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-gray-900 mb-3">Recommended Actions (建议行动)</h4>
                      <div className="space-y-2">
                        {aiAnalysis.analysis.recommended_actions.map((action, idx) => (
                          <div key={idx} className="flex items-start gap-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                            <span className="flex-shrink-0 w-6 h-6 bg-green-600 text-white rounded-full flex items-center justify-center text-sm font-medium">
                              {idx + 1}
                            </span>
                            <p className="text-sm text-green-800">{action}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-lg">
              <button
                onClick={() => {
                  setShowAnalysisModal(false)
                  setAiAnalysis(null)
                }}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Close
              </button>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(aiAnalysis, null, 2))
                  alert('AI analysis copied to clipboard')
                }}
                className="px-4 py-2 text-sm font-medium text-white bg-purple-600 rounded-lg hover:bg-purple-700 transition-colors"
              >
                Copy Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Filter Modal */}
      {showFilterModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Filter Alerts</h2>
              <button
                onClick={() => setShowFilterModal(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="px-6 py-4 space-y-4 max-h-[60vh] overflow-y-auto">
              {/* Severity Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Severity
                </label>
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
                    <button
                      key={severity}
                      onClick={() => {
                        const current = activeFilters.severity
                        if (Array.isArray(current)) {
                          if (current.includes(severity as any)) {
                            applyAlertFilters({
                              severity: current.filter((s) => s !== severity) as any,
                            })
                          } else {
                            applyAlertFilters({ severity: [...current, severity] as any })
                          }
                        } else {
                          applyAlertFilters({ severity: [severity] as any })
                        }
                      }}
                      className={`px-3 py-1.5 rounded-full text-sm font-medium border transition-colors ${
                        Array.isArray(activeFilters.severity) &&
                        activeFilters.severity.includes(severity as any)
                          ? 'bg-primary-600 border-primary-600 text-white'
                          : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      {severity.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              {/* Status Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Status
                </label>
                <div className="flex flex-wrap gap-2">
                  {['pending', 'analyzing', 'triaged', 'in_progress', 'resolved', 'closed', 'false_positive'].map(
                    (status) => (
                      <button
                        key={status}
                        onClick={() => {
                          const current = activeFilters.status
                          if (Array.isArray(current)) {
                            if (current.includes(status as any)) {
                              applyAlertFilters({
                                status: current.filter((s) => s !== status) as any,
                              })
                            } else {
                              applyAlertFilters({ status: [...current, status] as any })
                            }
                          } else {
                            applyAlertFilters({ status: [status] as any })
                          }
                        }}
                        className={`px-3 py-1.5 rounded-full text-sm font-medium border transition-colors ${
                          Array.isArray(activeFilters.status) && activeFilters.status.includes(status as any)
                            ? 'bg-primary-600 border-primary-600 text-white'
                            : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                        }`}
                      >
                        {status.replace('_', ' ').toUpperCase()}
                      </button>
                    )
                  )}
                </div>
              </div>

              {/* Alert Type Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Alert Type
                </label>
                <div className="flex flex-wrap gap-2">
                  {[
                    'malware',
                    'phishing',
                    'brute_force',
                    'ddos',
                    'intrusion',
                    'anomaly',
                    'data_exfiltration',
                    'other',
                  ].map((type) => (
                    <button
                      key={type}
                      onClick={() => {
                        const current = activeFilters.alert_type
                        if (Array.isArray(current)) {
                          if (current.includes(type as any)) {
                            applyAlertFilters({
                              alert_type: current.filter((t) => t !== type) as any,
                            })
                          } else {
                            applyAlertFilters({ alert_type: [...current, type] as any })
                          }
                        } else {
                          applyAlertFilters({ alert_type: [type] as any })
                        }
                      }}
                      className={`px-3 py-1.5 rounded-full text-sm font-medium border transition-colors ${
                        Array.isArray(activeFilters.alert_type) &&
                        activeFilters.alert_type.includes(type as any)
                          ? 'bg-primary-600 border-primary-600 text-white'
                          : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      {type.replace('_', ' ').toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              {/* Date Range Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Date Range
                </label>
                <select
                  value={activeFilters.date_from || ''}
                  onChange={(e) => {
                    const value = e.target.value
                    if (!value) {
                      const { date_from, date_to, ...rest } = activeFilters
                      applyAlertFilters(rest)
                    } else {
                      const now = new Date()
                      let cutoff = new Date()
                      if (value === '24h') {
                        cutoff.setHours(now.getHours() - 24)
                      } else if (value === '7d') {
                        cutoff.setDate(now.getDate() - 7)
                      } else if (value === '30d') {
                        cutoff.setDate(now.getDate() - 30)
                      }
                      applyAlertFilters({
                        date_from: cutoff.toISOString(),
                        date_to: now.toISOString(),
                      })
                    }
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="">All Time</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-lg">
              <button
                onClick={clearAlertFilters}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Clear All
              </button>
              <button
                onClick={() => setShowFilterModal(false)}
                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
              >
                Apply Filters
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Alert Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">创建新告警 (Create Alert)</h2>
              <button
                onClick={() => {
                  setShowCreateModal(false)
                  setNewAlert({
                    title: '',
                    description: '',
                    severity: 'medium',
                    type: 'other',
                    source_ip: '',
                    destination_ip: '',
                    source_port: '',
                    destination_port: '',
                    protocol: '',
                  })
                }}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="px-6 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
              {/* Title */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  标题 (Title) <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={newAlert.title}
                  onChange={(e) => setNewAlert({ ...newAlert, title: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="例如：可疑文件上传行为"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  描述 (Description)
                </label>
                <textarea
                  value={newAlert.description}
                  onChange={(e) => setNewAlert({ ...newAlert, description: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  rows={3}
                  placeholder="详细描述告警内容..."
                />
              </div>

              {/* Severity and Type */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    严重程度 (Severity)
                  </label>
                  <select
                    value={newAlert.severity}
                    onChange={(e) => setNewAlert({ ...newAlert, severity: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="critical">Critical (严重)</option>
                    <option value="high">High (高)</option>
                    <option value="medium">Medium (中)</option>
                    <option value="low">Low (低)</option>
                    <option value="info">Info (信息)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    类型 (Type)
                  </label>
                  <select
                    value={newAlert.type}
                    onChange={(e) => setNewAlert({ ...newAlert, type: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="malware">Malware (恶意软件)</option>
                    <option value="phishing">Phishing (钓鱼攻击)</option>
                    <option value="brute_force">Brute Force (暴力破解)</option>
                    <option value="ddos">DDoS (DDoS攻击)</option>
                    <option value="intrusion">Intrusion (入侵检测)</option>
                    <option value="anomaly">Anomaly (异常行为)</option>
                    <option value="data_exfiltration">Data Exfiltration (数据泄露)</option>
                    <option value="other">Other (其他)</option>
                  </select>
                </div>
              </div>

              {/* Network Information */}
              <div className="border-t border-gray-200 pt-4">
                <h3 className="text-sm font-medium text-gray-900 mb-3">网络信息 (Network Information)</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      源IP (Source IP)
                    </label>
                    <input
                      type="text"
                      value={newAlert.source_ip}
                      onChange={(e) => setNewAlert({ ...newAlert, source_ip: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                      placeholder="192.168.1.100"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      目标IP (Destination IP)
                    </label>
                    <input
                      type="text"
                      value={newAlert.destination_ip}
                      onChange={(e) => setNewAlert({ ...newAlert, destination_ip: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                      placeholder="10.0.0.1"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      源端口 (Source Port)
                    </label>
                    <input
                      type="text"
                      value={newAlert.source_port}
                      onChange={(e) => setNewAlert({ ...newAlert, source_port: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                      placeholder="8080"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      目标端口 (Destination Port)
                    </label>
                    <input
                      type="text"
                      value={newAlert.destination_port}
                      onChange={(e) => setNewAlert({ ...newAlert, destination_port: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                      placeholder="443"
                    />
                  </div>
                </div>

                <div className="mt-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    协议 (Protocol)
                  </label>
                  <select
                    value={newAlert.protocol}
                    onChange={(e) => setNewAlert({ ...newAlert, protocol: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="">选择协议...</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="HTTP">HTTP</option>
                    <option value="HTTPS">HTTPS</option>
                    <option value="ICMP">ICMP</option>
                    <option value="DNS">DNS</option>
                    <option value="OTHER">Other</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-lg">
              <button
                onClick={() => {
                  setShowCreateModal(false)
                  setNewAlert({
                    title: '',
                    description: '',
                    severity: 'medium',
                    type: 'other',
                    source_ip: '',
                    destination_ip: '',
                    source_port: '',
                    destination_port: '',
                    protocol: '',
                  })
                }}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                取消 (Cancel)
              </button>
              <button
                onClick={handleCreateAlert}
                disabled={createAlertMutation.isPending || !newAlert.title.trim()}
                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
              >
                {createAlertMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    创建中...
                  </>
                ) : (
                  <>
                    <Plus className="w-4 h-4" />
                    创建告警
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
