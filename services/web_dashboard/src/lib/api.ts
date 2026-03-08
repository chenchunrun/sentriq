/**
 * API Client for Security Triage Dashboard
 * Handles all HTTP requests to backend services through Kong Gateway
 */

import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios'
import type {
  Alert,
  AlertFilters,
  AlertMetrics,
  AlertTrends,
  ApiResponse,
  ApiError,
  AuthToken,
  LoginCredentials,
  PaginatedResponse,
  Report,
  ReportRequest,
  SystemConfig,
  TopAlerts,
  UserPreferences,
  Notification,
  Workflow,
  ThreatIntelSource,
  AuthUser,
} from '@/types'

// API Base URL (from environment variable or default)
// In production, use empty string to make requests to same host/port as frontend
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

/**
 * Create axios instance with default config
 */
const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

const decodeJwtPayload = (): Record<string, unknown> | null => {
  const token = localStorage.getItem('access_token')
  if (!token) {
    return null
  }

  try {
    const [, payload] = token.split('.')
    if (!payload) {
      return null
    }
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}

const getCurrentUserId = (): string => {
  const payload = decodeJwtPayload()
  return typeof payload?.sub === 'string' ? payload.sub : 'local-user'
}

/**
 * Request interceptor to add auth token
 */
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('access_token')
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

/**
 * Response interceptor to handle errors
 */
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiError>) => {
    if (error.response?.status === 401) {
      // Unauthorized - clear token and redirect to login
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// =============================================================================
// Authentication API
// =============================================================================

export const authApi = {
  /**
   * Login with username and password
   */
  login: async (credentials: LoginCredentials): Promise<AuthToken> => {
    const response = await apiClient.post<AuthToken>('/auth/login', credentials)
    const token = response.data

    // Store tokens
    localStorage.setItem('access_token', token.access_token)
    localStorage.setItem('refresh_token', token.refresh_token)

    return token
  },

  /**
   * Logout and clear tokens
   */
  logout: async (): Promise<void> => {
    try {
      await apiClient.post('/auth/logout')
    } finally {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
    }
  },

  /**
   * Refresh access token
   */
  refreshToken: async (): Promise<AuthToken> => {
    const refreshToken = localStorage.getItem('refresh_token')
    if (!refreshToken) {
      throw new Error('No refresh token available')
    }

    const response = await apiClient.post<AuthToken>('/auth/refresh', {
      refresh_token: refreshToken,
    })

    const token = response.data
    localStorage.setItem('access_token', token.access_token)
    localStorage.setItem('refresh_token', token.refresh_token)

    return token
  },

  /**
   * Fetch authenticated user profile
   */
  me: async (): Promise<AuthUser> => {
    const response = await apiClient.get<AuthUser>('/auth/me')
    return response.data
  },
}

// =============================================================================
// Alert API
// =============================================================================

export const alertApi = {
  /**
   * Get paginated list of alerts
   */
  getAlerts: async (filters?: AlertFilters): Promise<PaginatedResponse<Alert>> => {
    const page = filters?.page || 1
    const pageSize = filters?.page_size || 20
    const params = {
      ...filters,
      skip: Math.max(0, (page - 1) * pageSize),
      limit: pageSize,
      sort_by: filters?.sort_by === 'created_at' ? 'received_at' : filters?.sort_by,
    }
    delete (params as Partial<AlertFilters>).page
    delete (params as Partial<AlertFilters>).page_size
    delete (params as Partial<AlertFilters>).date_from
    delete (params as Partial<AlertFilters>).date_to

    const response = await apiClient.get<ApiResponse<Alert[]>>('/alerts', {
      params,
    })
    const items = response.data.data || []
    const meta = response.data.meta || {}
    const total = Number(meta.total || items.length || 0)

    return {
      data: items,
      total,
      page,
      page_size: pageSize,
      total_pages: Math.max(1, Math.ceil(total / pageSize)),
    }
  },

  /**
   * Get single alert by ID
   */
  getAlert: async (alertId: string): Promise<Alert> => {
    const response = await apiClient.get<ApiResponse<Alert>>(`/alerts/${alertId}`)
    return response.data.data
  },

  /**
   * Create new alert
   */
  createAlert: async (alert: Partial<Alert>): Promise<Alert> => {
    const payload = {
      alert_type: alert.alert_type || alert.metadata?.type || 'other',
      severity: alert.severity || 'medium',
      title: alert.title,
      description: alert.description,
      source_ip: alert.source_ip,
      destination_ip: alert.destination_ip || alert.target_ip,
      file_hash: alert.file_hash,
      url: alert.url,
      asset_id: alert.asset_id,
      user_id: alert.user_id,
      source: typeof alert.metadata?.source === 'string' ? alert.metadata.source : 'web_dashboard',
      raw_data: alert.metadata || {},
    }
    const response = await apiClient.post<Alert>('/alerts', payload)
    return response.data
  },

  /**
   * Update alert
   */
  updateAlert: async (alertId: string, alert: Partial<Alert>): Promise<Alert> => {
    const response = await apiClient.put<ApiResponse<Alert>>(`/alerts/${alertId}`, alert)
    return response.data.data
  },

  /**
   * Update alert status
   */
  updateAlertStatus: async (
    alertId: string,
    status: string,
    note?: string
  ): Promise<Alert> => {
    const response = await apiClient.patch<Alert>(
      `/alerts/${alertId}/status`,
      { status, comment: note }
    )
    return response.data
  },

  bulkAction: async (
    alertIds: string[],
    action: 'assign' | 'close',
    params?: Record<string, unknown>
  ): Promise<{
    action: string
    total: number
    success_count: number
    failure_count: number
    errors: Array<{ alert_id: string; error: string }>
  }> => {
    const response = await apiClient.post('/alerts/bulk', {
      alert_ids: alertIds,
      action,
      params,
    })
    return response.data
  },

  /**
   * Assign alert to user
   */
  assignAlert: async (alertId: string, userId: string): Promise<Alert> => {
    const response = await apiClient.patch<ApiResponse<Alert>>(
      `/alerts/${alertId}/assign`,
      { assigned_to: userId }
    )
    return response.data.data
  },

  /**
   * Delete alert
   */
  deleteAlert: async (alertId: string): Promise<void> => {
    await apiClient.delete(`/alerts/${alertId}`)
  },

  /**
   * Get triage result for alert
   */
  getTriageResult: async (alertId: string): Promise<TriageResult> => {
    const response = await apiClient.get<ApiResponse<TriageResult>>(
      `/alerts/${alertId}/triage`
    )
    return response.data.data
  },

  /**
   * Request new triage analysis
   */
  requestTriage: async (alertId: string): Promise<TriageResult> => {
    const response = await apiClient.post<ApiResponse<TriageResult>>(
      `/alerts/${alertId}/triage`
    )
    return response.data.data
  },
}

// =============================================================================
// Analytics API
// =============================================================================

export const analyticsApi = {
  /**
   * Get alert metrics
   */
  getMetrics: async (filters?: {
    date_from?: string
    date_to?: string
  }): Promise<AlertMetrics> => {
    const timeRange = filters?.date_from || filters?.date_to ? '7d' : '24h'
    const [dashboardResponse, severityResponse, statusResponse] = await Promise.all([
      apiClient.get('/analytics/dashboard', {
        params: {
          time_range: timeRange,
          include_trends: true,
        },
      }),
      apiClient.get('/analytics/metrics/severity-distribution'),
      apiClient.get('/analytics/metrics/status-distribution'),
    ])
    const data = dashboardResponse.data
    const bySeverity = severityResponse.data || {}
    const byStatus = statusResponse.data || {}
    return {
      total_alerts: data.total_alerts || 0,
      by_severity: bySeverity,
      by_type: {},
      by_status: byStatus,
      avg_resolution_time: data.avg_response_time || 0,
      mtta: 0,
      mttr: data.avg_response_time || 0,
    } as AlertMetrics
  },

  /**
   * Get alert trends
   */
  getTrends: async (filters?: {
    date_from?: string
    date_to?: string
    interval?: 'hour' | 'day' | 'week' | 'month'
  }): Promise<AlertTrends> => {
    const groupBy = filters?.interval === 'day' || filters?.interval === 'week' || filters?.interval === 'month'
      ? 'day'
      : 'hour'
    const response = await apiClient.get('/analytics/trends/alerts', {
      params: {
        time_range: filters?.date_from || filters?.date_to ? '7d' : '24h',
        group_by: groupBy,
      },
    })
    const points = response.data.data_points || []
    return {
      daily: points,
      weekly: points,
      monthly: points,
    }
  },

  /**
   * Get top alert types
   */
  getTopAlerts: async (limit?: number): Promise<TopAlerts[]> => {
    const response = await apiClient.get('/analytics/metrics/top-alert-types', {
      params: { limit },
    })
    const rows = response.data || []
    const total = rows.reduce((sum: number, item: { count?: number }) => sum + (item.count || 0), 0)
    return rows.map((item: { alert_type: string; count: number }) => ({
      alert_type: item.alert_type,
      count: item.count,
      percentage: total > 0 ? (item.count / total) * 100 : 0,
    }))
  },
}

// =============================================================================
// Reporting API
// =============================================================================

export const reportApi = {
  /**
   * Get list of reports
   */
  getReports: async (): Promise<Report[]> => {
    const response = await apiClient.get<ApiResponse<{ reports: Array<Record<string, unknown>> }>>('/reports')
    const reports = response.data.data?.reports || []
    return reports.map((report) => ({
      id: String(report.report_id || ''),
      name: String(report.name || report.report_id || 'Unnamed report'),
      description: typeof report.description === 'string' ? report.description : undefined,
      type: String(report.report_type || 'custom'),
      format: (report.format || 'html') as Report['format'],
      status: (report.status || 'pending') as Report['status'],
      created_at: String(report.created_at || new Date().toISOString()),
      created_by: String(report.created_by || 'system'),
      file_url: typeof report.file_path === 'string' ? report.file_path : undefined,
    }))
  },

  /**
   * Create new report
   */
  createReport: async (report: ReportRequest): Promise<Report> => {
    const payload = {
      name: report.name,
      description: report.description,
      format: report.format,
      report_type: report.type,
      date: report.date,
      alert_id: report.alert_id,
      parameters: report.filters,
    }
    const response = await apiClient.post<ApiResponse<Record<string, unknown>>>('/reports/generate', payload)
    const data = response.data.data || {}
    return {
      id: String(data.report_id || ''),
      name: String(data.name || report.name),
      description: typeof data.description === 'string' ? data.description : report.description,
      type: String(data.report_type || report.type),
      format: (data.format || report.format || 'html') as Report['format'],
      status: (data.status || 'pending') as Report['status'],
      created_at: new Date().toISOString(),
      created_by: 'system',
    }
  },

  /**
   * Get report by ID
   */
  getReport: async (reportId: string): Promise<Report> => {
    const response = await apiClient.get<ApiResponse<Record<string, unknown>>>(`/reports/${reportId}`)
    const report = response.data.data || {}
    return {
      id: String(report.report_id || reportId),
      name: String(report.name || reportId),
      description: typeof report.description === 'string' ? report.description : undefined,
      type: String(report.report_type || 'custom'),
      format: (report.format || 'html') as Report['format'],
      status: (report.status || 'pending') as Report['status'],
      created_at: String(report.created_at || new Date().toISOString()),
      created_by: String(report.created_by || 'system'),
      file_url: typeof report.file_path === 'string' ? report.file_path : undefined,
    }
  },

  /**
   * Download report file
   */
  downloadReport: async (reportId: string): Promise<Blob> => {
    const report = await reportApi.getReport(reportId)
    const response = await apiClient.get(`/reports/${reportId}/download`, {
      params: {
        format: report.format === 'pdf' ? 'html' : report.format === 'excel' ? 'csv' : report.format,
      },
      responseType: 'blob',
    })
    return response.data
  },

  /**
   * Delete report
   */
  deleteReport: async (reportId: string): Promise<void> => {
    await apiClient.delete(`/reports/${reportId}`)
  },
}

// =============================================================================
// Configuration API
// =============================================================================

export const configApi = {
  /**
   * Get all system configurations
   */
  getConfigs: async (category?: string): Promise<SystemConfig[]> => {
    const response = await apiClient.get<ApiResponse<Record<string, {
      value: Record<string, unknown>
      category?: string
      description?: string
      editable?: boolean
    }>>>('/config', {
      params: { category },
    })
    const groups = response.data.data || {}
    const entries = Object.entries(groups)

    return entries.flatMap(([groupKey, group]) =>
      Object.entries(group.value || {}).map(([key, value]) => ({
        key,
        value: value as SystemConfig['value'],
        description: group.description || `${groupKey} setting`,
        category: group.category || groupKey,
        editable: group.editable !== false,
      }))
    )
  },

  /**
   * Update configuration
   */
  updateConfig: async (
    key: string,
    value: string | number | boolean | string[] | Record<string, unknown>
  ): Promise<SystemConfig> => {
    const response = await apiClient.get<ApiResponse<Record<string, {
      value: Record<string, unknown>
      category?: string
    }>>>('/config')
    const groups = response.data.data || {}
    const match = Object.entries(groups).find(([, group]) =>
      Object.prototype.hasOwnProperty.call(group.value || {}, key)
    )

    if (!match) {
      throw new Error(`Unknown config key: ${key}`)
    }

    const [groupKey, group] = match
    const nextValue = {
      ...(group.value || {}),
      [key]: value,
    }

    await apiClient.put(`/config/${groupKey}`, nextValue, {
      params: { changed_by: getCurrentUserId() },
    })

    return {
      key,
      value,
      description: `${groupKey} setting`,
      category: group.category || groupKey,
      editable: true,
    }
  },

  /**
   * Reset configuration to defaults
   */
  resetToDefaults: async (category?: string): Promise<void> => {
    if (!category || category === 'preferences') {
      return
    }
    await apiClient.post(`/config/${category}/reset`, null, {
      params: { changed_by: getCurrentUserId() },
    })
  },

  /**
   * Get user preferences
   */
  getPreferences: async (): Promise<UserPreferences> => {
    const response = await apiClient.get<ApiResponse<UserPreferences>>('/config/preferences', {
      params: { user_id: getCurrentUserId() },
    })
    return response.data.data
  },

  /**
   * Update user preferences
   */
  updatePreferences: async (prefs: Partial<UserPreferences>): Promise<UserPreferences> => {
    const response = await apiClient.put<ApiResponse<UserPreferences>>('/config/preferences', prefs, {
      params: { user_id: getCurrentUserId() },
    })
    return response.data.data
  },

  /**
   * Get feature flags
   */
  getFeatureFlags: async (): Promise<Record<string, boolean>> => {
    const response = await apiClient.get<ApiResponse<Record<string, boolean>>>('/features')
    return response.data.data
  },
}

// =============================================================================
// Workflow API
// =============================================================================

export const workflowApi = {
  /**
   * Get list of workflows
   */
  getWorkflows: async (alertId?: string): Promise<Workflow[]> => {
    const response = await apiClient.get<ApiResponse<Workflow[]>>('/workflows', {
      params: { alert_id: alertId },
    })
    return response.data.data
  },

  /**
   * Get workflow by ID
   */
  getWorkflow: async (workflowId: string): Promise<Workflow> => {
    const response = await apiClient.get<ApiResponse<Workflow>>(`/workflows/${workflowId}`)
    return response.data.data
  },

  /**
   * Get workflow executions
   */
  getExecutions: async (filters?: { status?: string }): Promise<any[]> => {
    const response = await apiClient.get<ApiResponse<{ executions: any[]; total: number }>>('/workflows/executions', {
      params: filters,
    })
    return response.data.data?.executions || []
  },

  /**
   * Start a workflow execution
   */
  executeWorkflow: async (
    workflowId: string,
    inputData?: Record<string, unknown>
  ): Promise<{
    execution_id: string
    workflow_id: string
    status: string
    started_at: string
  }> => {
    const response = await apiClient.post('/workflows/execute', {
      workflow_id: workflowId,
      input_data: inputData || {},
    })
    return response.data.data
  },

  /**
   * Create new workflow
   */
  createWorkflow: async (workflow: Partial<Workflow>): Promise<Workflow> => {
    const response = await apiClient.post<ApiResponse<Workflow>>('/workflows', workflow)
    return response.data.data
  },

  /**
   * Execute workflow action
   */
  executeWorkflowAction: async (
    workflowId: string,
    action: string,
    params?: Record<string, unknown>
  ): Promise<Workflow> => {
    const response = await apiClient.post<ApiResponse<Workflow>>(
      `/workflows/${workflowId}/actions`,
      { action, params }
    )
    return response.data.data
  },

  /**
   * Get workflow templates
   */
  getWorkflowTemplates: async (): Promise<AutomationTemplate[]> => {
    const response = await apiClient.get<ApiResponse<{ playbooks: any[]; total: number }>>('/playbooks')
    const playbooks = response.data.data?.playbooks || []
    return playbooks.map((playbook: any) => ({
      id: playbook.playbook_id,
      name: playbook.name,
      description: playbook.description,
      category: inferPlaybookCategory(playbook),
      steps: Array.isArray(playbook.actions) ? playbook.actions.length : 0,
      stepDetails: Array.isArray(playbook.actions)
        ? playbook.actions.map((action: any) => ({
            id: action.action_id,
            name: action.name,
            description: action.description,
            type: action.action_type === 'manual' ? 'manual' : 'automated',
            estimated_time: formatDuration(action.timeout_seconds),
          }))
        : [],
      estimated_time: formatDuration(playbook.timeout_seconds),
    }))
  },

  /**
   * Get workflow configuration
   */
  getWorkflowConfig: async (): Promise<{
    auto_approve: boolean
    timeout_seconds: number
    retry_on_failure: boolean
    max_retries: number
    notification_on_complete: boolean
    notification_channels: string[]
    log_level: 'debug' | 'info' | 'warning' | 'error'
  }> => {
    const groups = await configApi.getConfigs('automation')
    const config = Object.fromEntries(groups.map((item) => [item.key, item.value]))
    return {
      auto_approve: Boolean(config.approval_required ?? false),
      timeout_seconds: Number(config.timeout_seconds ?? 600),
      retry_on_failure: Boolean(config.retry_on_failure ?? true),
      max_retries: Number(config.max_retries ?? 3),
      notification_on_complete: Boolean(config.notification_on_complete ?? true),
      notification_channels: Array.isArray(config.notification_channels)
        ? config.notification_channels.map(String)
        : ['email', 'slack'],
      log_level: (config.log_level || 'info') as 'debug' | 'info' | 'warning' | 'error',
    }
  },

  /**
   * Update workflow configuration
   */
  updateWorkflowConfig: async (config: {
    auto_approve: boolean
    timeout_seconds: number
    retry_on_failure: boolean
    max_retries: number
    notification_on_complete: boolean
    notification_channels: string[]
    log_level: 'debug' | 'info' | 'warning' | 'error'
  }): Promise<void> => {
    await apiClient.put(
      '/config/automation',
      {
        approval_required: config.auto_approve,
        timeout_seconds: config.timeout_seconds,
        max_concurrent_executions: 10,
        retry_on_failure: config.retry_on_failure,
        max_retries: config.max_retries,
        notification_on_complete: config.notification_on_complete,
        notification_channels: config.notification_channels,
        log_level: config.log_level,
      },
      { params: { changed_by: getCurrentUserId() } }
    )
  },

  /**
   * Execute workflow from template
   */
  executeFromTemplate: async (
    templateId: string,
    config: {
      auto_approve: boolean
      timeout_seconds: number
      retry_on_failure: boolean
      max_retries: number
      notification_on_complete: boolean
      notification_channels: string[]
      log_level: 'debug' | 'info' | 'warning' | 'error'
    }
  ): Promise<Workflow> => {
    const response = await apiClient.post('/playbooks/execute', {
      playbook_id: templateId,
      alert_id: `manual-${Date.now()}`,
      input_data: {
        source: 'web_dashboard',
        config,
      },
    })
    return {
      id: response.data.data.execution_id,
      name: templateId,
      description: 'Manual playbook execution',
      status: response.data.data.status,
      trigger_alert_id: response.data.data.trigger_alert_id,
      steps: [],
      created_at: response.data.data.started_at,
      updated_at: response.data.data.started_at,
    } as Workflow
  },

  getAutomationExecutions: async (): Promise<any[]> => {
    const response = await apiClient.get<ApiResponse<{ executions: any[]; total: number }>>('/executions')
    return response.data.data?.executions || []
  },

  cancelAutomationExecution: async (executionId: string): Promise<void> => {
    await apiClient.post(`/executions/${executionId}/cancel`)
  },
}

const formatDuration = (seconds?: number): string => {
  const totalSeconds = Number(seconds || 0)
  if (!totalSeconds) {
    return '0m'
  }
  const minutes = Math.max(1, Math.round(totalSeconds / 60))
  return `${minutes}m`
}

const inferPlaybookCategory = (playbook: any): AutomationTemplate['category'] => {
  const id = String(playbook.playbook_id || '').toLowerCase()
  const name = String(playbook.name || '').toLowerCase()
  const text = `${id} ${name}`
  if (text.includes('notify') || text.includes('email')) return 'notification'
  if (text.includes('enrich') || text.includes('intel')) return 'enrichment'
  if (text.includes('remed') || text.includes('patch')) return 'remediation'
  return 'containment'
}

// =============================================================================
// Notification API
// =============================================================================

export const notificationApi = {
  /**
   * Get user notifications
   */
  getNotifications: async (unreadOnly = false): Promise<Notification[]> => {
    const response = await apiClient.get<ApiResponse<Notification[]>>('/notifications', {
      params: { unreadOnly },
    })
    return response.data.data
  },

  /**
   * Mark notification as read
   */
  markAsRead: async (notificationId: string): Promise<void> => {
    await apiClient.patch(`/notifications/${notificationId}/read`)
  },

  /**
   * Mark all notifications as read
   */
  markAllAsRead: async (): Promise<void> => {
    await apiClient.patch('/notifications/read-all')
  },

  /**
   * Delete notification
   */
  delete: async (notificationId: string): Promise<void> => {
    await apiClient.delete(`/notifications/${notificationId}`)
  },
}

// =============================================================================
// AI Triage API (Zhipu AI / 智谱AI)
// =============================================================================

export interface TemplateStep {
  id: string
  name: string
  description: string
  type: 'manual' | 'automated'
  estimated_time: string
}

export interface AutomationTemplate {
  id: string
  name: string
  description: string
  category: 'containment' | 'remediation' | 'notification' | 'enrichment'
  steps: number
  stepDetails: TemplateStep[]
  estimated_time?: string
  created_at?: string
  updated_at?: string
}

export interface AIAnalysisResult {
  alert_id?: string
  analysis: {
    risk_score: number
    risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info'
    confidence: number
    summary: string
    analysis: string
    threat_indicators: string[]
    recommended_actions: string[]
    priority: 'critical' | 'high' | 'medium' | 'low'
  }
  model: string
  usage: {
    prompt_tokens?: number
    completion_tokens?: number
    total_tokens?: number
  }
  error?: string
  raw_content?: string
}

export interface AttackChainResult {
  attack_stages: string[]
  ttps: string[]
  techniques: Array<{
    id: string
    name: string
    tactic: string
    description: string
    detection_methods: string[]
    mitigations: string[]
  }>
  kill_chain_phase: string
  confidence: number
  attack_patterns: Array<{
    pattern: string
    confidence: number
    evidence: string[]
    affected_assets: string[]
  }>
  related_campaigns: Array<{
    name: string
    confidence: number
    description: string
    matched_techniques: string[]
  }>
  mitigations: Array<{
    name: string
    count: number
    related_techniques: string[]
  }>
  timeline: Array<{
    type: string
    timestamp: string
    event: string
  }>
}

export interface TriageResult {
  alert_id: string
  triaged_at: string
  risk_level: string
  confidence: number
  reasoning: string
  recommended_actions: Array<{
    action: string
    priority: string
    type: string
  }>
  requires_human_review: boolean
  processing_time_seconds?: number
  model_used?: string
  method?: string
}

export const aiApi = {
  /**
   * Analyze a single alert using AI
   */
  analyzeAlert: async (
    alert: Record<string, unknown>,
    context?: Record<string, unknown>
  ): Promise<AIAnalysisResult> => {
    const response = await apiClient.post<ApiResponse<AIAnalysisResult>>('/ai/analyze-alert', {
      alert,
      context,
    })
    return response.data.data
  },

  /**
   * Batch analyze multiple alerts using AI
   */
  batchAnalyze: async (alerts: Record<string, unknown>[]): Promise<AIAnalysisResult[]> => {
    const response = await apiClient.post<ApiResponse<AIAnalysisResult[]>>('/ai/batch-analyze', {
      alerts,
    })
    return response.data.data
  },

  /**
   * Triage alert using LangChain agent with tool calling
   */
  triageAlert: async (
    alert: Record<string, unknown>,
    enrichment?: Record<string, unknown>,
    useAgent: boolean = true
  ): Promise<TriageResult> => {
    const response = await apiClient.post<ApiResponse<TriageResult>>('/ai/triage/agent', alert, {
      params: { use_agent: useAgent, enrichment: enrichment ? JSON.stringify(enrichment) : undefined },
    })
    return response.data.data
  },

  /**
   * Analyze attack chain from multiple alerts
   */
  analyzeAttackChain: async (alerts: Record<string, unknown>[]): Promise<AttackChainResult> => {
    const response = await apiClient.post<ApiResponse<AttackChainResult>>('/ai/analyze-chain', {
      alerts,
    })
    return response.data.data
  },
}

// =============================================================================
// Threat Intelligence API
//=============================================================================

interface ThreatIntelQueryResult {
  ioc: string
  ioc_type: string
  aggregate_score: number
  threat_level: string
  confidence: number
  detected_by_count: number
  total_sources: number
  sources: ThreatIntelSource[]
  tags?: string[]
  queried_at: string
}

export const threatIntelApi = {
  /**
   * Query threat intelligence for an IOC
   */
  query: async (ioc: string, iocType?: string): Promise<ThreatIntelQueryResult> => {
    const params: Record<string, string> = {}
    if (iocType === 'ip') params.ip = ioc
    else if (iocType === 'hash') params.file_hash = ioc
    else if (iocType === 'url') params.url = ioc
    else params.ip = ioc // Default to IP

    const response = await apiClient.post<ApiResponse<ThreatIntelQueryResult>>(
      '/threat-intel/query',
      params
    )
    return response.data.data
  },

  /**
   * Batch query threat intelligence for multiple IOCs
   */
  batchQuery: async (iocs: string[]): Promise<Record<string, ThreatIntelQueryResult>> => {
    const response = await apiClient.post<ApiResponse<Record<string, ThreatIntelQueryResult>>>(
      '/threat-intel/batch-query',
      { iocs }
    )
    return response.data.data
  },
}

// =============================================================================
// Similarity Search API
//=============================================================================

interface SimilarAlert {
  alert_id: string
  similarity_score: number
  alert_data?: Record<string, unknown>
  risk_level?: string
  created_at: string
}

interface SimilaritySearchResult {
  results: SimilarAlert[]
  total_results: number
  search_time_ms: number
}

export const similarityApi = {
  /**
   * Find similar alerts using vector similarity search
   */
  findSimilar: async (alertId: string, topK: number = 3): Promise<SimilaritySearchResult> => {
    const response = await apiClient.post<ApiResponse<SimilaritySearchResult>>(
      '/similarity/search',
      { alert_id: alertId, top_k: topK }
    )
    return response.data.data
  },
}

// Update the main api export
export const api = {
  auth: authApi,
  alerts: alertApi,
  analytics: analyticsApi,
  reports: reportApi,
  config: configApi,
  workflows: workflowApi,
  notifications: notificationApi,
  ai: aiApi,
  threatIntel: threatIntelApi,
  similarity: similarityApi,
}

export default apiClient
