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
    const response = await apiClient.post<ApiResponse<AuthToken>>('/auth/login', credentials)
    const token = response.data.data

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

    const response = await apiClient.post<ApiResponse<AuthToken>>('/auth/refresh', {
      refresh_token: refreshToken,
    })

    const token = response.data.data
    localStorage.setItem('access_token', token.access_token)
    localStorage.setItem('refresh_token', token.refresh_token)

    return token
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
    const response = await apiClient.get<ApiResponse<PaginatedResponse<Alert>>>('/alerts', {
      params: filters,
    })
    return response.data.data
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
    const response = await apiClient.post<ApiResponse<Alert>>('/alerts', alert)
    return response.data.data
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
    const response = await apiClient.patch<ApiResponse<Alert>>(
      `/alerts/${alertId}/status`,
      { status, note }
    )
    return response.data.data
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
    const response = await apiClient.get<ApiResponse<AlertMetrics>>('/metrics', {
      params: filters,
    })
    return response.data.data
  },

  /**
   * Get alert trends
   */
  getTrends: async (filters?: {
    date_from?: string
    date_to?: string
    interval?: 'hour' | 'day' | 'week' | 'month'
  }): Promise<AlertTrends> => {
    const response = await apiClient.get<ApiResponse<AlertTrends>>('/trends', {
      params: filters,
    })
    return response.data.data
  },

  /**
   * Get top alert types
   */
  getTopAlerts: async (limit?: number): Promise<TopAlerts[]> => {
    const response = await apiClient.get<ApiResponse<TopAlerts[]>>('/top-alerts', {
      params: { limit },
    })
    return response.data.data
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
    const response = await apiClient.get<ApiResponse<Report[]>>('/reports')
    return response.data.data
  },

  /**
   * Create new report
   */
  createReport: async (report: ReportRequest): Promise<Report> => {
    const response = await apiClient.post<ApiResponse<Report>>('/reports', report)
    return response.data.data
  },

  /**
   * Get report by ID
   */
  getReport: async (reportId: string): Promise<Report> => {
    const response = await apiClient.get<ApiResponse<Report>>(`/reports/${reportId}`)
    return response.data.data
  },

  /**
   * Download report file
   */
  downloadReport: async (reportId: string): Promise<Blob> => {
    const response = await apiClient.get(`/reports/${reportId}/download`, {
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
    const response = await apiClient.get<ApiResponse<SystemConfig[]>>('/config', {
      params: { category },
    })
    return response.data.data
  },

  /**
   * Update configuration
   */
  updateConfig: async (key: string, value: string | number | boolean): Promise<SystemConfig> => {
    const response = await apiClient.put<ApiResponse<SystemConfig>>(`/config/${key}`, {
      value,
    })
    return response.data.data
  },

  /**
   * Reset configuration to defaults
   */
  resetToDefaults: async (category?: string): Promise<void> => {
    await apiClient.post('/config/reset', { category })
  },

  /**
   * Get user preferences
   */
  getPreferences: async (): Promise<UserPreferences> => {
    const response = await apiClient.get<ApiResponse<UserPreferences>>('/config/preferences')
    return response.data.data
  },

  /**
   * Update user preferences
   */
  updatePreferences: async (prefs: Partial<UserPreferences>): Promise<UserPreferences> => {
    const response = await apiClient.put<ApiResponse<UserPreferences>>('/config/preferences', prefs)
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
    const response = await apiClient.get<ApiResponse<AutomationTemplate[]>>('/workflow-templates')
    return response.data.data
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
    const response = await apiClient.get<ApiResponse<any>>('/workflows/config')
    return response.data.data
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
    await apiClient.put('/workflows/config', config)
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
    const response = await apiClient.post<ApiResponse<Workflow>>('/workflows/execute-from-template', {
      template_id: templateId,
      config,
    })
    return response.data.data
  },
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
