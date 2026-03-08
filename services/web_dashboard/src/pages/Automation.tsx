/**
 * Automation Page - Workflow and Automation Management
 */

import React, { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import type { WorkflowStatus } from '@/types'
import {
  Play,
  Pause,
  RotateCcw,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Zap,
  Settings,
  AlertCircle,
} from 'lucide-react'

interface TemplateStep {
  id: string
  name: string
  description: string
  type: 'manual' | 'automated'
  estimated_time: string
}

interface AutomationTemplate {
  id: string
  name: string
  description: string
  category: 'containment' | 'remediation' | 'notification' | 'enrichment'
  steps: number
  stepDetails: TemplateStep[]
}

interface WorkflowConfig {
  auto_approve: boolean
  timeout_seconds: number
  retry_on_failure: boolean
  max_retries: number
  notification_on_complete: boolean
  notification_channels: string[]
  log_level: 'debug' | 'info' | 'warning' | 'error'
}

interface AutomationExecutionStep {
  id: string
  name: string
  type: 'manual' | 'automated'
  error?: string
}

interface AutomationExecution {
  id: string
  name: string
  description: string
  status: WorkflowStatus
  created_at: string
  completed_at?: string
  current_step?: number
  steps: AutomationExecutionStep[]
  playbook_id: string
  trigger_alert_id?: string
}

const normalizeExecution = (execution: any, templates: AutomationTemplate[]): AutomationExecution => {
  const template = templates.find((item) => item.id === execution.playbook_id)
  const steps = template?.stepDetails.map((step) => ({
    id: step.id,
    name: step.name,
    type: step.type,
    error: execution.error,
  })) || []

  return {
    id: execution.execution_id,
    name: template?.name || execution.playbook_id,
    description: template?.description || `Playbook ${execution.playbook_id}`,
    status: execution.status,
    created_at: execution.started_at,
    completed_at: execution.completed_at,
    current_step: typeof execution.current_action_index === 'number' ? execution.current_action_index : undefined,
    steps,
    playbook_id: execution.playbook_id,
    trigger_alert_id: execution.trigger_alert_id,
  }
}

export const Automation: React.FC = () => {
  const [workflows, setWorkflows] = useState<AutomationExecution[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedWorkflow, setSelectedWorkflow] = useState<AutomationExecution | null>(null)
  const [selectedTemplate, setSelectedTemplate] = useState<AutomationTemplate | null>(null)
  const [executing, setExecuting] = useState<Record<string, boolean>>({})
  const [showConfigModal, setShowConfigModal] = useState(false)
  const [showRunModal, setShowRunModal] = useState(false)
  const [config, setConfig] = useState<WorkflowConfig>({
    auto_approve: false,
    timeout_seconds: 300,
    retry_on_failure: true,
    max_retries: 3,
    notification_on_complete: true,
    notification_channels: ['email', 'slack'],
    log_level: 'info',
  })
  const [savingConfig, setSavingConfig] = useState(false)
  const [automationTemplates, setAutomationTemplates] = useState<AutomationTemplate[]>([])

  useEffect(() => {
    loadWorkflows()
    loadConfig()
    loadTemplates()
    // Poll for workflow updates
    const interval = setInterval(loadWorkflows, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadTemplates = async () => {
    try {
      const templates = await api.workflows.getWorkflowTemplates()
      setAutomationTemplates(templates)
      return templates
    } catch (error) {
      console.error('Failed to load workflow templates:', error)
      return []
    }
  }

  const loadWorkflows = async () => {
    try {
      setLoading(true)
      const [executions, templates] = await Promise.all([
        api.workflows.getAutomationExecutions(),
        automationTemplates.length > 0 ? Promise.resolve(automationTemplates) : loadTemplates(),
      ])
      setWorkflows(executions.map((item: any) => normalizeExecution(item, templates)))
    } catch (error) {
      console.error('Failed to load workflows:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadConfig = async () => {
    try {
      const savedConfig = await api.workflows.getWorkflowConfig()
      if (savedConfig) {
        setConfig(savedConfig)
      }
    } catch (error) {
      console.error('Failed to load workflow config:', error)
      // Use defaults if not found
    }
  }

  const saveConfig = async () => {
    try {
      setSavingConfig(true)
      await api.workflows.updateWorkflowConfig(config)
      setShowConfigModal(false)
      alert('Configuration saved successfully!')
    } catch (error) {
      console.error('Failed to save workflow config:', error)
      alert('Failed to save configuration. Please try again.')
    } finally {
      setSavingConfig(false)
    }
  }

  const handleRunWorkflow = async (templateId?: string) => {
    try {
      if (templateId) {
        // Create and execute workflow from template
        await api.workflows.executeFromTemplate(templateId, config)
        alert('Workflow started successfully!')
        setShowRunModal(false)
        setSelectedTemplate(null)
      } else {
        setShowRunModal(true)
      }
    } catch (error) {
      console.error('Failed to run workflow:', error)
      alert('Failed to start workflow. Please try again.')
    }
  }

  const executeWorkflow = async (executionId: string, action: 'cancel' | 'retry') => {
    try {
      setExecuting((prev) => ({ ...prev, [executionId]: true }))
      const execution = workflows.find((item) => item.id === executionId)
      if (!execution) {
        return
      }
      if (action === 'cancel') {
        await api.workflows.cancelAutomationExecution(executionId)
      } else {
        await api.workflows.executeFromTemplate(execution.playbook_id, config)
      }
      await loadWorkflows()
    } catch (error) {
      console.error('Failed to execute workflow:', error)
    } finally {
      setExecuting((prev) => ({ ...prev, [executionId]: false }))
    }
  }

  const getStatusIcon = (status: WorkflowStatus) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="w-5 h-5 text-green-600" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-600" />
      case 'running':
        return <Loader2 className="w-5 h-5 text-blue-600 animate-spin" />
      default:
        return <Clock className="w-5 h-5 text-gray-400" />
    }
  }

  const getStatusBadge = (status: WorkflowStatus) => {
    const styles = {
      completed: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800',
      running: 'bg-blue-100 text-blue-800',
      pending: 'bg-gray-100 text-gray-800',
      cancelled: 'bg-yellow-100 text-yellow-800',
    }
    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[status]}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    )
  }

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      containment: 'bg-red-50 text-red-700',
      remediation: 'bg-orange-50 text-orange-700',
      notification: 'bg-blue-50 text-blue-700',
      enrichment: 'bg-purple-50 text-purple-700',
    }
    return colors[category] || 'bg-gray-50 text-gray-700'
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Automation</h1>
          <p className="text-sm text-gray-500">Manage automated response workflows and playbooks</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowConfigModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          >
            <Settings className="w-4 h-4" />
            Configure
          </button>
          <button
            onClick={() => handleRunWorkflow()}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
          >
            <Play className="w-4 h-4" />
            Run Workflow
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-50 rounded-lg">
              <Zap className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{automationTemplates.length}</p>
              <p className="text-sm text-gray-500">Available Playbooks</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-50 rounded-lg">
              <CheckCircle2 className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">
                {workflows.filter((w) => w.status === 'completed').length}
              </p>
              <p className="text-sm text-gray-500">Completed Today</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-50 rounded-lg">
              <Loader2 className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">
                {workflows.filter((w) => w.status === 'running').length}
              </p>
              <p className="text-sm text-gray-500">Currently Running</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-50 rounded-lg">
              <AlertCircle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">
                {workflows.filter((w) => w.status === 'failed').length}
              </p>
              <p className="text-sm text-gray-500">Failed Today</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Automation Templates */}
        <div className="lg:col-span-2">
          <div className="bg-white rounded-lg border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Automation Playbooks</h2>
              <p className="text-sm text-gray-500">Pre-built workflows for common security tasks</p>
            </div>

            <div className="divide-y divide-gray-200">
              {automationTemplates.map((template) => (
                <div
                  key={template.id}
                  className="px-6 py-4 hover:bg-gray-50 transition-colors cursor-pointer"
                  onClick={() => setSelectedTemplate(template)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 flex-1">
                      <div className="p-2 bg-primary-50 rounded-lg">
                        <Zap className="w-5 h-5 text-primary-600" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-medium text-gray-900">{template.name}</h3>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${getCategoryColor(template.category)}`}>
                            {template.category}
                          </span>
                        </div>
                        <p className="text-sm text-gray-500">{template.description}</p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                          <span>{template.steps} steps</span>
                          <span>Automated</span>
                        </div>
                      </div>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recent Workflows */}
        <div>
          <div className="bg-white rounded-lg border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Recent Workflows</h2>
              <p className="text-sm text-gray-500">Latest automation executions</p>
            </div>

            {loading ? (
              <div className="flex items-center justify-center h-64">
                <div className="spinner"></div>
              </div>
            ) : workflows.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-center px-6">
                <Zap className="w-12 h-12 text-gray-300 mb-3" />
                <p className="text-sm text-gray-500">No recent workflow executions</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                {workflows.map((workflow) => (
                  <div
                    key={workflow.id}
                    className="px-6 py-4 hover:bg-gray-50 transition-colors cursor-pointer"
                    onClick={() => setSelectedWorkflow(workflow)}
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">{getStatusIcon(workflow.status)}</div>
                      <div className="flex-1 min-w-0">
                        <h3 className="text-sm font-medium text-gray-900 truncate">
                          {workflow.name}
                        </h3>
                        <p className="text-xs text-gray-500 mt-0.5">
                          {new Date(workflow.created_at).toLocaleString()}
                        </p>
                        <div className="flex items-center gap-2 mt-2">
                          {getStatusBadge(workflow.status)}
                          {workflow.current_step !== undefined && (
                            <span className="text-xs text-gray-500">
                              Step {workflow.current_step + 1} of {workflow.steps.length}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Selected Template Detail */}
      {selectedTemplate && (
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Playbook Details</h2>
              <p className="text-sm text-gray-500">{selectedTemplate.name}</p>
            </div>
            <button
              onClick={() => setSelectedTemplate(null)}
              className="text-gray-400 hover:text-gray-500"
            >
              ✕
            </button>
          </div>

          <div className="px-6 py-4">
            <div className="mb-6">
              <p className="text-sm text-gray-700 mb-4">{selectedTemplate.description}</p>
              <div className="flex items-center gap-4 text-sm">
                <span className={`px-3 py-1 rounded-full font-medium ${getCategoryColor(selectedTemplate.category)}`}>
                  {selectedTemplate.category}
                </span>
                <span className="text-gray-600">{selectedTemplate.steps} steps</span>
                <span className="text-gray-600">
                  ~{selectedTemplate.stepDetails.reduce((acc, step) => {
                    const mins = parseInt(step.estimated_time) || 0
                    return acc + mins
                  }, 0)} minutes total
                </span>
              </div>
            </div>

            {/* Steps */}
            <div className="mb-6">
              <h3 className="text-sm font-medium text-gray-900 mb-3">Workflow Steps</h3>
              <div className="space-y-3">
                {selectedTemplate.stepDetails.map((step, index) => (
                  <div key={step.id} className="flex items-center gap-4 p-4 bg-gray-50 rounded-lg">
                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-primary-100 text-primary-700 font-medium text-sm">
                      {index + 1}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h4 className="text-sm font-medium text-gray-900">{step.name}</h4>
                        <span className={`text-xs px-2 py-0.5 rounded ${step.type === 'automated' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}`}>
                          {step.type}
                        </span>
                      </div>
                      <p className="text-xs text-gray-600">{step.description}</p>
                    </div>
                    <div className="text-xs text-gray-500">
                      ~{step.estimated_time}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3 pt-4 border-t border-gray-200">
              <button
                onClick={() => handleRunWorkflow(selectedTemplate.id)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
              >
                <Play className="w-4 h-4" />
                Run Playbook
              </button>
              <button
                onClick={() => setSelectedTemplate(null)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Selected Workflow Detail */}
      {selectedWorkflow && !selectedTemplate && (
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Workflow Details</h2>
              <p className="text-sm text-gray-500">{selectedWorkflow.name}</p>
            </div>
            <button
              onClick={() => setSelectedWorkflow(null)}
              className="text-gray-400 hover:text-gray-500"
            >
              ✕
            </button>
          </div>

          <div className="px-6 py-4">
            <div className="mb-4">
              <p className="text-sm text-gray-700">{selectedWorkflow.description}</p>
            </div>

            {/* Progress Steps */}
            <div className="mb-6">
              <h3 className="text-sm font-medium text-gray-900 mb-3">Progress</h3>
              <div className="space-y-2">
                {selectedWorkflow.steps.map((step, index) => (
                  <div key={step.id} className="flex items-center gap-3">
                    <div
                      className={`flex items-center justify-center w-6 h-6 rounded-full text-xs font-medium ${
                        index < (selectedWorkflow.current_step || 0)
                          ? 'bg-green-100 text-green-800'
                          : index === (selectedWorkflow.current_step || 0)
                          ? 'bg-blue-100 text-blue-800'
                          : 'bg-gray-100 text-gray-500'
                      }`}
                    >
                      {index < (selectedWorkflow.current_step || 0) ? (
                        <CheckCircle2 className="w-4 h-4" />
                      ) : (
                        index + 1
                      )}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900">{step.name}</p>
                      {step.error && (
                        <p className="text-xs text-red-600 mt-0.5">{step.error}</p>
                      )}
                    </div>
                    <span className={`text-xs ${getCategoryColor(step.type)}`}>
                      {step.type}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3 pt-4 border-t border-gray-200">
              {selectedWorkflow.status === 'running' && (
                <button
                  onClick={() => executeWorkflow(selectedWorkflow.id, 'cancel')}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 transition-colors"
                >
                  <Pause className="w-4 h-4" />
                  Cancel
                </button>
              )}
              {(selectedWorkflow.status === 'failed' || selectedWorkflow.status === 'cancelled') && (
                <button
                  onClick={() => executeWorkflow(selectedWorkflow.id, 'retry')}
                  disabled={executing[selectedWorkflow.id]}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
                >
                  {executing[selectedWorkflow.id] ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <RotateCcw className="w-4 h-4" />
                  )}
                  Retry
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">Workflow Configuration</h2>
                <p className="text-sm text-gray-500">Configure automation workflow settings</p>
              </div>
              <button
                onClick={() => setShowConfigModal(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                ✕
              </button>
            </div>

            <div className="px-6 py-4 space-y-6">
              {/* Auto Approve */}
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium text-gray-900">Auto Approve Workflows</label>
                  <p className="text-xs text-gray-500">Automatically approve workflow execution without manual confirmation</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.auto_approve}
                    onChange={(e) => setConfig({ ...config, auto_approve: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                </label>
              </div>

              {/* Timeout */}
              <div>
                <label className="text-sm font-medium text-gray-900">Workflow Timeout (seconds)</label>
                <input
                  type="number"
                  value={config.timeout_seconds}
                  onChange={(e) => setConfig({ ...config, timeout_seconds: parseInt(e.target.value) || 300 })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  min="60"
                  max="3600"
                />
                <p className="mt-1 text-xs text-gray-500">Maximum time to wait for workflow completion (60-3600 seconds)</p>
              </div>

              {/* Retry on Failure */}
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium text-gray-900">Retry on Failure</label>
                  <p className="text-xs text-gray-500">Automatically retry failed workflow steps</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.retry_on_failure}
                    onChange={(e) => setConfig({ ...config, retry_on_failure: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                </label>
              </div>

              {/* Max Retries */}
              <div>
                <label className="text-sm font-medium text-gray-900">Maximum Retries</label>
                <input
                  type="number"
                  value={config.max_retries}
                  onChange={(e) => setConfig({ ...config, max_retries: parseInt(e.target.value) || 3 })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  min="1"
                  max="10"
                  disabled={!config.retry_on_failure}
                />
                <p className="mt-1 text-xs text-gray-500">Maximum number of retry attempts (1-10)</p>
              </div>

              {/* Notification on Complete */}
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium text-gray-900">Notify on Completion</label>
                  <p className="text-xs text-gray-500">Send notifications when workflow completes</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.notification_on_complete}
                    onChange={(e) => setConfig({ ...config, notification_on_complete: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                </label>
              </div>

              {/* Notification Channels */}
              <div>
                <label className="text-sm font-medium text-gray-900">Notification Channels</label>
                <div className="mt-2 space-y-2">
                  {['email', 'slack', 'webhook'].map((channel) => (
                    <label key={channel} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={config.notification_channels.includes(channel)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setConfig({
                              ...config,
                              notification_channels: [...config.notification_channels, channel],
                            })
                          } else {
                            setConfig({
                              ...config,
                              notification_channels: config.notification_channels.filter((c) => c !== channel),
                            })
                          }
                        }}
                        disabled={!config.notification_on_complete}
                        className="mr-2 h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                      />
                      <span className="text-sm text-gray-700 capitalize">{channel}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Log Level */}
              <div>
                <label className="text-sm font-medium text-gray-900">Log Level</label>
                <select
                  value={config.log_level}
                  onChange={(e) => setConfig({ ...config, log_level: e.target.value as any })}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                >
                  <option value="debug">Debug</option>
                  <option value="info">Info</option>
                  <option value="warning">Warning</option>
                  <option value="error">Error</option>
                </select>
                <p className="mt-1 text-xs text-gray-500">Verbosity level for workflow execution logs</p>
              </div>
            </div>

            <div className="px-6 py-4 bg-gray-50 border-t border-gray-200 flex items-center justify-end gap-3">
              <button
                onClick={() => setShowConfigModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={saveConfig}
                disabled={savingConfig}
                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
              >
                {savingConfig ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Run Workflow Modal */}
      {showRunModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Run Workflow</h2>
              <p className="text-sm text-gray-500">Select a playbook to execute</p>
            </div>

            <div className="px-6 py-4 max-h-96 overflow-y-auto">
              <div className="space-y-2">
                {automationTemplates.map((template) => (
                  <button
                    key={template.id}
                    onClick={() => handleRunWorkflow(template.id)}
                    className="w-full text-left px-4 py-3 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-primary-50 rounded-lg">
                        <Zap className="w-4 h-4 text-primary-600" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-sm font-medium text-gray-900">{template.name}</h3>
                        <p className="text-xs text-gray-500">{template.description}</p>
                      </div>
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="px-6 py-4 bg-gray-50 border-t border-gray-200">
              <button
                onClick={() => setShowRunModal(false)}
                className="w-full px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
