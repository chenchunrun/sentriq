/**
 * Workflows Page - Display workflow status and executions
 */

import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import {
  CheckCircle,
  XCircle,
  Clock,
  Eye,
  RefreshCw,
  Filter,
  Play,
} from 'lucide-react'

const statusColors = {
  pending: 'bg-gray-100 text-gray-800',
  running: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  cancelled: 'bg-yellow-100 text-yellow-800',
}

const statusIcons = {
  pending: Clock,
  running: RefreshCw,
  completed: CheckCircle,
  failed: XCircle,
  cancelled: XCircle,
  skipped: Clock,
}

interface WorkflowExecution {
  workflow_id: string
  execution_id: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  current_step?: string
  started_at: string
  completed_at?: string
  alert_id?: string
  playbook_id?: string
  progress?: number
  steps: WorkflowStep[]
}

interface WorkflowStep {
  step_id: string
  name: string
  type: 'activity' | 'decision' | 'human_task'
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  started_at?: string
  completed_at?: string
  error?: string
}

const normalizeWorkflow = (workflow: any): WorkflowExecution => {
  const outputSteps = Array.isArray(workflow?.output?.steps) ? workflow.output.steps : []
  const steps: WorkflowStep[] = outputSteps.map((step: any, index: number) => ({
    step_id: step.step || `step-${index + 1}`,
    name: step.step || `Step ${index + 1}`,
    type: step.type || 'activity',
    status: step.status || 'completed',
    error: step.error,
  }))

  return {
    workflow_id: workflow.workflow_id,
    execution_id: workflow.execution_id,
    status: workflow.status,
    current_step: workflow.current_step || workflow.output?.current_step,
    started_at: workflow.started_at,
    completed_at: workflow.completed_at,
    alert_id: workflow.input?.alert_id,
    playbook_id: workflow.input?.playbook_id,
    progress: workflow.progress,
    steps,
  }
}

export const Workflows: React.FC = () => {
  const [selectedWorkflow, setSelectedWorkflow] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const queryClient = useQueryClient()

  // Fetch workflow executions
  const { data: workflows, isLoading, refetch } = useQuery({
    queryKey: ['workflows', statusFilter],
    queryFn: () => api.workflows.getExecutions({ status: statusFilter === 'all' ? undefined : statusFilter }),
    refetchInterval: 5000, // Poll every 5 seconds
  })

  const executeWorkflowMutation = useMutation({
    mutationFn: () =>
      api.workflows.executeWorkflow('alert-processing', {
        alert_id: `wf-ui-${Date.now()}`,
        risk_level: 'HIGH',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['workflows'] })
      void refetch()
    },
  })

  const handleStatusFilter = (status: string) => {
    setStatusFilter(status)
  }

  const getFilteredWorkflows = () => {
    if (!workflows) return []
    const normalized = workflows.map((w: any) => normalizeWorkflow(w))
    if (statusFilter === 'all') return normalized
    return normalized.filter((w: WorkflowExecution) => w.status === statusFilter)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
      </div>
    )
  }

  const filteredWorkflows = getFilteredWorkflows()
  const stats = {
    total: workflows?.length || 0,
    running: workflows?.filter((w: WorkflowExecution) => w.status === 'running').length || 0,
    completed: workflows?.filter((w: WorkflowExecution) => w.status === 'completed').length || 0,
    failed: workflows?.filter((w: WorkflowExecution) => w.status === 'failed').length || 0,
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Workflows</h1>
          <p className="text-sm text-gray-600 mt-1">
            Monitor and manage automated workflow executions
          </p>
        </div>
        <button onClick={() => refetch()} className="btn btn-outline flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
        <button
          onClick={() => executeWorkflowMutation.mutate()}
          disabled={executeWorkflowMutation.isPending}
          className="btn btn-primary flex items-center gap-2"
        >
          <Play className="w-4 h-4" />
          Start Demo Workflow
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total</p>
                <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
              </div>
              <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                <Activity className="w-5 h-5 text-gray-600" />
              </div>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Running</p>
                <p className="text-2xl font-bold text-blue-600">{stats.running}</p>
              </div>
              <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                <RefreshCw className="w-5 h-5 text-blue-600" />
              </div>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Completed</p>
                <p className="text-2xl font-bold text-green-600">{stats.completed}</p>
              </div>
              <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-green-600" />
              </div>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Failed</p>
                <p className="text-2xl font-bold text-red-600">{stats.failed}</p>
              </div>
              <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                <XCircle className="w-5 h-5 text-red-600" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Status Filters */}
      <div className="flex items-center gap-2">
        <Filter className="w-4 h-4 text-gray-600" />
        <button
          onClick={() => handleStatusFilter('all')}
          className={`px-3 py-1 rounded-full text-sm ${
            statusFilter === 'all' ? 'bg-primary-500 text-white' : 'bg-gray-100 text-gray-600'
          }`}
        >
          All
        </button>
        <button
          onClick={() => handleStatusFilter('running')}
          className={`px-3 py-1 rounded-full text-sm ${
            statusFilter === 'running' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-600'
          }`}
        >
          Running
        </button>
        <button
          onClick={() => handleStatusFilter('completed')}
          className={`px-3 py-1 rounded-full text-sm ${
            statusFilter === 'completed' ? 'bg-green-500 text-white' : 'bg-gray-100 text-gray-600'
          }`}
        >
          Completed
        </button>
        <button
          onClick={() => handleStatusFilter('failed')}
          className={`px-3 py-1 rounded-full text-sm ${
            statusFilter === 'failed' ? 'bg-red-500 text-white' : 'bg-gray-100 text-gray-600'
          }`}
        >
          Failed
        </button>
      </div>

      {/* Workflow List */}
      <div className="space-y-4">
        {filteredWorkflows.length === 0 ? (
          <div className="card">
            <div className="card-body text-center py-12">
              <p className="text-gray-600">No workflows found</p>
            </div>
          </div>
        ) : (
          filteredWorkflows.map((workflow: WorkflowExecution) => {
            const StatusIcon = statusIcons[workflow.status]
            return (
              <div key={workflow.execution_id} className="card">
                <div className="card-body">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-lg font-semibold text-gray-900">{workflow.workflow_id}</h3>
                        <span className={`badge badge-sm ${statusColors[workflow.status]}`}>
                          <StatusIcon className="w-3 h-3 mr-1 inline" />
                          {workflow.status}
                        </span>
                        {workflow.alert_id && (
                          <span className="text-sm text-gray-500">
                            Alert: {workflow.alert_id}
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600">
                        Started: {new Date(workflow.started_at).toLocaleString()}
                      </p>
                      {workflow.completed_at && (
                        <p className="text-sm text-gray-600">
                          Completed: {new Date(workflow.completed_at).toLocaleString()}
                        </p>
                      )}
                      {workflow.current_step && (
                        <p className="text-sm text-blue-600 mt-1">
                          Current: {workflow.current_step}
                        </p>
                      )}
                      <div className="mt-3">
                        <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
                          <span>Progress</span>
                          <span>{Math.round((workflow.progress || 0) * 100)}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-primary-500 h-2 rounded-full transition-all"
                            style={{ width: `${Math.round((workflow.progress || 0) * 100)}%` }}
                          />
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => setSelectedWorkflow(
                        selectedWorkflow === workflow.execution_id ? null : workflow.execution_id
                      )}
                      className="btn btn-sm btn-outline"
                    >
                      <Eye className="w-4 h-4 mr-1" />
                      Details
                    </button>
                  </div>

                  {/* Workflow Steps */}
                  {selectedWorkflow === workflow.execution_id && (
                    <div className="mt-4 border-t pt-4">
                      <h4 className="text-sm font-semibold text-gray-700 mb-3">Execution Steps</h4>
                      <div className="space-y-2">
                        {(workflow.steps || []).map((step, idx) => {
                          const StepIcon = statusIcons[step.status] || Clock
                          return (
                            <div key={step.step_id} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50">
                              <div className="flex-shrink-0 mt-0.5">
                                <StepIcon className={`w-4 h-4 ${
                                  step.status === 'completed' ? 'text-green-600' :
                                  step.status === 'failed' ? 'text-red-600' :
                                  step.status === 'running' ? 'text-blue-600' :
                                  'text-gray-400'
                                }`} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-medium text-gray-900">
                                    {idx + 1}. {step.name}
                                  </span>
                                  <span className={`text-xs px-2 py-0.5 rounded ${
                                    step.status === 'completed' ? 'bg-green-100 text-green-800' :
                                    step.status === 'failed' ? 'bg-red-100 text-red-800' :
                                    step.status === 'running' ? 'bg-blue-100 text-blue-800' :
                                    'bg-gray-100 text-gray-800'
                                  }`}>
                                    {step.type}
                                  </span>
                                </div>
                                {step.error && (
                                  <p className="text-sm text-red-600 mt-1">{step.error}</p>
                                )}
                                {step.started_at && (
                                  <p className="text-xs text-gray-500 mt-1">
                                    {new Date(step.started_at).toLocaleString()}
                                  </p>
                                )}
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

const Activity = ({ className }: { className?: string }) => (
  <svg
    className={className}
    fill="none"
    stroke="currentColor"
    viewBox="0 0 24 24"
    strokeWidth={2}
  >
    <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
  </svg>
)
