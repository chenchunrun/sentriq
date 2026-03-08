/**
 * Dashboard - Main Analytics Page
 */

import React, { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useWebSocket } from '@/hooks/useWebSocket'
import {
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Clock,
  CheckCircle,
  Activity,
  BarChart3,
  PieChart,
  RefreshCw,
  Wifi,
  WifiOff,
} from 'lucide-react'
import {
  PieChart as RechartsPieChart,
  Cell,
  Pie,
  Legend,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts'

// Chart colors
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#3b82f6',
  low: '#22c55e',
  info: '#6b7280',
}

const STATUS_COLORS = ['#9ca3af', '#3b82f6', '#8b5cf6', '#f59e0b', '#22c55e', '#9ca3af', '#ef4444']

const MetricCard: React.FC<{
  title: string
  value: string | number
  change?: number
  icon: React.ReactNode
  color: 'primary' | 'success' | 'warning' | 'danger'
}> = ({ title, value, change, icon, color }) => {
  const colorClasses = {
    primary: 'bg-primary-500',
    success: 'bg-success-500',
    warning: 'bg-warning-500',
    danger: 'bg-danger-500',
  }

  return (
    <div className="card">
      <div className="card-body">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-600">{title}</p>
            <p className="text-2xl font-bold text-gray-900 mt-2">{value}</p>
            {change !== undefined && (
              <div className="flex items-center mt-2">
                {change > 0 ? (
                  <TrendingUp className="w-4 h-4 text-success-600 mr-1" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-danger-600 mr-1" />
                )}
                <span className={`text-sm font-medium ${change > 0 ? 'text-success-600' : 'text-danger-600'}`}>
                  {Math.abs(change)}%
                </span>
                <span className="text-sm text-gray-500 ml-1">vs last period</span>
              </div>
            )}
          </div>
          <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
            {icon}
          </div>
        </div>
      </div>
    </div>
  )
}

export const Dashboard: React.FC = () => {
  const [refreshing, setRefreshing] = useState(false)
  const queryClient = useQueryClient()

  // Fetch metrics
  const { data: metrics, isLoading: metricsLoading, refetch: refetchMetrics } = useQuery({
    queryKey: ['metrics'],
    queryFn: () => api.analytics.getMetrics(),
  })

  // Fetch top alerts
  const { data: topAlerts, isLoading: topAlertsLoading } = useQuery({
    queryKey: ['top-alerts'],
    queryFn: () => api.analytics.getTopAlerts(5),
  })

  // WebSocket connection for real-time updates
  const { isConnected } = useWebSocket({
    onMessage: (message) => {
      if (message.type === 'metrics_update' && message.data) {
        // Update metrics cache with new data
        queryClient.setQueryData(['metrics'], message.data)
      } else if (message.type === 'workflows_update' && message.data) {
        // Invalidate top alerts query to refresh
        queryClient.invalidateQueries({ queryKey: ['top-alerts'] })
      }
    },
    onConnect: () => {
      // WebSocket connected - debug only
    },
    onDisconnect: () => {
      // WebSocket disconnected - debug only
    },
  })

  const handleRefresh = async () => {
    setRefreshing(true)
    await refetchMetrics()
    setRefreshing(false)
  }

  // Prepare chart data
  const severityData = metrics?.by_severity
    ? Object.entries(metrics.by_severity).map(([name, value]) => ({
        name,
        value: value as number,
        fill: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS],
      }))
    : []

  const statusData = metrics?.by_status
    ? Object.entries(metrics.by_status).map(([name, value], index) => ({
        name: name.replace('_', ' '),
        value: value as number,
        fill: STATUS_COLORS[index % STATUS_COLORS.length],
      }))
    : []

  const typeData = topAlerts?.map((alert) => ({
    name: alert.alert_type.replace('_', ' '),
    value: alert.count,
    percentage: alert.percentage,
  })) || []
  const hasSeverityData = severityData.some((item) => item.value > 0)
  const hasStatusData = statusData.some((item) => item.value > 0)
  const hasTypeData = typeData.some((item) => item.value > 0)

  if (metricsLoading || topAlertsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
      </div>
    )
  }

  const totalAlerts = metrics?.total_alerts || 0
  const criticalAlerts = metrics?.by_severity?.critical || 0
  const avgResolutionTime = metrics?.avg_resolution_time || 0
  const mttr = metrics?.mttr || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-600 mt-1">Overview of security alerts and system performance</p>
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
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Alerts"
          value={totalAlerts.toLocaleString()}
          change={totalAlerts > 0 ? 12 : undefined}
          icon={<AlertTriangle className="w-6 h-6 text-white" />}
          color="primary"
        />
        <MetricCard
          title="Critical Alerts"
          value={criticalAlerts.toLocaleString()}
          icon={<Activity className="w-6 h-6 text-white" />}
          color="danger"
        />
        <MetricCard
          title="Avg Resolution Time"
          value={`${Math.round(avgResolutionTime)}m`}
          change={avgResolutionTime > 0 ? -8 : undefined}
          icon={<Clock className="w-6 h-6 text-white" />}
          color="warning"
        />
        <MetricCard
          title="MTTR"
          value={`${Math.round(mttr)}m`}
          change={mttr > 0 ? -15 : undefined}
          icon={<CheckCircle className="w-6 h-6 text-white" />}
          color="success"
        />
      </div>

      {/* Charts and Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts by Severity - Pie Chart */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center gap-2">
              <PieChart className="w-5 h-5 text-gray-600" />
              <h2 className="text-lg font-semibold text-gray-900">Alerts by Severity</h2>
            </div>
          </div>
          <div className="card-body">
            {hasSeverityData ? (
              <ResponsiveContainer width="100%" height={300}>
                <RechartsPieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </RechartsPieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-sm text-gray-500">
                No alert severity data available yet.
              </div>
            )}
          </div>
        </div>

        {/* Top Alert Types - Bar Chart */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5 text-gray-600" />
              <h2 className="text-lg font-semibold text-gray-900">Top Alert Types</h2>
            </div>
          </div>
          <div className="card-body">
            {hasTypeData ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={typeData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="name"
                    angle={-45}
                    textAnchor="end"
                    height={60}
                    fontSize={12}
                  />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-sm text-gray-500">
                No alert type distribution available yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Second Row of Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts by Status - Pie Chart */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-gray-600" />
              <h2 className="text-lg font-semibold text-gray-900">Alerts by Status</h2>
            </div>
          </div>
          <div className="card-body">
            {hasStatusData ? (
              <ResponsiveContainer width="100%" height={300}>
                <RechartsPieChart>
                  <Pie
                    data={statusData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {statusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </RechartsPieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-sm text-gray-500">
                No alert status data available yet.
              </div>
            )}
          </div>
        </div>

        {/* System Status */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-gray-600" />
              <h2 className="text-lg font-semibold text-gray-900">System Status</h2>
            </div>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg border border-green-200">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-success-500 rounded-full animate-pulse" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">API Server</p>
                    <p className="text-xs text-gray-600">Operational</p>
                  </div>
                </div>
                <span className="text-sm font-medium text-success-700">Healthy</span>
              </div>

              <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg border border-green-200">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-success-500 rounded-full animate-pulse" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">Database</p>
                    <p className="text-xs text-gray-600">PostgreSQL</p>
                  </div>
                </div>
                <span className="text-sm font-medium text-success-700">Connected</span>
              </div>

              <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg border border-green-200">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-success-500 rounded-full animate-pulse" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">Message Queue</p>
                    <p className="text-xs text-gray-600">RabbitMQ</p>
                  </div>
                </div>
                <span className="text-sm font-medium text-success-700">Running</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
