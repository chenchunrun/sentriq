/**
 * Dashboard Page
 *
 * Main dashboard with statistics, charts, and recent alerts
 */

import { useQuery } from '@tanstack/react-query';
import {
  getDashboardStats,
  getAlertTrends,
  getSeverityDistribution,
  getHighPriorityAlerts,
} from '@/api';
import { StatCard, TrendChart, SeverityDistribution, SeverityBadge, StatusBadge } from '@/components';
import { formatNumber } from '@/utils/formatters';
import { Shield, AlertTriangle, Clock, CheckCircle, TrendingUp } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SecurityAlert } from '@/api';
import { formatRelativeTime } from '@/utils/formatters';

export function DashboardPage() {
  const navigate = useNavigate();

  const { data: dashboardStats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => getDashboardStats({ time_range: '24h', include_trends: true }),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: alertTrends } = useQuery({
    queryKey: ['alert-trends'],
    queryFn: () => getAlertTrends({ time_range: '24h', group_by: 'hour' }),
    refetchInterval: 30000,
  });

  const { data: severityDist } = useQuery({
    queryKey: ['severity-distribution'],
    queryFn: getSeverityDistribution,
    refetchInterval: 30000,
  });

  const { data: highPriorityAlerts } = useQuery({
    queryKey: ['high-priority-alerts'],
    queryFn: () => getHighPriorityAlerts(5),
    refetchInterval: 30000,
  });

  if (statsLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="text-center">
          <div className="inline-block h-12 w-12 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
          <p className="mt-4 text-sm text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  const systemHealthColor = {
    healthy: 'text-green-600',
    degraded: 'text-yellow-600',
    unhealthy: 'text-red-600',
  }[dashboardStats?.system_health || 'healthy'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="mt-1 text-sm text-gray-600">
            Real-time overview of security alerts and system status
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="text-sm text-gray-600">System Health:</div>
          <div className={`text-sm font-semibold ${systemHealthColor}`}>
            {dashboardStats?.system_health?.toUpperCase() || 'UNKNOWN'}
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Total Alerts"
          value={formatNumber(dashboardStats?.total_alerts || 0)}
          icon={Shield}
          color="blue"
        />
        <StatCard
          label="Critical Alerts"
          value={formatNumber(dashboardStats?.critical_alerts || 0)}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          label="High Risk Alerts"
          value={formatNumber(dashboardStats?.high_risk_alerts || 0)}
          icon={TrendingUp}
          color="yellow"
        />
        <StatCard
          label="Pending Triage"
          value={formatNumber(dashboardStats?.pending_triage || 0)}
          icon={Clock}
          color="blue"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <TrendChart
          data={dashboardStats?.trends?.alert_volume || alertTrends?.data_points || []}
          title="Alert Volume (24h)"
          color="#0ea5e9"
        />
        <SeverityDistribution
          data={severityDist || {}}
          title="Severity Distribution"
        />
      </div>

      {/* High Priority Alerts */}
      {highPriorityAlerts && highPriorityAlerts.length > 0 && (
        <div className="card">
          <div className="border-b border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900">High Priority Alerts</h2>
            <p className="mt-1 text-sm text-gray-600">
              Most recent critical and high-severity alerts requiring attention
            </p>
          </div>
          <div className="divide-y divide-gray-200">
            {highPriorityAlerts.map((alert) => (
              <div
                key={alert.alert_id}
                className="cursor-pointer p-6 transition-colors hover:bg-gray-50"
                onClick={() => navigate(`/alerts/${alert.alert_id}`)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={alert.severity} size="sm" />
                      <StatusBadge status={alert.status} size="sm" />
                    </div>
                    <h3 className="mt-2 text-base font-semibold text-gray-900">{alert.title}</h3>
                    <p className="mt-1 text-sm text-gray-600">{alert.description}</p>
                  </div>
                  <div className="ml-4 text-right">
                    <div className="text-xs text-gray-500">{formatRelativeTime(alert.timestamp)}</div>
                    {alert.risk_score !== undefined && (
                      <div className="mt-1 text-sm font-semibold text-gray-900">
                        Risk: {alert.risk_score}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="border-t border-gray-200 bg-gray-50 p-4">
            <button
              onClick={() => navigate('/alerts')}
              className="w-full text-center text-sm font-medium text-primary-600 hover:text-primary-700"
            >
              View All Alerts →
            </button>
          </div>
        </div>
      )}

      {/* Additional Stats */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
        <div className="card p-6">
          <div className="text-sm font-medium text-gray-600">Alerts Today</div>
          <div className="mt-2 text-3xl font-semibold text-gray-900">
            {formatNumber(dashboardStats?.alerts_today || 0)}
          </div>
        </div>
        <div className="card p-6">
          <div className="text-sm font-medium text-gray-600">Threats Blocked</div>
          <div className="mt-2 text-3xl font-semibold text-green-600">
            {formatNumber(dashboardStats?.threats_blocked || 0)}
          </div>
        </div>
        <div className="card p-6">
          <div className="text-sm font-medium text-gray-600">Avg Response Time</div>
          <div className="mt-2 text-3xl font-semibold text-gray-900">
            {dashboardStats?.avg_response_time
              ? `${Math.round(dashboardStats.avg_response_time / 60)}m`
              : 'N/A'}
          </div>
        </div>
      </div>
    </div>
  );
}
