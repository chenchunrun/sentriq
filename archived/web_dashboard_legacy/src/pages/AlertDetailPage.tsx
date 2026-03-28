/**
 * Alert Detail Page
 *
 * Detailed view of a single alert with triage results and context
 */

import { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, AlertTriangle, Shield, Info, Activity } from 'lucide-react';
import { getAlert } from '@/api';
import { SeverityBadge, StatusBadge } from '@/components';
import { formatDate, getRiskScoreColor, getRiskLevel } from '@/utils/formatters';

export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();

  const { data: alertData, isLoading } = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => getAlert(alertId!),
    enabled: !!alertId,
  });

  const alert = alertData?.data;

  useEffect(() => {
    if (alert?.severity === 'critical') {
      // Flash the browser tab for critical alerts
      const originalTitle = document.title;
      document.title = `⚠️ Critical Alert - ${alert.title}`;
      return () => {
        document.title = originalTitle;
      };
    }
  }, [alert]);

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="text-center">
          <div className="inline-block h-12 w-12 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
          <p className="mt-4 text-sm text-gray-600">Loading alert details...</p>
        </div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="mx-auto h-12 w-12 text-gray-400" />
          <p className="mt-2 text-sm text-gray-600">Alert not found</p>
          <button
            onClick={() => navigate('/alerts')}
            className="mt-4 btn btn-primary"
          >
            Back to Alerts
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/alerts')}
          className="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Alerts
        </button>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={alert.severity} size="lg" />
          <StatusBadge status={alert.status} size="lg" />
        </div>
      </div>

      {/* Alert Info */}
      <div className="card p-6">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <h1 className="text-2xl font-bold text-gray-900">{alert.title}</h1>
            <p className="mt-2 text-gray-600">{alert.description}</p>
          </div>
          {alert.risk_score !== undefined && (
            <div className="ml-6 text-right">
              <div className="text-sm text-gray-600">Risk Score</div>
              <div className={`text-3xl font-bold ${getRiskScoreColor(alert.risk_score)}`}>
                {alert.risk_score}
              </div>
              <div className="text-sm text-gray-600">{getRiskLevel(alert.risk_score)}</div>
            </div>
          )}
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="text-sm font-medium text-gray-500">Alert ID</div>
            <div className="mt-1 text-sm text-gray-900">{alert.alert_id}</div>
          </div>
          <div>
            <div className="text-sm font-medium text-gray-500">Timestamp</div>
            <div className="mt-1 text-sm text-gray-900">{formatDate(alert.timestamp)}</div>
          </div>
          <div>
            <div className="text-sm font-medium text-gray-500">Alert Type</div>
            <div className="mt-1 text-sm text-gray-900">
              {alert.alert_type.replace('_', ' ').toUpperCase()}
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-gray-500">Source IP</div>
            <div className="mt-1 text-sm text-gray-900">{alert.source_ip || 'N/A'}</div>
          </div>
        </div>

        {/* IOCs */}
        {alert.iocs && alert.iocs.length > 0 && (
          <div className="mt-6">
            <h3 className="text-sm font-medium text-gray-900">Indicators of Compromise (IOCs)</h3>
            <div className="mt-2 space-y-2">
              {alert.iocs.map((ioc, index) => (
                <div key={index} className="flex items-center justify-between rounded border border-gray-200 bg-gray-50 p-3">
                  <div className="flex-1">
                    <div className="text-sm font-medium text-gray-900">{ioc.type.toUpperCase()}</div>
                    <div className="text-sm text-gray-600">{ioc.value}</div>
                  </div>
                  <div className="ml-4 text-sm text-gray-600">
                    Confidence: {Math.round(ioc.confidence * 100)}%
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Triage Result */}
      {alert.triage_result && (
        <div className="card p-6">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary-600" />
            <h2 className="text-lg font-semibold text-gray-900">AI Triage Analysis</h2>
          </div>
          <div className="mt-4">
            <div className="rounded bg-gray-50 p-4">
              <p className="text-sm text-gray-700 whitespace-pre-wrap">{alert.triage_result.analysis}</p>
            </div>
          </div>
          {alert.triage_result.risk_factors && alert.triage_result.risk_factors.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-medium text-gray-900">Risk Factors</h3>
              <ul className="mt-2 space-y-1">
                {alert.triage_result.risk_factors.map((factor, index) => (
                  <li key={index} className="flex items-start gap-2 text-sm text-gray-600">
                    <span className="text-red-500">•</span>
                    <span>{factor}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {alert.triage_result.recommended_actions && alert.triage_result.recommended_actions.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-medium text-gray-900">Recommended Actions</h3>
              <ol className="mt-2 space-y-2">
                {alert.triage_result.recommended_actions.map((action, index) => (
                  <li key={index} className="flex items-start gap-3 text-sm text-gray-600">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary-100 text-xs font-medium text-primary-700">
                      {index + 1}
                    </span>
                    <span>{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}

      {/* Threat Intelligence */}
      {alert.threat_intel && (
        <div className="card p-6">
          <div className="flex items-center gap-2">
            <Info className="h-5 w-5 text-primary-600" />
            <h2 className="text-lg font-semibold text-gray-900">Threat Intelligence</h2>
          </div>
          <div className="mt-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {alert.threat_intel.sources.virustotal && (
                <div className="rounded border border-gray-200 p-4">
                  <div className="text-sm font-medium text-gray-900">VirusTotal</div>
                  <div className="mt-2 text-sm text-gray-600">
                    Detection Rate: {Math.round(alert.threat_intel.sources.virustotal.detection_rate * 100)}%
                  </div>
                  <div className="text-xs text-gray-500">
                    {alert.threat_intel.sources.virustotal.positives} / {alert.threat_intel.sources.virustotal.total} detections
                  </div>
                </div>
              )}
              {alert.threat_intel.sources.otx && (
                <div className="rounded border border-gray-200 p-4">
                  <div className="text-sm font-medium text-gray-900">AlienVault OTX</div>
                  <div className="mt-2 text-sm text-gray-600">
                    Pulses: {alert.threat_intel.sources.otx.pulses}
                  </div>
                  <div className="text-xs text-gray-500">
                    Severity: {alert.threat_intel.sources.otx.severity}
                  </div>
                </div>
              )}
              {alert.threat_intel.sources.abuse_ch && (
                <div className="rounded border border-gray-200 p-4">
                  <div className="text-sm font-medium text-gray-900">Abuse.ch</div>
                  <div className="mt-2 text-sm text-gray-600">
                    {alert.threat_intel.sources.abuse_ch.detected ? 'Detected' : 'Not Detected'}
                  </div>
                  <div className="text-xs text-gray-500">
                    {alert.threat_intel.sources.abuse_ch.threat}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Context */}
      {alert.context && (
        <div className="card p-6">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary-600" />
            <h2 className="text-lg font-semibold text-gray-900">Alert Context</h2>
          </div>
          <div className="mt-4 grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* Network Context */}
            {alert.context.network_context && (
              <div>
                <h3 className="text-sm font-medium text-gray-900">Network Context</h3>
                <div className="mt-2 space-y-2">
                  {alert.context.network_context.geo_location && (
                    <div>
                      <div className="text-xs text-gray-500">Location</div>
                      <div className="text-sm text-gray-900">
                        {alert.context.network_context.geo_location.city}, {alert.context.network_context.geo_location.country}
                      </div>
                    </div>
                  )}
                  {alert.context.network_context.reputation && (
                    <div>
                      <div className="text-xs text-gray-500">Reputation Score</div>
                      <div className="text-sm text-gray-900">
                        {alert.context.network_context.reputation.score}/100
                      </div>
                    </div>
                  )}
                  <div>
                    <div className="text-xs text-gray-500">TOR Exit Node</div>
                    <div className="text-sm text-gray-900">
                      {alert.context.network_context.is_tor_exit_node ? 'Yes' : 'No'}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Asset Context */}
            {alert.context.asset_context && (
              <div>
                <h3 className="text-sm font-medium text-gray-900">Asset Context</h3>
                <div className="mt-2 space-y-2">
                  {alert.context.asset_context.owner && (
                    <div>
                      <div className="text-xs text-gray-500">Owner</div>
                      <div className="text-sm text-gray-900">{alert.context.asset_context.owner}</div>
                    </div>
                  )}
                  {alert.context.asset_context.department && (
                    <div>
                      <div className="text-xs text-gray-500">Department</div>
                      <div className="text-sm text-gray-900">{alert.context.asset_context.department}</div>
                    </div>
                  )}
                  <div>
                    <div className="text-xs text-gray-500">Criticality</div>
                    <div className="text-sm text-gray-900">
                      {alert.context.asset_context.criticality.toUpperCase()}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* User Context */}
            {alert.context.user_context && (
              <div>
                <h3 className="text-sm font-medium text-gray-900">User Context</h3>
                <div className="mt-2 space-y-2">
                  {alert.context.user_context.department && (
                    <div>
                      <div className="text-xs text-gray-500">Department</div>
                      <div className="text-sm text-gray-900">{alert.context.user_context.department}</div>
                    </div>
                  )}
                  {alert.context.user_context.manager && (
                    <div>
                      <div className="text-xs text-gray-500">Manager</div>
                      <div className="text-sm text-gray-900">{alert.context.user_context.manager}</div>
                    </div>
                  )}
                  {alert.context.user_context.groups && alert.context.user_context.groups.length > 0 && (
                    <div>
                      <div className="text-xs text-gray-500">Groups</div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {alert.context.user_context.groups.map((group, index) => (
                          <span
                            key={index}
                            className="inline-flex items-center rounded-full bg-gray-100 px-2 py-1 text-xs font-medium text-gray-700"
                          >
                            {group}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
