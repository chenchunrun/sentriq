/**
 * Alerts API
 *
 * API functions for alert management operations
 */

import apiClient from './client';
import type {
  SecurityAlert,
  AlertDetail,
  AlertFilter,
  AlertStats,
  PaginatedResponse,
  ApiResponse,
} from './types';

/**
 * List alerts with filtering and pagination
 */
export async function listAlerts(params: {
  alert_type?: string;
  severity?: string;
  status?: string;
  source_ip?: string;
  search?: string;
  skip?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}): Promise<PaginatedResponse<SecurityAlert>> {
  const response = await apiClient.get<PaginatedResponse<SecurityAlert>>('/v1/alerts/', {
    params,
  });
  return response.data;
}

/**
 * Get alert details by ID
 */
export async function getAlert(alertId: string): Promise<ApiResponse<AlertDetail>> {
  const response = await apiClient.get<ApiResponse<AlertDetail>>(`/v1/alerts/${alertId}`);
  return response.data;
}

/**
 * Create a new alert
 */
export async function createAlert(data: Partial<SecurityAlert>): Promise<ApiResponse<SecurityAlert>> {
  const response = await apiClient.post<ApiResponse<SecurityAlert>>('/v1/alerts/', data);
  return response.data;
}

/**
 * Update alert status
 */
export async function updateAlertStatus(
  alertId: string,
  status: string,
  assigned_to?: string
): Promise<ApiResponse<SecurityAlert>> {
  const response = await apiClient.patch<ApiResponse<SecurityAlert>>(
    `/v1/alerts/${alertId}/status`,
    { status, assigned_to }
  );
  return response.data;
}

/**
 * Get alert statistics
 */
export async function getAlertStats(): Promise<ApiResponse<AlertStats>> {
  const response = await apiClient.get<ApiResponse<AlertStats>>('/v1/alerts/stats/summary');
  return response.data;
}

/**
 * Get high-priority alerts
 */
export async function getHighPriorityAlerts(limit: number = 10): Promise<SecurityAlert[]> {
  const response = await apiClient.get<SecurityAlert[]>('/v1/alerts/high-priority', {
    params: { limit },
  });
  return response.data;
}

/**
 * Get active alerts
 */
export async function getActiveAlerts(limit: number = 10): Promise<SecurityAlert[]> {
  const response = await apiClient.get<SecurityAlert[]>('/v1/alerts/active', {
    params: { limit },
  });
  return response.data;
}

/**
 * Bulk action on alerts
 */
export async function bulkActionAlerts(data: {
  action: string;
  alert_ids: string[];
  params?: Record<string, unknown>;
}): Promise<ApiResponse<{ updated: number; failed: number }>> {
  const response = await apiClient.post<ApiResponse<{ updated: number; failed: number }>>(
    '/v1/alerts/bulk',
    data
  );
  return response.data;
}

/**
 * Get triage result for an alert
 */
export async function getAlertTriage(alertId: string): Promise<ApiResponse<any>> {
  const response = await apiClient.get<ApiResponse<any>>(`/v1/alerts/${alertId}/triage`);
  return response.data;
}
