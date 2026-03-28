/**
 * Analytics API
 *
 * API functions for dashboard analytics and statistics
 */

import apiClient from './client';
import type {
  DashboardStats,
  TrendResponse,
  ApiResponse,
} from './types';

/**
 * Get dashboard statistics
 */
export async function getDashboardStats(params: {
  time_range?: '1h' | '24h' | '7d' | '30d';
  include_trends?: boolean;
} = {}): Promise<DashboardStats> {
  const response = await apiClient.get<DashboardStats>('/v1/analytics/dashboard', { params });
  return response.data;
}

/**
 * Get alert trends
 */
export async function getAlertTrends(params: {
  time_range?: '1h' | '24h' | '7d' | '30d';
  group_by?: 'hour' | 'day';
} = {}): Promise<TrendResponse> {
  const response = await apiClient.get<TrendResponse>('/v1/analytics/trends/alerts', { params });
  return response.data;
}

/**
 * Get risk score trends
 */
export async function getRiskScoreTrends(params: {
  time_range?: '1h' | '24h' | '7d' | '30d';
  group_by?: 'hour' | 'day';
} = {}): Promise<TrendResponse> {
  const response = await apiClient.get<TrendResponse>('/v1/analytics/trends/risk-scores', {
    params,
  });
  return response.data;
}

/**
 * Get severity distribution
 */
export async function getSeverityDistribution(): Promise<Record<string, number>> {
  const response = await apiClient.get<Record<string, number>>(
    '/v1/analytics/metrics/severity-distribution'
  );
  return response.data;
}

/**
 * Get status distribution
 */
export async function getStatusDistribution(): Promise<Record<string, number>> {
  const response = await apiClient.get<Record<string, number>>(
    '/v1/analytics/metrics/status-distribution'
  );
  return response.data;
}

/**
 * Get top alert sources
 */
export async function getTopSources(limit: number = 10): Promise<Array<{ source: string; count: number }>> {
  const response = await apiClient.get<Array<{ source: string; count: number }>>(
    '/v1/analytics/metrics/top-sources',
    { params: { limit } }
  );
  return response.data;
}

/**
 * Get top alert types
 */
export async function getTopAlertTypes(
  limit: number = 10
): Promise<Array<{ alert_type: string; count: number }>> {
  const response = await apiClient.get<Array<{ alert_type: string; count: number }>>(
    '/v1/analytics/metrics/top-alert-types',
    { params: { limit } }
  );
  return response.data;
}

/**
 * Get performance metrics
 */
export async function getPerformanceMetrics(): Promise<Record<string, number>> {
  const response = await apiClient.get<Record<string, number>>(
    '/v1/analytics/metrics/performance'
  );
  return response.data;
}
