/**
 * Utility Functions
 *
 * Helper functions for formatting and styling
 */

import { type ClassValue, clsx } from 'clsx';
import { Severity, AlertStatus } from '@/api';

/**
 * Merge Tailwind CSS classes
 */
export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

/**
 * Format date string to readable format
 */
export function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(dateString);
}

/**
 * Get severity color class
 */
export function getSeverityColor(severity: Severity): string {
  const colors = {
    critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical',
    high: 'text-severity-high bg-severity-high/10 border-severity-high',
    medium: 'text-severity-medium bg-severity-medium/10 border-severity-medium',
    low: 'text-severity-low bg-severity-low/10 border-severity-low',
    info: 'text-severity-info bg-severity-info/10 border-severity-info',
  };
  return colors[severity];
}

/**
 * Get status color class
 */
export function getStatusColor(status: AlertStatus): string {
  const colors = {
    new: 'bg-blue-100 text-blue-800 border-blue-200',
    in_progress: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    assigned: 'bg-purple-100 text-purple-800 border-purple-200',
    resolved: 'bg-green-100 text-green-800 border-green-200',
    closed: 'bg-gray-100 text-gray-800 border-gray-200',
  };
  return colors[status];
}

/**
 * Get risk score color
 */
export function getRiskScoreColor(score: number): string {
  if (score >= 90) return 'text-severity-critical';
  if (score >= 70) return 'text-severity-high';
  if (score >= 40) return 'text-severity-medium';
  if (score >= 20) return 'text-severity-low';
  return 'text-severity-info';
}

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): string {
  if (score >= 90) return 'Critical';
  if (score >= 70) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 20) return 'Low';
  return 'Info';
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, maxLength: number = 50): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + '...';
}

/**
 * Format numbers with commas
 */
export function formatNumber(num: number): string {
  return num.toLocaleString('en-US');
}

/**
 * Format percentage
 */
export function formatPercentage(value: number, total: number): string {
  if (total === 0) return '0%';
  return `${Math.round((value / total) * 100)}%`;
}
