/**
 * Alert Table Component
 *
 * Displays alerts in a sortable table with pagination
 */

import { useState } from 'react';
import { ArrowUpDown, ArrowUp, ArrowDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { SecurityAlert } from '@/api';
import { formatRelativeTime, truncate } from '@/utils/formatters';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';

interface AlertTableProps {
  alerts: SecurityAlert[];
  total: number;
  isLoading?: boolean;
  onSort?: (field: string, order: 'asc' | 'desc') => void;
  onPageChange?: (page: number) => void;
  onAlertClick?: (alert: SecurityAlert) => void;
  currentPage?: number;
  pageSize?: number;
}

export function AlertTable({
  alerts,
  total,
  isLoading = false,
  onSort,
  onPageChange,
  onAlertClick,
  currentPage = 1,
  pageSize = 20,
}: AlertTableProps) {
  const [sortField, setSortField] = useState<string>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const handleSort = (field: string) => {
    let newOrder: 'asc' | 'desc' = 'asc';
    if (sortField === field && sortOrder === 'asc') {
      newOrder = 'desc';
    }
    setSortField(field);
    setSortOrder(newOrder);
    onSort?.(field, newOrder);
  };

  const totalPages = Math.ceil(total / pageSize);
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + alerts.length;

  if (isLoading) {
    return (
      <div className="card">
        <div className="p-8 text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-primary-600 border-r-transparent"></div>
          <p className="mt-2 text-sm text-gray-600">Loading alerts...</p>
        </div>
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="card">
        <div className="p-8 text-center">
          <p className="text-sm text-gray-600">No alerts found</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th
                scope="col"
                className="cursor-pointer px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 hover:bg-gray-100"
                onClick={() => handleSort('timestamp')}
              >
                <div className="flex items-center gap-1">
                  Time
                  {sortField === 'timestamp' && (
                    sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                  )}
                  {sortField !== 'timestamp' && <ArrowUpDown className="h-3 w-3" />}
                </div>
              </th>
              <th
                scope="col"
                className="cursor-pointer px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 hover:bg-gray-100"
                onClick={() => handleSort('severity')}
              >
                <div className="flex items-center gap-1">
                  Severity
                  {sortField === 'severity' && (
                    sortOrder === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                  )}
                  {sortField !== 'severity' && <ArrowUpDown className="h-3 w-3" />}
                </div>
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                Type
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                Title
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                Source
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                Status
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                Risk Score
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 bg-white">
            {alerts.map((alert) => (
              <tr
                key={alert.alert_id}
                className={`cursor-pointer transition-colors hover:bg-gray-50 ${
                  alert.severity === 'critical' ? 'bg-red-50' : ''
                }`}
                onClick={() => onAlertClick?.(alert)}
              >
                <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-900">
                  {formatRelativeTime(alert.timestamp)}
                </td>
                <td className="whitespace-nowrap px-6 py-4 text-sm">
                  <SeverityBadge severity={alert.severity} size="sm" />
                </td>
                <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-900">
                  {alert.alert_type.replace('_', ' ')}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">
                  <div className="font-medium">{alert.title}</div>
                  <div className="text-gray-500">{truncate(alert.description, 60)}</div>
                </td>
                <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-900">
                  {alert.source_ip || '-'}
                </td>
                <td className="whitespace-nowrap px-6 py-4 text-sm">
                  <StatusBadge status={alert.status} size="sm" />
                </td>
                <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-900">
                  {alert.risk_score !== undefined ? (
                    <span
                      className={`font-semibold ${
                        alert.risk_score >= 70
                          ? 'text-red-600'
                          : alert.risk_score >= 40
                          ? 'text-yellow-600'
                          : 'text-green-600'
                      }`}
                    >
                      {alert.risk_score}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between border-t border-gray-200 bg-gray-50 px-6 py-3">
        <div className="text-sm text-gray-700">
          Showing <span className="font-medium">{startIndex + 1}</span> to{' '}
          <span className="font-medium">{endIndex}</span> of <span className="font-medium">{total}</span>{' '}
          results
        </div>
        {totalPages > 1 && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange?.(currentPage - 1)}
              disabled={currentPage === 1}
              className="btn btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </button>
            <span className="text-sm text-gray-700">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => onPageChange?.(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="btn btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
