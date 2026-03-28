/**
 * Alert Filters Component
 *
 * Filter controls for the alert list
 */

import { useState } from 'react';
import { Filter, X } from 'lucide-react';
import { AlertType, Severity, AlertStatus } from '@/api';

interface AlertFiltersProps {
  onFilterChange: (filters: {
    alert_type?: string;
    severity?: string;
    status?: string;
    search?: string;
  }) => void;
}

export function AlertFilters({ onFilterChange }: AlertFiltersProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [filters, setFilters] = useState<{
    alert_type?: string;
    severity?: string;
    status?: string;
    search?: string;
  }>({});

  const handleFilterChange = (key: string, value: string) => {
    const newFilters = { ...filters, [key]: value || undefined };
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const clearFilters = () => {
    setFilters({});
    onFilterChange({});
  };

  const hasActiveFilters = Object.values(filters).some((v) => v !== undefined);

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="flex items-center gap-2 text-sm font-medium text-gray-700 hover:text-gray-900"
          >
            <Filter className="h-4 w-4" />
            Filters
            {hasActiveFilters && (
              <span className="ml-1 rounded-full bg-primary-100 px-2 py-0.5 text-xs font-medium text-primary-700">
                {Object.values(filters).filter((v) => v !== undefined).length}
              </span>
            )}
          </button>

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"
            >
              <X className="h-4 w-4" />
              Clear all
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Search alerts..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="input w-64"
          />
        </div>
      </div>

      {isOpen && (
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <label className="block text-sm font-medium text-gray-700">Alert Type</label>
            <select
              value={filters.alert_type || ''}
              onChange={(e) => handleFilterChange('alert_type', e.target.value)}
              className="select mt-1"
            >
              <option value="">All Types</option>
              {Object.values(AlertType).map((type) => (
                <option key={type} value={type}>
                  {type.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Severity</label>
            <select
              value={filters.severity || ''}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="select mt-1"
            >
              <option value="">All Severities</option>
              {Object.values(SecuritySeverity).map((severity) => (
                <option key={severity} value={severity}>
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Status</label>
            <select
              value={filters.status || ''}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              className="select mt-1"
            >
              <option value="">All Statuses</option>
              {Object.values(AlertStatus).map((status) => (
                <option key={status} value={status}>
                  {status.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}
    </div>
  );
}

// Temporary workaround for enum access
const SecuritySeverity = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
} as const;
