/**
 * Status Badge Component
 *
 * Displays alert status with appropriate color coding
 */

import { AlertStatus } from '@/api';
import { getStatusColor } from '@/utils/formatters';

interface StatusBadgeProps {
  status: AlertStatus;
  size?: 'sm' | 'md' | 'lg';
}

export function StatusBadge({ status, size = 'md' }: StatusBadgeProps) {
  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs font-medium',
    lg: 'px-3 py-1.5 text-sm',
  };

  const displayStatus = status
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

  return (
    <span
      className={`inline-flex items-center rounded-full border ${getStatusColor(status)} ${sizeClasses[size]}`}
    >
      {displayStatus}
    </span>
  );
}
