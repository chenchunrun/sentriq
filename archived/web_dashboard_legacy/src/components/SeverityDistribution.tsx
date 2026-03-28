/**
 * Severity Distribution Component
 *
 * Pie chart for displaying alert severity distribution
 */

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { Severity } from '@/api';

interface SeverityDistributionProps {
  data: Record<string, number>;
  title?: string;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#6b7280',
};

export function SeverityDistribution({ data, title }: SeverityDistributionProps) {
  const chartData = Object.entries(data)
    .filter(([_, count]) => count > 0)
    .map(([severity, count]) => ({
      name: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: count,
      color: SEVERITY_COLORS[severity as Severity],
    }));

  if (chartData.length === 0) {
    return (
      <div className="card p-6">
        {title && <h3 className="mb-4 text-lg font-semibold text-gray-900">{title}</h3>}
        <div className="flex h-64 items-center justify-center text-sm text-gray-500">
          No data available
        </div>
      </div>
    );
  }

  return (
    <div className="card p-6">
      {title && <h3 className="mb-4 text-lg font-semibold text-gray-900">{title}</h3>}
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '0.5rem',
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
