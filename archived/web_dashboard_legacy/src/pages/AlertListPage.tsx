/**
 * Alert List Page
 *
 * Main page for displaying and filtering alerts
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { listAlerts } from '@/api';
import { SecurityAlert } from '@/api';
import { AlertFilters, AlertTable } from '@/components';

export function AlertListPage() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<{
    alert_type?: string;
    severity?: string;
    status?: string;
    search?: string;
  }>({});
  const [pagination, setPagination] = useState({
    page: 1,
    skip: 0,
    limit: 20,
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['alerts', filters, pagination],
    queryFn: () =>
      listAlerts({
        ...filters,
        skip: pagination.skip,
        limit: pagination.limit,
      }),
  });

  const handleFilterChange = (newFilters: typeof filters) => {
    setFilters(newFilters);
    setPagination({ page: 1, skip: 0, limit: 20 });
  };

  const handlePageChange = (page: number) => {
    const skip = (page - 1) * pagination.limit;
    setPagination({ ...pagination, page, skip });
  };

  const handleAlertClick = (alert: SecurityAlert) => {
    navigate(`/alerts/${alert.alert_id}`);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Alerts</h1>
          <p className="mt-1 text-sm text-gray-600">
            {data?.meta.total ? `${data.meta.total} alerts` : 'Loading...'}
          </p>
        </div>
      </div>

      <AlertFilters onFilterChange={handleFilterChange} />

      <AlertTable
        alerts={data?.data || []}
        total={data?.meta.total || 0}
        isLoading={isLoading}
        currentPage={pagination.page}
        pageSize={pagination.limit}
        onPageChange={handlePageChange}
        onAlertClick={handleAlertClick}
      />
    </div>
  );
}
