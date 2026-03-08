/**
 * Reports Page - Report Generation and Management
 */

import React, { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import type { Report, ReportRequest, ReportFormat } from '@/types'
import {
  FileText,
  Download,
  Trash2,
  Plus,
  Filter,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  Eye,
  X,
} from 'lucide-react'

type ReportStatus = 'pending' | 'generating' | 'completed' | 'failed'

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showFilterModal, setShowFilterModal] = useState(false)
  const [downloading, setDownloading] = useState<Record<string, boolean>>({})
  const [previewingReport, setPreviewingReport] = useState<Report | null>(null)
  const [previewContent, setPreviewContent] = useState<string>('')
  const [previewLoading, setPreviewLoading] = useState(false)

  // Filter state
  const [reportFilters, setReportFilters] = useState<{
    format?: string
    date_range?: string
  }>({})

  // New report form state
  const [newReport, setNewReport] = useState<Partial<ReportRequest>>({
    name: '',
    description: '',
    type: 'daily_summary',
    format: 'html' as ReportFormat,
    filters: {},
  })

  useEffect(() => {
    loadReports()
  }, [])

  const loadReports = async () => {
    try {
      setLoading(true)
      const data = await api.reports.getReports()
      setReports(data)
    } catch (error) {
      console.error('Failed to load reports:', error)
    } finally {
      setLoading(false)
    }
  }

  const applyFilters = async () => {
    try {
      setLoading(true)
      const data = await api.reports.getReports()
      // Client-side filtering
      let filtered = data
      if (reportFilters.format) {
        filtered = filtered.filter((r) => r.format === reportFilters.format)
      }
      if (reportFilters.date_range) {
        const now = new Date()
        const cutoff = new Date()
        if (reportFilters.date_range === '7d') {
          cutoff.setDate(now.getDate() - 7)
        } else if (reportFilters.date_range === '30d') {
          cutoff.setDate(now.getDate() - 30)
        }
        filtered = filtered.filter((r) => new Date(r.created_at) >= cutoff)
      }
      setReports(filtered)
      setShowFilterModal(false)
    } catch (error) {
      console.error('Failed to apply filters:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateReport = async () => {
    try {
      await api.reports.createReport(newReport as ReportRequest)
      await loadReports()
      setShowCreateModal(false)
      setNewReport({
        name: '',
        description: '',
        type: 'daily_summary',
        format: 'html' as ReportFormat,
        filters: {},
      })
    } catch (error) {
      console.error('Failed to create report:', error)
    }
  }

  const handleDownload = async (reportId: string, reportName: string) => {
    try {
      setDownloading((prev) => ({ ...prev, [reportId]: true }))
      const blob = await api.reports.downloadReport(reportId)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${reportName}.${reports.find((r) => r.id === reportId)?.format || 'pdf'}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error('Failed to download report:', error)
    } finally {
      setDownloading((prev) => ({ ...prev, [reportId]: false }))
    }
  }

  const handleDelete = async (reportId: string) => {
    if (!confirm('Are you sure you want to delete this report?')) return
    try {
      await api.reports.deleteReport(reportId)
      setReports(reports.filter((r) => r.id !== reportId))
    } catch (error) {
      console.error('Failed to delete report:', error)
    }
  }

  const handlePreview = async (report: Report) => {
    try {
      setPreviewLoading(true)
      setPreviewingReport(report)

      // Fetch report content for preview
      const normalizedFormat = report.format === 'pdf'
        ? 'html'
        : report.format === 'excel'
          ? 'csv'
          : report.format
      const response = await fetch(`/api/v1/reports/${report.id}/download?format=${normalizedFormat}`)
      if (!response.ok) throw new Error('Failed to fetch report')

      if (normalizedFormat === 'html') {
        const text = await response.text()
        setPreviewContent(text)
      } else if (normalizedFormat === 'json') {
        const json = await response.json()
        setPreviewContent(JSON.stringify(json, null, 2))
      } else if (normalizedFormat === 'csv') {
        const text = await response.text()
        setPreviewContent(text)
      } else {
        const text = await response.text()
        setPreviewContent(text)
      }
    } catch (error) {
      console.error('Failed to preview report:', error)
      setPreviewContent('Failed to load report preview')
    } finally {
      setPreviewLoading(false)
    }
  }

  const getStatusIcon = (status: ReportStatus) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-600" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-600" />
      case 'generating':
        return <Loader2 className="w-5 h-5 text-blue-600 animate-spin" />
      default:
        return <Clock className="w-5 h-5 text-gray-400" />
    }
  }

  const getStatusBadge = (status: ReportStatus) => {
    const styles = {
      completed: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800',
      generating: 'bg-blue-100 text-blue-800',
      pending: 'bg-gray-100 text-gray-800',
    }
    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[status]}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
          <p className="text-sm text-gray-500">Generate and manage security reports</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create Report
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-50 rounded-lg">
              <FileText className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{reports.length}</p>
              <p className="text-sm text-gray-500">Total Reports</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-50 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">
                {reports.filter((r) => r.status === 'completed').length}
              </p>
              <p className="text-sm text-gray-500">Completed</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-50 rounded-lg">
              <Loader2 className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">
                {reports.filter((r) => r.status === 'generating').length}
              </p>
              <p className="text-sm text-gray-500">Generating</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-50 rounded-lg">
              <XCircle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">
                {reports.filter((r) => r.status === 'failed').length}
              </p>
              <p className="text-sm text-gray-500">Failed</p>
            </div>
          </div>
        </div>
      </div>

      {/* Reports List */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <input
                type="text"
                placeholder="Search reports..."
                className="w-full px-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
            <button
              onClick={() => setShowFilterModal(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <Filter className="w-4 h-4" />
              Filter
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="spinner"></div>
          </div>
        ) : reports.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-center">
            <FileText className="w-16 h-16 text-gray-300 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No reports yet</h3>
            <p className="text-sm text-gray-500 mb-4">Create your first report to get started</p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
            >
              <Plus className="w-4 h-4" />
              Create Report
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {reports.map((report) => (
              <div key={report.id} className="px-6 py-4 hover:bg-gray-50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    <div className="p-2 bg-gray-100 rounded-lg">
                      <FileText className="w-5 h-5 text-gray-600" />
                    </div>
                    <div className="flex-1">
                      <h3 className="text-sm font-medium text-gray-900">{report.name}</h3>
                      <p className="text-sm text-gray-500">{report.description || 'No description'}</p>
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                        <span className="capitalize">{report.type}</span>
                        <span className="uppercase">{report.format}</span>
                        <span>Created {new Date(report.created_at).toLocaleString()}</span>
                        <span>by {report.created_by}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(report.status as ReportStatus)}
                      {getStatusBadge(report.status as ReportStatus)}
                    </div>
                    {report.status === 'completed' && (
                      <>
                        <button
                          onClick={() => handlePreview(report)}
                          className="p-2 text-gray-400 hover:text-primary-600 transition-colors"
                          title="Preview"
                        >
                          <Eye className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => handleDownload(report.id, report.name)}
                          disabled={downloading[report.id]}
                          className="p-2 text-gray-400 hover:text-primary-600 transition-colors disabled:opacity-50"
                          title="Download"
                        >
                          {downloading[report.id] ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                          ) : (
                            <Download className="w-5 h-5" />
                          )}
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => handleDelete(report.id)}
                      className="p-2 text-gray-400 hover:text-red-600 transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Filter Modal */}
      {showFilterModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Filter Reports</h2>
              <button
                onClick={() => setShowFilterModal(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                ✕
              </button>
            </div>

            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Report Format
                </label>
                <select
                  value={reportFilters.format || ''}
                  onChange={(e) => setReportFilters({ ...reportFilters, format: e.target.value || undefined })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="">All Formats</option>
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                  <option value="excel">Excel</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Date Range
                </label>
                <select
                  value={reportFilters.date_range || ''}
                  onChange={(e) => setReportFilters({ ...reportFilters, date_range: e.target.value || undefined })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="">All Time</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200">
              <button
                onClick={() => {
                  setReportFilters({})
                  setShowFilterModal(false)
                  loadReports()
                }}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Clear
              </button>
              <button
                onClick={applyFilters}
                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
              >
                Apply Filters
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Report Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Create New Report</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                ✕
              </button>
            </div>

            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Report Name
                </label>
                <input
                  type="text"
                  value={newReport.name || ''}
                  onChange={(e) => setNewReport({ ...newReport, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="e.g., Weekly Security Summary"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description
                </label>
                <textarea
                  value={newReport.description || ''}
                  onChange={(e) => setNewReport({ ...newReport, description: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  rows={3}
                  placeholder="Brief description of the report..."
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Type
                  </label>
                  <select
                    value={newReport.type}
                    onChange={(e) => setNewReport({ ...newReport, type: e.target.value as any })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="daily_summary">Daily Summary</option>
                    <option value="weekly_summary">Weekly Summary</option>
                    <option value="monthly_summary">Monthly Summary</option>
                    <option value="trend_analysis">Trend Analysis</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Format
                  </label>
                  <select
                    value={newReport.format}
                    onChange={(e) => setNewReport({ ...newReport, format: e.target.value as ReportFormat })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="html">HTML</option>
                    <option value="csv">CSV</option>
                    <option value="json">JSON</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Schedule (Optional)
                </label>
                <select
                  value={newReport.schedule?.frequency || 'manual'}
                  onChange={(e) => {
                    const freq = e.target.value as 'daily' | 'weekly' | 'monthly' | 'manual'
                    setNewReport({
                      ...newReport,
                      schedule: freq === 'manual' ? undefined : { frequency: freq },
                    })
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="manual">Run Once (Manual)</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateReport}
                disabled={!newReport.name}
                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
              >
                Create Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {previewingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-6xl max-h-[90vh] flex flex-col mx-4">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">Report Preview</h2>
                <p className="text-sm text-gray-500">{previewingReport.name}</p>
              </div>
              <button
                onClick={() => {
                  setPreviewingReport(null)
                  setPreviewContent('')
                }}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-auto p-6">
              {previewLoading ? (
                <div className="flex items-center justify-center h-64">
                  <Loader2 className="w-8 h-8 text-primary-600 animate-spin" />
                </div>
              ) : previewingReport.format === 'pdf' ? (
                <div
                  className="prose prose-sm max-w-none"
                  dangerouslySetInnerHTML={{ __html: previewContent }}
                />
              ) : previewingReport.format === 'json' ? (
                <pre className="bg-gray-50 p-4 rounded-lg overflow-auto text-xs">
                  {previewContent}
                </pre>
              ) : (
                <pre className="bg-gray-50 p-4 rounded-lg overflow-auto text-xs whitespace-pre-wrap">
                  {previewContent}
                </pre>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200">
              <button
                onClick={() => handleDownload(previewingReport.id, previewingReport.name)}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
              <button
                onClick={() => {
                  setPreviewingReport(null)
                  setPreviewContent('')
                }}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
