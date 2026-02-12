/**
 * System-wide notification component
 * Displays real-time alerts, errors, and system status
 */

import React, { useState, useEffect, useCallback } from 'react'
import { LogEntry } from '@/types'

// Log level colors
const levelColors: Record<string, string> = {
  DEBUG: 'text-gray-400',
  INFO: 'text-green-600',
  WARNING: 'text-yellow-600',
  ERROR: 'text-red-600',
  CRITICAL: 'text-red-700 font-bold',
}

// Log level backgrounds
const levelBgColors: Record<string, string> = {
  DEBUG: 'bg-gray-100',
  INFO: 'bg-green-100',
  WARNING: 'bg-yellow-100',
  ERROR: 'bg-red-100',
  CRITICAL: 'bg-red-200',
}

// Log level icons
const levelIcons: Record<string, string> = {
  DEBUG: '🔍',
  INFO: 'ℹ️',
  WARNING: '⚠️',
  ERROR: '❌',
  CRITICAL: '🚨',
}

interface SystemNotificationsProps {
  maxLogs?: number
  pollInterval?: number
  position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left'
}

/**
 * SystemNotifications Component
 * 系统级通知组件 - 显示实时告警、错误和系统状态
 */
export const SystemNotifications: React.FC<SystemNotificationsProps> = ({
  maxLogs = 50,
  pollInterval = 10000,
  position = 'bottom-right',
}) => {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [alerts, setAlerts] = useState<LogEntry[]>([])
  const [isHealthy, setIsHealthy] = useState(true)
  const [isExpanded, setIsExpanded] = useState(false)
  const [unreadCount, setUnreadCount] = useState(0)

  // Add new log entry
  const addLog = useCallback((log: Omit<LogEntry, 'timestamp'>) => {
    const newLog: LogEntry = {
      timestamp: new Date().toISOString(),
      ...log,
    }
    setLogs(prev => {
      const updated = [newLog, ...prev]
      return updated.slice(0, maxLogs)
    })

    // Also add to alerts if it's WARNING or higher
    if (log.level === 'WARNING' || log.level === 'ERROR' || log.level === 'CRITICAL') {
      setAlerts(prev => {
        const alert: LogEntry = newLog
        const updated = [alert, ...prev.slice(-9)] // Keep last 10 alerts
        setUnreadCount(updated.length)
        return updated
      })
    }
  }, [maxLogs])

  // Clear all logs
  const clearLogs = useCallback(() => {
    setLogs([])
  }, [])

  // Clear all alerts
  const clearAlerts = useCallback(() => {
    setAlerts([])
    setUnreadCount(0)
  }, [])

  // System health check
  useEffect(() => {
    const healthCheck = async (): Promise<void> => {
      try {
        const response = await fetch('/health')
        const data = await response.json()

        const wasHealthy = isHealthy
        // Health endpoint returns {status: "healthy"|"degraded"}
        const currentlyHealthy = data.status === 'healthy'

        setIsHealthy(currentlyHealthy)

        if (wasHealthy && !currentlyHealthy) {
          addLog({
            level: 'ERROR',
            message: '系统健康检查失败',
            extra: { endpoint: '/health' },
          })
        } else if (!wasHealthy && currentlyHealthy) {
          addLog({
            level: 'INFO',
            message: '系统已恢复健康',
            extra: { endpoint: '/health' },
          })
        }
      } catch (error) {
        setIsHealthy(false)
        addLog({
          level: 'ERROR',
          message: '健康检查请求失败',
          extra: { error: error instanceof Error ? error.message : 'Unknown error' },
        })
      }
    }

    // Initial check
    healthCheck()

    // Poll for health status
    const interval = setInterval(healthCheck, pollInterval)
    return () => clearInterval(interval)
  }, [pollInterval, isHealthy, addLog])

  // Get position classes
  const getPositionClasses = (): string => {
    const base = 'fixed z-50'
    const positions: Record<string, string> = {
      'top-right': 'top-4 right-4',
      'top-left': 'top-4 left-4',
      'bottom-right': 'bottom-4 right-4',
      'bottom-left': 'bottom-4 left-4',
    }
    return `${base} ${positions[position]}`
  }

  // Format timestamp
  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleString('zh-CN', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  // Recent logs (display first 20 when collapsed, all when expanded)
  const displayLogs = isExpanded ? logs : logs.slice(0, 20)

  if (!logs.length && !alerts.length) {
    return null
  }

  return (
    <div className={getPositionClasses()}>
      {/* Collapsed state - show notification icon with badge */}
      {!isExpanded && (
        <button
          onClick={() => setIsExpanded(true)}
          className="relative bg-gray-800 hover:bg-gray-700 text-white rounded-lg p-3 shadow-xl transition-all duration-200"
        >
          <div className="flex items-center gap-2">
            {/* Health indicator */}
            <div className={`w-3 h-3 rounded-full ${isHealthy ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm font-medium">系统通知</span>
            {unreadCount > 0 && (
              <span className="bg-red-500 text-white text-xs rounded-full px-2 py-0.5">
                {unreadCount}
              </span>
            )}
          </div>
        </button>
      )}

      {/* Expanded state */}
      {isExpanded && (
        <div className="bg-gray-800 rounded-lg shadow-xl w-96 max-h-[600px] overflow-hidden flex flex-col">
          {/* Header */}
          <div className="bg-gray-900 p-4 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-bold text-white">系统状态</h3>
                {/* Health badge */}
                <span className={`px-2 py-1 rounded text-xs font-semibold ${
                  isHealthy ? 'bg-green-600 text-white' : 'bg-red-600 text-white'
                }`}>
                  {isHealthy ? '✓ 健康' : '⚠ 异常'}
                </span>
              </div>
              <button
                onClick={() => setIsExpanded(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Alerts section */}
            {alerts.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-semibold text-white">告警通知 ({alerts.length})</h4>
                  <button
                    onClick={clearAlerts}
                    className="text-xs px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded transition-colors"
                  >
                    清除
                  </button>
                </div>
                <div className="space-y-2">
                  {alerts.slice(0, 5).map((alert, index) => (
                    <div
                      key={index}
                      className={`${levelBgColors[alert.level]} rounded p-2 text-sm`}
                    >
                      <div className="flex items-start gap-2">
                        <span>{levelIcons[alert.level]}</span>
                        <div className="flex-1 min-w-0">
                          <div className={`font-medium ${levelColors[alert.level]}`}>
                            {alert.level}
                          </div>
                          <div className="text-gray-700 truncate">{alert.message}</div>
                          <div className="text-xs text-gray-500">
                            {formatTimestamp(alert.timestamp)}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Logs section */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-semibold text-white">
                  系统日志 ({displayLogs.length})
                </h4>
                <button
                  onClick={clearLogs}
                  className="text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
                >
                  清除
                </button>
              </div>
              <div className="space-y-1">
                {displayLogs.slice(0, 20).map((log, index) => (
                  <div
                    key={index}
                    className="text-xs font-mono bg-gray-900 rounded p-2 hover:bg-gray-700 transition-colors"
                  >
                    <div className="flex items-start gap-2">
                      <span className="text-gray-500 flex-shrink-0">
                        {formatTimestamp(log.timestamp)}
                      </span>
                      <span className={`flex-shrink-0 ${levelColors[log.level]}`}>
                        {levelIcons[log.level]} {log.level}
                      </span>
                      <span className="text-gray-300 truncate">{log.message}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default SystemNotifications
