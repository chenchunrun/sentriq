/**
 * System-wide utility functions
 */

import type { LogEntry, LogLevel } from '@/types'

// Log level colors
const levelColors: Record<string, string> = {
  DEBUG: 'text-gray-400',
  INFO: 'text-green-600',
  WARNING: 'text-yellow-600',
  ERROR: 'text-red-600',
  CRITICAL: 'text-red-700 font-bold',
}

// Log level backgrounds
const levelClass: Record<string, string> = {
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

/**
 * Format log entry for display
 */
export function formatLogEntry(entry: LogEntry): string {
  const timestamp = new Date(entry.timestamp).toLocaleString('zh-CN', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })

  return `[${timestamp}] ${levelIcons[entry.level] || ''} ${entry.level}] - ${entry.message}${entry.extra ? ' | ' + JSON.stringify(entry.extra) : ''}`
}

/**
 * Parse structured log data from API responses
 */
export function parseLogData(data: unknown): LogEntry[] {
  if (!data) return []

  if (Array.isArray(data)) {
    return data.map((item: unknown) => ({
      timestamp: (item as any).timestamp || new Date().toISOString(),
      level: (item as any).level || 'INFO',
      message: (item as any).message || '',
      extra: (item as any).extra || null,
    }))
  }

  return Object.values(data as Record<string, unknown>).map(item => ({
    timestamp: (item as any).timestamp || new Date().toISOString(),
    level: (item as any).level || 'INFO',
    message: (item as any).message || '',
    extra: (item as any).extra || null,
  }))
}

/**
 * Get log level color class
 */
export function getLevelColor(level: LogLevel): string {
  return levelColors[level] || 'text-gray-600'
}

/**
 * Get log level background class
 */
export function getLevelBg(level: LogLevel): string {
  return levelClass[level] || 'bg-gray-100'
}

/**
 * Get log level icon
 */
export function getLevelIcon(level: LogLevel): string {
  return levelIcons[level] || '📝'
}

/**
 * Safe API request wrapper with error handling
 */
export async function safeApiRequest<T>(
  url: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
  data?: unknown,
  headers?: Record<string, string>
): Promise<T> {
  try {
    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(headers || {}),
      },
    }

    if (data && method !== 'GET') {
      options.body = JSON.stringify(data)
    }

    const response = await fetch(url, options)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new Error(errorData.error?.message || '请求失败')
    }

    return await response.json() as T
  } catch (error) {
    // Log error for debugging
    console.error('API request failed:', url, error)

    // Show user-friendly error message
    if (error instanceof Error) {
      if (error.message.includes('fetch')) {
        throw new Error('网络连接失败，请检查网络设置')
      } else if (error.message.includes('timeout')) {
        throw new Error('请求超时，请稍后再试')
      } else {
        throw error
      }
    }
    throw new Error('未知错误')
  }
}

/**
 * Debounced function factory
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout> | null = null
  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout)
    timeout = setTimeout(() => {
      func(...args)
    }, delay)
  }
}

/**
 * Check system health status
 */
export async function checkSystemHealth(): Promise<{
  api: boolean
  database: boolean
  services: Record<string, boolean>
}> {
  try {
    const [healthResult, servicesResult] = await Promise.allSettled([
      safeApiRequest<{ success: boolean; status?: string }>('/api/v1/health'),
      safeApiRequest<{ data?: { services?: Record<string, boolean>; database?: { connected?: boolean } } }>('/api/v1/services/health'),
    ])

    const apiHealthy =
      healthResult.status === 'fulfilled' && healthResult.value?.success === true

    const servicesData =
      servicesResult.status === 'fulfilled' && servicesResult.value?.data
        ? servicesResult.value.data
        : {}

    return {
      api: apiHealthy,
      database: servicesData.database?.connected || false,
      services: servicesData.services || {},
    }
  } catch (error) {
    console.error('Health check failed:', error)
    return {
      api: false,
      database: false,
      services: {},
    }
  }
}

/**
 * Format timestamp for display
 */
export function formatTimestamp(timestamp: string | Date): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp
  return date.toLocaleString('zh-CN', {
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
