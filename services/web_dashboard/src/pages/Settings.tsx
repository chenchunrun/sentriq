/**
 * Settings Page - System Configuration Management
 */

import React, { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import type { SystemConfig, UserPreferences } from '@/types'
import {
  Save,
  RotateCcw,
  Check,
  X,
  Bell,
  Shield,
  Settings as SettingsIcon,
  Brain,
  Sliders,
} from 'lucide-react'

type ConfigCategory = 'alerts' | 'automation' | 'notifications' | 'llm' | 'preferences'

interface ConfigItem {
  key: string
  value: string | number | boolean | string[] | Record<string, unknown>
  description: string
  category: string
  editable: boolean
}

export const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ConfigCategory>('alerts')
  const [configs, setConfigs] = useState<Record<string, ConfigItem>>({})
  const [preferences, setPreferences] = useState<UserPreferences | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [changes, setChanges] = useState<Record<string, unknown>>({})

  // Load configurations
  useEffect(() => {
    loadConfigs()
    loadPreferences()
  }, [activeTab])

  const loadConfigs = async () => {
    try {
      setLoading(true)
      const data = await api.config.getConfigs(activeTab)
      const configMap: Record<string, ConfigItem> = {}
      data.forEach((item: SystemConfig) => {
        configMap[item.key] = {
          key: item.key,
          value: item.value,
          description: item.description,
          category: item.category,
          editable: item.editable,
        }
      })
      setConfigs(configMap)
    } catch (error) {
      console.error('Failed to load configs:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadPreferences = async () => {
    try {
      const prefs = await api.config.getPreferences()
      setPreferences(prefs)
    } catch (error) {
      console.error('Failed to load preferences:', error)
    }
  }

  const updateConfig = (
    key: string,
    value: string | number | boolean | string[] | Record<string, unknown>
  ) => {
    setConfigs((prev) => ({
      ...prev,
      [key]: { ...prev[key], value },
    }))
    setChanges((prev) => ({ ...prev, [key]: value }))
  }

  const updatePreference = (path: string, value: unknown) => {
    if (!preferences) return
    const updated = { ...preferences }
    const keys = path.split('.')
    let current: any = updated
    for (let i = 0; i < keys.length - 1; i++) {
      current = current[keys[i]]
    }
    current[keys[keys.length - 1]] = value
    setPreferences(updated)
    setChanges((prev) => ({ ...prev, [path]: value }))
  }

  const saveChanges = async () => {
    try {
      setSaving(true)
      setSaveStatus('idle')

      // Save config changes
      for (const [key, value] of Object.entries(changes)) {
        if (key.includes('.')) {
          // It's a preference
          continue
        }
        await api.config.updateConfig(
          key,
          value as string | number | boolean | string[] | Record<string, unknown>
        )
      }

      // Save preferences
      if (preferences) {
        await api.config.updatePreferences(preferences)
      }

      setChanges({})
      setSaveStatus('success')
      setTimeout(() => setSaveStatus('idle'), 3000)
    } catch (error) {
      console.error('Failed to save:', error)
      setSaveStatus('error')
    } finally {
      setSaving(false)
    }
  }

  const resetToDefaults = async () => {
    if (!confirm('Are you sure you want to reset all settings to defaults? This action cannot be undone.')) return

    try {
      setSaving(true)
      setSaveStatus('idle')

      // Call API to reset configs
      if (activeTab === 'preferences') {
        await api.config.updatePreferences({
          theme: 'light',
          notifications: {
            email: true,
            browser: true,
            slack: false,
          },
          dashboard: {
            default_view: 'overview',
            refresh_interval: 30,
          },
          alerts: {
            default_filters: {},
          },
        })
        await loadPreferences()
      } else {
        await api.config.resetToDefaults(activeTab)
        await loadConfigs()
      }

      // Clear changes
      setChanges({})

      setSaveStatus('success')
      setTimeout(() => setSaveStatus('idle'), 3000)
    } catch (error) {
      console.error('Failed to reset:', error)
      setSaveStatus('error')
    } finally {
      setSaving(false)
    }
  }

  const hasChanges = Object.keys(changes).length > 0

  const renderAlertSettings = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-gray-900">Alert Processing</h3>

      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Auto-Triage Enabled</h4>
            <p className="text-sm text-gray-500">Automatically triage incoming alerts using AI</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={configs['auto_triage_enabled']?.value as boolean || false}
              onChange={(e) => updateConfig('auto_triage_enabled', e.target.checked)}
              className="sr-only peer"
              disabled={!configs['auto_triage_enabled']?.editable}
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Auto-Response Threshold</h4>
            <p className="text-sm text-gray-500">Minimum severity for automatic response actions</p>
          </div>
          <select
            value={configs['auto_response_threshold']?.value as string || 'high'}
            onChange={(e) => updateConfig('auto_response_threshold', e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            disabled={!configs['auto_response_threshold']?.editable}
          >
            <option value="critical">Critical Only</option>
            <option value="high">High and Above</option>
            <option value="medium">Medium and Above</option>
          </select>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Human Review Required</h4>
            <p className="text-sm text-gray-500">Alert severities requiring human review</p>
          </div>
          <div className="flex gap-2">
            {['critical', 'high', 'medium'].map((severity) => (
              <label key={severity} className="inline-flex items-center">
                <input
                  type="checkbox"
                  checked={(configs['human_review_required']?.value as unknown as string[] || []).includes(severity)}
                  onChange={(e) => {
                    const current = (configs['human_review_required']?.value as unknown as string[]) || []
                    const updated = e.target.checked
                      ? [...current, severity]
                      : current.filter((s) => s !== severity)
                    updateConfig('human_review_required', updated as unknown as boolean)
                  }}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <span className="ml-2 text-sm capitalize text-gray-700">{severity}</span>
              </label>
            ))}
          </div>
        </div>
      </div>
    </div>
  )

  const renderAutomationSettings = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-gray-900">Automation Rules</h3>

      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Approval Required</h4>
            <p className="text-sm text-gray-500">Require approval before executing automation playbooks</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={configs['approval_required']?.value as boolean || false}
              onChange={(e) => updateConfig('approval_required', e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Execution Timeout (seconds)</h4>
            <p className="text-sm text-gray-500">Maximum time to wait for automation completion</p>
          </div>
          <input
            type="number"
            value={configs['timeout_seconds']?.value as number || 600}
            onChange={(e) => updateConfig('timeout_seconds', parseInt(e.target.value))}
            className="w-24 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            min={60}
            max={3600}
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Max Concurrent Executions</h4>
            <p className="text-sm text-gray-500">Maximum number of parallel automation workflows</p>
          </div>
          <input
            type="number"
            value={configs['max_concurrent_executions']?.value as number || 10}
            onChange={(e) => updateConfig('max_concurrent_executions', parseInt(e.target.value))}
            className="w-24 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            min={1}
            max={50}
          />
        </div>
      </div>
    </div>
  )

  const renderNotificationSettings = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-gray-900">Notification Channels</h3>

      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Email Notifications</h4>
            <p className="text-sm text-gray-500">Receive alerts via email</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={preferences?.notifications?.email || false}
              onChange={(e) => updatePreference('notifications.email', e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Browser Notifications</h4>
            <p className="text-sm text-gray-500">Show in-app notification banners</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={preferences?.notifications?.browser || false}
              onChange={(e) => updatePreference('notifications.browser', e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Slack Notifications</h4>
            <p className="text-sm text-gray-500">Send alerts to Slack channels</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={preferences?.notifications?.slack || false}
              onChange={(e) => updatePreference('notifications.slack', e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        </div>
      </div>

      <h3 className="text-lg font-semibold text-gray-900">Severity Mapping</h3>
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <p className="text-sm text-gray-500 mb-4">Configure which channels receive notifications for each severity level</p>
        <div className="space-y-3">
          {['critical', 'high', 'medium', 'low'].map((severity) => (
            <div key={severity} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
              <span className="text-sm font-medium capitalize text-gray-700">{severity}</span>
              <div className="flex gap-4 text-xs text-gray-500">
                <span>Email: ✓</span>
                <span>Slack: {['critical', 'high'].includes(severity) ? '✓' : '✗'}</span>
                <span>Browser: ✓</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )

  const renderLLMSettings = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-gray-900">AI Model Configuration</h3>

      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
        {/* LLM Provider Selection */}
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">LLM Provider</h4>
            <p className="text-sm text-gray-500">Primary LLM provider for alert analysis</p>
          </div>
          <select
            value={configs['llm_provider']?.value as string || 'zhipu'}
            onChange={(e) => updateConfig('llm_provider', e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          >
            <option value="zhipu">Zhipu AI (智谱AI)</option>
            <option value="deepseek">DeepSeek</option>
            <option value="qwen">Qwen (通义千问)</option>
            <option value="openai">OpenAI</option>
          </select>
        </div>

        {/* Zhipu AI Configuration */}
        {configs['llm_provider']?.value === 'zhipu' && (
          <>
            <div className="mt-4 pt-4 border-t border-gray-200">
              <div className="mb-3">
                <span className="text-sm font-medium text-gray-900">Zhipu AI Configuration (智谱AI)</span>
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">API Key</h4>
                  <p className="text-sm text-gray-500">Zhipu AI API key</p>
                </div>
                <input
                  type="password"
                  value={configs['zhipu_api_key']?.value as string || ''}
                  onChange={(e) => updateConfig('zhipu_api_key', e.target.value)}
                  className="w-80 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="Enter your Zhipu API key"
                />
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Model</h4>
                  <p className="text-sm text-gray-500">Zhipu AI model to use</p>
                </div>
                <select
                  value={configs['zhipu_model']?.value as string || 'glm-4-flash'}
                  onChange={(e) => updateConfig('zhipu_model', e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="glm-4-flash">GLM-4 Flash (Fast)</option>
                  <option value="glm-4-plus">GLM-4 Plus (Balanced)</option>
                  <option value="glm-4-air">GLM-4 Air (Economical)</option>
                  <option value="glm-4">GLM-4 (Standard)</option>
                </select>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Base URL</h4>
                  <p className="text-sm text-gray-500">API base URL</p>
                </div>
                <input
                  type="text"
                  value={configs['zhipu_base_url']?.value as string || 'https://open.bigmodel.cn/api/paas/v4/'}
                  onChange={(e) => updateConfig('zhipu_base_url', e.target.value)}
                  className="w-96 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="https://open.bigmodel.cn/api/paas/v4/"
                />
              </div>
            </div>
          </>
        )}

        {/* DeepSeek Configuration */}
        {configs['llm_provider']?.value === 'deepseek' && (
          <>
            <div className="mt-4 pt-4 border-t border-gray-200">
              <div className="mb-3">
                <span className="text-sm font-medium text-gray-900">DeepSeek Configuration</span>
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">API Key</h4>
                  <p className="text-sm text-gray-500">DeepSeek API key</p>
                </div>
                <input
                  type="password"
                  value={configs['deepseek_api_key']?.value as string || ''}
                  onChange={(e) => updateConfig('deepseek_api_key', e.target.value)}
                  className="w-80 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="Enter your DeepSeek API key"
                />
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Model</h4>
                  <p className="text-sm text-gray-500">DeepSeek model to use</p>
                </div>
                <select
                  value={configs['deepseek_model']?.value as string || 'deepseek-v3'}
                  onChange={(e) => updateConfig('deepseek_model', e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="deepseek-v3">DeepSeek V3 (Latest)</option>
                  <option value="deepseek-chat">DeepSeek Chat</option>
                </select>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Base URL</h4>
                  <p className="text-sm text-gray-500">API base URL</p>
                </div>
                <input
                  type="text"
                  value={configs['deepseek_base_url']?.value as string || 'https://api.deepseek.com/v1'}
                  onChange={(e) => updateConfig('deepseek_base_url', e.target.value)}
                  className="w-96 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="https://api.deepseek.com/v1"
                />
              </div>
            </div>
          </>
        )}

        {/* Qwen Configuration */}
        {configs['llm_provider']?.value === 'qwen' && (
          <>
            <div className="mt-4 pt-4 border-t border-gray-200">
              <div className="mb-3">
                <span className="text-sm font-medium text-gray-900">Qwen Configuration (通义千问)</span>
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">API Key</h4>
                  <p className="text-sm text-gray-500">Alibaba Qwen API key</p>
                </div>
                <input
                  type="password"
                  value={configs['qwen_api_key']?.value as string || ''}
                  onChange={(e) => updateConfig('qwen_api_key', e.target.value)}
                  className="w-80 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="Enter your Qwen API key"
                />
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Model</h4>
                  <p className="text-sm text-gray-500">Qwen model to use</p>
                </div>
                <select
                  value={configs['qwen_model']?.value as string || 'qwen3-max'}
                  onChange={(e) => updateConfig('qwen_model', e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="qwen3-max">Qwen 3 Max (Best Quality)</option>
                  <option value="qwen3-plus">Qwen 3 Plus</option>
                  <option value="qwen-turbo">Qwen Turbo (Fast)</option>
                  <option value="qwen-long">Qwen Long (Long Context)</option>
                </select>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Base URL</h4>
                  <p className="text-sm text-gray-500">API base URL</p>
                </div>
                <input
                  type="text"
                  value={configs['qwen_base_url']?.value as string || 'https://dashscope.aliyuncs.com/compatible-mode/v1'}
                  onChange={(e) => updateConfig('qwen_base_url', e.target.value)}
                  className="w-96 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="https://dashscope.aliyuncs.com/compatible-mode/v1"
                />
              </div>
            </div>
          </>
        )}

        {/* OpenAI Configuration */}
        {configs['llm_provider']?.value === 'openai' && (
          <>
            <div className="mt-4 pt-4 border-t border-gray-200">
              <div className="mb-3">
                <span className="text-sm font-medium text-gray-900">OpenAI Configuration</span>
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">API Key</h4>
                  <p className="text-sm text-gray-500">OpenAI API key</p>
                </div>
                <input
                  type="password"
                  value={configs['openai_api_key']?.value as string || ''}
                  onChange={(e) => updateConfig('openai_api_key', e.target.value)}
                  className="w-80 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="sk-..."
                />
              </div>

              <div className="flex items-center justify-between mb-4">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Model</h4>
                  <p className="text-sm text-gray-500">OpenAI model to use</p>
                </div>
                <select
                  value={configs['openai_model']?.value as string || 'gpt-4-turbo'}
                  onChange={(e) => updateConfig('openai_model', e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="gpt-4-turbo">GPT-4 Turbo (Recommended)</option>
                  <option value="gpt-4">GPT-4</option>
                  <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                </select>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <h4 className="font-medium text-gray-900">Base URL</h4>
                  <p className="text-sm text-gray-500">API base URL</p>
                </div>
                <input
                  type="text"
                  value={configs['openai_base_url']?.value as string || 'https://api.openai.com/v1'}
                  onChange={(e) => updateConfig('openai_base_url', e.target.value)}
                  className="w-96 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="https://api.openai.com/v1"
                />
              </div>
            </div>
          </>
        )}

        {/* Common Settings for All Providers */}
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="mb-3">
            <span className="text-sm font-medium text-gray-900">Common Settings</span>
          </div>

          <div className="flex items-center justify-between mb-4">
            <div className="flex-1">
              <h4 className="font-medium text-gray-900">Temperature</h4>
              <p className="text-sm text-gray-500">Model randomness (0.0 - 1.0)</p>
            </div>
            <input
              type="number"
              value={configs['temperature']?.value as number || 0.0}
              onChange={(e) => updateConfig('temperature', parseFloat(e.target.value))}
              className="w-24 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              min={0}
              max={1}
              step={0.1}
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex-1">
              <h4 className="font-medium text-gray-900">Max Tokens</h4>
              <p className="text-sm text-gray-500">Maximum response length</p>
            </div>
            <input
              type="number"
              value={configs['max_tokens']?.value as number || 2000}
              onChange={(e) => updateConfig('max_tokens', parseInt(e.target.value))}
              className="w-24 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              min={100}
              max={8000}
            />
          </div>
        </div>
      </div>
    </div>
  )

  const renderPreferences = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-gray-900">User Preferences</h3>

      <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Theme</h4>
            <p className="text-sm text-gray-500">Interface appearance</p>
          </div>
          <select
            value={preferences?.theme || 'light'}
            onChange={(e) => updatePreference('theme', e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          >
            <option value="light">Light</option>
            <option value="dark">Dark</option>
            <option value="auto">Auto (System)</option>
          </select>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-medium text-gray-900">Dashboard Refresh Interval</h4>
            <p className="text-sm text-gray-500">Auto-refresh frequency (seconds)</p>
          </div>
          <select
            value={preferences?.dashboard?.refresh_interval || 30}
            onChange={(e) => updatePreference('dashboard.refresh_interval', parseInt(e.target.value))}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          >
            <option value={10}>10s</option>
            <option value={30}>30s</option>
            <option value={60}>60s</option>
            <option value={0}>Manual Only</option>
          </select>
        </div>
      </div>
    </div>
  )

  const tabs: { key: ConfigCategory; label: string; icon: any }[] = [
    { key: 'alerts', label: 'Alerts', icon: Shield },
    { key: 'automation', label: 'Automation', icon: Sliders },
    { key: 'notifications', label: 'Notifications', icon: Bell },
    { key: 'llm', label: 'AI Models', icon: Brain },
    { key: 'preferences', label: 'Preferences', icon: SettingsIcon },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
          <p className="text-sm text-gray-500">Configure system behavior and preferences</p>
        </div>
        <div className="flex items-center gap-3">
          {hasChanges && (
            <span className="text-sm text-orange-600">
              {Object.keys(changes).length} unsaved change{Object.keys(changes).length > 1 ? 's' : ''}
            </span>
          )}
          <button
            onClick={resetToDefaults}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            Reset to Defaults
          </button>
          <button
            onClick={saveChanges}
            disabled={!hasChanges || saving}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
          >
            {saving ? (
              <>Saving...</>
            ) : (
              <>
                <Save className="w-4 h-4" />
                Save Changes
              </>
            )}
          </button>
        </div>
      </div>

      {/* Save Status */}
      {saveStatus === 'success' && (
        <div className="flex items-center gap-2 px-4 py-3 bg-green-50 border border-green-200 rounded-lg text-green-800">
          <Check className="w-5 h-5" />
          <span className="text-sm font-medium">Settings saved successfully</span>
        </div>
      )}
      {saveStatus === 'error' && (
        <div className="flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-200 rounded-lg text-red-800">
          <X className="w-5 h-5" />
          <span className="text-sm font-medium">Failed to save settings</span>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8 -mb-px">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-2 px-1 py-4 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.key
                    ? 'border-primary-500 text-primary-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="spinner"></div>
          </div>
        ) : (
          <>
            {activeTab === 'alerts' && renderAlertSettings()}
            {activeTab === 'automation' && renderAutomationSettings()}
            {activeTab === 'notifications' && renderNotificationSettings()}
            {activeTab === 'llm' && renderLLMSettings()}
            {activeTab === 'preferences' && renderPreferences()}
          </>
        )}
      </div>
    </div>
  )
}
