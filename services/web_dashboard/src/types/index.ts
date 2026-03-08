/**
 * Type definitions for Security Triage Dashboard
 */

// =============================================================================
// Alert Types
// =============================================================================

export enum AlertType {
  MALWARE = 'malware',
  PHISHING = 'phishing',
  BRUTE_FORCE = 'brute_force',
  DATA_EXFILTRATION = 'data_exfiltration',
  ANOMALY = 'anomaly',
  DDOS = 'ddos',
  INTRUSION = 'intrusion',
  MALICIOUS_CODE = 'malicious_code',
  POLICY_VIOLATION = 'policy_violation',
  OTHER = 'other',
}

export enum AlertSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum AlertStatus {
  PENDING = 'pending',
  ANALYZING = 'analyzing',
  ANALYZED = 'analyzed',
  INVESTIGATING = 'investigating',
  TRIAGED = 'triaged',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  CLOSED = 'closed',
  FALSE_POSITIVE = 'false_positive',
  SUPPRESSED = 'suppressed',
}

export interface IOC {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  severity?: AlertSeverity;
  confidence?: number;
}

export interface Alert {
  alert_id: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  description: string;
  source_ip?: string;
  destination_ip?: string;
  target_ip?: string;  // Alias for destination_ip
  iocs?: IOC[];
  timestamp?: string;
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  asset_id?: string;
  user_id?: string;
  file_hash?: string;
  url?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

// =============================================================================
// Triage Result Types
// =============================================================================

export enum RiskLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export interface RiskAssessment {
  risk_score: number; // 0-100
  risk_level: RiskLevel;
  confidence: number; // 0-100
  factors: {
    severity: number;
    threat_intel: number;
    asset_criticality: number;
    exploitability: number;
  };
}

export interface ThreatIntelligence {
  ioc: string;
  ioc_type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  sources: ThreatIntelSource[];
  aggregate_score: number; // 0-100
  threat_level: RiskLevel;
  confidence: number; // 0-1
  detected_by_count: number;
  total_sources: number;
  tags?: string[];
  last_seen?: string;
  first_seen?: string;
  queried_at?: string;
}

export interface ThreatIntelSource {
  source: string; // 'virustotal', 'abuse_ch', 'otx', etc.
  detected: boolean;
  detection_rate?: number;
  positives?: number;
  total?: number;
  threat_type?: string;
  tags?: string[];
  country?: string;
  as_owner?: string;
  scan_date?: string;
  permalink?: string;
  details?: Record<string, unknown>;
}

export interface RemediationAction {
  action: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  automated: boolean;
  estimated_time?: string;
}

export interface TriageResult {
  alert_id: string;
  risk_assessment: RiskAssessment;
  threat_intelligence: ThreatIntelligence[];
  remediation: RemediationAction[];
  requires_human_review: boolean;
  analysis_summary: string;
  similar_alerts?: string[];
  created_at: string;
}

// =============================================================================
// API Response Types
// =============================================================================

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
  meta?: Record<string, unknown>;
}

export interface ApiError {
  success: false;
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Filter and Query Types
// =============================================================================

export interface AlertFilters {
  alert_type?: AlertType;
  severity?: AlertSeverity;
  status?: AlertStatus;
  source_ip?: string;
  assigned_to?: string;
  date_from?: string;
  date_to?: string;
  search?: string;
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export interface MetricsFilters {
  date_from?: string;
  date_to?: string;
  interval?: 'hour' | 'day' | 'week' | 'month';
}

// =============================================================================
// Metrics and Analytics Types
// =============================================================================

export interface AlertMetrics {
  total_alerts: number;
  by_severity: Record<AlertSeverity, number>;
  by_type: Record<string, number>;
  by_status: Record<AlertStatus, number>;
  avg_resolution_time: number;
  mtta: number; // Mean Time to Acknowledge
  mttr: number; // Mean Time to Resolve
}

export interface TrendDataPoint {
  timestamp: string;
  value: number;
  label?: string;
}

export interface AlertTrends {
  daily: TrendDataPoint[];
  weekly: TrendDataPoint[];
  monthly: TrendDataPoint[];
}

export interface TopAlerts {
  alert_type: string;
  count: number;
  percentage: number;
}

// =============================================================================
// Report Types
// =============================================================================

export enum ReportFormat {
  PDF = 'pdf',
  EXCEL = 'excel',
  CSV = 'csv',
  JSON = 'json',
  HTML = 'html',
}

export interface ReportRequest {
  name: string;
  description?: string;
  type: 'daily_summary' | 'weekly_summary' | 'monthly_summary' | 'incident_report' | 'trend_analysis';
  format: ReportFormat;
  filters: AlertFilters | MetricsFilters | Record<string, unknown>;
  date?: string;
  alert_id?: string;
  schedule?: {
    frequency: 'daily' | 'weekly' | 'monthly';
    time?: string;
    recipients?: string[];
  };
}

export interface Report {
  id: string;
  name: string;
  description?: string;
  type: string;
  format: ReportFormat;
  status: 'pending' | 'generating' | 'completed' | 'failed';
  created_at: string;
  created_by: string;
  file_url?: string;
}

// =============================================================================
// Configuration Types
// =============================================================================

export interface SystemConfig {
  key: string;
  value: string | number | boolean | string[] | Record<string, unknown>;
  description: string;
  category: string;
  editable: boolean;
  updated_at?: string;
}

export interface FeatureFlag {
  name: string;
  enabled: boolean;
  description: string;
  conditions?: Record<string, unknown>;
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  notifications: {
    email: boolean;
    browser: boolean;
    slack: boolean;
  };
  dashboard: {
    default_view: string;
    refresh_interval: number;
  };
  alerts: {
    default_filters: AlertFilters;
  };
}

// =============================================================================
// Authentication Types
// =============================================================================

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer' | 'analyst' | 'security_analyst' | 'auditor';
  permissions: string[];
}

export interface AuthToken {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'bearer';
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthContextType {
  user: AuthUser | null;
  token: string | null;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
  hasPermission: (permission: string) => boolean;
}

// =============================================================================
// WebSocket Types
// =============================================================================

export enum WSMessageType {
  ALERT_CREATED = 'alert.created',
  ALERT_UPDATED = 'alert.updated',
  ALERT_STATUS_CHANGED = 'alert.status_changed',
  TRIAGE_COMPLETED = 'triage.completed',
  SYSTEM_ANNOUNCEMENT = 'system.announcement',
}

export interface WSMessage {
  type: WSMessageType;
  data: unknown;
  timestamp: string;
}

export interface WSAlertUpdate {
  alert_id: string;
  status: AlertStatus;
  severity?: AlertSeverity;
  assigned_to?: string;
}

// =============================================================================
// Workflow Types
// =============================================================================

export enum WorkflowStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

export interface Workflow {
  id: string;
  name: string;
  description: string;
  status: WorkflowStatus;
  trigger_alert_id: string;
  steps: WorkflowStep[];
  current_step?: number;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

export interface WorkflowStep {
  id: string;
  name: string;
  type: 'manual' | 'automated';
  status: WorkflowStatus;
  result?: unknown;
  error?: string;
  started_at?: string;
  completed_at?: string;
}

// =============================================================================
// Notification Types
// =============================================================================

export interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  alert_id?: string;
  read: boolean;
  created_at: string;
  action_url?: string;
}

// =============================================================================
// Log Types
// =============================================================================

export type LogLevel = 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  extra?: Record<string, unknown> | null;
}
