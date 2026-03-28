/**
 * API Type Definitions
 *
 * TypeScript interfaces matching the API Gateway response models
 */

export type AlertType =
  | 'malware'
  | 'phishing'
  | 'brute_force'
  | 'data_exfiltration'
  | 'anomaly'
  | 'unauthorized_access'
  | 'ddos'
  | 'suspicious_activity';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus = 'new' | 'in_progress' | 'assigned' | 'resolved' | 'closed';

export interface IOC {
  type: 'ip' | 'hash' | 'url' | 'domain' | 'email';
  value: string;
  confidence: number;
}

export interface SecurityAlert {
  alert_id: string;
  timestamp: string;
  alert_type: AlertType;
  severity: Severity;
  status: AlertStatus;
  title: string;
  description: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  user?: string;
  asset?: string;
  iocs: IOC[];
  risk_score?: number;
  created_at: string;
  updated_at: string;
}

export interface TriageResult {
  id: string;
  alert_id: string;
  analysis: string;
  risk_score: number;
  risk_factors: string[];
  recommended_actions: string[];
  confidence: number;
  model_used: 'deepseek' | 'qwen';
  created_at: string;
}

export interface ThreatIntel {
  ioc: string;
  sources: {
    virustotal?: {
      detection_rate: number;
      positives: number;
      total: number;
    };
    otx?: {
      pulses: number;
      severity: string;
    };
    abuse_ch?: {
      detected: boolean;
      threat: string;
    };
  };
  aggregate_score: number;
  last_updated: string;
}

export interface AlertContext {
  alert_id: string;
  network_context?: {
    geo_location?: {
      country: string;
      city: string;
      latitude: number;
      longitude: number;
    };
    reputation?: {
      score: number;
      source: string;
    };
    is_tor_exit_node: boolean;
    is_vpn: boolean;
  };
  asset_context?: {
    owner?: string;
    department?: string;
    criticality: 'critical' | 'high' | 'medium' | 'low';
    vulnerabilities?: number;
  };
  user_context?: {
    department?: string;
    manager?: string;
    location?: string;
    groups: string[];
  };
}

export interface AlertDetail extends SecurityAlert {
  triage_result?: TriageResult;
  threat_intel?: ThreatIntel;
  context?: AlertContext;
}

export interface AlertStats {
  total: number;
  by_severity: Record<Severity, number>;
  by_status: Record<AlertStatus, number>;
  by_type: Record<string, number>;
}

export interface DashboardStats {
  total_alerts: number;
  critical_alerts: number;
  high_risk_alerts: number;
  pending_triage: number;
  avg_response_time?: number;
  alerts_today: number;
  threats_blocked: number;
  system_health: 'healthy' | 'degraded' | 'unhealthy';
  trends?: {
    alert_volume: Array<{
      timestamp: string;
      value: number;
    }>;
  };
}

export interface TrendDataPoint {
  timestamp: string;
  value: number;
  label?: string;
}

export interface TrendResponse {
  metric: string;
  time_range: string;
  data_points: TrendDataPoint[];
  summary: 'increasing' | 'decreasing' | 'stable' | 'insufficient_data';
}

export interface AlertFilter {
  alert_id?: string;
  alert_type?: AlertType;
  severity?: Severity;
  status?: AlertStatus;
  source_ip?: string;
  search?: string;
  start_date?: string;
  end_date?: string;
}

export interface PaginatedResponse<T> {
  success: boolean;
  message?: string;
  data: T[];
  meta: {
    total: number;
    skip: number;
    limit: number;
    has_more: boolean;
  };
}

export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data?: T;
}
