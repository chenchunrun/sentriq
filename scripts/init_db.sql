-- =============================================================================
-- Security Triage System - Database Initialization (Fixed)
-- =============================================================================
-- Version: 1.0 (Fixed)
-- Date: 2026-01-10
-- Fixes: Removed pg_cron extension, fixed execution order
-- =============================================================================

-- 1. Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION generate_alert_id()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.alert_id IS NULL THEN
        NEW.alert_id = 'ALT-' || TO_CHAR(NOW(), 'YYYYMMDD-HH24MISS') || '-' || substr(md5(random()::text), 1, 4);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 3. Tables
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    phone VARCHAR(20),
    password_hash VARCHAR(255) NOT NULL,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    role VARCHAR(50) DEFAULT 'analyst' CHECK (role IN ('admin', 'supervisor', 'analyst', 'viewer', 'auditor')),
    department VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id VARCHAR(100) UNIQUE NOT NULL,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL CHECK (asset_type IN ('server', 'workstation', 'network', 'mobile', 'cloud', 'application', 'database')),
    ip_address INET,
    mac_address MACADDR,
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    owner VARCHAR(100),
    location VARCHAR(255),
    criticality VARCHAR(20) DEFAULT 'medium' CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    business_unit VARCHAR(100),
    environment VARCHAR(20) DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development', 'test')),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) UNIQUE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    alert_type VARCHAR(50) NOT NULL CHECK (alert_type IN ('malware', 'phishing', 'brute_force', 'data_exfiltration', 'anomaly', 'denial_of_service', 'unauthorized_access', 'policy_violation', 'other')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title VARCHAR(500),
    description TEXT,
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    user_name VARCHAR(100),
    asset_id VARCHAR(100),
    file_hash VARCHAR(100),
    file_name VARCHAR(255),
    url VARCHAR(1000),
    dns_query VARCHAR(500),
    raw_data JSONB,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'analyzing', 'analyzed', 'investigating', 'resolved', 'false_positive', 'suppressed')),
    assigned_to VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS triage_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) UNIQUE NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level VARCHAR(20) CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    analysis_result TEXT,
    recommended_actions TEXT,
    requires_human_review BOOLEAN DEFAULT false,
    human_reviewer VARCHAR(100),
    human_review_notes TEXT,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc VARCHAR(1000) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url', 'hash', 'email', 'certificate')),
    threat_level VARCHAR(20) CHECK (threat_level IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    source VARCHAR(100),
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    detection_rate DECIMAL(5,2),
    positives INTEGER,
    total INTEGER,
    tags TEXT[],
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(ioc, ioc_type)
);

CREATE TABLE IF NOT EXISTS alert_context (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(100) NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    context_type VARCHAR(50) NOT NULL CHECK (context_type IN ('network', 'asset', 'user', 'threat_intel', 'historical', 'correlation')),
    context_data JSONB NOT NULL,
    source VARCHAR(100),
    confidence_score DECIMAL(5,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'eradicated', 'resolved', 'closed')),
    assigned_to VARCHAR(100),
    detection_date TIMESTAMP WITH TIME ZONE NOT NULL,
    containment_date TIMESTAMP WITH TIME ZONE,
    eradication_date TIMESTAMP WITH TIME ZONE,
    resolution_date TIMESTAMP WITH TIME ZONE,
    root_cause TEXT,
    impact_assessment TEXT,
    lessons_learned TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id VARCHAR(100),
    alert_id VARCHAR(100) REFERENCES alerts(alert_id) ON DELETE SET NULL,
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN ('containment', 'eradication', 'patching', 'configuration_change', 'access_revocation', 'isolation', 'other')),
    description TEXT NOT NULL,
    priority INTEGER CHECK (priority >= 1 AND priority <= 5),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'skipped', 'failed')),
    assigned_to VARCHAR(100),
    due_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id VARCHAR(100),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_triage_results_alert_id ON triage_results(alert_id);
CREATE INDEX IF NOT EXISTS idx_triage_results_risk_score ON triage_results(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc ON threat_intel(ioc);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc_type ON threat_intel(ioc_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_threat_level ON threat_intel(threat_level);
CREATE INDEX IF NOT EXISTS idx_alert_context_alert_id ON alert_context(alert_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- 5. Triggers
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_alert_id_trigger BEFORE INSERT ON alerts
    FOR EACH ROW EXECUTE FUNCTION generate_alert_id();

CREATE TRIGGER update_triage_results_updated_at BEFORE UPDATE ON triage_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_intel_updated_at BEFORE UPDATE ON threat_intel
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alert_context_updated_at BEFORE UPDATE ON alert_context
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_incidents_updated_at BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_remediation_actions_updated_at BEFORE UPDATE ON remediation_actions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 6. Insert initial data (passwords are bcrypt hashes for 'admin123' and 'analyst123')
INSERT INTO users (username, email, full_name, password_hash, role, is_active) VALUES
('admin', 'admin@security.local', 'System Administrator', '$2b$12$svOZMDNSYb.al8C8YJSwJOsVHCMzjl3fj5kI1cKHThH6kN.Eb/A8u', 'admin', true),
('analyst', 'analyst@security.local', 'Security Analyst', '$2b$12$dPSYhAe/UjkkH4XuslF/ZuDS.B/4eJRVZS8rey4TOR7OaDD1C3AUy', 'analyst', true)
ON CONFLICT (username) DO NOTHING;

INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, criticality, environment) VALUES
('SRV-001', 'Production Web Server', 'server', '10.0.1.10', 'high', 'production'),
('SRV-002', 'Database Server', 'server', '10.0.1.20', 'critical', 'production'),
('WS-001', 'HR Workstation', 'workstation', '10.0.2.50', 'medium', 'production')
ON CONFLICT (asset_id) DO NOTHING;

-- 7. System Configurations Table
CREATE TABLE IF NOT EXISTS system_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(255) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    category VARCHAR(100),
    is_sensitive BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_system_configs_key ON system_configs(config_key);
CREATE INDEX IF NOT EXISTS idx_system_configs_category ON system_configs(category);

-- Trigger for system_configs
CREATE TRIGGER update_system_configs_updated_at BEFORE UPDATE ON system_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 9. Workflow Templates Table
CREATE TABLE IF NOT EXISTS workflow_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    steps JSONB NOT NULL,
    steps_count INTEGER NOT NULL,
    estimated_time VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_workflow_templates_template_id ON workflow_templates(template_id);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_category ON workflow_templates(category);

-- Trigger for workflow_templates
CREATE TRIGGER update_workflow_templates_updated_at BEFORE UPDATE ON workflow_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 9.1 Workflows Table
CREATE TABLE IF NOT EXISTS workflows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL DEFAULT 'manual',
    trigger_conditions JSONB,
    status VARCHAR(50) NOT NULL DEFAULT 'draft',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    total_executions INTEGER NOT NULL DEFAULT 0,
    successful_executions INTEGER NOT NULL DEFAULT 0,
    failed_executions INTEGER NOT NULL DEFAULT 0,
    last_execution_at TIMESTAMP WITH TIME ZONE,
    last_execution_status VARCHAR(50),
    created_by VARCHAR(255) NOT NULL DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflows_workflow_id ON workflows(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
CREATE INDEX IF NOT EXISTS idx_workflows_category ON workflows(category);

CREATE TRIGGER update_workflows_updated_at BEFORE UPDATE ON workflows
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 9.2 Workflow Executions Table
CREATE TABLE IF NOT EXISTS workflow_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id VARCHAR(100) UNIQUE NOT NULL,
    workflow_id VARCHAR(100) NOT NULL REFERENCES workflows(workflow_id) ON DELETE CASCADE,
    trigger_type VARCHAR(50) NOT NULL,
    trigger_reference VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    steps_execution JSONB,
    result TEXT,
    error_message TEXT,
    executed_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_executions_execution_id ON workflow_executions(execution_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow_id ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_started_at ON workflow_executions(started_at);

-- 9.3 Human Tasks Table
CREATE TABLE IF NOT EXISTS human_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id VARCHAR(100) UNIQUE NOT NULL,
    execution_id VARCHAR(100),
    task_type VARCHAR(100) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    assigned_to VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    due_date TIMESTAMP WITH TIME ZONE,
    input_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_human_tasks_task_id ON human_tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_human_tasks_execution_id ON human_tasks(execution_id);
CREATE INDEX IF NOT EXISTS idx_human_tasks_status ON human_tasks(status);
CREATE INDEX IF NOT EXISTS idx_human_tasks_assigned_to ON human_tasks(assigned_to);

-- 10. Automation Playbooks Table
CREATE TABLE IF NOT EXISTS automation_playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    version VARCHAR(50),
    actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    approval_required BOOLEAN DEFAULT false,
    timeout_seconds INTEGER,
    trigger_conditions JSONB,
    created_by VARCHAR(255) DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_automation_playbooks_playbook_id ON automation_playbooks(playbook_id);

CREATE TRIGGER update_automation_playbooks_updated_at BEFORE UPDATE ON automation_playbooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 10.1 Automation Playbook Executions Table
CREATE TABLE IF NOT EXISTS playbook_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id VARCHAR(100) UNIQUE NOT NULL,
    playbook_id VARCHAR(100) NOT NULL REFERENCES automation_playbooks(playbook_id) ON DELETE CASCADE,
    trigger_alert_id VARCHAR(100),
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    current_action VARCHAR(100),
    current_action_index INTEGER,
    approval_status VARCHAR(50),
    results JSONB NOT NULL DEFAULT '[]'::jsonb,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbook_executions_execution_id ON playbook_executions(execution_id);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_playbook_id ON playbook_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_status ON playbook_executions(status);

-- Insert default workflow templates
INSERT INTO workflow_templates (template_id, name, description, category, steps, steps_count, estimated_time) VALUES
('isolate-host', 'Isolate Compromised Host', 'Isolate a host from the network when malware is detected', 'containment',
 '[{"id":"step-1","name":"Verify Alert","description":"Confirm malware detection and identify affected host","type":"automated","estimated_time":"30s"},
   {"id":"step-2","name":"Block Network Access","description":"Block all network traffic from compromised host","type":"automated","estimated_time":"1m"},
   {"id":"step-3","name":"Isolate from VLAN","description":"Move host to isolated VLAN segment","type":"automated","estimated_time":"2m"},
   {"id":"step-4","name":"Notify Team","description":"Send alert to security team","type":"automated","estimated_time":"30s"},
   {"id":"step-5","name":"Update Ticket","description":"Create/update incident ticket","type":"automated","estimated_time":"1m"}]',
 5, '5m'),

('block-ip', 'Block Malicious IP', 'Block IP address at firewall level', 'containment',
 '[{"id":"step-1","name":"Verify IP Reputation","description":"Check threat intelligence feeds","type":"automated","estimated_time":"30s"},
   {"id":"step-2","name":"Add to Firewall Blocklist","description":"Push block rule to all firewalls","type":"automated","estimated_time":"2m"},
   {"id":"step-3","name":"Verify Block","description":"Confirm rule is active","type":"automated","estimated_time":"1m"}]',
 3, '3.5m'),

('quarantine-file', 'Quarantine Malicious File', 'Move suspicious file to quarantine and delete from original location', 'remediation',
 '[{"id":"step-1","name":"Identify File Location","description":"Locate file on filesystem","type":"automated","estimated_time":"30s"},
   {"id":"step-2","name":"Copy to Quarantine","description":"Copy file to secure quarantine directory","type":"automated","estimated_time":"1m"},
   {"id":"step-3","name":"Delete Original","description":"Remove file from original location","type":"automated","estimated_time":"30s"},
   {"id":"step-4","name":"Update Scan Results","description":"Mark file as quarantined in scan database","type":"automated","estimated_time":"30s"}]',
 4, '2.5m'),

('create-ticket', 'Create Incident Ticket', 'Create ticket in incident tracking system (ServiceNow, Jira)', 'notification',
 '[{"id":"step-1","name":"Gather Alert Details","description":"Compile alert information and context","type":"automated","estimated_time":"30s"},
   {"id":"step-2","name":"Submit Ticket","description":"Create ticket via API","type":"automated","estimated_time":"1m"}]',
 2, '1.5m'),

('enrich-context', 'Enrich Alert Context', 'Gather additional context about the alert (threat intel, asset info)', 'enrichment',
 '[{"id":"step-1","name":"Query Threat Intel","description":"Check IOCs against threat databases","type":"automated","estimated_time":"2m"},
   {"id":"step-2","name":"Get Asset Info","description":"Retrieve asset details from CMDB","type":"automated","estimated_time":"30s"},
   {"id":"step-3","name":"Check User Context","description":"Get user information and activity","type":"automated","estimated_time":"1m"},
   {"id":"step-4","name":"Query Historical Alerts","description":"Find similar past alerts","type":"automated","estimated_time":"1m"},
   {"id":"step-5","name":"Calculate Risk Score","description":"Compute overall risk assessment","type":"automated","estimated_time":"30s"},
   {"id":"step-6","name":"Update Alert","description":"Enrich alert with gathered context","type":"automated","estimated_time":"30s"}]',
 6, '5.5m'),

('notify-team', 'Notify Security Team', 'Send notifications to security team via multiple channels', 'notification',
 '[{"id":"step-1","name":"Prepare Notification","description":"Format alert message","type":"automated","estimated_time":"30s"},
   {"id":"step-2","name":"Send Email","description":"Email security team","type":"automated","estimated_time":"1m"},
   {"id":"step-3","name":"Send Slack Message","description":"Post to Slack channel","type":"automated","estimated_time":"30s"}]',
 3, '2m')
ON CONFLICT (template_id) DO NOTHING;

-- 11. Notifications Table
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    notification_id VARCHAR(255) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    message TEXT,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    is_read BOOLEAN DEFAULT false,
    is_deleted BOOLEAN DEFAULT false,
    link VARCHAR(500),
    user_id VARCHAR(100) DEFAULT 'default',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    read_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_notifications_notification_id ON notifications(notification_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);

-- 12. Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO triage_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO triage_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO triage_user;

-- Database initialization completed successfully
-- Default users: admin/admin123, analyst/analyst123 (CHANGE THESE IN PRODUCTION!)
