use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Metrics collector for MPC operations
#[derive(Clone)]
pub struct MetricsCollector {
    metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
    events: Arc<RwLock<Vec<AuditEvent>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub value: f64,
    pub timestamp: DateTime<Utc>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: EventType,
    pub participant_id: Option<u32>,
    pub timestamp: DateTime<Utc>,
    pub details: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    DkgStarted,
    DkgCompleted,
    ShareGenerated,
    ShareDistributed,
    SignatureRequested,
    SignatureGenerated,
    SecretStored,
    SecretRetrieved,
    ErrorOccurred,
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record a metric
    pub async fn record_metric(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let metric = MetricValue {
            value,
            timestamp: Utc::now(),
            labels,
        };

        let mut metrics = self.metrics.write().await;
        metrics.insert(name.to_string(), metric);

        info!(metric_name = name, value = value, "Metric recorded");
    }

    /// Record an audit event
    pub async fn record_event(&self, event: AuditEvent) {
        let mut events = self.events.write().await;
        events.push(event.clone());

        match event.success {
            true => info!(
                event_type = ?event.event_type,
                participant = ?event.participant_id,
                "Audit event recorded"
            ),
            false => warn!(
                event_type = ?event.event_type,
                participant = ?event.participant_id,
                details = %event.details,
                "Failed operation recorded"
            ),
        }
    }

    /// Get metrics summary
    pub async fn get_metrics_summary(&self) -> HashMap<String, MetricValue> {
        self.metrics.read().await.clone()
    }

    /// Get audit log
    pub async fn get_audit_log(&self, limit: Option<usize>) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        match limit {
            Some(n) => events.iter().rev().take(n).cloned().collect(),
            None => events.clone(),
        }
    }
}

/// Performance tracker for operations
pub struct PerformanceTracker {
    start_time: std::time::Instant,
    operation: String,
    metrics: MetricsCollector,
}

impl PerformanceTracker {
    pub fn new(operation: &str, metrics: MetricsCollector) -> Self {
        info!(operation = operation, "Operation started");
        PerformanceTracker {
            start_time: std::time::Instant::now(),
            operation: operation.to_string(),
            metrics,
        }
    }

    pub async fn complete(self) {
        let duration = self.start_time.elapsed();
        let duration_ms = duration.as_millis() as f64;

        let mut labels = HashMap::new();
        labels.insert("operation".to_string(), self.operation.clone());

        self.metrics
            .record_metric(
                &format!("{}_duration_ms", self.operation),
                duration_ms,
                labels,
            )
            .await;

        info!(
            operation = %self.operation,
            duration_ms = duration_ms,
            "Operation completed"
        );
    }
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: ServiceStatus,
    pub uptime: std::time::Duration,
    pub last_activity: DateTime<Utc>,
    pub active_sessions: usize,
    pub storage_health: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

pub struct HealthMonitor {
    start_time: std::time::Instant,
    last_activity: Arc<RwLock<DateTime<Utc>>>,
    active_sessions: Arc<RwLock<usize>>,
}

impl HealthMonitor {
    pub fn new() -> Self {
        HealthMonitor {
            start_time: std::time::Instant::now(),
            last_activity: Arc::new(RwLock::new(Utc::now())),
            active_sessions: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn update_activity(&self) {
        let mut last_activity = self.last_activity.write().await;
        *last_activity = Utc::now();
    }

    pub async fn increment_sessions(&self) {
        let mut sessions = self.active_sessions.write().await;
        *sessions += 1;
    }

    pub async fn decrement_sessions(&self) {
        let mut sessions = self.active_sessions.write().await;
        if *sessions > 0 {
            *sessions -= 1;
        }
    }

    pub async fn get_health_status(&self) -> HealthStatus {
        let last_activity = *self.last_activity.read().await;
        let active_sessions = *self.active_sessions.read().await;

        // Check storage health (TODO: need to implement storage health check)
        let mut storage_health = HashMap::new();
        storage_health.insert("aws".to_string(), true);
        storage_health.insert("cloudflare".to_string(), true);
        storage_health.insert("memory".to_string(), true);

        // Determine overall status
        let status = if storage_health.values().all(|&v| v) {
            ServiceStatus::Healthy
        } else if storage_health.values().any(|&v| v) {
            ServiceStatus::Degraded
        } else {
            ServiceStatus::Unhealthy
        };

        HealthStatus {
            status,
            uptime: self.start_time.elapsed(),
            last_activity,
            active_sessions,
            storage_health,
        }
    }
}

// Alert manager for critical events
pub struct AlertManager {
    alerts: Arc<RwLock<Vec<Alert>>>,
    webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertManager {
    pub fn new(webhook_url: Option<String>) -> Self {
        AlertManager {
            alerts: Arc::new(RwLock::new(Vec::new())),
            webhook_url,
        }
    }

    pub async fn send_alert(&self, severity: AlertSeverity, message: String) {
        let alert = Alert {
            severity: severity.clone(),
            message: message.clone(),
            timestamp: Utc::now(),
            resolved: false,
        };

        let mut alerts = self.alerts.write().await;
        alerts.push(alert.clone());

        match severity {
            AlertSeverity::Critical => {
                error!(message = %message, "Critical alert");
                if let Some(url) = &self.webhook_url {
                    self.send_webhook(url, &alert).await;
                }
            }
            AlertSeverity::Warning => warn!(message = %message, "Warning alert"),
            AlertSeverity::Info => info!(message = %message, "Info alert"),
        }
    }

    async fn send_webhook(&self, url: &str, _alert: &Alert) {
        // TODO: need to implement webhook notification
        info!(webhook_url = url, "Sending alert to webhook");
    }

    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.alerts
            .read()
            .await
            .iter()
            .filter(|a| !a.resolved)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        let mut labels = HashMap::new();
        labels.insert("test".to_string(), "value".to_string());

        collector.record_metric("test_metric", 42.0, labels).await;

        let summary = collector.get_metrics_summary().await;
        assert!(summary.contains_key("test_metric"));
        assert_eq!(summary["test_metric"].value, 42.0);
    }

    #[tokio::test]
    async fn test_audit_events() {
        let collector = MetricsCollector::new();

        let event = AuditEvent {
            event_type: EventType::DkgStarted,
            participant_id: Some(1),
            timestamp: Utc::now(),
            details: "Test DKG".to_string(),
            success: true,
        };

        collector.record_event(event).await;

        let log = collector.get_audit_log(Some(10)).await;
        assert_eq!(log.len(), 1);
    }

    #[tokio::test]
    async fn test_health_monitor() {
        let monitor = HealthMonitor::new();

        monitor.increment_sessions().await;
        monitor.update_activity().await;

        let status = monitor.get_health_status().await;
        assert_eq!(status.active_sessions, 1);
        assert!(matches!(status.status, ServiceStatus::Healthy));
    }
}
