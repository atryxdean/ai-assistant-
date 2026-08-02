"""Real-time monitoring and alerting system"""

import logging
from typing import Dict, List, Callable, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels"""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class AlertAction(Enum):
    """Actions to take on alerts"""

    NOTIFY = "notify"
    CREATE_TICKET = "create_ticket"
    ESCALATE = "escalate"
    BLOCK = "block"
    QUARANTINE = "quarantine"


@dataclass
class Alert:
    """Security alert"""

    id: str
    title: str
    message: str
    level: AlertLevel
    source: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    actions_taken: List[AlertAction] = field(default_factory=list)

    def acknowledge(self) -> None:
        """Mark alert as acknowledged"""
        self.acknowledged = True


class RealTimeMonitor:
    """Real-time vulnerability monitoring"""

    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules: List["AlertRule"] = []
        self.subscribers: Dict[AlertLevel, List[Callable]] = {}
        self.alert_history: List[Alert] = []

    def register_rule(self, rule: "AlertRule") -> None:
        """
        Register an alert rule
        """
        self.alert_rules.append(rule)
        logger.info(f"Registered alert rule: {rule.name}")

    def subscribe(self, level: AlertLevel, callback: Callable) -> None:
        """
        Subscribe to alerts at specific level
        """
        if level not in self.subscribers:
            self.subscribers[level] = []
        self.subscribers[level].append(callback)

    def on_vulnerability_detected(self, vulnerability: Any) -> None:
        """
        Handle newly detected vulnerability
        """
        for rule in self.alert_rules:
            if rule.matches(vulnerability):
                alert = self._create_alert(vulnerability, rule)
                self._trigger_alert(alert)

    def _create_alert(self, vulnerability: Any, rule: "AlertRule") -> Alert:
        """
        Create alert from vulnerability and rule
        """
        alert = Alert(
            id=f"alert_{len(self.alerts)}",
            title=f"{rule.name}: {vulnerability.title}",
            message=rule.format_message(vulnerability),
            level=rule.alert_level,
            source=vulnerability.vulnerability_type.value,
        )
        self.alerts[alert.id] = alert
        self.alert_history.append(alert)
        return alert

    def _trigger_alert(self, alert: Alert) -> None:
        """
        Trigger alert and notify subscribers
        """
        logger.warning(f"Alert triggered: {alert.title}")

        for level in AlertLevel:
            if level.value <= alert.level.value:
                if level in self.subscribers:
                    for callback in self.subscribers[level]:
                        try:
                            callback(alert)
                        except Exception as e:
                            logger.error(f"Error in alert callback: {e}")

    def get_active_alerts(self) -> List[Alert]:
        """
        Get all unacknowledged alerts
        """
        return [a for a in self.alerts.values() if not a.acknowledged]

    def get_alerts_by_level(self, level: AlertLevel) -> List[Alert]:
        """
        Get alerts at specific level
        """
        return [a for a in self.alerts.values() if a.level == level]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """
        Acknowledge an alert
        """
        if alert_id in self.alerts:
            self.alerts[alert_id].acknowledge()
            return True
        return False

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics
        """
        return {
            "total": len(self.alerts),
            "active": len(self.get_active_alerts()),
            "critical": len(self.get_alerts_by_level(AlertLevel.CRITICAL)),
            "high": len(self.get_alerts_by_level(AlertLevel.HIGH)),
            "medium": len(self.get_alerts_by_level(AlertLevel.MEDIUM)),
            "acknowledged": sum(1 for a in self.alerts.values() if a.acknowledged),
        }

    def get_recent_alerts(self, minutes: int = 60) -> List[Alert]:
        """
        Get alerts from last N minutes
        """
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return [a for a in self.alert_history if a.created_at >= cutoff]


class AlertRule:
    """Rule for triggering alerts"""

    def __init__(
        self,
        name: str,
        description: str,
        match_condition: Callable[[Any], bool],
        alert_level: AlertLevel,
        recommended_action: AlertAction,
    ):
        self.name = name
        self.description = description
        self.match_condition = match_condition
        self.alert_level = alert_level
        self.recommended_action = recommended_action

    def matches(self, vulnerability: Any) -> bool:
        """
        Check if vulnerability matches rule
        """
        try:
            return self.match_condition(vulnerability)
        except Exception as e:
            logger.error(f"Error evaluating rule {self.name}: {e}")
            return False

    def format_message(self, vulnerability: Any) -> str:
        """
        Format alert message
        """
        return f"""Vulnerability: {vulnerability.title}
Type: {vulnerability.vulnerability_type.value}
Severity: {vulnerability.severity.value}
Recommended Action: {self.recommended_action.value}"""


class AlertRuleBuilder:
    """Builder for creating alert rules"""

    @staticmethod
    def critical_vulnerability() -> AlertRule:
        """Rule for critical vulnerabilities"""
        return AlertRule(
            name="Critical Vulnerability Detected",
            description="Alert on any critical severity vulnerability",
            match_condition=lambda v: v.severity.value == "critical",
            alert_level=AlertLevel.CRITICAL,
            recommended_action=AlertAction.ESCALATE,
        )

    @staticmethod
    def exploitable_vulnerability() -> AlertRule:
        """Rule for vulnerabilities with public exploits"""
        return AlertRule(
            name="Exploitable Vulnerability Found",
            description="Alert when exploitable vulnerability detected",
            match_condition=lambda v: "exploit" in str(v.evidence).lower(),
            alert_level=AlertLevel.CRITICAL,
            recommended_action=AlertAction.BLOCK,
        )

    @staticmethod
    def exposed_secrets() -> AlertRule:
        """Rule for exposed secrets"""
        return AlertRule(
            name="Exposed Secrets Detected",
            description="Alert when credentials/secrets found in code",
            match_condition=lambda v: any(
                t in v.vulnerability_type.value.lower()
                for t in ["secret", "credential", "key"]
            ),
            alert_level=AlertLevel.CRITICAL,
            recommended_action=AlertAction.QUARANTINE,
        )

    @staticmethod
    def approaching_deadline() -> AlertRule:
        """Rule for approaching remediation deadlines"""

        def check_deadline(v):
            if not v.remediation_deadline:
                return False
            days_remaining = (v.remediation_deadline - datetime.utcnow()).days
            return 0 <= days_remaining <= 7

        return AlertRule(
            name="Remediation Deadline Approaching",
            description="Alert when remediation deadline is within 7 days",
            match_condition=check_deadline,
            alert_level=AlertLevel.HIGH,
            recommended_action=AlertAction.NOTIFY,
        )

    @staticmethod
    def unpatched_dependency() -> AlertRule:
        """Rule for unpatched dependencies"""
        return AlertRule(
            name="Unpatched Dependency Detected",
            description="Alert when dependency has known vulnerabilities",
            match_condition=lambda v: "dependency"
            in v.vulnerability_type.value.lower(),
            alert_level=AlertLevel.HIGH,
            recommended_action=AlertAction.CREATE_TICKET,
        )


class TrendAnalyzer:
    """Analyze vulnerability trends over time"""

    def __init__(self):
        self.vulnerability_history: List[Dict[str, Any]] = []

    def record_scan(
        self, vulnerabilities: List[Any], timestamp: Optional[datetime] = None
    ) -> None:
        """
        Record vulnerability scan results
        """
        if timestamp is None:
            timestamp = datetime.utcnow()

        self.vulnerability_history.append(
            {
                "timestamp": timestamp,
                "total": len(vulnerabilities),
                "critical": sum(
                    1 for v in vulnerabilities if v.severity.value == "critical"
                ),
                "high": sum(1 for v in vulnerabilities if v.severity.value == "high"),
                "medium": sum(
                    1 for v in vulnerabilities if v.severity.value == "medium"
                ),
                "low": sum(1 for v in vulnerabilities if v.severity.value == "low"),
            }
        )

    def get_trend(self, days: int = 30) -> Dict[str, Any]:
        """
        Get vulnerability trend over N days
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent = [h for h in self.vulnerability_history if h["timestamp"] >= cutoff]

        if not recent:
            return {}

        return {
            "data_points": len(recent),
            "initial_total": recent[0]["total"],
            "current_total": recent[-1]["total"],
            "trend": (
                "improving" if recent[-1]["total"] < recent[0]["total"] else "worsening"
            ),
            "critical_average": sum(h["critical"] for h in recent) / len(recent),
            "high_average": sum(h["high"] for h in recent) / len(recent),
        }

    def predict_vulnerability_count(self, days_ahead: int = 30) -> Dict[str, Any]:
        """
        Predict future vulnerability count based on trends
        """
        if len(self.vulnerability_history) < 2:
            return {"prediction": "Insufficient data"}

        recent = self.vulnerability_history[-10:]

        x_values = list(range(len(recent)))
        y_values = [h["total"] for h in recent]

        avg_x = sum(x_values) / len(x_values)
        avg_y = sum(y_values) / len(y_values)

        numerator = sum(
            (x_values[i] - avg_x) * (y_values[i] - avg_y) for i in range(len(x_values))
        )
        denominator = sum((x_values[i] - avg_x) ** 2 for i in range(len(x_values)))

        slope = numerator / denominator if denominator != 0 else 0
        intercept = avg_y - slope * avg_x

        predicted = intercept + slope * (len(x_values) + days_ahead)

        return {
            "predicted_count": max(0, int(predicted)),
            "trend_direction": "decreasing" if slope < 0 else "increasing",
            "confidence": min(0.9, 0.5 + len(recent) * 0.05),
            "slope": slope,
        }

    def get_scan_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get scan history
        """
        return self.vulnerability_history[-limit:]
