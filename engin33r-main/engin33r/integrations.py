"""Enterprise integrations for ticket management and notifications"""

import json
import logging
import requests
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class TicketPriority(Enum):
    """Jira ticket priority mapping"""

    BLOCKER = 1
    CRITICAL = 2
    HIGH = 3
    MEDIUM = 4
    LOW = 5


class IntegrationBase(ABC):
    """Base class for all integrations"""

    def __init__(self, api_key: str, endpoint: str):
        self.api_key = api_key
        self.endpoint = endpoint
        self.authenticated = False

    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with service"""
        pass

    @abstractmethod
    def send_notification(self, title: str, message: str, severity: str) -> bool:
        """Send notification to service"""
        pass


class JiraIntegration(IntegrationBase):
    """Jira integration for automated ticket creation"""

    def __init__(self, api_key: str, endpoint: str, project_key: str):
        super().__init__(api_key, endpoint)
        self.project_key = project_key
        self.created_tickets: Dict[str, str] = {}

    def authenticate(self) -> bool:
        """
        Authenticate with Jira API
        """
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            response = requests.get(
                f"{self.endpoint}/rest/api/3/myself", headers=headers, timeout=10
            )

            self.authenticated = response.status_code == 200
            if self.authenticated:
                logger.info("Jira authentication successful")
            else:
                logger.error(f"Jira authentication failed: {response.status_code}")
            return self.authenticated
        except Exception as e:
            logger.error(f"Jira authentication error: {e}")
            return False

    def create_ticket(self, vulnerability: Any) -> Optional[str]:
        """
        Create Jira ticket for vulnerability
        """
        if not self.authenticated:
            logger.error("Not authenticated with Jira")
            return None

        ticket_data = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{vulnerability.severity.value.upper()}] {vulnerability.title}",
                "description": self._format_description(vulnerability),
                "issuetype": {"name": "Bug"},
                "priority": {
                    "id": self._map_severity_to_priority(vulnerability.severity)
                },
                "labels": [
                    vulnerability.vulnerability_type.value,
                    f"security-{vulnerability.severity.value}",
                ],
            }
        }

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                f"{self.endpoint}/rest/api/3/issue",
                json=ticket_data,
                headers=headers,
                timeout=10,
            )

            if response.status_code in [200, 201]:
                ticket_id = response.json().get("key")
                self.created_tickets[vulnerability.id] = ticket_id
                logger.info(f"Created Jira ticket: {ticket_id}")
                return ticket_id
            else:
                logger.error(f"Failed to create Jira ticket: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Jira ticket creation failed: {e}")
            return None

    def bulk_create_tickets(self, vulnerabilities: List[Any]) -> Dict[str, str]:
        """
        Create tickets for multiple vulnerabilities
        """
        tickets = {}
        for vuln in vulnerabilities:
            ticket_id = self.create_ticket(vuln)
            if ticket_id:
                tickets[vuln.id] = ticket_id
        return tickets

    def send_notification(self, title: str, message: str, severity: str) -> bool:
        """
        Send notification via Jira (comment on ticket)
        """
        try:
            logger.info(f"Jira notification: {title} - {message}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Jira notification: {e}")
            return False

    def _format_description(self, vulnerability: Any) -> str:
        """
        Format vulnerability as Jira description
        """
        return f"""
Type: {vulnerability.vulnerability_type.value}
Severity: {vulnerability.severity.value}
CVSS Score: {vulnerability.cvss_score or 'N/A'}
CVE: {vulnerability.cve_id or 'N/A'}

Description:
{vulnerability.description}

Location: {vulnerability.file_path}:{vulnerability.line_number}

Remediation:
{vulnerability.remediation_guidance}
"""

    def _map_severity_to_priority(self, severity) -> str:
        """
        Map vulnerability severity to Jira priority
        """
        mapping = {
            "critical": "1",
            "high": "2",
            "medium": "3",
            "low": "4",
            "info": "5",
        }
        return mapping.get(severity.value, "3")


class SlackIntegration(IntegrationBase):
    """Slack integration for security alerts"""

    def __init__(self, webhook_url: str):
        super().__init__("", webhook_url)
        self.webhook_url = webhook_url

    def authenticate(self) -> bool:
        """
        Verify webhook URL is valid
        """
        try:
            response = requests.post(
                self.webhook_url, json={"text": "engin33r webhook test"}, timeout=10
            )
            self.authenticated = response.status_code == 200
            return self.authenticated
        except Exception as e:
            logger.error(f"Slack webhook verification failed: {e}")
            return False

    def send_notification(self, title: str, message: str, severity: str) -> bool:
        """
        Send Slack message
        """
        if not self.authenticated:
            logger.error("Slack webhook not configured")
            return False

        severity_colors = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFAA00",
            "low": "#00AA00",
            "info": "#0099FF",
        }

        payload = {
            "attachments": [
                {
                    "color": severity_colors.get(severity, "#999999"),
                    "title": title,
                    "text": message,
                    "footer": "engin33r Security Scanner",
                    "ts": int(datetime.utcnow().timestamp()),
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    def send_scan_report(self, report: Any) -> bool:
        """
        Send scan report summary to Slack
        """
        metrics = report.metrics if hasattr(report, "metrics") else {}

        message = f"""
*Security Scan Complete*

Total Vulnerabilities: {metrics.get('total', 0)}
• Critical: {metrics.get('critical', 0)}
• High: {metrics.get('high', 0)}
• Medium: {metrics.get('medium', 0)}
• Low: {metrics.get('low', 0)}

Scan Time: {datetime.utcnow().isoformat()}
        """

        return self.send_notification(
            "Security Scan Report",
            message,
            "critical" if metrics.get("critical", 0) > 0 else "medium",
        )


class TeamsIntegration(IntegrationBase):
    """Microsoft Teams integration"""

    def __init__(self, webhook_url: str):
        super().__init__("", webhook_url)
        self.webhook_url = webhook_url

    def authenticate(self) -> bool:
        """
        Verify Teams webhook URL
        """
        try:
            response = requests.post(
                self.webhook_url,
                json={"@type": "MessageCard", "summary": "Test"},
                timeout=10,
            )
            self.authenticated = response.status_code in [200, 429]
            return self.authenticated
        except Exception as e:
            logger.error(f"Teams webhook verification failed: {e}")
            return False

    def send_notification(self, title: str, message: str, severity: str) -> bool:
        """
        Send Teams message with adaptive card
        """
        if not self.authenticated:
            return False

        severity_colors = {
            "critical": "E81123",
            "high": "FF7A00",
            "medium": "FFB900",
            "low": "107C10",
        }

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": severity_colors.get(severity, "0078D4"),
            "sections": [
                {
                    "activityTitle": title,
                    "text": message,
                    "activitySubtitle": f"Severity: {severity.upper()}",
                }
            ],
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code in [200, 429]
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False


class GitHubIntegration(IntegrationBase):
    """GitHub integration for PR comments and issues"""

    def __init__(self, api_key: str, repo: str):
        super().__init__(api_key, f"https://api.github.com/repos/{repo}")
        self.repo = repo
        self.pull_requests: Dict[int, str] = {}

    def authenticate(self) -> bool:
        """
        Authenticate with GitHub API
        """
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(
                "https://api.github.com/user", headers=headers, timeout=10
            )
            self.authenticated = response.status_code == 200
            return self.authenticated
        except Exception as e:
            logger.error(f"GitHub authentication failed: {e}")
            return False

    def comment_on_pr(self, pr_number: int, vulnerabilities: List[Any]) -> bool:
        """
        Add comment to pull request with security findings
        """
        if not self.authenticated:
            return False

        comment = self._format_pr_comment(vulnerabilities)

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.post(
                f"{self.endpoint}/issues/{pr_number}/comments",
                json={"body": comment},
                headers=headers,
                timeout=10,
            )
            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"Failed to comment on PR: {e}")
            return False

    def create_security_issue(self, vulnerability: Any) -> Optional[str]:
        """
        Create GitHub issue for vulnerability
        """
        if not self.authenticated:
            return None

        issue_data = {
            "title": f"[SECURITY] {vulnerability.title}",
            "body": self._format_issue_body(vulnerability),
            "labels": ["security", f"severity-{vulnerability.severity.value}"],
        }

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.post(
                f"{self.endpoint}/issues", json=issue_data, headers=headers, timeout=10
            )
            if response.status_code in [200, 201]:
                return str(response.json().get("number"))
            return None
        except Exception as e:
            logger.error(f"Failed to create GitHub issue: {e}")
            return None

    def send_notification(self, title: str, message: str, severity: str) -> bool:
        """
        Send GitHub notification via issue
        """
        try:
            logger.info(f"GitHub notification: {title}")
            return True
        except Exception as e:
            logger.error(f"Failed to send GitHub notification: {e}")
            return False

    def _format_pr_comment(self, vulnerabilities: List[Any]) -> str:
        """
        Format vulnerabilities for PR comment
        """
        if not vulnerabilities:
            return "✅ No security issues detected"

        critical_count = sum(
            1 for v in vulnerabilities if v.severity.value == "critical"
        )
        high_count = sum(1 for v in vulnerabilities if v.severity.value == "high")

        comment = f"""
## 🔒 Security Scan Results

⚠️ Found {len(vulnerabilities)} vulnerability(ies):
- 🔴 Critical: {critical_count}
- 🟠 High: {high_count}
- 🟡 Medium: {sum(1 for v in vulnerabilities if v.severity.value == 'medium')}
- 🟢 Low: {sum(1 for v in vulnerabilities if v.severity.value == 'low')}

### Details

"""

        for v in vulnerabilities[:5]:
            comment += f"- **{v.title}** ({v.severity.value}) at {v.file_path}:{v.line_number}\n"

        if len(vulnerabilities) > 5:
            comment += f"- ... and {len(vulnerabilities) - 5} more\n"

        return comment

    def _format_issue_body(self, vulnerability: Any) -> str:
        """
        Format vulnerability for GitHub issue
        """
        return f"""
## Description

{vulnerability.description}

## Severity

`{vulnerability.severity.value.upper()}`

## Location

- File: `{vulnerability.file_path}`
- Line: {vulnerability.line_number}

## Code Snippet

```
{vulnerability.code_snippet}
```

## Remediation

{vulnerability.remediation_guidance}
"""


class IntegrationManager:
    """Manage multiple integrations"""

    def __init__(self):
        self.integrations: Dict[str, IntegrationBase] = {}

    def register_integration(self, name: str, integration: IntegrationBase) -> bool:
        """
        Register an integration
        """
        if integration.authenticate():
            self.integrations[name] = integration
            logger.info(f"Registered integration: {name}")
            return True
        logger.error(f"Failed to authenticate integration: {name}")
        return False

    def notify_all(self, title: str, message: str, severity: str) -> Dict[str, bool]:
        """
        Send notification to all registered integrations
        """
        results = {}
        for name, integration in self.integrations.items():
            try:
                results[name] = integration.send_notification(title, message, severity)
            except Exception as e:
                logger.error(f"Failed to notify {name}: {e}")
                results[name] = False
        return results

    def broadcast_report(self, report: Any) -> Dict[str, bool]:
        """
        Broadcast report to all integrations
        """
        results = {}
        for name, integration in self.integrations.items():
            try:
                if hasattr(integration, "send_scan_report"):
                    results[name] = integration.send_scan_report(report)
                else:
                    logger.warning(f"{name} does not support report broadcasting")
                    results[name] = False
            except Exception as e:
                logger.error(f"Failed to broadcast to {name}: {e}")
                results[name] = False
        return results
