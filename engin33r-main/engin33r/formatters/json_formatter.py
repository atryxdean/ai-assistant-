"""JSON output formatter"""

import json
from datetime import datetime
from engin33r.core.vulnerability import VulnerabilityReport
from engin33r.formatters.base import Formatter


class JSONFormatter(Formatter):
    """Formats vulnerability reports as JSON"""

    def format_report(self, report: VulnerabilityReport) -> str:
        """
        Format report as JSON

        Args:
            report: Report to format

        Returns:
            JSON string
        """
        report_dict = {
            "id": report.id,
            "title": report.title,
            "created_at": report.created_at.isoformat(),
            "summary": report.summary,
            "metrics": report.metrics,
            "vulnerabilities": [
                json.loads(vuln.json()) for vuln in report.vulnerabilities
            ],
        }

        return json.dumps(report_dict, indent=2, default=str)
