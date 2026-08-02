"""Text output formatter"""

from tabulate import tabulate
from engin33r.core.vulnerability import VulnerabilityReport, VulnerabilitySeverity
from engin33r.formatters.base import Formatter


class TextFormatter(Formatter):
    """Formats vulnerability reports as human-readable text"""

    def format_report(self, report: VulnerabilityReport) -> str:
        """
        Format report as text

        Args:
            report: Report to format

        Returns:
            Formatted text string
        """
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append(f"Vulnerability Report: {report.title}")
        lines.append(f"Generated: {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        lines.append("")

        # Summary
        if report.summary:
            lines.append("SUMMARY")
            lines.append("-" * 80)
            lines.append(report.summary)
            lines.append("")

        # Metrics
        lines.append("STATISTICS")
        lines.append("-" * 80)
        stats = report.metrics
        lines.append(f"Total Vulnerabilities: {stats.get('total', 0)}")
        lines.append(f"  Critical: {stats.get('critical', 0)}")
        lines.append(f"  High:     {stats.get('high', 0)}")
        lines.append(f"  Medium:   {stats.get('medium', 0)}")
        lines.append(f"  Low:      {stats.get('low', 0)}")
        lines.append(f"  Info:     {stats.get('info', 0)}")
        lines.append("")

        # Vulnerabilities table
        if report.vulnerabilities:
            lines.append("VULNERABILITIES")
            lines.append("-" * 80)

            # Sort by severity
            severity_order = {
                VulnerabilitySeverity.CRITICAL: 0,
                VulnerabilitySeverity.HIGH: 1,
                VulnerabilitySeverity.MEDIUM: 2,
                VulnerabilitySeverity.LOW: 3,
                VulnerabilitySeverity.INFO: 4,
            }

            sorted_vulns = sorted(
                report.vulnerabilities, key=lambda v: severity_order.get(v.severity, 5)
            )

            table_data = []
            for vuln in sorted_vulns:
                table_data.append(
                    [
                        vuln.id[:8],
                        vuln.severity.upper(),
                        vuln.vulnerability_type,
                        vuln.title[:40],
                        vuln.remediation_status,
                    ]
                )

            lines.append(
                tabulate(
                    table_data,
                    headers=["ID", "SEVERITY", "TYPE", "TITLE", "STATUS"],
                    tablefmt="grid",
                )
            )
            lines.append("")

            # Detailed view
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 80)
            for vuln in sorted_vulns:
                lines.append(f"\n[{vuln.severity.upper()}] {vuln.title}")
                lines.append(f"ID: {vuln.id}")
                lines.append(f"Type: {vuln.vulnerability_type}")
                lines.append(f"Description: {vuln.description}")

                if vuln.file_path:
                    lines.append(f"File: {vuln.file_path}")
                if vuln.line_number:
                    lines.append(f"Line: {vuln.line_number}")
                if vuln.code_snippet:
                    lines.append(f"Code: {vuln.code_snippet}")

                if vuln.remediation_guidance:
                    lines.append(f"Remediation: {vuln.remediation_guidance}")

                if vuln.references:
                    lines.append(f"References: {', '.join(vuln.references)}")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)
