"""Main vulnerability analysis engine"""

from typing import List, Dict, Any, Optional, Type
from datetime import datetime
import logging

from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilityReport,
    VulnerabilitySeverity,
)
from engin33r.analyzers.base import VulnerabilityAnalyzer

logger = logging.getLogger(__name__)


class VulnerabilityEngine:
    """Main engine for vulnerability detection and analysis"""

    def __init__(self, name: str = "engin33r"):
        self.name = name
        self.analyzers: List[VulnerabilityAnalyzer] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.reports: List[VulnerabilityReport] = []

    def register_analyzer(self, analyzer: VulnerabilityAnalyzer) -> None:
        """Register a vulnerability analyzer"""
        if analyzer not in self.analyzers:
            self.analyzers.append(analyzer)
            logger.info(f"Registered analyzer: {analyzer.name}")

    def register_analyzers(self, analyzers: List[VulnerabilityAnalyzer]) -> None:
        """Register multiple analyzers"""
        for analyzer in analyzers:
            self.register_analyzer(analyzer)

    def unregister_analyzer(self, analyzer: VulnerabilityAnalyzer) -> None:
        """Unregister an analyzer"""
        if analyzer in self.analyzers:
            self.analyzers.remove(analyzer)
            logger.info(f"Unregistered analyzer: {analyzer.name}")

    def scan(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Run all registered analyzers against a target

        Args:
            target: Target to analyze (file path, URL, code, etc.)
            context: Additional context for analysis

        Returns:
            List of discovered vulnerabilities
        """
        discovered = []
        context = context or {}

        logger.info(f"Starting vulnerability scan on target: {target}")

        for analyzer in self.analyzers:
            try:
                logger.info(f"Running analyzer: {analyzer.name}")
                vulns = analyzer.analyze(target, context)
                discovered.extend(vulns)
                logger.info(
                    f"Analyzer {analyzer.name} found {len(vulns)} vulnerabilities"
                )
            except Exception as e:
                logger.error(f"Error in analyzer {analyzer.name}: {str(e)}")

        self.vulnerabilities.extend(discovered)
        return discovered

    def generate_report(
        self,
        title: str = "Vulnerability Report",
        vulnerabilities: Optional[List[Vulnerability]] = None,
    ) -> VulnerabilityReport:
        """
        Generate a vulnerability report

        Args:
            title: Report title
            vulnerabilities: Vulnerabilities to include (uses all if None)

        Returns:
            VulnerabilityReport
        """
        report = VulnerabilityReport(title=title)

        vulns_to_report = vulnerabilities or self.vulnerabilities
        for vuln in vulns_to_report:
            report.add_vulnerability(vuln)

        report.metrics = report.get_statistics()
        logger.info(
            f"Generated report '{title}' with {len(vulns_to_report)} vulnerabilities"
        )

        self.reports.append(report)
        return report

    def filter_vulnerabilities(
        self,
        severity: Optional[VulnerabilitySeverity] = None,
        vuln_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Vulnerability]:
        """
        Filter vulnerabilities by criteria

        Args:
            severity: Filter by severity level
            vuln_type: Filter by vulnerability type
            status: Filter by remediation status

        Returns:
            Filtered list of vulnerabilities
        """
        filtered = self.vulnerabilities

        if severity:
            filtered = [v for v in filtered if v.severity == severity]
        if vuln_type:
            filtered = [v for v in filtered if v.vulnerability_type == vuln_type]
        if status:
            filtered = [v for v in filtered if v.remediation_status == status]

        return filtered

    def get_summary(self) -> Dict[str, Any]:
        """Get engine summary statistics"""
        critical = sum(
            1
            for v in self.vulnerabilities
            if v.severity == VulnerabilitySeverity.CRITICAL
        )
        high = sum(
            1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH
        )

        return {
            "engine_name": self.name,
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical_count": critical,
            "high_count": high,
            "registered_analyzers": len(self.analyzers),
            "generated_reports": len(self.reports),
        }

    def clear_vulnerabilities(self) -> None:
        """Clear all discovered vulnerabilities"""
        self.vulnerabilities.clear()
        logger.info("Cleared all vulnerabilities")
