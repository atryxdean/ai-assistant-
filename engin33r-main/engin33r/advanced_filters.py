"""Advanced filtering and querying system"""

from typing import List, Callable, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from engin33r.core.vulnerability import Vulnerability, VulnerabilitySeverity


class AdvancedFilter:
    """Advanced vulnerability filtering with complex queries"""

    def __init__(self, vulnerabilities: List[Vulnerability]):
        self.vulnerabilities = vulnerabilities

    def by_severity_range(
        self, min_severity: int, max_severity: int
    ) -> List[Vulnerability]:
        """
        Filter by CVSS score range
        """
        return [
            v
            for v in self.vulnerabilities
            if min_severity <= (v.cvss_score or v.severity.score) <= max_severity
        ]

    def by_severity_level(self, levels: List[str]) -> List[Vulnerability]:
        """
        Filter by severity levels
        """
        return [v for v in self.vulnerabilities if v.severity.value in levels]

    def by_remediation_effort(self, effort: str) -> List[Vulnerability]:
        """
        Filter by remediation effort
        """
        return [v for v in self.vulnerabilities if v.remediation_effort == effort]

    def by_affected_component(self, component: str) -> List[Vulnerability]:
        """
        Filter by affected component
        """
        return [v for v in self.vulnerabilities if component in v.affected_components]

    def by_recent(self, days: int) -> List[Vulnerability]:
        """
        Filter vulnerabilities discovered in last N days
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        return [v for v in self.vulnerabilities if v.discovered_date >= cutoff]

    def by_remediation_deadline(self, days_until: int = 7) -> List[Vulnerability]:
        """
        Filter vulnerabilities with approaching deadlines
        """
        cutoff = datetime.utcnow() + timedelta(days=days_until)
        return [
            v
            for v in self.vulnerabilities
            if v.remediation_deadline and v.remediation_deadline <= cutoff
        ]

    def by_status(self, status: str) -> List[Vulnerability]:
        """
        Filter by remediation status
        """
        return [v for v in self.vulnerabilities if v.remediation_status.value == status]

    def by_file_path(self, pattern: str) -> List[Vulnerability]:
        """
        Filter by file path pattern
        """
        import re

        regex = re.compile(pattern)
        return [
            v for v in self.vulnerabilities if v.file_path and regex.search(v.file_path)
        ]

    def by_type(self, vuln_type: str) -> List[Vulnerability]:
        """
        Filter by vulnerability type
        """
        return [
            v for v in self.vulnerabilities if v.vulnerability_type.value == vuln_type
        ]

    def by_exploit_availability(self, exploitable: bool = True) -> List[Vulnerability]:
        """
        Filter by known exploit availability
        """
        return [
            v
            for v in self.vulnerabilities
            if ("exploit" in str(v.evidence).lower()) == exploitable
        ]

    def complex_query(
        self, query_func: Callable[[Vulnerability], bool]
    ) -> List[Vulnerability]:
        """
        Execute complex filter using custom function
        """
        return [v for v in self.vulnerabilities if query_func(v)]

    def group_by_type(self) -> Dict[str, List[Vulnerability]]:
        """
        Group vulnerabilities by type
        """
        grouped: Dict[str, List[Vulnerability]] = {}
        for v in self.vulnerabilities:
            vuln_type = v.vulnerability_type.value
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(v)
        return grouped

    def group_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """
        Group vulnerabilities by severity
        """
        grouped: Dict[str, List[Vulnerability]] = {}
        for v in self.vulnerabilities:
            severity = v.severity.value
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(v)
        return grouped

    def group_by_component(self) -> Dict[str, List[Vulnerability]]:
        """
        Group vulnerabilities by affected component
        """
        grouped: Dict[str, List[Vulnerability]] = {}
        for v in self.vulnerabilities:
            for component in v.affected_components:
                if component not in grouped:
                    grouped[component] = []
                grouped[component].append(v)
        return grouped

    def group_by_file(self) -> Dict[str, List[Vulnerability]]:
        """
        Group vulnerabilities by file path
        """
        grouped: Dict[str, List[Vulnerability]] = {}
        for v in self.vulnerabilities:
            file_path = v.file_path or "unknown"
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(v)
        return grouped

    def sort_by_risk(self, reverse: bool = True) -> List[Vulnerability]:
        """
        Sort vulnerabilities by risk score (highest first)
        """
        return sorted(
            self.vulnerabilities, key=lambda v: v.get_risk_score(), reverse=reverse
        )

    def sort_by_severity(self, reverse: bool = True) -> List[Vulnerability]:
        """
        Sort by severity level
        """
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return sorted(
            self.vulnerabilities,
            key=lambda v: severity_order.get(v.severity.value, 0),
            reverse=reverse,
        )

    def sort_by_remediation_effort(self) -> List[Vulnerability]:
        """
        Sort by remediation effort (easiest first)
        """
        effort_order = {"low": 1, "medium": 2, "high": 3, None: 4}
        return sorted(
            self.vulnerabilities,
            key=lambda v: effort_order.get(v.remediation_effort, 4),
        )

    def sort_by_deadline(self) -> List[Vulnerability]:
        """
        Sort by remediation deadline (earliest first)
        """
        return sorted(
            self.vulnerabilities, key=lambda v: v.remediation_deadline or datetime.max
        )

    def deduplicate(self) -> List[Vulnerability]:
        """
        Remove duplicate vulnerabilities (same type in same file)
        """
        seen: Set[tuple] = set()
        unique = []

        for v in self.vulnerabilities:
            key = (v.file_path, v.vulnerability_type.value, v.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return unique

    def get_stats(self) -> Dict[str, Any]:
        """
        Get filtering statistics
        """
        return {
            "total": len(self.vulnerabilities),
            "by_severity": self._count_by_severity(),
            "by_type": self._count_by_type(),
            "by_status": self._count_by_status(),
            "high_risk": len(self.by_severity_range(7, 10)),
            "medium_risk": len(self.by_severity_range(4, 6)),
            "low_risk": len(self.by_severity_range(0, 3)),
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            severity = v.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type"""
        counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            vuln_type = v.vulnerability_type.value
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts

    def _count_by_status(self) -> Dict[str, int]:
        """Count vulnerabilities by status"""
        counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            status = v.remediation_status.value
            counts[status] = counts.get(status, 0) + 1
        return counts
