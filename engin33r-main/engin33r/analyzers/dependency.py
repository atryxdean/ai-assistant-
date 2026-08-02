"""Dependency vulnerability analyzer"""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path

from engin33r.analyzers.base import VulnerabilityAnalyzer
from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
    RemediationStatus,
)


class DependencyAnalyzer(VulnerabilityAnalyzer):
    """Detects vulnerabilities in project dependencies"""

    # Known vulnerable dependency versions (example database)
    KNOWN_VULNS = {
        "lodash": {
            "<4.17.21": {
                "severity": VulnerabilitySeverity.HIGH,
                "cve": "CVE-2021-23337",
                "description": "Prototype pollution vulnerability in lodash",
            }
        },
        "django": {
            "<3.2.13": {
                "severity": VulnerabilitySeverity.MEDIUM,
                "cve": "CVE-2022-22818",
                "description": "SQL Injection vulnerability in Django ORM",
            }
        },
        "requests": {
            "<2.27.0": {
                "severity": VulnerabilitySeverity.LOW,
                "description": "Potential security issue in requests library",
            }
        },
    }

    def __init__(self):
        super().__init__(
            name="DependencyAnalyzer",
            description="Analyzes project dependencies for known vulnerabilities",
        )

    def analyze(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Analyze dependencies for vulnerabilities

        Args:
            target: Path to requirements file or package.json
            context: Additional context

        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        dependencies = self._parse_dependencies(target)

        for dep_name, version in dependencies.items():
            vulns = self._check_known_vulns(dep_name, version)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _parse_dependencies(self, target: str) -> Dict[str, str]:
        """Parse dependencies from various formats"""
        dependencies = {}

        try:
            path = Path(target)
            if path.name == "package.json":
                data = json.loads(path.read_text())
                deps = data.get("dependencies", {})
                deps.update(data.get("devDependencies", {}))
                return deps
            elif path.name == "requirements.txt":
                for line in path.read_text().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "==" in line:
                            name, version = line.split("==")
                            dependencies[name.strip()] = version.strip()
                        elif ">=" in line:
                            name, version = line.split(">=")
                            dependencies[name.strip()] = version.strip()
        except Exception:
            pass

        return dependencies

    def _check_known_vulns(
        self, package_name: str, version: str
    ) -> List[Vulnerability]:
        """Check if a package/version has known vulnerabilities"""
        vulnerabilities = []

        if package_name not in self.KNOWN_VULNS:
            return vulnerabilities

        known = self.KNOWN_VULNS[package_name]
        for vuln_version, details in known.items():
            if self._version_matches(version, vuln_version):
                vuln = Vulnerability(
                    title=f"Known Vulnerability in {package_name}",
                    description=details.get(
                        "description",
                        f"Known vulnerability in {package_name} {version}",
                    ),
                    vulnerability_type=VulnerabilityType.DEPENDENCY_VULNERABILITY,
                    severity=details.get("severity", VulnerabilitySeverity.MEDIUM),
                    cve_id=details.get("cve"),
                    remediation_status=RemediationStatus.OPEN,
                    affected_components=[package_name],
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _version_matches(self, current: str, constraint: str) -> bool:
        """Simple version matching (simplified)"""
        # This is a simplified version comparison
        if constraint.startswith("<"):
            try:
                constraint_version = constraint[1:].strip()
                return current < constraint_version
            except Exception:
                return False
        return False
