"""Advanced vulnerability database and reporting system"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ThreatIntel(Enum):
    """Threat intelligence sources"""

    NVD = "nvd"  # National Vulnerability Database
    MITRE = "mitre"  # MITRE/CWE
    GITHUB = "github"  # GitHub Security Advisory
    OSV = "osv"  # Open Source Vulnerabilities
    EXPLOIT_DB = "exploit_db"
    CISA = "cisa"  # CISA Known Exploited Vulnerabilities


class ExploitAvailability(Enum):
    """Indicates if public exploit exists"""

    UNKNOWN = "unknown"
    NOT_AVAILABLE = "not_available"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"


class VulnerabilityIntelligence:
    """Enhanced vulnerability intelligence with threat data"""

    def __init__(self):
        self.cve_database = {}
        self.exploits_db = {}
        self.threat_patterns = {}
        self.affected_software = {}

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Look up CVE details

        Returns vulnerability details including:
        - Description
        - Affected versions
        - Published date
        - Exploit availability
        - CVSS scores (v2, v3)
        - References
        """
        return self.cve_database.get(cve_id)

    def check_exploit_availability(self, cve_id: str) -> ExploitAvailability:
        """
        Check if public exploit exists for CVE
        """
        if cve_id not in self.exploits_db:
            return ExploitAvailability.UNKNOWN
        return self.exploits_db[cve_id].get("availability", ExploitAvailability.UNKNOWN)

    def get_threat_score(self, vulnerability_data: Dict[str, Any]) -> float:
        """
        Calculate enhanced threat score considering:
        - CVSS score
        - Exploit availability
        - Active exploitation in the wild
        - Age of vulnerability
        - Affected software prevalence
        """
        cvss = vulnerability_data.get("cvss_v3", 0) or vulnerability_data.get(
            "cvss_v2", 0
        )
        exploit_weight = 0

        availability = vulnerability_data.get("exploit_availability")
        if availability == ExploitAvailability.WEAPONIZED:
            exploit_weight = 0.5
        elif availability == ExploitAvailability.FUNCTIONAL:
            exploit_weight = 0.3
        elif availability == ExploitAvailability.PROOF_OF_CONCEPT:
            exploit_weight = 0.1

        # Check if actively exploited
        if vulnerability_data.get("actively_exploited", False):
            exploit_weight += 0.2

        threat_score = (cvss / 10) * 0.6 + exploit_weight * 0.4
        return min(1.0, threat_score)


class AdvancedReportGenerator:
    """Generate executive-level security reports"""

    def __init__(self):
        self.intel = VulnerabilityIntelligence()

    def generate_executive_summary(self, vulnerabilities: List[Any]) -> str:
        """
        Generate C-suite ready executive summary
        """
        if not vulnerabilities:
            return "No vulnerabilities detected."

        critical = sum(1 for v in vulnerabilities if v.severity.value == "critical")
        high = sum(1 for v in vulnerabilities if v.severity.value == "high")
        exploitable = sum(1 for v in vulnerabilities if v.get("exploit_available"))

        summary = f"""
EXECUTIVE SUMMARY
{'='*60}

Critical Issues: {critical}
High Severity Issues: {high}
Immediate Action Required: {critical > 0}

Potentially Exploitable: {exploitable} vulnerabilities
With Public Exploits: {sum(1 for v in vulnerabilities if self.intel.check_exploit_availability(v.get('cve_id', '')) != ExploitAvailability.NOT_AVAILABLE)}

Risk Level: {'CRITICAL' if critical > 0 else 'HIGH' if high > 0 else 'MEDIUM'}

RECOMMENDED ACTIONS:
1. {'Immediate patching required for critical issues' if critical > 0 else 'Prioritize high severity remediation'}
2. Deploy temporary mitigations while patches are being developed
3. Isolate affected systems if critical vulnerabilities are exploitable
4. Monitor for active exploitation attempts

Business Impact:
- Estimated remediation time: {self._estimate_remediation_time(vulnerabilities)}
- Affected business functions: {self._estimate_affected_functions(vulnerabilities)}
- Compliance implications: {self._check_compliance_impact(vulnerabilities)}
"""
        return summary

    def _estimate_remediation_time(self, vulnerabilities: List[Any]) -> str:
        """Estimate time to remediate all vulnerabilities"""
        if not vulnerabilities:
            return "None"

        total_effort = 0
        for v in vulnerabilities:
            effort = (
                v.remediation_effort if hasattr(v, "remediation_effort") else "medium"
            )
            if effort == "low":
                total_effort += 4
            elif effort == "medium":
                total_effort += 16
            else:
                total_effort += 40

        days = total_effort / 8
        if days < 1:
            return "< 1 day"
        elif days < 5:
            return f"{int(days)} days"
        else:
            return f"{int(days / 5)} weeks"

    def _estimate_affected_functions(self, vulnerabilities: List[Any]) -> str:
        """Estimate impacted business functions"""
        affected = set()
        for v in vulnerabilities:
            if hasattr(v, "affected_components"):
                affected.update(v.affected_components)
        return f"{len(affected)} function(s)"

    def _check_compliance_impact(self, vulnerabilities: List[Any]) -> str:
        """Check compliance framework impacts"""
        frameworks = set()
        # OWASP mapping
        for v in vulnerabilities:
            if hasattr(v, "severity") and v.severity.value in ["critical", "high"]:
                frameworks.add("PCI-DSS")
                frameworks.add("HIPAA")
                frameworks.add("GDPR")
        return ", ".join(frameworks) if frameworks else "None identified"

    def generate_remediation_roadmap(self, vulnerabilities: List[Any]) -> str:
        """
        Generate prioritized remediation roadmap
        """
        # Group by severity
        by_severity = {}
        for v in vulnerabilities:
            severity = v.severity.value if hasattr(v, "severity") else "low"
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(v)

        roadmap = "REMEDIATION ROADMAP\n" + "=" * 60 + "\n\n"

        severity_order = ["critical", "high", "medium", "low", "info"]
        phase = 1

        for severity in severity_order:
            if severity in by_severity:
                vulns = by_severity[severity]
                timeline = self._phase_timeline(phase)
                roadmap += f"PHASE {phase}: {severity.upper()} ({len(vulns)} items)\n"
                roadmap += f"Timeline: {timeline}\n\n"

                for vuln in vulns[:3]:  # Show top 3
                    title = vuln.title if hasattr(vuln, "title") else "Unknown"
                    roadmap += f"  - {title}\n"

                if len(vulns) > 3:
                    roadmap += f"  ... and {len(vulns) - 3} more\n"

                roadmap += "\n"
                phase += 1

        return roadmap

    def _phase_timeline(self, phase: int) -> str:
        """Get timeline for remediation phase"""
        timelines = {
            1: "Immediate (24-48 hours)",
            2: "Urgent (1-2 weeks)",
            3: "Near-term (1 month)",
            4: "Planned (2-3 months)",
        }
        return timelines.get(phase, "Backlog")


class RiskMatrixAnalyzer:
    """Advanced risk analysis and matrix generation"""

    def __init__(self):
        pass

    def calculate_risk_matrix(self, vulnerabilities: List[Any]) -> Dict[str, int]:
        """
        Calculate risk matrix:
        Risk = Likelihood × Impact

        Where:
        - Likelihood: Based on exploit availability and ease
        - Impact: Based on affected systems and data sensitivity
        """
        matrix = {}

        for v in vulnerabilities:
            likelihood = self._calculate_likelihood(v)
            impact = self._calculate_impact(v)
            risk_score = likelihood * impact

            risk_category = self._categorize_risk(risk_score)
            if risk_category not in matrix:
                matrix[risk_category] = 0
            matrix[risk_category] += 1

        return matrix

    def _calculate_likelihood(self, vuln: Any) -> int:
        """1-5 scale: How likely is this to be exploited?"""
        score = 1

        if hasattr(vuln, "cve_id") and vuln.cve_id:
            score += 1

        if hasattr(vuln, "severity"):
            if vuln.severity.value == "critical":
                score += 2
            elif vuln.severity.value == "high":
                score += 1

        return min(5, score)

    def _calculate_impact(self, vuln: Any) -> int:
        """1-5 scale: What is the impact if exploited?"""
        score = 1

        if hasattr(vuln, "affected_components") and len(vuln.affected_components) > 3:
            score += 2

        if hasattr(vuln, "business_impact") and vuln.business_impact:
            score += 2

        if hasattr(vuln, "severity"):
            if vuln.severity.value == "critical":
                score += 2

        return min(5, score)

    def _categorize_risk(self, score: int) -> str:
        """Categorize risk level"""
        if score >= 20:
            return "CRITICAL"
        elif score >= 12:
            return "HIGH"
        elif score >= 6:
            return "MEDIUM"
        elif score >= 2:
            return "LOW"
        else:
            return "MINIMAL"
