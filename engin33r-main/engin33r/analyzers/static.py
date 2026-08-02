"""Static code analysis vulnerability detector"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from engin33r.analyzers.base import VulnerabilityAnalyzer
from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
    RemediationStatus,
)


class StaticAnalyzer(VulnerabilityAnalyzer):
    """Detects vulnerabilities through static code analysis"""

    # Pattern definitions for common vulnerabilities
    PATTERNS = {
        "sql_injection": [
            r"query\s*\(.*\+.*variable",
            r"execute\s*\(\s*['\"].*\{.*\}",
            r"SELECT.*FROM.*WHERE.*=.*\+",
        ],
        "hardcoded_secrets": [
            r"(password|api_key|secret|token)\s*=\s*['\"]([a-zA-Z0-9_]+)['\"]",
            r"(AWS_SECRET|PRIVATE_KEY|DATABASE_PASSWORD)\s*=\s*['\"].*['\"]",
        ],
        "xss": [
            r"innerHTML\s*=\s*",
            r"document\.write\s*\(",
            r"eval\s*\(",
        ],
        "unsafe_deserialization": [
            r"pickle\.loads",
            r"yaml\.load\s*\(",
            r"json\.loads.*unsafe",
        ],
        "weak_crypto": [
            r"md5\(",
            r"sha1\(",
            r"DES\(",
            r"rc4\(",
        ],
    }

    def __init__(self):
        super().__init__(
            name="StaticAnalyzer",
            description="Static code analysis for common vulnerabilities",
        )

    def analyze(
        self, target: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Vulnerability]:
        """
        Analyze code for vulnerabilities

        Args:
            target: File path or code string
            context: Additional context

        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        context = context or {}

        # Try to read as file first
        code_content = None
        file_path = None

        try:
            path = Path(target)
            if path.is_file():
                code_content = path.read_text(encoding="utf-8", errors="ignore")
                file_path = str(path)
            else:
                code_content = target
        except (OSError, ValueError):
            # Treat invalid paths as code strings
            code_content = target

        if not code_content:
            return vulnerabilities

        # Scan for each vulnerability pattern
        for vuln_type, patterns in self.PATTERNS.items():
            for line_num, line in enumerate(code_content.split("\n"), 1):
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = self._create_vulnerability(
                            vuln_type=vuln_type,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            file_path=file_path,
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _create_vulnerability(
        self,
        vuln_type: str,
        line_number: int,
        code_snippet: str,
        file_path: Optional[str] = None,
    ) -> Vulnerability:
        """Create a Vulnerability object from detected issue"""

        # Map vuln type to classification
        type_map = {
            "sql_injection": VulnerabilityType.INJECTION,
            "hardcoded_secrets": VulnerabilityType.SENSITIVE_DATA,
            "xss": VulnerabilityType.XSS,
            "unsafe_deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
            "weak_crypto": VulnerabilityType.CRYPTOGRAPHIC,
        }

        severity_map = {
            "sql_injection": VulnerabilitySeverity.CRITICAL,
            "hardcoded_secrets": VulnerabilitySeverity.HIGH,
            "xss": VulnerabilitySeverity.HIGH,
            "unsafe_deserialization": VulnerabilitySeverity.HIGH,
            "weak_crypto": VulnerabilitySeverity.MEDIUM,
        }

        return Vulnerability(
            title=f"Potential {vuln_type.replace('_', ' ').title()}",
            description=f"Detected potential {vuln_type} vulnerability",
            vulnerability_type=type_map.get(vuln_type, VulnerabilityType.LOGIC_ERROR),
            severity=severity_map.get(vuln_type, VulnerabilitySeverity.MEDIUM),
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            remediation_status=RemediationStatus.OPEN,
        )
