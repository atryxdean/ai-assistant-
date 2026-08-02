"""Specialized vulnerability detectors for advanced scanning"""

import re
import logging
import json
from typing import List, Optional, Any, Dict
from abc import ABC, abstractmethod
from pathlib import Path
from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
)

logger = logging.getLogger(__name__)


class SpecializedAnalyzerBase(ABC):
    """Base class for specialized analyzers"""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def analyze(self, target: str) -> List[Vulnerability]:
        pass


class ContainerSecurityAnalyzer(SpecializedAnalyzerBase):
    """Analyze Docker/container security"""

    def __init__(self):
        super().__init__(
            "ContainerSecurityAnalyzer", "Analyzes Docker and container security"
        )

    def analyze(self, target: str) -> List[Vulnerability]:
        if target.lower().endswith("dockerfile"):
            return self.analyze_dockerfile(target)
        return []

    def analyze_dockerfile(self, dockerfile_path: str) -> List[Vulnerability]:
        """Analyze Dockerfile for security issues"""
        vulnerabilities = []

        try:
            content = Path(dockerfile_path).read_text()
            lines = content.split("\n")

            patterns = {
                r"FROM\s+\S+:latest": ("Using latest tag", VulnerabilitySeverity.HIGH),
                r"RUN.*sudo": ("Using sudo in RUN", VulnerabilitySeverity.MEDIUM),
                r"COPY.*\.(key|pem|secret)": (
                    "Copying secrets into image",
                    VulnerabilitySeverity.CRITICAL,
                ),
                r"ENV.*PASSWORD": ("Password in ENV", VulnerabilitySeverity.HIGH),
            }

            for line_num, line in enumerate(lines, 1):
                for pattern, (title, severity) in patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = Vulnerability(
                            title=title,
                            description=f"Found in Dockerfile at line {line_num}: {line.strip()}",
                            vulnerability_type=VulnerabilityType.CONFIGURATION_ISSUE,
                            severity=severity,
                            file_path=dockerfile_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            remediation_guidance=f"Fix: {title} issue",
                        )
                        vulnerabilities.append(vuln)
        except Exception as e:
            logger.error(f"Dockerfile analysis failed: {e}")

        return vulnerabilities


class SecretsScanner(SpecializedAnalyzerBase):
    """Advanced secrets and credentials detection"""

    def __init__(self):
        super().__init__("SecretsScanner", "Detects exposed secrets and credentials")
        self.secret_patterns = {
            "api_key": r'api[_-]?key[\s=]+["\']([\w-]+)["\']',
            "aws_key": r"(AKIA[0-9A-Z]{16})",
            "private_key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "password": r'password[\s=]+["\']([^"\'+)+["\']',
            "db_connection": r"(mongodb|mysql|postgresql)://([^:]+):([^@]+)@",
        }

    def analyze(self, target: str) -> List[Vulnerability]:
        vulnerabilities = []

        try:
            if Path(target).is_file():
                vulnerabilities.extend(self.scan_file(target))
            elif Path(target).is_dir():
                for file_path in Path(target).rglob("*"):
                    if file_path.is_file() and not self._should_skip(file_path):
                        vulnerabilities.extend(self.scan_file(str(file_path)))
        except Exception as e:
            logger.error(f"Secrets scanning failed: {e}")

        return vulnerabilities

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """Scan file for secrets"""
        vulnerabilities = []

        try:
            content = Path(file_path).read_text(errors="ignore")

            for line_num, line in enumerate(content.split("\n"), 1):
                for secret_type, pattern in self.secret_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = Vulnerability(
                            title=f"Exposed {secret_type}",
                            description=f"Potential {secret_type} detected in {file_path}",
                            vulnerability_type=VulnerabilityType.SENSITIVE_DATA,
                            severity=VulnerabilitySeverity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                            remediation_guidance="Remove the secret and rotate credentials",
                        )
                        vulnerabilities.append(vuln)
        except Exception as e:
            logger.warning(f"Could not scan {file_path}: {e}")

        return vulnerabilities

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        skip_dirs = {".git", ".venv", "node_modules", "venv", "__pycache__"}
        skip_exts = {".pyc", ".o", ".so", ".bin", ".exe"}

        return (
            any(skip in file_path.parts for skip in skip_dirs)
            or file_path.suffix in skip_exts
        )


class IaCSecurityAnalyzer(SpecializedAnalyzerBase):
    """Analyze Infrastructure as Code"""

    def __init__(self):
        super().__init__(
            "IaCSecurityAnalyzer",
            "Analyzes Terraform, CloudFormation, Kubernetes for security",
        )

    def analyze(self, target: str) -> List[Vulnerability]:
        vulnerabilities = []
        target_path = Path(target)

        if target_path.suffix == ".tf":
            vulnerabilities.extend(self.analyze_terraform(target))
        elif target_path.suffix in [".yaml", ".yml"]:
            vulnerabilities.extend(self.analyze_kubernetes(target))

        return vulnerabilities

    def analyze_terraform(self, tf_file: str) -> List[Vulnerability]:
        """Analyze Terraform for security issues"""
        vulnerabilities = []

        patterns = {
            r'"publicly_accessible"\s*=\s*true': (
                "Publicly accessible resource",
                VulnerabilitySeverity.HIGH,
            ),
            r'"enable_encryption"\s*=\s*false': (
                "Encryption disabled",
                VulnerabilitySeverity.HIGH,
            ),
            r'"storage_encrypted"\s*=\s*false': (
                "Storage not encrypted",
                VulnerabilitySeverity.HIGH,
            ),
            r'"skip_final_snapshot"\s*=\s*true': (
                "Skip final snapshot",
                VulnerabilitySeverity.MEDIUM,
            ),
        }

        try:
            content = Path(tf_file).read_text()
            for line_num, line in enumerate(content.split("\n"), 1):
                for pattern, (title, severity) in patterns.items():
                    if re.search(pattern, line):
                        vuln = Vulnerability(
                            title=title,
                            description=f"Found in Terraform at line {line_num}",
                            vulnerability_type=VulnerabilityType.MISCONFIGURATION,
                            severity=severity,
                            file_path=tf_file,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            remediation_guidance=f"Fix: {title}",
                        )
                        vulnerabilities.append(vuln)
        except Exception as e:
            logger.error(f"Terraform analysis failed: {e}")

        return vulnerabilities

    def analyze_kubernetes(self, manifest_path: str) -> List[Vulnerability]:
        """Analyze Kubernetes manifests"""
        vulnerabilities = []

        try:
            content = Path(manifest_path).read_text()
            # Simple YAML analysis

            if "privileged: true" in content:
                vuln = Vulnerability(
                    title="Privileged container detected",
                    description="Container running with privilege escalation enabled",
                    vulnerability_type=VulnerabilityType.BROKEN_ACCESS,
                    severity=VulnerabilitySeverity.CRITICAL,
                    file_path=manifest_path,
                    remediation_guidance="Remove privileged: true from security context",
                )
                vulnerabilities.append(vuln)

            if "runAsRoot: true" in content or "runAsUser: 0" in content:
                vuln = Vulnerability(
                    title="Container running as root",
                    description="Container is running with root privileges",
                    vulnerability_type=VulnerabilityType.BROKEN_ACCESS,
                    severity=VulnerabilitySeverity.HIGH,
                    file_path=manifest_path,
                    remediation_guidance="Set runAsUser to non-zero value",
                )
                vulnerabilities.append(vuln)
        except Exception as e:
            logger.error(f"Kubernetes analysis failed: {e}")

        return vulnerabilities


class DataFlowAnalyzer(SpecializedAnalyzerBase):
    """Analyze data flow for security issues"""

    def __init__(self):
        super().__init__(
            "DataFlowAnalyzer", "Analyzes data flow for exposure and leaks"
        )

    def analyze(self, target: str) -> List[Vulnerability]:
        vulnerabilities = []

        try:
            content = Path(target).read_text(errors="ignore")
            vulnerabilities.extend(self.detect_information_disclosure(target, content))
        except Exception as e:
            logger.error(f"Data flow analysis failed: {e}")

        return vulnerabilities

    def detect_information_disclosure(
        self, file_path: str, content: str
    ) -> List[Vulnerability]:
        """Detect information disclosure vulnerabilities"""
        vulnerabilities = []

        patterns = {
            r"print\(.*exception.*\)": (
                "Exception in print",
                VulnerabilitySeverity.MEDIUM,
            ),
            r"logger\.debug\(.*\)": ("Debug logging", VulnerabilitySeverity.LOW),
            r"console\.log\(.*\)": (
                "Console log in production",
                VulnerabilitySeverity.LOW,
            ),
        }

        for line_num, line in enumerate(content.split("\n"), 1):
            for pattern, (title, severity) in patterns.items():
                if re.search(pattern, line):
                    vuln = Vulnerability(
                        title=f"Potential {title}",
                        description=f"Found at line {line_num}",
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        remediation_guidance="Remove or properly handle sensitive information in logs",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities
