"""Tests for the vulnerability engine"""

import pytest
from engin33r.core.engine import VulnerabilityEngine
from engin33r.core.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from engin33r.analyzers.static import StaticAnalyzer


def test_engine_initialization():
    """Test engine initialization"""
    engine = VulnerabilityEngine("test")
    assert engine.name == "test"
    assert len(engine.analyzers) == 0
    assert len(engine.vulnerabilities) == 0


def test_register_analyzer():
    """Test registering an analyzer"""
    engine = VulnerabilityEngine()
    analyzer = StaticAnalyzer()

    engine.register_analyzer(analyzer)
    assert len(engine.analyzers) == 1
    assert analyzer in engine.analyzers


def test_filter_vulnerabilities():
    """Test filtering vulnerabilities"""
    engine = VulnerabilityEngine()

    # Add test vulnerabilities
    critical_vuln = Vulnerability(
        title="Critical",
        description="Test",
        vulnerability_type=VulnerabilityType.INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
    )

    low_vuln = Vulnerability(
        title="Low",
        description="Test",
        vulnerability_type=VulnerabilityType.LOGIC_ERROR,
        severity=VulnerabilitySeverity.LOW,
    )

    engine.vulnerabilities.append(critical_vuln)
    engine.vulnerabilities.append(low_vuln)

    # Filter by severity
    critical_only = engine.filter_vulnerabilities(
        severity=VulnerabilitySeverity.CRITICAL
    )
    assert len(critical_only) == 1
    assert critical_only[0].severity == VulnerabilitySeverity.CRITICAL


def test_generate_report():
    """Test report generation"""
    engine = VulnerabilityEngine()

    vuln = Vulnerability(
        title="Test",
        description="Test vulnerability",
        vulnerability_type=VulnerabilityType.INJECTION,
        severity=VulnerabilitySeverity.HIGH,
    )

    engine.vulnerabilities.append(vuln)
    report = engine.generate_report("Test Report")

    assert report.title == "Test Report"
    assert len(report.vulnerabilities) == 1
    assert report.metrics["total"] == 1
    assert report.metrics["high"] == 1


def test_static_analyzer_analyzes_raw_code_strings():
    from engin33r.analyzers.static import StaticAnalyzer

    analyzer = StaticAnalyzer()
    vulns = analyzer.analyze("const el = document.write(userInput);\n")

    assert vulns
    assert vulns[0].file_path is None
