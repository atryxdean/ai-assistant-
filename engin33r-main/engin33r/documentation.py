"""Comprehensive documentation for engin33r framework"""

# ===== ENGIN33R COMPREHENSIVE DOCUMENTATION =====

DOCUMENTATION = """
# ENGIN33R - Complete Bug Vulnerability Framework

## TABLE OF CONTENTS

1. [Installation & Setup](#installation--setup)
2. [Core Concepts](#core-concepts)
3. [Usage Guide](#usage-guide)
4. [Error Handling](#error-handling)
5. [AI Assistant](#ai-assistant)
6. [Advanced Features](#advanced-features)
7. [API Reference](#api-reference)
8. [Troubleshooting](#troubleshooting)

---

## INSTALLATION & SETUP

### Prerequisites
- Python 3.8+
- pip or conda

### Installation

```bash
# Clone repository
git clone https://github.com/atryxdean/engin33r.git
cd engin33r

# Install with development dependencies
pip install -e ".[dev]"

# Install with ML support
pip install -e ".[ml]"

# Install with all AI providers
pip install -e ".[ai]"
```

### Environment Setup

```bash
# Set up environment variables for AI providers
export GEMINI_API_KEY="your-gemini-key"
export DEEPSEEK_API_KEY="your-deepseek-key"
export ANTHROPIC_API_KEY="your-anthropic-key"

# Set up Jira integration
export JIRA_API_KEY="your-jira-token"
export JIRA_ENDPOINT="https://your-jira.atlassian.net"
export JIRA_PROJECT="SEC"

# Set up Slack integration
export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

---

## CORE CONCEPTS

### Vulnerability Model

Each vulnerability contains:
- **ID**: Unique identifier (UUID)
- **Title**: Brief description
- **Type**: OWASP/CWE classification
- **Severity**: critical, high, medium, low, info
- **CVSS Score**: 0-10 numerical rating
- **File Location**: Path, line number, code snippet
- **Remediation**: Guidance, effort level, deadline
- **Status**: open, in_progress, resolved, wontfix, deferred

### Analysis Flow

```
Target (File/Directory)
        ↓
[Multiple Analyzers Run in Parallel]
    ├─ Static Analyzer
    ├─ Dependency Analyzer
    ├─ ML Analyzer
    ├─ Secrets Scanner
    └─ Specialized Analyzers
        ↓
[Vulnerabilities Aggregated]
        ↓
[Advanced Filtering & Deduplication]
        ↓
[AI-Powered Analysis & Risk Assessment]
        ↓
[Report Generation]
        ↓
[Integration (Jira, Slack, GitHub)]
```

---

## USAGE GUIDE

### Command Line Interface

```bash
# Basic scan
engin33r /path/to/code

# Specify analyzers
engin33r /path/to/code -a static dependency ml

# Output to file
engin33r /path/to/code -o report.json -f json

# Verbose logging
engin33r /path/to/code -v

# Combine options
engin33r /path/to/code -a static secrets -f json -o results.json -v
```

### Python API - Basic Usage

```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer
from engin33r.analyzers.dependency import DependencyAnalyzer

# Create engine
engine = VulnerabilityEngine(name="SecurityAudit")

# Register analyzers
engine.register_analyzer(StaticAnalyzer())
engine.register_analyzer(DependencyAnalyzer())

# Scan
vulnerabilities = engine.scan("/path/to/code")

# Generate report
report = engine.generate_report("Security Audit 2024")

print(f"Found {len(report.vulnerabilities)} vulnerabilities")
print(f"Critical: {report.metrics['critical']}")
print(f"High: {report.metrics['high']}")
```

### Async/Parallel Scanning

```python
import asyncio
from engin33r.performance import AsyncPerformanceOptimizer
from engin33r.analyzers.specialized_analyzers import SecretsScanner

# Async multi-target scanning
optimizer = AsyncPerformanceOptimizer(max_workers=4)
analyzer = SecretsScanner()
targets = ['app.py', 'utils.py', 'config.py']

results = asyncio.run(
    optimizer.analyze_multiple_targets_async(analyzer, targets)
)

for target, vulns in results.items():
    print(f"{target}: {len(vulns)} vulnerabilities")
```

### Dependency Vulnerability Scanning

```python
from engin33r.dependency_db import DependencyVulnerabilityDB

# Initialize database with multiple sources
db = DependencyVulnerabilityDB(
    use_nvd=True,
    use_osv=True,
    use_github=True,
    nvd_api_key="optional-nvd-key"
)

# Search for package vulnerabilities
cves = db.search_vulnerabilities(
    package_name='requests',
    version='2.28.0',
    ecosystem='PyPI'
)

# Filter by severity
for cve in db.filter_by_severity(cves, 'CRITICAL'):
    print(f"CVE: {cve.cve_id}")
    print(f"Description: {cve.description}")
    print(f"Fixed in: {cve.fixed_version}")

# Get report
report = db.generate_report(cves)
print(report)
```

### Advanced Filtering

```python
from engin33r.advanced_filters import AdvancedFilter

filter = AdvancedFilter(vulnerabilities)

# Single filters
critical = filter.by_severity_level(['critical'])
recent = filter.by_recent(days=7)
by_status = filter.by_status('open')

# Complex queries
high_risk_open = filter.complex_query(
    lambda v: v.severity.value in ['critical', 'high'] 
    and v.remediation_status.value == 'open'
)

# Grouping and statistics
by_file = filter.group_by_file()
stats = filter.get_stats()
print(f"High risk: {stats['high_risk']}")
print(f"Medium risk: {stats['medium_risk']}")
```

### AI-Powered Analysis

```python
from engin33r.ai_assistant import VulnerabilityAssistant

# Initialize with all AI providers (fallback enabled)
assistant = VulnerabilityAssistant()

# Check available providers
status = assistant.get_provider_status()
print(f"Available providers: {status}")

# Analyze vulnerability
analysis = assistant.analyze_vulnerability(vulnerability)
if analysis['status'] == 'success':
    print(analysis['analysis'])

# Generate remediation
fixes = assistant.generate_remediation(vulnerability)
print(fixes)

# Risk assessment
risk = assistant.risk_assessment(vulnerability)
if risk['status'] == 'success':
    print(f"Exploitability: {risk['risk_assessment']['exploitability']}")
    print(f"Business Impact: {risk['risk_assessment']['business_impact']}")
```

### Integration with Jira

```python
from engin33r.integrations import JiraIntegration, IntegrationManager

# Create Jira integration
jira = JiraIntegration(
    api_key="your-api-token",
    endpoint="https://your-jira.atlassian.net",
    project_key="SEC"
)

# Create tickets for vulnerabilities
for vuln in vulnerabilities:
    ticket_id = jira.create_ticket(vuln)
    print(f"Created ticket: {ticket_id}")

# Or use manager for multiple integrations
manager = IntegrationManager()
manager.register_integration("jira", jira)
manager.notify_all(
    title="Security Alert",
    message="Critical vulnerability detected",
    severity="critical"
)
```

---

## ERROR HANDLING

### Input Validation

```python
from engin33r.error_handling import InputValidator, ValidationError

# Validate string
try:
    api_key = InputValidator.validate_string(
        value="abc123",
        name="API Key",
        min_length=3,
        max_length=50
    )
except ValidationError as e:
    print(f"Validation failed: {e.message}")
    print(f"Context: {e.context}")

# Validate integer
workers = InputValidator.validate_integer(
    value=4,
    name="Max Workers",
    min_value=1,
    max_value=16
)

# Validate choice
severity = InputValidator.validate_choice(
    value="high",
    name="Severity",
    choices=["critical", "high", "medium", "low"]
)
```

### Error Handling Decorator

```python
from engin33r.error_handling import handle_errors

@handle_errors(default_return=[], log_traceback=True)
def analyze_file(file_path):
    # Your code here
    pass
```

### Error Handler

```python
from engin33r.error_handling import ErrorHandler

handler = ErrorHandler()

try:
    # Some operation
    pass
except Exception as e:
    handler.record_error(error)
    handler.record_warning("Something went wrong", context={"file": "app.py"})

# Get summary
summary = handler.get_summary()
print(f"Critical errors: {summary['critical']}")
print(f"High errors: {summary['high']}")

if handler.has_critical_errors():
    print("Critical issues detected!")
```

---

## AI ASSISTANT

### Supported Providers

1. **Google Gemini**: `GEMINI_API_KEY`
2. **DeepSeek**: `DEEPSEEK_API_KEY`
3. **Anthropic Claude**: `ANTHROPIC_API_KEY`

### Fallback Strategy

If the primary provider fails, the assistant automatically tries the next provider:

```
Primary: Gemini
  ↓ (if fails)
Secondary: DeepSeek
  ↓ (if fails)
Tertiary: Anthropic
  ↓ (if all fail)
Return error status
```

### Setting Up AI Providers

#### Gemini

```bash
export GEMINI_API_KEY="your-api-key"
pip install google-generativeai
```

#### DeepSeek

```bash
export DEEPSEEK_API_KEY="your-api-key"
# Uses standard HTTP requests, no extra package needed
```

#### Anthropic

```bash
export ANTHROPIC_API_KEY="your-api-key"
pip install anthropic
```

---

## ADVANCED FEATURES

### Real-Time Monitoring

```python
from engin33r.monitoring import RealTimeMonitor, AlertRuleBuilder, TrendAnalyzer

monitor = RealTimeMonitor()

# Register alert rules
monitor.register_rule(AlertRuleBuilder.critical_vulnerability())
monitor.register_rule(AlertRuleBuilder.exposed_secrets())
monitor.register_rule(AlertRuleBuilder.approaching_deadline())

# Subscribe to alerts
def alert_callback(alert):
    print(f"ALERT: {alert.title}")

monitor.subscribe(AlertLevel.CRITICAL, alert_callback)

# Detect vulnerabilities
for vuln in vulnerabilities:
    monitor.on_vulnerability_detected(vuln)

# Trend analysis
analyzer = TrendAnalyzer()
analyzer.record_scan(vulnerabilities)
trend = analyzer.get_trend(days=30)
prediction = analyzer.predict_vulnerability_count(days_ahead=30)
```

### Performance Optimization

```python
from engin33r.performance import PerformanceBenchmark

bench = PerformanceBenchmark(max_workers=4)

# Benchmark with parallelization
result = bench.benchmark_analyzer(
    analyzer=analyzer,
    target="/path/to/code",
    iterations=3,
    parallel=True
)

print(f"Execution Time: {result.execution_time:.2f}s")
print(f"Peak Memory: {result.peak_memory_mb:.2f}MB")
print(f"Performance Score: {result.performance_score:.2f} vulns/sec")

# Compare analyzers
comparison = bench.compare_analyzers(
    analyzers=[static, dependency, ml],
    target="/path/to/code",
    parallel=True
)
```

---

## API REFERENCE

### Core Classes

#### VulnerabilityEngine

```python
class VulnerabilityEngine:
    def register_analyzer(analyzer: VulnerabilityAnalyzer) -> None
    def register_analyzers(analyzers: List[VulnerabilityAnalyzer]) -> None
    def scan(target: str, context: Dict) -> List[Vulnerability]
    def generate_report(title: str, vulnerabilities: List) -> VulnerabilityReport
    def filter_vulnerabilities(severity, vuln_type, status) -> List[Vulnerability]
    def get_summary() -> Dict[str, Any]
```

#### Vulnerability

```python
class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: VulnerabilitySeverity
    cvss_score: Optional[float]
    file_path: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    remediation_guidance: Optional[str]
    remediation_status: RemediationStatus
```

#### AdvancedFilter

```python
class AdvancedFilter:
    def by_severity_range(min, max) -> List[Vulnerability]
    def by_severity_level(levels) -> List[Vulnerability]
    def by_remediation_effort(effort) -> List[Vulnerability]
    def by_recent(days) -> List[Vulnerability]
    def by_file_path(pattern) -> List[Vulnerability]
    def group_by_type() -> Dict[str, List[Vulnerability]]
    def sort_by_risk(reverse) -> List[Vulnerability]
    def get_stats() -> Dict[str, Any]
```

---

## TROUBLESHOOTING

### Common Issues

#### Issue: "AI Provider not available"

**Solution**: Set environment variables for API keys

```bash
export GEMINI_API_KEY="your-key"
export DEEPSEEK_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"
```

#### Issue: "Validation failed: must be a string"

**Solution**: Check input types

```python
# Wrong
engine.scan(123)  # integer

# Correct
engine.scan("/path/to/code")  # string
```

#### Issue: "Jira authentication failed"

**Solution**: Verify API credentials

```bash
# Test Jira API
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://your-jira.atlassian.net/rest/api/3/myself
```

#### Issue: "Memory usage too high"

**Solution**: Use async/parallel with appropriate worker count

```python
# Wrong: too many workers
optimizer = AsyncPerformanceOptimizer(max_workers=64)

# Correct: based on CPU cores
import multiprocessing
optimizer = AsyncPerformanceOptimizer(max_workers=multiprocessing.cpu_count())
```

---

## SUPPORT & RESOURCES

- GitHub Issues: https://github.com/atryxdean/engin33r/issues
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1

"""


def get_documentation() -> str:
    """Get full documentation"""
    return DOCUMENTATION


def get_quick_start() -> str:
    """Get quick start guide"""
    return """
# ENGIN33R QUICK START

## Install
```
pip install engin33r
```

## Setup AI (Optional)
```
export GEMINI_API_KEY="your-key"
```

## Scan
```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer

engine = VulnerabilityEngine()
engine.register_analyzer(StaticAnalyzer())
vulns = engine.scan("/path/to/code")

for v in vulns:
    print(f"{v.severity}: {v.title}")
```

## Get AI Insights
```python
from engin33r.ai_assistant import VulnerabilityAssistant

assistant = VulnerabilityAssistant()
analysis = assistant.analyze_vulnerability(vuln)
fixes = assistant.generate_remediation(vuln)
```
"""


def get_error_reference() -> str:
    """Get error handling reference"""
    return """
# ERROR HANDLING REFERENCE

## Exception Hierarchy

EngineeringException (base)
├── ValidationError
├── ConfigurationError
├── AnalysisError
├── DatabaseError
└── IntegrationError

## Severity Levels

- CRITICAL: System cannot continue
- HIGH: Major issue requiring immediate action
- MEDIUM: Should be addressed soon
- LOW: Can be planned for later
- INFO: Informational only

## Usage

```python
from engin33r.error_handling import (
    ValidationError,
    handle_errors,
    InputValidator
)

try:
    value = InputValidator.validate_string(user_input, "Email")
except ValidationError as e:
    print(f"Error: {e.message}")
    print(f"Context: {e.context}")

@handle_errors(default_return=[])
def my_function():
    pass
```
"""
