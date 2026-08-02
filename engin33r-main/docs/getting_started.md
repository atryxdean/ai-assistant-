# Getting Started with engin33r

## Installation

### From PyPI

```bash
pip install engin33r
```

### From Source

```bash
git clone https://github.com/atryxdean/engin33r.git
cd engin33r
pip install -e .
```

### With Machine Learning Support

```bash
pip install engin33r[ml]
```

### Development Installation

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Quick Start

### Command Line Usage

**Scan a Python file:**
```bash
engin33r app.py
```

**Scan with specific analyzers:**
```bash
engin33r app.py -a static dependency ml
```

**Output to JSON file:**
```bash
engin33r app.py -o report.json -f json
```

**Verbose output:**
```bash
engin33r app.py -v
```

**Full help:**
```bash
engin33r --help
```

### Python API

**Basic scanning:**
```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer

engine = VulnerabilityEngine()
engine.register_analyzer(StaticAnalyzer())

vulnerabilities = engine.scan("app.py")
for vuln in vulnerabilities:
    print(f"{vuln.severity}: {vuln.title}")
```

**Generate reports:**
```python
report = engine.generate_report("Security Audit")

print(f"Total: {report.metrics['total']}")
print(f"Critical: {report.metrics['critical']}")
print(f"High: {report.metrics['high']}")
```

**Output formatting:**
```python
from engin33r.formatters.text_formatter import TextFormatter
from engin33r.formatters.json_formatter import JSONFormatter

# Text output
text_formatter = TextFormatter()
print(text_formatter.format_report(report))

# JSON output
json_formatter = JSONFormatter()
with open('report.json', 'w') as f:
    f.write(json_formatter.format_report(report))
```

## Understanding Results

### Severity Levels

- **CRITICAL** (Score: 9): Immediate action required. Exploit is trivial or weaponized.
- **HIGH** (Score: 7): Urgent fix needed. Likely exploitable vulnerability.
- **MEDIUM** (Score: 5): Should be addressed soon. May have security implications.
- **LOW** (Score: 3): Can be planned for next release. Minor security issue.
- **INFO** (Score: 1): Informational only. No immediate action required.

### Vulnerability Types

```
Injection (injection)
├─ SQL Injection
├─ Command Injection
├─ LDAP Injection
└─ ... (see docs/analyzers.md)

Broken Authentication (broken_authentication)
├─ Weak Credentials
├─ Session Management Issues
└─ ...

Sensitive Data Exposure (sensitive_data_exposure)
├─ Hardcoded Secrets
├─ Unencrypted Data
└─ ...

Cross-Site Scripting (cross_site_scripting)
├─ Reflected XSS
├─ Stored XSS
└─ DOM-based XSS

... and more (see docs/analyzers.md)
```

### Remediation Status

- **OPEN**: Vulnerability discovered and not yet addressed
- **IN_PROGRESS**: Work is underway to fix the vulnerability
- **RESOLVED**: Vulnerability has been fixed
- **WONTFIX**: Decision made not to fix this vulnerability
- **DEFERRED**: Fix scheduled for future release

## Common Tasks

### Scan Multiple Files

```python
from pathlib import Path

all_vulns = []
for py_file in Path('.').rglob('*.py'):
    vulns = engine.scan(str(py_file))
    all_vulns.extend(vulns)

report = engine.generate_report(vulnerabilities=all_vulns)
```

### Filter Vulnerabilities

```python
from engin33r.core.vulnerability import (
    VulnerabilitySeverity,
    VulnerabilityType,
    RemediationStatus
)

# By severity
critical = engine.filter_vulnerabilities(
    severity=VulnerabilitySeverity.CRITICAL
)

# By type
injections = engine.filter_vulnerabilities(
    vuln_type=VulnerabilityType.INJECTION
)

# By status
open_issues = engine.filter_vulnerabilities(
    status=RemediationStatus.OPEN
)
```

### CI/CD Integration

```bash
#!/bin/bash
# scan.sh
engin33r ./src -f json -o vulnerability_report.json

if [ $? -eq 2 ]; then
    echo "Critical vulnerabilities found!"
    exit 1
fi

if [ $? -eq 1 ]; then
    echo "High severity vulnerabilities found!"
    exit 0  # Warning only
fi

echo "No major vulnerabilities detected"
exit 0
```

## Troubleshooting

### "Module not found" errors

```bash
# Ensure engin33r is installed
pip install --upgrade engin33r

# Check installation
python -c "import engin33r; print(engin33r.__version__)"
```

### ML features not available

```bash
# Install scikit-learn
pip install scikit-learn numpy joblib

# Or install with ML support
pip install engin33r[ml]
```

### No vulnerabilities found

- Check file path is correct
- Ensure file is readable
- Verify analyzers are registered
- Check verbose output: `engin33r file.py -v`

### High false positive rate

- Use ML analyzer with confidence filtering
- Combine multiple analyzers for validation
- Review manual remediation guidance
- Report false positives for model improvement

## Next Steps

- Read [Architecture Guide](./architecture.md) to understand how engin33r works
- See [Analyzers Guide](./analyzers.md) for detailed analyzer documentation
- Check [Examples](./examples.md) for more advanced usage
- Review [API Reference](./api_reference.md) for complete API documentation
