# engin33r - Complete Bug Vulnerability Framework

**engin33r** is a comprehensive, enterprise-grade framework for identifying, analyzing, categorizing, and managing security vulnerabilities in software systems. It combines traditional static analysis with advanced machine learning capabilities for deep vulnerability detection.

## 🎯 Key Features

### Core Components
- **Vulnerability Detection**: Multi-layered detection using static analysis and ML
- **Classification System**: OWASP Top 10 and extended vulnerability categorization
- **Severity Rating**: CVSS-based severity assessment with confidence scoring
- **Impact Assessment**: Business and technical impact analysis
- **Remediation Guidance**: Actionable fix recommendations with effort estimation

### Detection Methods
1. **Static Code Analysis** - Pattern-based vulnerability detection
2. **Dependency Analysis** - Known vulnerability checks for dependencies
3. **Machine Learning Analysis** - ML-based pattern recognition and classification
4. **Anomaly Detection** - Identifies unusual code patterns that may hide vulnerabilities
5. **Complexity Analysis** - Detects complex code structures prone to vulnerabilities

### Output & Reporting
- **JSON Reports** - Machine-readable vulnerability data
- **Text Reports** - Human-readable formatted reports with statistics
- **Filtering & Sorting** - Query vulnerabilities by severity, type, or status
- **Compliance Tracking** - Monitor remediation progress

## 🚀 Quick Start

### Installation

```bash
pip install engin33r
```

### Basic Usage

**Command Line:**
```bash
# Scan a file
engin33r /path/to/code.py

# Use specific analyzers
engin33r /path/to/code.py -a static dependency ml

# Output to JSON
engin33r /path/to/code.py -o report.json -f json

# Verbose output
engin33r /path/to/code.py -v
```

**Python API:**
```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer
from engin33r.ml import MLVulnerabilityAnalyzer

# Create engine
engine = VulnerabilityEngine()

# Register analyzers
engine.register_analyzer(StaticAnalyzer())
engine.register_analyzer(MLVulnerabilityAnalyzer())

# Scan code
vulnerabilities = engine.scan("/path/to/code.py")

# Generate report
report = engine.generate_report("Security Audit")

# Print results
for vuln in report.vulnerabilities:
    print(f"[{vuln.severity.upper()}] {vuln.title}")
```

## 📊 Vulnerability Types Detected

### OWASP Top 10
- SQL Injection
- Broken Authentication
- Sensitive Data Exposure
- XML External Entities (XXE)
- Broken Access Control
- Security Misconfiguration
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

### Extended Categories
- Buffer Overflow
- Race Conditions
- Privilege Escalation
- Cryptographic Failures
- Information Disclosure
- Logic Errors
- Configuration Issues
- Dependency Vulnerabilities

## 🤖 Machine Learning Features

### Intelligent Pattern Recognition
- Learns from known vulnerability patterns
- Identifies novel vulnerability signatures
- Confidence-based reporting

### Code Anomaly Detection
- Detects unusual code structures
- Identifies overly complex functions
- Flags undocumented critical sections

### Severity Prediction
- ML-based severity estimation
- Risk scoring based on context
- False positive reduction

## 📈 Severity Levels

| Level | Score | Action Required |
|-------|-------|------------------|
| CRITICAL | 9 | Immediate fix required |
| HIGH | 7 | Urgent remediation needed |
| MEDIUM | 5 | Should be addressed soon |
| LOW | 3 | Can be planned for next cycle |
| INFO | 1 | Informational only |

## 📚 Documentation

- [Getting Started](./docs/getting_started.md)
- [Architecture](./docs/architecture.md)
- [Analyzers Guide](./docs/analyzers.md)
- [API Reference](./docs/api_reference.md)
- [Examples](./docs/examples.md)

## 🛠️ Development

### Setup Development Environment
```bash
git clone https://github.com/atryxdean/engin33r.git
cd engin33r
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest tests/ -v
```

### Install with ML Support
```bash
pip install engin33r[ml]
```

## 🔧 Configuration

Create an `engin33r.config.yaml` file:

```yaml
analyzer:
  static:
    enabled: true
  dependency:
    enabled: true
  ml:
    enabled: true
    model_path: ./models/engin33r_model.pkl
  anomaly:
    enabled: true

reporting:
  format: json
  include_metrics: true
  include_recommendations: true

severity_thresholds:
  fail_on_critical: true
  fail_on_high: false
  warning_on_medium: true
```

## 📝 Example Report

```
================================================================================
Vulnerability Report: Security Audit
Generated: 2024-01-15 10:30:45
================================================================================

STATISTICS
--------------------------------------------------------------------------------
Total Vulnerabilities: 12
  Critical: 1
  High:     3
  Medium:   5
  Low:      3
  Info:     0

VULNERABILITIES
┌────────┬──────────┬──────────────┬────────────────────┬────────────┐
│ ID     │ SEVERITY │ TYPE         │ TITLE              │ STATUS     │
├────────┼──────────┼──────────────┼────────────────────┼────────────┤
│ a1b2c3 │ CRITICAL │ injection    │ SQL Injection      │ open       │
│ d4e5f6 │ HIGH     │ xss          │ XSS Vulnerability  │ open       │
│ g7h8i9 │ MEDIUM   │ logic_error  │ Weak Crypto Usage  │ in_progress│
└────────┴──────────┴─────────��────┴────────────────────┴────────────┘

DETAILED FINDINGS
--------------------------------------------------------------------------------

[CRITICAL] SQL Injection in User Login
ID: a1b2c3d4e5f6g7h8
Type: injection
Description: Direct SQL query concatenation detected
File: app/auth.py
Line: 42
Code: query = "SELECT * FROM users WHERE email='" + email + "'"
Remediation: Use parameterized queries or ORM
References: https://owasp.org/www-community/attacks/SQL_Injection
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - See [LICENSE](./LICENSE) for details

## ⚠️ Disclaimer

engin33r is a security analysis tool. While it aims for accuracy, no automated vulnerability scanner is 100% reliable. Always:
- Review findings manually
- Test in non-production environments
- Have security experts review critical vulnerabilities
- Follow responsible disclosure practices

## 🔗 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

## 📧 Support

For issues and questions:
- GitHub Issues: [engin33r/issues](https://github.com/atryxdean/engin33r/issues)
- Email: support@engin33r.dev
