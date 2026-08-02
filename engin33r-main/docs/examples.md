# engin33r Examples

## Basic Scanning

### Scan a Single File

```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer

engine = VulnerabilityEngine(name="MyScanner")
engine.register_analyzer(StaticAnalyzer())

vulnerabilities = engine.scan("/path/to/app.py")
print(f"Found {len(vulnerabilities)} vulnerabilities")
```

### Scan with Multiple Analyzers

```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer
from engin33r.analyzers.dependency import DependencyAnalyzer
from engin33r.ml import MLVulnerabilityAnalyzer

engine = VulnerabilityEngine()
engine.register_analyzers([
    StaticAnalyzer(),
    DependencyAnalyzer(),
    MLVulnerabilityAnalyzer(),
])

vulnerabilities = engine.scan("/path/to/code")
report = engine.generate_report("Comprehensive Security Audit")
```

## Filtering and Analysis

### Filter by Severity

```python
from engin33r.core.vulnerability import VulnerabilitySeverity

# Get only critical vulnerabilities
critical = engine.filter_vulnerabilities(
    severity=VulnerabilitySeverity.CRITICAL
)

print(f"Critical vulnerabilities: {len(critical)}")
for vuln in critical:
    print(f"  - {vuln.title}")
```

### Filter by Type

```python
from engin33r.core.vulnerability import VulnerabilityType

# Get only injection vulnerabilities
injections = engine.filter_vulnerabilities(
    vuln_type=VulnerabilityType.INJECTION
)
```

### Filter by Status

```python
from engin33r.core.vulnerability import RemediationStatus

# Get unresolved vulnerabilities
open_vulns = engine.filter_vulnerabilities(
    status=RemediationStatus.OPEN
)
```

## Report Generation

### Generate Full Report

```python
report = engine.generate_report(
    title="Q1 2024 Security Audit",
    vulnerabilities=vulnerabilities
)

print(report.metrics)
# Output:
# {
#   'total': 25,
#   'critical': 2,
#   'high': 5,
#   'medium': 10,
#   'low': 8,
#   'info': 0
# }
```

### Output as JSON

```python
from engin33r.formatters.json_formatter import JSONFormatter

formatter = JSONFormatter()
json_output = formatter.format_report(report)
print(json_output)
```

### Output as Text

```python
from engin33r.formatters.text_formatter import TextFormatter

formatter = TextFormatter()
text_output = formatter.format_report(report)
print(text_output)
```

## Machine Learning Examples

### Using ML Analyzer

```python
from engin33r.ml import MLVulnerabilityAnalyzer

ml_analyzer = MLVulnerabilityAnalyzer()
engine.register_analyzer(ml_analyzer)

# Analyze code
vulnerabilities = engine.scan(code_snippet)

# Get confidence scores
for vuln in vulnerabilities:
    print(f"{vuln.title}: {vuln.get_risk_score():.2%} risk")
```

### Using Anomaly Detection

```python
from engin33r.ml.anomaly import AnomalyDetector, CodeComplexityAnalyzer

engine.register_analyzer(AnomalyDetector())
engine.register_analyzer(CodeComplexityAnalyzer())

anomalies = engine.scan(code_snippet)
for anomaly in anomalies:
    print(f"Anomaly: {anomaly.title}")
```

### Save and Load Models

```python
from engin33r.ml import MLVulnerabilityAnalyzer

# Train and save
analyzer = MLVulnerabilityAnalyzer()
analyzer.save_model('security_model.pkl')

# Later, load it back
analyzer = MLVulnerabilityAnalyzer(model_path='security_model.pkl')
engine.register_analyzer(analyzer)
```

## Integration Examples

### CI/CD Pipeline

```python
import sys
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer

def scan_pull_request(code_path):
    engine = VulnerabilityEngine()
    engine.register_analyzer(StaticAnalyzer())
    
    vulnerabilities = engine.scan(code_path)
    report = engine.generate_report()
    
    # Fail CI if critical vulnerabilities found
    if report.metrics['critical'] > 0:
        print("CRITICAL vulnerabilities found!")
        return 1
    
    # Warn if high severity found
    if report.metrics['high'] > 0:
        print(f"Warning: {report.metrics['high']} high severity issues")
    
    return 0

if __name__ == "__main__":
    exit_code = scan_pull_request("./src")
    sys.exit(exit_code)
```

### Scheduled Security Audits

```python
import json
from datetime import datetime
from pathlib import Path
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer
from engin33r.analyzers.dependency import DependencyAnalyzer
from engin33r.formatters.json_formatter import JSONFormatter

def run_security_audit(project_path, output_dir):
    engine = VulnerabilityEngine(name="ScheduledAudit")
    engine.register_analyzer(StaticAnalyzer())
    engine.register_analyzer(DependencyAnalyzer())
    
    vulnerabilities = engine.scan(project_path)
    report = engine.generate_report(f"Audit {datetime.now().isoformat()}")
    
    # Save report
    formatter = JSONFormatter()
    output_file = Path(output_dir) / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_file.write_text(formatter.format_report(report))
    
    return output_file
```

### Custom Analysis Pipeline

```python
class SecurityAnalysisPipeline:
    def __init__(self):
        self.engine = VulnerabilityEngine(name="CustomPipeline")
        self._setup_analyzers()
    
    def _setup_analyzers(self):
        from engin33r.analyzers.static import StaticAnalyzer
        from engin33r.analyzers.dependency import DependencyAnalyzer
        from engin33r.ml import MLVulnerabilityAnalyzer
        from engin33r.ml.anomaly import AnomalyDetector
        
        self.engine.register_analyzers([
            StaticAnalyzer(),
            DependencyAnalyzer(),
            MLVulnerabilityAnalyzer(),
            AnomalyDetector(),
        ])
    
    def analyze(self, target_path):
        vulnerabilities = self.engine.scan(target_path)
        
        # Custom filtering
        critical = [v for v in vulnerabilities if v.requires_urgent_action()]
        medium = self.engine.filter_vulnerabilities(
            severity=VulnerabilitySeverity.MEDIUM
        )
        
        return {
            'total': len(vulnerabilities),
            'critical': len(critical),
            'medium': len(medium),
            'vulnerabilities': vulnerabilities,
        }

# Usage
pipeline = SecurityAnalysisPipeline()
results = pipeline.analyze("/path/to/project")
```
