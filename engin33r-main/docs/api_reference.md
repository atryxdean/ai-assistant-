# API Reference

## Core Classes

### VulnerabilityEngine

```python
class VulnerabilityEngine:
    def __init__(self, name: str = "engin33r"):
        """Initialize the vulnerability engine"""
    
    def register_analyzer(self, analyzer: VulnerabilityAnalyzer) -> None:
        """Register a single analyzer"""
    
    def register_analyzers(self, analyzers: List[VulnerabilityAnalyzer]) -> None:
        """Register multiple analyzers"""
    
    def unregister_analyzer(self, analyzer: VulnerabilityAnalyzer) -> None:
        """Unregister an analyzer"""
    
    def scan(self, target: str, context: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """Run all analyzers on target"""
    
    def generate_report(
        self,
        title: str = "Vulnerability Report",
        vulnerabilities: Optional[List[Vulnerability]] = None,
    ) -> VulnerabilityReport:
        """Generate a report from vulnerabilities"""
    
    def filter_vulnerabilities(
        self,
        severity: Optional[VulnerabilitySeverity] = None,
        vuln_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Vulnerability]:
        """Filter vulnerabilities by criteria"""
    
    def get_summary(self) -> Dict[str, Any]:
        """Get engine summary statistics"""
    
    def clear_vulnerabilities(self) -> None:
        """Clear all stored vulnerabilities"""
```

### Vulnerability

```python
class Vulnerability(BaseModel):
    id: str                                      # Unique identifier
    title: str                                  # Brief description
    description: str                            # Detailed description
    vulnerability_type: VulnerabilityType       # Type classification
    severity: VulnerabilitySeverity             # Severity level
    cvss_score: Optional[float]                 # CVSS v3.1 score (0-10)
    cve_id: Optional[str]                       # CVE identifier
    cwe_id: Optional[str]                       # CWE identifier
    file_path: Optional[str]                    # Affected file
    line_number: Optional[int]                  # Line number
    code_snippet: Optional[str]                 # Code excerpt
    affected_components: List[str]              # Affected parts
    business_impact: Optional[str]              # Business impact
    technical_impact: Optional[str]             # Technical impact
    remediation_status: RemediationStatus       # Fix status
    remediation_guidance: Optional[str]         # How to fix
    remediation_effort: Optional[str]           # low/medium/high
    remediation_deadline: Optional[datetime]    # Target date
    discovered_date: datetime                   # Discovery date
    discovered_by: Optional[str]                # Who found it
    last_updated: datetime                      # Last update
    tags: List[str]                             # Custom tags
    references: List[str]                       # External links
    evidence: Dict[str, Any]                    # Supporting data
    
    def get_risk_score(self) -> float:
        """Calculate risk score (0-10)"""
    
    def is_critical(self) -> bool:
        """Check if critical severity"""
    
    def requires_urgent_action(self) -> bool:
        """Check if critical or high severity"""
```

### VulnerabilityReport

```python
class VulnerabilityReport(BaseModel):
    id: str                                 # Report ID
    title: str                              # Report title
    created_at: datetime                    # Creation time
    vulnerabilities: List[Vulnerability]    # Found vulnerabilities
    summary: Optional[str]                  # Executive summary
    metrics: Dict[str, Any]                 # Statistics
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add vulnerability to report"""
    
    def get_statistics(self) -> Dict[str, int]:
        """Get severity breakdown statistics"""
```

## Enumerations

### VulnerabilitySeverity

```python
class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"  # Score: 9
    HIGH = "high"         # Score: 7
    MEDIUM = "medium"     # Score: 5
    LOW = "low"           # Score: 3
    INFO = "info"         # Score: 1
    
    @property
    def score(self) -> int:
        """Get CVSS-based score"""
```

### VulnerabilityType

```python
class VulnerabilityType(str, Enum):
    # OWASP Top 10
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XML_EXTERNAL = "xml_external_entities"
    BROKEN_ACCESS = "broken_access_control"
    MISCONFIGURATION = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    USING_COMPONENTS = "using_components_with_known_vulns"
    INSUFFICIENT_LOGGING = "insufficient_logging_monitoring"
    
    # Additional types
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CRYPTOGRAPHIC = "cryptographic_failure"
    INFORMATION_DISCLOSURE = "information_disclosure"
    LOGIC_ERROR = "logic_error"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    CONFIGURATION_ISSUE = "configuration_issue"
```

### RemediationStatus

```python
class RemediationStatus(str, Enum):
    OPEN = "open"               # Not yet addressed
    IN_PROGRESS = "in_progress" # Being fixed
    RESOLVED = "resolved"       # Fixed
    WONTFIX = "wontfix"         # Intentionally not fixing
    DEFERRED = "deferred"       # Scheduled for later
```

## Analyzer Base Class

```python
class VulnerabilityAnalyzer(ABC):
    def __init__(self, name: str, description: str = ""):
        """Initialize analyzer"""
    
    @abstractmethod
    def analyze(self, target: str, context: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """Analyze target for vulnerabilities"""
    
    def supports_target(self, target: str) -> bool:
        """Check if analyzer supports target"""
```

## Formatter Base Class

```python
class Formatter(ABC):
    @abstractmethod
    def format_report(self, report: VulnerabilityReport) -> str:
        """Format report to string"""
```

## Built-in Analyzers

### StaticAnalyzer

```python
from engin33r.analyzers.static import StaticAnalyzer

analyzer = StaticAnalyzer()
```

Detects patterns for:
- SQL injection
- Hardcoded secrets
- XSS vulnerabilities
- Unsafe deserialization
- Weak cryptography

### DependencyAnalyzer

```python
from engin33r.analyzers.dependency import DependencyAnalyzer

analyzer = DependencyAnalyzer()
```

Checks:
- package.json dependencies
- requirements.txt dependencies
- Known vulnerable versions

### MLVulnerabilityAnalyzer

```python
from engin33r.ml import MLVulnerabilityAnalyzer

analyzer = MLVulnerabilityAnalyzer()
analyzer = MLVulnerabilityAnalyzer(model_path='model.pkl')
```

Methods:
- `save_model(path)`: Save trained model
- `load_model(path)`: Load trained model

### AnomalyDetector

```python
from engin33r.ml.anomaly import AnomalyDetector

analyzer = AnomalyDetector()
```

Detects:
- Excessive line lengths
- Low documentation ratio
- Dense code structures

### CodeComplexityAnalyzer

```python
from engin33r.ml.anomaly import CodeComplexityAnalyzer

analyzer = CodeComplexityAnalyzer()
```

Analyzes:
- Cyclomatic complexity
- Code structure complexity

## Built-in Formatters

### JSONFormatter

```python
from engin33r.formatters.json_formatter import JSONFormatter

formatter = JSONFormatter()
json_string = formatter.format_report(report)
```

### TextFormatter

```python
from engin33r.formatters.text_formatter import TextFormatter

formatter = TextFormatter()
text_string = formatter.format_report(report)
```

## Complete Example

```python
from engin33r.core.engine import VulnerabilityEngine
from engin33r.analyzers.static import StaticAnalyzer
from engin33r.analyzers.dependency import DependencyAnalyzer
from engin33r.ml import MLVulnerabilityAnalyzer
from engin33r.formatters.json_formatter import JSONFormatter
from engin33r.core.vulnerability import VulnerabilitySeverity

# Create engine
engine = VulnerabilityEngine(name="MyScanner")

# Register analyzers
engine.register_analyzers([
    StaticAnalyzer(),
    DependencyAnalyzer(),
    MLVulnerabilityAnalyzer(),
])

# Scan target
vulnerabilities = engine.scan("/path/to/code")

# Filter critical vulnerabilities
critical = engine.filter_vulnerabilities(
    severity=VulnerabilitySeverity.CRITICAL
)

# Generate report
report = engine.generate_report(
    title="Security Audit",
    vulnerabilities=critical
)

# Format output
formatter = JSONFormatter()
output = formatter.format_report(report)

print(output)
```
