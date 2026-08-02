# engin33r Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    engin33r Framework                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           VulnerabilityEngine (Orchestrator)         │   │
│  │  - Manages analyzer registration                     │   │
│  │  - Runs scans across all analyzers                   │   │
│  │  - Aggregates results                                │   │
│  │  - Generates reports                                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                    │
│          ┌───────────────┼───────────────┐                   │
│          ▼               ▼               ▼                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │   Static     │ │ Dependency   │ │   Machine    │        │
│  │  Analyzer    │ │  Analyzer    │ │  Learning    │        │
│  │              │ │              │ │  Analyzer    │        │
│  │ Pattern-based│ │ Dependency   │ │ ML-based     │        │
│  │ Detection    │ │ Scanning     │ │ Pattern Recog│        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│                                                              │
│          Additional Analyzers (Optional)                    │
│  ┌──────────────────────┐    ┌──────────────────────┐      │
│  │  Anomaly Detector    │    │ Code Complexity      │      │
│  │                      │    │ Analyzer             │      │
│  │ Detects unusual code │    │                      │      │
│  │ patterns that may    │    │ Analyzes cyclomatic  │      │
│  │ hide vulnerabilities │    │ complexity           │      │
│  └──────────────────────┘    └──────────────────────┘      │
│                                                              │
│          ┌─────────────────────────────────────┐            │
│          │   Vulnerability Model (Core Data)   │            │
│          │                                     │            │
│          │ - Vulnerability details             │            │
│          │ - Severity & classification         │            │
│          │ - Location information              │            │
│          │ - Remediation guidance              │            │
│          │ - Impact assessment                 │            │
│          └─────────────────────────────────────┘            │
│                          │                                    │
│          ┌───────────────┼───────────────┐                   │
│          ▼               ▼               ▼                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │   JSON       │ │   Text       │ │   Custom     │        │
│  │  Formatter   │ │  Formatter   │ │  Formatter   │        │
│  │              │ │              │ │              │        │
│  │ Machine-     │ │ Human-       │ │ Custom output│        │
│  │ readable     │ │ readable     │ │ format       │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. VulnerabilityEngine

**Purpose**: Main orchestrator that coordinates vulnerability scanning

**Responsibilities**:
- Register/unregister analyzers
- Execute scans using all registered analyzers
- Aggregate vulnerability results
- Generate reports from results
- Filter vulnerabilities by criteria

**Key Methods**:
```python
engine.register_analyzer(analyzer)      # Add analyzer
engine.scan(target, context)            # Run scan
engine.generate_report(title, vulns)    # Create report
engine.filter_vulnerabilities(...)      # Query vulns
```

### 2. Vulnerability Model

**Purpose**: Core data structure representing a single vulnerability

**Key Fields**:
- `id`: Unique identifier
- `title`: Brief vulnerability description
- `description`: Detailed description
- `vulnerability_type`: Classification (VulnerabilityType enum)
- `severity`: Severity level (VulnerabilitySeverity enum)
- `cvss_score`: Optional CVSS v3.1 score (0-10)
- `cve_id`: CVE identifier if applicable
- `cwe_id`: CWE identifier if applicable
- `file_path`: Affected file path
- `line_number`: Line number of vulnerability
- `code_snippet`: Affected code excerpt
- `remediation_guidance`: How to fix it
- `remediation_status`: Current remediation state

### 3. Analyzer System

**Base Class**: `VulnerabilityAnalyzer`

**Interface**:
```python
class VulnerabilityAnalyzer(ABC):
    def analyze(self, target: str, context: Dict) -> List[Vulnerability]:
        """Analyze target and return vulnerabilities"""
        pass
    
    def supports_target(self, target: str) -> bool:
        """Check if analyzer can handle target"""
        pass
```

**Built-in Analyzers**:

1. **StaticAnalyzer**
   - Uses regex patterns to detect vulnerabilities
   - Detects: SQL injection, XSS, hardcoded secrets, weak crypto, unsafe deserialization
   - Fast and deterministic

2. **DependencyAnalyzer**
   - Checks project dependencies for known vulnerabilities
   - Supports: package.json, requirements.txt
   - Maintains database of vulnerable versions

3. **MLVulnerabilityAnalyzer**
   - Uses machine learning for pattern recognition
   - TF-IDF vectorization + Random Forest classifier
   - Provides confidence scores

4. **AnomalyDetector**
   - Detects unusual code patterns
   - Analyzes: line lengths, documentation, code density
   - Uses IsolationForest for anomaly detection

5. **CodeComplexityAnalyzer**
   - Analyzes cyclomatic complexity
   - Estimates complexity from code structure
   - Flags overly complex functions

### 4. Report System

**VulnerabilityReport**
```python
class VulnerabilityReport:
    id: str                                  # Report ID
    title: str                              # Report title
    created_at: datetime                    # Creation timestamp
    vulnerabilities: List[Vulnerability]    # Found vulns
    summary: Optional[str]                  # Executive summary
    metrics: Dict[str, int]                 # Statistics
```

**Metrics Included**:
- Total vulnerabilities
- Count by severity (critical, high, medium, low, info)
- Count by type
- Remediation status breakdown

### 5. Formatter System

**Base Class**: `Formatter`

**Built-in Formatters**:

1. **JSONFormatter**
   - Machine-readable JSON output
   - Includes all vulnerability details
   - Suitable for programmatic processing

2. **TextFormatter**
   - Human-readable formatted text
   - Includes tables and statistics
   - Suitable for reports and dashboards

## Data Flow

```
Input Code
    │
    ▼
VulnerabilityEngine.scan()
    │
    ├─► StaticAnalyzer
    │   └─► Pattern Matching ──┐
    │                           │
    ├─► DependencyAnalyzer     │
    │   └─► DB Lookup ─────────┤
    │                           │
    ├─► MLVulnerabilityAnalyzer│
    │   └─► ML Model ──────────┤
    │                           │
    ├─► AnomalyDetector        │
    │   └─► Statistical Analysis┤
    │                           │
    └─► Custom Analyzers       │
        └─► Custom Logic ──────┤
                                │
                    Aggregate Results
                                │
                                ▼
                    List[Vulnerability]
                                │
                                ▼
                  VulnerabilityEngine.generate_report()
                                │
                                ▼
                        VulnerabilityReport
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                JSON        Text          Custom
                Report      Report        Format
```

## Analyzer Execution Order

Analyzers execute in registration order:

```python
engine.register_analyzer(StaticAnalyzer())      # Runs first (fast)
engine.register_analyzer(DependencyAnalyzer())  # Runs second
engine.register_analyzer(MLVulnerabilityAnalyzer()) # Runs third (slower)
```

## Extension Points

### Creating Custom Analyzers

```python
from engin33r.analyzers.base import VulnerabilityAnalyzer
from engin33r.core.vulnerability import Vulnerability

class CustomAnalyzer(VulnerabilityAnalyzer):
    def __init__(self):
        super().__init__(
            name="CustomAnalyzer",
            description="My custom vulnerability detector"
        )
    
    def analyze(self, target, context=None):
        vulnerabilities = []
        # Your analysis logic here
        return vulnerabilities

engine.register_analyzer(CustomAnalyzer())
```

### Creating Custom Formatters

```python
from engin33r.formatters.base import Formatter

class CSVFormatter(Formatter):
    def format_report(self, report):
        # Convert report to CSV
        return csv_string

formatter = CSVFormatter()
csv_output = formatter.format_report(report)
```

## Performance Considerations

### Execution Time

- **StaticAnalyzer**: O(n) where n = lines of code
- **DependencyAnalyzer**: O(m) where m = dependencies
- **MLVulnerabilityAnalyzer**: O(n*k) where k = model complexity
- **AnomalyDetector**: O(n) with statistical analysis

### Memory Usage

- Store code in memory: O(size of source)
- ML models: ~1-5 MB loaded
- Report generation: O(number of vulnerabilities)

### Optimization Tips

1. Process large codebases in chunks
2. Cache ML model after loading
3. Use filtering to reduce report size
4. Run fast analyzers before slow ones

## Thread Safety

⚠️ **Note**: Current implementation is NOT thread-safe. For concurrent scanning:

```python
from concurrent.futures import ThreadPoolExecutor

def scan_file(filepath):
    engine = VulnerabilityEngine()  # Create per-thread
    engine.register_analyzer(StaticAnalyzer())
    return engine.scan(filepath)

with ThreadPoolExecutor(max_workers=4) as executor:
    results = executor.map(scan_file, file_list)
```

## Integration Architecture

```
┌─────────────────────────────────────────────┐
│         External Systems                    │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────┐    ┌──────────────┐     │
│  │   CI/CD      │    │   SIEM       │     │
│  │  Platforms   │    │  Systems     │     │
│  └──────┬───────┘    └──────┬───────┘     │
│         │                   │              │
│         └─────────┬─────────┘              │
│                   │                        │
│                   ▼                        │
│         ┌─────────────────┐               │
│         │  engin33r API   │               │
│         │  (Web Server)   │               │
│         └─────────────────┘               │
│                   │                        │
│        ┌──────────┴──────────┐            │
│        ▼                     ▼            │
│  ┌──────────────┐    ┌──────────────┐   │
│  │  REST API    │    │  CLI Tool    │   │
│  └──────────────┘    └──────────────┘   │
│                                          │
│        └──────────┬──────────┘           │
│                   ▼                      │
│       ┌─────────────────────┐           │
│       │ VulnerabilityEngine │           │
│       └─────────────────────┘           │
│                                          │
└─────────────────────────────────────────┘
```
