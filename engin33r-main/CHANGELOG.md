# Changelog

All notable changes to engin33r will be documented in this file.

## [0.1.0] - 2026-06-29

### Added

- Initial release of engin33r
- Core vulnerability detection engine
- Vulnerability model with OWASP/CWE classification
- Static code analyzer with pattern detection
- Dependency vulnerability analyzer
- Machine learning-based vulnerability detection
  - TF-IDF vectorization
  - Random Forest classification
  - Confidence-based scoring
- Code anomaly detection
- Code complexity analysis
- Report generation (JSON and Text formatters)
- CLI interface with multiple options
- Comprehensive test suite
- Full documentation
- Support for Python 3.8+

### Features

#### Core Engine
- Multi-analyzer support with registration system
- Vulnerability aggregation from multiple sources
- Flexible filtering by severity, type, and status
- Report generation with statistics
- Extensible analyzer architecture

#### Detection Methods
1. **Static Analysis**: Pattern-based detection of common vulnerabilities
2. **Dependency Analysis**: Known vulnerability database checks
3. **ML Analysis**: Machine learning pattern recognition
4. **Anomaly Detection**: Statistical anomaly detection
5. **Complexity Analysis**: Code complexity metrics

#### Vulnerability Classification
- OWASP Top 10 categories
- CWE/SANS mapping support
- CVSS scoring support
- Severity levels (Critical, High, Medium, Low, Info)
- Remediation status tracking

#### Output Formats
- JSON: Machine-readable vulnerability data
- Text: Human-readable formatted reports
- Extensible formatter system for custom formats

#### CLI Features
- Multiple analyzer selection
- Output file specification
- Format selection (JSON/Text)
- Verbose logging
- Exit codes for CI/CD integration

### Documentation

- Getting Started Guide
- Architecture Documentation
- API Reference
- CLI Reference
- ML Configuration Guide
- Comprehensive Examples
- Contributing Guidelines

### Dependencies

**Core**:
- pydantic >= 1.10.0
- requests >= 2.28.0
- pyyaml >= 6.0
- colorama >= 0.4.6
- tabulate >= 0.9.0

**Optional (ML)**:
- scikit-learn >= 0.24
- numpy >= 1.19
- joblib >= 1.0

**Development**:
- pytest >= 7.0
- pytest-cov >= 4.0
- black >= 22.0
- flake8 >= 5.0
- mypy >= 0.990

### Known Limitations

- Single-threaded execution (create per-thread engine for concurrent scanning)
- Pattern-based static analysis may have false positives/negatives
- ML models trained on common vulnerability patterns
- Dependency analyzer limited to package.json and requirements.txt
- Code complexity analysis is simplified (not full cyclomatic complexity)

### Future Enhancements

- [ ] SBOM (Software Bill of Materials) support
- [ ] Integration with vulnerability databases (NVD, OSV)
- [ ] Custom rule system
- [ ] Advanced remediation recommendations
- [ ] Performance improvements and benchmarking
- [ ] Additional language support beyond Python
- [ ] Web UI for reports
- [ ] Integration with more package managers
- [ ] Webhook support for CI/CD systems
- [ ] Distributed scanning support

---

For detailed changes and updates, see [GitHub Releases](https://github.com/atryxdean/engin33r/releases)
