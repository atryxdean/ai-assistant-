# Contributing to engin33r

## Code of Conduct

This project is committed to providing a welcoming and inspiring community for all. Please read and follow our Code of Conduct.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Create a new issue with:
   - Clear, descriptive title
   - Detailed description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Use the Issues tab with label `enhancement`
2. Clearly describe the feature and use case
3. Explain how it would benefit users
4. Include examples if possible

### Development Setup

```bash
# Clone repository
git clone https://github.com/atryxdean/engin33r.git
cd engin33r

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=engin33r --cov-report=html
```

### Code Style

We use:
- **Black** for code formatting
- **Flake8** for linting
- **MyPy** for type checking

```bash
# Format code
black engin33r/ tests/

# Check linting
flake8 engin33r/ tests/

# Type checking
mypy engin33r/
```

### Creating a Pull Request

1. Create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit
   ```bash
   git add .
   git commit -m "Add descriptive commit message"
   ```

3. Push to your fork
   ```bash
   git push origin feature/your-feature-name
   ```

4. Open a Pull Request with:
   - Clear description of changes
   - Reference to related issues
   - Tests for new functionality
   - Documentation updates

### Adding New Analyzers

1. Create a new file in `engin33r/analyzers/`
2. Inherit from `VulnerabilityAnalyzer`
3. Implement the `analyze()` method
4. Add unit tests in `tests/`
5. Update documentation

```python
from engin33r.analyzers.base import VulnerabilityAnalyzer
from engin33r.core.vulnerability import Vulnerability

class MyAnalyzer(VulnerabilityAnalyzer):
    def __init__(self):
        super().__init__(
            name="MyAnalyzer",
            description="Description of what it does"
        )
    
    def analyze(self, target, context=None):
        vulnerabilities = []
        # Your logic here
        return vulnerabilities
```

### Testing Requirements

- Minimum 80% code coverage
- All tests must pass
- Tests should cover:
  - Normal cases
  - Edge cases
  - Error handling

```bash
# Run specific test
pytest tests/test_engine.py::test_engine_initialization

# Run with verbose output
pytest tests/ -vv

# Run with specific marker
pytest tests/ -m unit
```

### Documentation

- Update README.md for user-facing changes
- Update docs/ for architecture/design changes
- Use docstrings for all public APIs
- Keep CHANGELOG.md updated

### Release Process

1. Update version in `engin33r/__init__.py`
2. Update CHANGELOG.md
3. Create a git tag
4. Push to PyPI

```bash
# Build distribution
python setup.py sdist bdist_wheel

# Upload to PyPI
twine upload dist/*
```

## Project Structure

```
engin33r/
├── core/                  # Core functionality
│   ├── vulnerability.py   # Vulnerability models
│   └── engine.py         # Main engine
├── analyzers/             # Vulnerability analyzers
│   ├── base.py           # Base analyzer class
│   ├── static.py         # Static analysis
│   └── dependency.py     # Dependency checking
├── ml/                    # Machine learning
│   ├── __init__.py       # ML analyzer
│   └── anomaly.py        # Anomaly detection
├── formatters/            # Output formatters
│   ├── base.py           # Base formatter
│   ├── json_formatter.py # JSON output
│   └── text_formatter.py # Text output
├── cli.py                 # Command-line interface
and __init__.py
├── tests/                 # Test suite
├── docs/                  # Documentation
└── setup.py              # Package setup
```

## Getting Help

- GitHub Issues: Report bugs and ask questions
- Discussions: General questions and ideas
- Documentation: Read docs/ for detailed info

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
