# engin33r CLI Reference

## Installation

Once installed, use the `engin33r` command:

```bash
engin33r --help
```

## Global Options

```
usage: engin33r [-h] [-a ANALYZERS ...] [-o OUTPUT] [-f {json,text}] [-v] target

Positional Arguments:
  target                Target file or directory to scan

Optional Arguments:
  -h, --help           Show help message
  -a, --analyzers      Analyzers to use (default: static dependency)
  -o, --output         Output file path
  -f, --format         Output format: json or text (default: text)
  -v, --verbose        Enable verbose logging
```

## Examples

### Basic Scanning

```bash
# Scan single file
engin33r app.py

# Scan directory
engin33r ./src

# Scan with all analyzers
engin33r app.py -a static dependency ml anomaly complexity
```

### Output Options

```bash
# Output to console (default)
engin33r app.py

# Output to file
engin33r app.py -o report.txt

# JSON output
engin33r app.py -f json -o report.json

# Verbose JSON
engin33r app.py -f json -v
```

### Analyzer Selection

```bash
# Only static analysis (fast)
engin33r app.py -a static

# Only dependencies
engin33r app.py -a dependency

# Machine learning only
engin33r app.py -a ml

# Multiple analyzers
engin33r app.py -a static dependency ml
```

## Exit Codes

```
0 - Success, no critical/high vulnerabilities
1 - High severity vulnerabilities found (warning)
2 - Critical vulnerabilities found (failure)
```

## Environment Variables

```bash
# Set default analyzer
export ENGIN33R_ANALYZERS="static dependency ml"

# Set output format
export ENGIN33R_FORMAT="json"

# Enable debug logging
export ENGIN33R_DEBUG=1
```

## Integration Examples

### Bash Script

```bash
#!/bin/bash
set -e

echo "Running security scan..."
engin33r ./src -f json -o security_report.json

CRITICAL=$(grep '"CRITICAL"' security_report.json | wc -l)
HIGH=$(grep '"HIGH"' security_report.json | wc -l)

echo "Found $CRITICAL critical and $HIGH high vulnerabilities"

if [ $CRITICAL -gt 0 ]; then
    echo "Build failed: Critical vulnerabilities found"
    exit 1
fi

echo "Build passed"
exit 0
```

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install engin33r
        run: pip install engin33r[ml]
      
      - name: Run security scan
        run: |
          engin33r ./src -f json -o report.json || true
      
      - name: Check for critical vulnerabilities
        run: |
          CRITICAL=$(grep -c '"CRITICAL"' report.json || true)
          if [ $CRITICAL -gt 0 ]; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi
      
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.json
```

### GitLab CI

```yaml
security_scan:
  stage: security
  image: python:3.9
  script:
    - pip install engin33r[ml]
    - engin33r ./src -f json -o report.json
  artifacts:
    reports:
      sast: report.json
    paths:
      - report.json
  allow_failure: true
```

## Troubleshooting

### Command not found

```bash
# Ensure engin33r is installed
pip install --user engin33r

# Add to PATH if needed
export PATH="$PATH:$HOME/.local/bin"
```

### Permission denied

```bash
# Ensure execution permissions
chmod +x $(which engin33r)
```

### Module import errors

```bash
# Reinstall with dependencies
pip install --force-reinstall engin33r
```

## Performance Tips

1. **Use specific analyzers**: Faster than running all
   ```bash
   engin33r app.py -a static  # ~100ms
   ```

2. **Disable verbose output**: Reduces overhead
   ```bash
   engin33r app.py  # vs engin33r app.py -v
   ```

3. **Process large codebases in chunks**
   ```bash
   for file in src/*.py; do engin33r "$file"; done
   ```

4. **Cache ML models**
   ```python
   # Model loads once, reuse for multiple scans
   analyzer = MLVulnerabilityAnalyzer(model_path='cached_model.pkl')
   ```
