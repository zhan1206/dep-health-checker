# 🛡️ Dependency Health Checker

AI-powered dependency health checker that automatically scans your project dependencies for security vulnerabilities and outdated packages. Supports multiple languages and generates comprehensive reports.

[中文](README_zh.md) | English

## ✨ Features

- **Multi-Language Support**: Python (requirements.txt), JavaScript (package.json), Go (go.mod), Rust (Cargo.toml), Java (pom.xml)
- **Vulnerability Detection**: Checks for known security vulnerabilities (CVE, RUSTSEC, etc.)
- **Outdated Package Detection**: Identifies outdated dependencies
- **Multiple Report Formats**: Text, JSON, Markdown, HTML
- **CI/CD Integration**: GitHub Actions workflow included
- **Risk Scoring**: Calculates project risk score (0-100)

## 🔧 Supported Package Managers

| Language | Package Manager | Dependency File |
|----------|-----------------|----------------|
| Python | pip | `requirements.txt` |
| JavaScript/TypeScript | npm | `package.json` |
| Go | Go Modules | `go.mod` |
| Rust | Cargo | `Cargo.toml` |
| Java | Maven | `pom.xml` |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/zhan1206/dep-health-checker.git
cd dep-health-checker

# Python 3.8+ only - no additional dependencies needed (pure standard library)
```

### Basic Usage

```bash
# Check current directory (auto-detect dependency files)
python scripts/dep_health_checker.py .

# Check specific project
python scripts/dep_health_checker.py /path/to/project

# Generate HTML report
python scripts/dep_health_checker.py . --format html --output report.html

# Generate JSON report (for programmatic use)
python scripts/dep_health_checker.py . --format json --output report.json

# Use online vulnerability database (OSV API)
python scripts/dep_health_checker.py . --online

# Ignore dev dependencies
python scripts/dep_health_checker.py . --ignore-dev
```

## 📖 Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `project_path` | | Path to project directory | (required) |
| `--format` | `-f` | Output format | text |
| `--output` | `-o` | Output file path | stdout |
| `--online` | | Use online vulnerability DB | False |
| `--ignore-dev` | | Ignore dev dependencies | False |

## 📊 Output Format Examples

### Text (Default)
Human-readable colored output in terminal.

### JSON
Structured data for CI/CD pipelines and programmatic use:
```json
{
  "project_path": "/path/to/project",
  "generated_at": "2026-05-04T11:30:00",
  "dependencies": [...],
  "summary": {
    "total_dependencies": 45,
    "vulnerable_dependencies": 3,
    "outdated_dependencies": 8,
    "risk_score": 25.5
  }
}
```

### Markdown
GitHub-flavored markdown report.

### HTML
Beautiful, responsive web page with interactive elements.

## 🔒 Vulnerability Database

### Mock Database (Default)
Built-in database with common vulnerabilities for demonstration.

### OSV API (Online)
Open Source Vulnerabilities database from Google:
- URL: https://osv.dev/
- API: https://api.osv.dev/v1/query
- Supports: PyPI, npm, Go, Maven, crates.io, and more

## 📈 Risk Score Calculation

Risk score is calculated on a scale of 0-100:
- Vulnerabilities weight: 70%
- Outdated packages weight: 30%

Score interpretation:
- 0-20: Low risk 
- 21-50: Medium risk 
- 51-100: High risk 

## 🔄 GitHub Actions Integration

Add to your workflow (`.github/workflows/security-check.yml`):

```yaml
name: Dependency Security Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Run Dependency Health Check
        run: |
          python scripts/dep_health_checker.py . \
            --format html \
            --output dependency-report.html
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dependency-health-report
          path: dependency-report.html
      
      - name: Check for Critical Vulnerabilities
        run: |
          python scripts/dep_health_checker.py . --format json > report.json
          CRITICAL=$(python -c "import json; d=json.load(open('report.json')); print(d['summary']['vulnerability_severity_counts']['CRITICAL'])" 2>/dev/null || echo "0")
          if [ "$CRITICAL" -gt "0" ]; then
            echo "🚨 Critical vulnerabilities found: $CRITICAL"
            exit 1
          fi
```

## 🔧 Adding Custom Vulnerability Data

```python
from scripts.dep_health_checker import VulnerabilityChecker

# Access mock database
checker = VulnerabilityChecker(use_mock=True)

# Add custom vulnerability
checker.MOCK_VULNERABILITIES['python']['my_package'] = [
    {
        'id': 'CUSTOM-2024-0001',
        'severity': 'HIGH',
        'summary': 'Custom vulnerability description',
        'details': 'Detailed information...',
        'cvss_score': 7.5,
        'affected_versions': ['<1.0.0'],
        'fixed_versions': ['1.0.0'],
    }
]
```

## 🎯 Use Cases

1. **Pre-commit Security Check**: Scan dependencies before committing
2. **CI/CD Pipeline**: Integrate into automated build process
3. **Daily Security Audit**: Scheduled vulnerability scanning
4. **Dependency Audit Report**: Generate reports for compliance
5. **Tech Stack Assessment**: Evaluate project dependency health

## 📄 License

MIT License - free to use and modify for your projects.
