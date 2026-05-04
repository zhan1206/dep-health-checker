# 🛡️ Dependency Health Checker

AI 驱动的项目依赖健康检查器，自动扫描项目依赖的安全漏洞和过期包。支持多种语言，生成多格式报告。

[English](README.md) | 中文

## ✨ 功能特点

- **多语言支持**: Python (requirements.txt), JavaScript (package.json), Go (go.mod), Rust (Cargo.toml), Java (pom.xml)
- **漏洞检测**: 检测已知安全漏洞 (CVE, RUSTSEC 等)
- **过期包检测**: 识别过期依赖
- **多格式输出**: 文本、JSON、Markdown、HTML
- **CI/CD 集成**: 包含 GitHub Actions 工作流
- **风险评分**: 计算项目风险评分 (0-100)

## 🔧 支持的包管理器

| 语言 | 包管理器 | 依赖文件 |
|------|----------|----------|
| Python | pip | `requirements.txt` |
| JavaScript/TypeScript | npm | `package.json` |
| Go | Go Modules | `go.mod` |
| Rust | Cargo | `Cargo.toml` |
| Java | Maven | `pom.xml` |

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/zhan1206/dep-health-checker.git
cd dep-health-checker

# 仅需 Python 3.8+，无需额外依赖（纯标准库实现）
```

### 基本使用

```bash
# 检查当前目录（自动检测依赖文件）
python scripts/dep_health_checker.py .

# 检查指定项目
python scripts/dep_health_checker.py /path/to/project

# 生成 HTML 报告
python scripts/dep_health_checker.py . --format html --output report.html

# 生成 JSON 报告（用于程序化处理）
python scripts/dep_health_checker.py . --format json --output report.json

# 使用在线漏洞数据库 (OSV API)
python scripts/dep_health_checker.py . --online

# 忽略 dev 依赖
python scripts/dep_health_checker.py . --ignore-dev
```

## 📖 命令行选项

| 选项 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `project_path` | | 项目目录路径 | （必需） |
| `--format` | `-f` | 输出格式 | text |
| `--output` | `-o` | 输出文件路径 | 标准输出 |
| `--online` | | 使用在线漏洞数据库 | False |
| `--ignore-dev` | | 忽略 dev 依赖 | False |

## 📊 输出格式示例

### 文本格式（默认）
```
======================================================================
🛡️ Dependency Health Check Report
📁 Project: /path/to/project
📅 Generated: 2026-05-04T11:30:00
======================================================================

📊 Summary
----------------------------------------------------------------------
  Total dependencies:       45
  Production dependencies:  30
  Dev dependencies:         15
  Vulnerable dependencies:  3 ⚠️
  Outdated dependencies:     8 ⚠️
  Risk score:               25.50

🚨 Vulnerable Dependencies
======================================================================

📦 django (3.2.0)
   Ecosystem: python
   Type: dependency

   Vulnerabilities:
     🔴 CVE-2023-46695 - HIGH
        Django potential SQL injection vulnerability
        CVSS Score: 7.5
        Fixed in: 4.2.7, 5.0.3
```

### JSON 格式
适合 CI/CD 流水线和程序化处理。

### Markdown 格式
适合 GitHub 文档和 Pull Request 评论。

### HTML 格式
美观的响应式网页，带有交互元素。

## 🔒 漏洞数据库

### 模拟数据库（默认）
内置常见漏洞数据库，用于演示。

### OSV API（在线）
来自 Google 的开源漏洞数据库：
- 网址: https://osv.dev/
- API: https://api.osv.dev/v1/query
- 支持: PyPI, npm, Go, Maven, crates.io 等

## 📈 风险评分计算

风险评分按 0-100 计算：
- 漏洞权重: 70%
- 过期包权重: 30%

评分解释：
- 0-20: 低风险 
- 21-50: 中等风险 
- 51-100: 高风险 

## 🔄 GitHub Actions 集成

添加到工作流 (`.github/workflows/security-check.yml`):

```yaml
name: Dependency Security Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # 每天凌晨 2 点
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

## 🔧 添加自定义漏洞数据

```python
from scripts.dep_health_checker import VulnerabilityChecker

# 访问模拟数据库
checker = VulnerabilityChecker(use_mock=True)

# 添加自定义漏洞
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

## 🎯 使用场景

1. **提交前安全检查**: 提交前扫描依赖
2. **CI/CD 流水线**: 集成到自动化构建流程
3. **每日安全审计**: 定期漏洞扫描
4. **依赖审计报告**: 生成合规报告
5. **技术栈评估**: 评估项目依赖健康度

## 📄 许可证

MIT 许可证 - 可自由使用和修改。
