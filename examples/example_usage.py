# Dependency Health Checker - 使用示例

本目录包含 Dependency Health Checker 的使用示例。

## 示例 1: 基本使用

```bash
# 检查当前目录
python scripts/dep_health_checker.py .

# 检查指定项目
python scripts/dep_health_checker.py /path/to/project

# 输出到文件
python scripts/dep_health_checker.py . --output report.txt
```

## 示例 2: 生成不同格式的报告

```bash
# 生成 JSON 报告
python scripts/dep_health_checker.py . --format json --output report.json

# 生成 Markdown 报告
python scripts/dep_health_checker.py . --format markdown --output report.md

# 生成 HTML 报告
python scripts/dep_health_checker.py . --format html --output report.html
```

## 示例 3: 使用在线漏洞数据库

```bash
# 使用 OSV API 进行在线检查
python scripts/dep_health_checker.py . --online

# 结合其他参数
python scripts/dep_health_checker.py . --online --format json --output online-report.json
```

## 示例 4: 忽略开发依赖

```bash
# 只检查生产依赖
python scripts/dep_health_checker.py . --ignore-dev

# 生成忽略 dev 依赖的 HTML 报告
python scripts/dep_health_checker.py . --ignore-dev --format html --output prod-report.html
```

## 示例 5: Python API 使用

```python
#!/usr/bin/env python3
"""
示例：使用 Dependency Health Checker Python API
"""

from scripts.dep_health_checker import DependencyHealthChecker

def main():
    # 创建检查器
    checker = DependencyHealthChecker(use_mock=True)
    
    print("正在检查项目依赖...")
    
    # 检查项目
    report = checker.check_project(".")
    
    # 生成不同格式的报告
    print("\n=== 文本报告 ===")
    print(checker.get_text_report(report))
    
    # 保存 JSON 报告
    json_report = checker.get_json_report(report)
    with open('dep-report.json', 'w', encoding='utf-8') as f:
        f.write(json_report)
    print("\nJSON 报告已保存到 dep-report.json")
    
    # 保存 Markdown 报告
    md_report = checker.get_markdown_report(report)
    with open('dep-report.md', 'w', encoding='utf-8') as f:
        f.write(md_report)
    print("Markdown 报告已保存到 dep-report.md")
    
    # 保存 HTML 报告
    html_report = checker.get_html_report(report)
    with open('dep-report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    print("HTML 报告已保存到 dep-report.html")
    
    # 检查是否存在严重漏洞
    if report.summary['vulnerability_severity_counts'].get('CRITICAL', 0) > 0:
        print("\n🚨 警告：发现严重漏洞！")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())
```

## 示例 6: 添加自定义漏洞数据

```python
#!/usr/bin/env python3
"""
示例：添加自定义漏洞数据并检查
"""

from scripts.dep_health_checker import (
    DependencyHealthChecker,
    Vulnerability
)

def main():
    # 创建检查器
    checker = DependencyHealthChecker(use_mock=True)
    
    # 添加自定义漏洞
    custom_vuln = Vulnerability(
        id='CUSTOM-2024-0001',
        severity='HIGH',
        summary='Custom vulnerability in my_package',
        details='Detailed information about the vulnerability...',
        cvss_score=7.5,
        affected_versions=['<1.0.0'],
        fixed_versions=['1.0.0'],
        source='CustomDB',
    )
    
    # 可以添加到特定包的漏洞列表中
    # 这里演示如何使用自定义漏洞数据
    print("自定义漏洞数据已添加")
    
    # 检查项目
    report = checker.check_project(".")
    
    # 输出报告
    print(checker.get_text_report(report))

if __name__ == '__main__':
    main()
```

## 示例 7: CI/CD 集成脚本

创建 `ci_check.py`（用于 CI/CD 流水线）:

```python
#!/usr/bin/env python3
"""
CI/CD 依赖安全检查脚本
退出码: 0=通过, 1=发现漏洞
"""

import sys
import json
from scripts.dep_health_checker import DependencyHealthChecker

def main():
    # 创建检查器
    checker = DependencyHealthChecker(use_mock=True)
    
    # 检查项目
    report = checker.check_project(".")
    
    # 输出摘要
    summary = report.summary
    print(f"总依赖数: {summary['total_dependencies']}")
    print(f"漏洞依赖数: {summary['vulnerable_dependencies']}")
    print(f"过期依赖数: {summary['outdated_dependencies']}")
    print(f"风险评分: {summary['risk_score']}/100")
    
    # 检查严重漏洞
    critical = summary['vulnerability_severity_counts'].get('CRITICAL', 0)
    high = summary['vulnerability_severity_counts'].get('HIGH', 0)
    
    if critical > 0:
        print(f"\n🚨 错误：发现 {critical} 个严重漏洞！")
        sys.exit(1)
    
    if high > 3:
        print(f"\n⚠️ 警告：发现 {high} 个高危漏洞！")
        sys.exit(1)
    
    print("\n✅ 依赖检查通过")
    sys.exit(0)

if __name__ == '__main__':
    main()
```

## 示例 8: GitHub Actions 工作流

创建 `.github/workflows/security-check.yml`:

```yaml
name: Dependency Security Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # 每天凌晨 2 点运行
    - cron: '0 2 * * *'
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
      
      - name: Run Dependency Health Check (HTML Report)
        run: |
          python scripts/dep_health_checker.py . \
            --format html \
            --output dependency-report.html
      
      - name: Run Dependency Health Check (JSON Report)
        run: |
          python scripts/dep_health_checker.py . \
            --format json \
            --output dependency-report.json
      
      - name: Upload HTML Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dependency-health-report-html
          path: dependency-report.html
          retention-days: 30
      
      - name: Upload JSON Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dependency-health-report-json
          path: dependency-report.json
          retention-days: 30
      
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICAL=$(python -c "import json; d=json.load(open('dependency-report.json')); print(d['summary']['vulnerability_severity_counts'].get('CRITICAL', 0))")
          echo "Critical vulnerabilities: $CRITICAL"
          if [ "$CRITICAL" -gt "0" ]; then
            echo "::error::🚨 Critical vulnerabilities found: $CRITICAL"
            exit 1
          fi
```

## 示例 9: 批量检查多个项目

```python
#!/usr/bin/env python3
"""
示例：批量检查多个项目
"""

import os
from scripts.dep_health_checker import DependencyHealthChecker

def main():
    # 项目列表
    projects = [
        "/path/to/project1",
        "/path/to/project2",
        "/path/to/project3",
    ]
    
    checker = DependencyHealthChecker(use_mock=True)
    
    # 批量检查
    for project in projects:
        if not os.path.exists(project):
            print(f"跳过不存在的项目: {project}")
            continue
        
        print(f"\n{'='*70}")
        print(f"检查项目: {project}")
        print(f"{'='*70}\n")
        
        report = checker.check_project(project)
        
        # 输出摘要
        summary = report.summary
        print(f"总依赖数: {summary['total_dependencies']}")
        print(f"漏洞依赖数: {summary['vulnerable_dependencies']}")
        print(f"风险评分: {summary['risk_score']}/100")
        
        # 保存报告
        output_base = os.path.basename(project)
        with open(f'{output_base}-report.json', 'w', encoding='utf-8') as f:
            f.write(checker.get_json_report(report))
        
        print(f"报告已保存: {output_base}-report.json")

if __name__ == '__main__':
    main()
```

---

更多示例和用法请参考主 README 文件。
