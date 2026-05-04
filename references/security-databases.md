# 安全漏洞数据库参考

本文档介绍 Dependency Health Checker 支持的安全漏洞数据库。

## 数据库列表

| 数据库 | 覆盖范围 | URL | API |
|---------|----------|-----|-----|
| OSV (Open Source Vulnerabilities) | 多语言 | https://osv.dev/ | https://api.osv.dev/v1/query |
| NVD (National Vulnerability Database) | CVE | https://nvd.nist.gov/ | https://nvd.nist.gov/developers/vulnerabilities |
| PyUP | Python | https://pyup.io/ | - |
| npm Audit | Node.js | https://npmjs.com/ | `npm audit` |
| RustSec | Rust | https://rustsec.org/ | https://rustsec.org/database/ |
| Go Vulnerability Database | Go | https://vuln.go.dev/ | https://vuln.go.dev/ |

## OSV (Open Source Vulnerabilities)

Google 维护的开源漏洞数据库，支持多种生态系统。

### API 使用

**查询漏洞**:
```bash
curl -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "package": {
      "name": "django",
      "ecosystem": "PyPI"
    }
  }'
```

**按 ID 查询**:
```bash
curl https://api.osv.dev/v1/vulns/CVE-2023-46695
```

### 支持的生态系统

- PyPI (Python)
- npm (JavaScript)
- Go
- Maven (Java)
- NuGet (.NET)
- crates.io (Rust)
- Packagist (PHP)
- RubyGems (Ruby)
- CocoaPods (iOS)

### 响应格式

```json
{
  "vulns": [
    {
      "id": "CVE-2023-46695",
      "published": "2024-01-01T00:00:00Z",
      "modified": "2024-01-02T00:00:00Z",
      "summary": "Vulnerability summary",
      "details": "Detailed description...",
      "severity": [
        {
          "type": "CVSS_V3",
          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      ],
      "affected": [...],
      "references": [...]
    }
  ]
}
```

## NVD (National Vulnerability Database)

美国国家标准与技术研究院维护的漏洞数据库。

### API v2

```bash
# 按 CVE ID 查询
curl https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-46695

# 按关键词查询
curl https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=django
```

### 速率限制

- 无 API Key: 5 次/秒
- 有 API Key: 50 次/秒

### 获取 API Key

访问: https://nvd.nist.gov/developers/request-an-api-key

## RustSec

Rust 生态系统的安全漏洞数据库。

### 使用 cargo-audit

```bash
# 安装
cargo install cargo-audit

# 检查
cargo audit
```

### 数据库格式

RustSec 数据库使用 TOML 格式：
```toml
[advisory]
id = "RUSTSEC-2022-0048"
package = "serde"
date = "2022-01-01"
url = "https://github.com/advisory/..."
description = "Description of vulnerability"
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

[affected.functions]
"serde::function" = [">=1.0.0, <1.0.136"]

[patched]
fix = ">=1.0.136"
```

## npm Audit

Node.js 包审计工具，内置于 npm。

### 使用

```bash
# 检查项目
npm audit

# 修复漏洞
npm audit fix

# 仅输出 JSON
npm audit --json
```

### 输出格式

```json
{
  "vulnerabilities": {
    "lodash": {
      "severity": "high",
      "vulnerable_versions": "<4.17.21",
      "patched_versions": ">=4.17.21",
      "finding": [...]
    }
  },
  "metadata": {
    "vulnerabilities": {
      "info": 0,
      "low": 2,
      "moderate": 1,
      "high": 1,
      "critical": 0
    }
  }
}
```

## Go Vulnerability Database

Go 官方漏洞数据库。

### 使用 govulncheck

```bash
# 安装
go install golang.org/x/vulncheck/cmd/govulncheck@latest

# 检查
govulncheck ./...
```

### API

```bash
# 查询模块漏洞
curl https://vuln.go.dev/ID/GO-2022-1144
```

## 集成建议

### 本地开发

```python
# 使用本地工具
import subprocess

def run_npm_audit(project_path):
    result = subprocess.run(
        ['npm', 'audit', '--json'],
        cwd=project_path,
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)
```

### CI/CD

```yaml
# GitHub Actions 示例
- name: Run Security Checks
  run: |
    # Python
    pip install safety
    safety check
    
    # JavaScript
    npm audit
    
    # Go
    govulncheck ./...
    
    # Rust
    cargo audit
```

## 漏洞严重级别

### CVSS v3 评分

| 评分范围 | 严重级别 |
|----------|----------|
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

### CVSS v3 向量示例

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

AV: Attack Vector (攻击向量)
  - N: Network (网络)
  - A: Adjacent (相邻网络)
  - L: Local (本地)
  - P: Physical (物理)

AC: Attack Complexity (攻击复杂度)
  - L: Low (低)
  - H: High (高)

PR: Privileges Required (所需权限)
  - N: None (无)
  - L: Low (低)
  - H: High (高)

UI: User Interaction (用户交互)
  - N: None (无)
  - R: Required (需要)

S: Scope (范围)
  - U: Unchanged (不变)
  - C: Changed (改变)

C: Confidentiality Impact (机密性影响)
I: Integrity Impact (完整性影响)
A: Availability Impact (可用性影响)
  - N: None (无)
  - L: Low (低)
  - H: High (高)
```

## 最佳实践

1. **定期扫描**: 设置每日/每周自动扫描
2. **多源验证**: 使用多个漏洞数据库交叉验证
3. **及时更新**: 发现漏洞后立即更新依赖
4. **最小化依赖**: 减少依赖数量以降低风险
5. **锁定版本**: 使用 lock 文件锁定依赖版本
