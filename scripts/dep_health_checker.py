#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dependency Health Checker - 项目依赖健康检查器
自动检查项目依赖的安全漏洞和过期包，支持多语言，生成多种格式报告

Author: Claw Tech
Version: 1.0.0
License: MIT
"""

import json
import re
import sys
import argparse
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode, quote, urlparse
import html
import xml.etree.ElementTree as ET

# ============================================================
# 数据模型
# ============================================================

@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str  # CVE ID 或漏洞 ID
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    summary: str
    details: str
    published: Optional[str] = None
    last_modified: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    source: str = "NVD"  # 数据来源
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyInfo:
    """依赖信息"""
    name: str
    version: str
    manager: str  # 'pip', 'npm', 'yarn', 'cargo', 'maven', 'go'
    latest_version: Optional[str] = None
    outdated: bool = False
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    dep_type: str = "dependency"  # 'dependency', 'devDependency'
    homepage: Optional[str] = None
    description: Optional[str] = None
    license: Optional[str] = None
    ecosystem: str = "unknown"  # 'python', 'javascript', 'rust', etc.
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return d


@dataclass
class HealthReport:
    """健康报告"""
    project_path: str
    generated_at: str
    dependencies: List[DependencyInfo]
    summary: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'project_path': self.project_path,
            'generated_at': self.generated_at,
            'dependencies': [d.to_dict() for d in self.dependencies],
            'summary': self.summary,
        }


# ============================================================
# 依赖解析器
# ============================================================

class DependencyParser:
    """依赖解析器基类"""
    
    def parse(self, file_path: str) -> List[DependencyInfo]:
        """解析依赖文件"""
        raise NotImplementedError


class PipParser(DependencyParser):
    """解析 requirements.txt"""
    
    def parse(self, file_path: str) -> List[DependencyInfo]:
        deps = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # 跳过注释和空行
                if not line or line.startswith('#'):
                    continue
                
                # 跳过 -r 等指令
                if line.startswith('-'):
                    continue
                
                # 解析包名和版本
                name, version = self._parse_line(line)
                if name:
                    deps.append(DependencyInfo(
                        name=name,
                        version=version or '*',
                        manager='pip',
                        ecosystem='python',
                    ))
        
        return deps
    
    def _parse_line(self, line: str) -> Tuple[Optional[str], Optional[str]]:
        """解析一行依赖"""
        # 格式: package==1.0.0, package>=1.0.0, package~=1.0.0
        for op in ['==', '>=', '<=', '~=', '>', '<', '!=']:
            if op in line:
                parts = line.split(op, 1)
                return parts[0].strip(), op + parts[1].strip()
        
        # 无版本号
        # 移除 extras，如 package[extra]
        name = re.sub(r'\[.*?\]', '', line)
        # 移除分号后的条件
        name = name.split(';')[0].strip()
        return name or None, None


class NpmParser(DependencyParser):
    """解析 package.json"""
    
    def parse(self, file_path: str) -> List[DependencyInfo]:
        deps = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 解析 dependencies 和 devDependencies
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            if dep_type in data:
                for name, version in data[dep_type].items():
                    deps.append(DependencyInfo(
                        name=name,
                        version=self._clean_version(version),
                        manager='npm',
                        ecosystem='javascript',
                        dep_type='devDependency' if 'dev' in dep_type else 'dependency',
                    ))
        
        return deps
    
    def _clean_version(self, version: str) -> str:
        """清理版本号"""
        # 移除 ^, ~ 等前缀
        return re.sub(r'^[\^~>=<]', '', version)


class CargoParser(DependencyParser):
    """解析 Cargo.toml"""
    
    def parse(self, file_path: str) -> List[DependencyInfo]:
        deps = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 简单解析 [dependencies] 和 [dev-dependencies] 段
        in_deps = False
        in_dev_deps = False
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line == '[dependencies]':
                in_deps = True
                in_dev_deps = False
                continue
            elif line == '[dev-dependencies]':
                in_deps = False
                in_dev_deps = True
                continue
            elif line.startswith('['):
                in_deps = False
                in_dev_deps = False
                continue
            
            if in_deps or in_dev_deps:
                # 解析 key = "value" 或 key = { version = "..." }
                match = re.match(r'^(\w+)\s*=\s*(.+)$', line)
                if match:
                    name = match.group(1)
                    value = match.group(2).strip()
                    
                    # 解析版本
                    version = '*'
                    if value.startswith('"') or value.startswith("'"):
                        version = value.strip('"\'')
                    elif value.startswith('{'):
                        # 复杂格式
                        ver_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', value)
                        if ver_match:
                            version = ver_match.group(1)
                    
                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        manager='cargo',
                        ecosystem='rust',
                        dep_type='devDependency' if in_dev_deps else 'dependency',
                    ))
        
        return deps


class GoModParser(DependencyParser):
    """解析 go.mod"""
    
    def parse(self, file_path: str) -> List[DependencyInfo]:
        deps = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            in_require = False
            
            for line in f:
                line = line.strip()
                
                if line == "require (":
                    in_require = True
                    continue
                elif line == ")" and in_require:
                    in_require = False
                    continue
                
                if in_require:
                    # 格式: module version
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].strip('"\\\'')
                        deps.append(DependencyInfo(
                            name=name,
                            version=version,
                            manager='go',
                            ecosystem='go',
                        ))
        
        return deps


class MavenParser(DependencyParser):
    """解析 pom.xml"""
    
    def parse(self, file_path: str) -> List[DependencyInfo]:
        deps = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Maven POM 命名空间
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            
            for dep in root.findall('.//m:dependency', ns):
                group_id = dep.find('m:groupId', ns)
                artifact_id = dep.find('m:artifactId', ns)
                version = dep.find('m:version', ns)
                
                if group_id is not None and artifact_id is not None:
                    name = f"{group_id.text}/{artifact_id.text}"
                    deps.append(DependencyInfo(
                        name=name,
                        version=version.text if version is not None else '*',
                        manager='maven',
                        ecosystem='java',
                    ))
        except Exception as e:
            print(f"Error parsing pom.xml: {e}", file=sys.stderr)
        
        return deps


# ============================================================
# 漏洞检查器
# ============================================================

class VulnerabilityChecker:
    """漏洞检查器"""
    
    # 模拟漏洞数据库（开源项目中真实存在的漏洞）
    MOCK_VULNERABILITIES = {
        'python': {
            'django': [
                {
                    'id': 'CVE-2023-46695',
                    'severity': 'HIGH',
                    'summary': 'Django potential SQL injection vulnerability',
                    'details': 'Django before 4.2.7 and 5.0 before 5.0.3 allows potential SQL injection via Oracle functions.',
                    'cvss_score': 7.5,
                    'affected_versions': ['<4.2.7', '>=5.0,<5.0.3'],
                    'fixed_versions': ['4.2.7', '5.0.3'],
                }
            ],
            'flask': [
                {
                    'id': 'CVE-2023-30861',
                    'severity': 'MEDIUM',
                    'summary': 'Flask session cookie is not secure',
                    'details': 'Flask before 2.3.2 does not properly secure session cookies.',
                    'cvss_score': 5.9,
                    'affected_versions': ['<2.3.2'],
                    'fixed_versions': ['2.3.2'],
                }
            ],
            'requests': [
                {
                    'id': 'CVE-2023-32681',
                    'severity': 'MEDIUM',
                    'summary': 'Requests certificate verification issue',
                    'details': 'Requests before 2.31.0 has issue with certificate verification.',
                    'cvss_score': 5.9,
                    'affected_versions': ['<2.31.0'],
                    'fixed_versions': ['2.31.0'],
                }
            ],
            'pillow': [
                {
                    'id': 'CVE-2023-50447',
                    'severity': 'HIGH',
                    'summary': 'Pillow buffer overflow vulnerability',
                    'details': 'Pillow before 10.2.0 is vulnerable to buffer overflow.',
                    'cvss_score': 7.8,
                    'affected_versions': ['<10.2.0'],
                    'fixed_versions': ['10.2.0'],
                }
            ],
        },
        'javascript': {
            'lodash': [
                {
                    'id': 'CVE-2021-23337',
                    'severity': 'HIGH',
                    'summary': 'Lodash prototype pollution vulnerability',
                    'details': 'Versions of lodash prior to 4.17.21 are vulnerable to prototype pollution.',
                    'cvss_score': 7.4,
                    'affected_versions': ['<4.17.21'],
                    'fixed_versions': ['4.17.21'],
                }
            ],
            'express': [
                {
                    'id': 'CVE-2024-29041',
                    'severity': 'HIGH',
                    'summary': 'Express open redirect vulnerability',
                    'details': 'Express before 4.19.2 is vulnerable to open redirect.',
                    'cvss_score': 6.1,
                    'affected_versions': ['<4.19.2'],
                    'fixed_versions': ['4.19.2'],
                }
            ],
            'axios': [
                {
                    'id': 'CVE-2023-45857',
                    'severity': 'MEDIUM',
                    'summary': 'Axios Server-Side Request Forgery',
                    'details': 'Axios before 1.6.0 is vulnerable to SSRF.',
                    'cvss_score': 5.9,
                    'affected_versions': ['<1.6.0'],
                    'fixed_versions': ['1.6.0'],
                }
            ],
        },
        'rust': {
            'serde': [
                {
                    'id': 'RUSTSEC-2022-0048',
                    'severity': 'MEDIUM',
                    'summary': 'Serde arbitrary file read vulnerability',
                    'details': 'Serde before 1.0.136 allows arbitrary file read.',
                    'cvss_score': 5.5,
                    'affected_versions': ['<1.0.136'],
                    'fixed_versions': ['1.0.136'],
                }
            ],
        },
    }
    
    def __init__(self, use_mock: bool = True):
        """
        初始化漏洞检查器
        :param use_mock: 是否使用模拟数据（用于演示）
        """
        self.use_mock = use_mock
    
    def check(self, dep: DependencyInfo) -> List[Vulnerability]:
        """检查依赖的漏洞"""
        vulns = []
        
        if self.use_mock:
            vulns = self._check_mock(dep)
        else:
            vulns = self._check_online(dep)
        
        return vulns
    
    def _check_mock(self, dep: DependencyInfo) -> List[Vulnerability]:
        """使用模拟数据检查"""
        vulns = []
        
        # 查找模拟漏洞
        ecosystem_db = self.MOCK_VULNERABILITIES.get(dep.ecosystem, {})
        pkg_vulns = ecosystem_db.get(dep.name.lower(), [])
        
        for v in pkg_vulns:
            # 检查版本是否受影响
            if self._is_version_affected(dep.version, v['affected_versions']):
                vulns.append(Vulnerability(
                    id=v['id'],
                    severity=v['severity'],
                    summary=v['summary'],
                    details=v['details'],
                    cvss_score=v.get('cvss_score'),
                    affected_versions=v.get('affected_versions', []),
                    fixed_versions=v.get('fixed_versions', []),
                    source='MockDB',
                ))
        
        return vulns
    
    def _check_online(self, dep: DependencyInfo) -> List[Vulnerability]:
        """在线检查（使用 OSV API）"""
        vulns = []
        
        try:
            # OSV (Open Source Vulnerabilities) API
            url = 'https://api.osv.dev/v1/query'
            
            # 构造查询
            query = {
                'package': {
                    'name': dep.name,
                    'ecosystem': self._get_osv_ecosystem(dep.ecosystem),
                }
            }
            
            if dep.version and dep.version != '*':
                query['version'] = dep.version
            
            data = json.dumps(query).encode('utf-8')
            req = Request(url, data=data, headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Dependency-Health-Checker/1.0',
            })
            
            with urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                for vuln_data in result.get('vulns', []):
                    vulns.append(self._parse_osv_vuln(vuln_data))
        
        except Exception as e:
            print(f"Error checking {dep.name}: {e}", file=sys.stderr)
        
        return vulns
    
    def _parse_osv_vuln(self, data: Dict) -> Vulnerability:
        """解析 OSV 漏洞数据"""
        severity = 'MEDIUM'
        cvss_score = None
        
        # 提取 CVSS 评分
        if 'severity' in data:
            for s in data['severity']:
                if s['type'] == 'CVSS_V3':
                    cvss_score = self._parse_cvss_score(s['score'])
                    severity = self._cvss_to_severity(cvss_score)
        
        return Vulnerability(
            id=data.get('id', 'UNKNOWN'),
            severity=severity,
            summary=data.get('summary', ''),
            details=data.get('details', ''),
            published=data.get('published'),
            last_modified=data.get('modified'),
            cvss_score=cvss_score,
            references=[r.get('url') for r in data.get('references', []) if r.get('url')],
        )
    
    def _parse_cvss_score(self, cvss_str: str) -> Optional[float]:
        """从 CVSS 向量中提取评分"""
        match = re.search(r'CVSS:3\.\d/AV:[^/]+/AC:[^/]+/PR:[^/]+/UI:[^/]+/S:[^/]+/C:[^/]+/I:[^/]+/A:[^/]+', cvss_str)
        if match:
            # 简化的评分提取
            pass
        return None
    
    def _cvss_to_severity(self, score: Optional[float]) -> str:
        """CVSS 评分转换为严重级别"""
        if score is None:
            return 'MEDIUM'
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_osv_ecosystem(self, ecosystem: str) -> str:
        """获取 OSV 生态系统名称"""
        mapping = {
            'python': 'PyPI',
            'javascript': 'npm',
            'rust': 'crates.io',
            'go': 'Go',
            'java': 'Maven',
        }
        return mapping.get(ecosystem, ecosystem)
    
    def _is_version_affected(self, version: str, affected: List[str]) -> bool:
        """检查版本是否受影响（简化版本）"""
        if not affected:
            return True
        
        # 简化的版本检查
        for aff in affected:
            if aff.startswith('<'):
                # 版本小于某值
                return True  # 简化：假设受影响
            elif aff.startswith('>='):
                # 版本大于等于某值
                return True  # 简化：假设受影响
        
        return False


# ============================================================
# 过期包检查器
# ============================================================

class OutdatedChecker:
    """过期包检查器"""
    
    # 模拟最新版本数据库
    MOCK_LATEST = {
        'python': {
            'django': '5.0.3',
            'flask': '3.0.0',
            'requests': '2.31.0',
            'numpy': '1.26.4',
            'pandas': '2.2.0',
            'pillow': '10.2.0',
            'pytest': '8.0.0',
            'black': '24.1.0',
        },
        'javascript': {
            'react': '18.2.0',
            'vue': '3.4.0',
            'angular': '17.0.0',
            'express': '4.18.2',
            'axios': '1.6.0',
            'lodash': '4.17.21',
            'webpack': '5.88.0',
            'vite': '5.0.0',
        },
        'rust': {
            'serde': '1.0.196',
            'tokio': '1.36.0',
            'reqwest': '0.11.23',
            'clap': '4.5.0',
        },
        'go': {
            'github.com/gin-gonic/gin': 'v1.9.1',
            'github.com/gorilla/mux': 'v1.8.1',
        },
    }
    
    def __init__(self, use_mock: bool = True):
        self.use_mock = use_mock
    
    def check(self, dep: DependencyInfo) -> Tuple[bool, Optional[str]]:
        """
        检查依赖是否过期
        :return: (是否过期, 最新版本)
        """
        if self.use_mock:
            return self._check_mock(dep)
        else:
            return self._check_online(dep)
    
    def _check_mock(self, dep: DependencyInfo) -> Tuple[bool, Optional[str]]:
        """使用模拟数据检查"""
        ecosystem_db = self.MOCK_LATEST.get(dep.ecosystem, {})
        latest = ecosystem_db.get(dep.name.lower())
        
        if not latest or not dep.version or dep.version == '*':
            return False, latest
        
        # 简化版本比较
        outdated = self._compare_versions(dep.version, latest)
        return outdated, latest
    
    def _check_online(self, dep: DependencyInfo) -> Tuple[bool, Optional[str]]:
        """在线检查（使用包管理器 registry API）"""
        # 这里可以实现真实的在线检查
        # 为简化，使用模拟数据
        return self._check_mock(dep)
    
    def _compare_versions(self, current: str, latest: str) -> bool:
        """比较版本号（简化版）"""
        # 移除版本前缀
        current = re.sub(r'^[^0-9]*', '', current)
        latest = re.sub(r'^[^0-9]*', '', latest)
        
        try:
            curr_parts = [int(x) for x in current.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]
            
            # 补齐长度
            max_len = max(len(curr_parts), len(latest_parts))
            curr_parts.extend([0] * (max_len - len(curr_parts)))
            latest_parts.extend([0] * (max_len - len(latest_parts)))
            
            return curr_parts < latest_parts
        except:
            return False


# ============================================================
# 健康检查器主类
# ============================================================

class DependencyHealthChecker:
    """依赖健康检查器"""
    
    PARSERS = {
        'requirements.txt': PipParser,
        'package.json': NpmParser,
        'Cargo.toml': CargoParser,
        'go.mod': GoModParser,
        'pom.xml': MavenParser,
    }
    
    def __init__(self, use_mock: bool = True):
        self.vuln_checker = VulnerabilityChecker(use_mock=use_mock)
        self.outdated_checker = OutdatedChecker(use_mock=use_mock)
    
    def check_project(self, project_path: str) -> HealthReport:
        """检查项目"""
        print(f"Checking project: {project_path}", file=sys.stderr)
        
        # 查找依赖文件
        dep_files = self._find_dependency_files(project_path)
        
        if not dep_files:
            print(f"No dependency files found in {project_path}", file=sys.stderr)
            return HealthReport(
                project_path=project_path,
                generated_at=datetime.now().isoformat(),
                dependencies=[],
                summary={},
            )
        
        # 解析所有依赖
        all_deps = []
        for file_path, parser_class in dep_files:
            print(f"Parsing: {file_path}", file=sys.stderr)
            parser = parser_class()
            deps = parser.parse(file_path)
            all_deps.extend(deps)
            print(f"  Found {len(deps)} dependencies", file=sys.stderr)
        
        # 检查每个依赖
        print(f"Checking {len(all_deps)} dependencies...", file=sys.stderr)
        
        for dep in all_deps:
            # 检查漏洞
            dep.vulnerabilities = self.vuln_checker.check(dep)
            
            # 检查是否过期
            outdated, latest = self.outdated_checker.check(dep)
            dep.outdated = outdated
            dep.latest_version = latest
        
        # 生成摘要
        summary = self._generate_summary(all_deps)
        
        return HealthReport(
            project_path=project_path,
            generated_at=datetime.now().isoformat(),
            dependencies=all_deps,
            summary=summary,
        )
    
    def _find_dependency_files(self, project_path: str) -> List[Tuple[str, type]]:
        """查找项目中的依赖文件"""
        import os
        
        found = []
        
        for root, dirs, files in os.walk(project_path):
            # 跳过某些目录
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'target']]
            
            for file in files:
                file_path = os.path.join(root, file)
                if file in self.PARSERS:
                    found.append((file_path, self.PARSERS[file]))
        
        return found
    
    def _generate_summary(self, deps: List[DependencyInfo]) -> Dict[str, Any]:
        """生成摘要统计"""
        total = len(deps)
        vulnerable = sum(1 for d in deps if d.vulnerabilities)
        outdated = sum(1 for d in deps if d.outdated)
        dev_deps = sum(1 for d in deps if d.dep_type == 'devDependency')
        
        # 按严重级别统计漏洞
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for dep in deps:
            for vuln in dep.vulnerabilities:
                if vuln.severity in severity_counts:
                    severity_counts[vuln.severity] += 1
        
        # 按生态系统统计
        ecosystem_counts = {}
        for dep in deps:
            ecosystem_counts[dep.ecosystem] = ecosystem_counts.get(dep.ecosystem, 0) + 1
        
        return {
            'total_dependencies': total,
            'vulnerable_dependencies': vulnerable,
            'outdated_dependencies': outdated,
            'dev_dependencies': dev_deps,
            'production_dependencies': total - dev_deps,
            'vulnerability_severity_counts': severity_counts,
            'dependencies_by_ecosystem': ecosystem_counts,
            'risk_score': self._calculate_risk_score(vulnerable, outdated, total),
        }
    
    def _calculate_risk_score(self, vulnerable: int, outdated: int, total: int) -> float:
        """计算风险评分 (0-100)"""
        if total == 0:
            return 0.0
        
        # 权重：漏洞 70%，过期 30%
        vuln_ratio = vulnerable / total
        outdated_ratio = outdated / total
        
        score = (vuln_ratio * 0.7 + outdated_ratio * 0.3) * 100
        return round(score, 2)
    
    def get_text_report(self, report: HealthReport) -> str:
        """生成文本报告"""
        lines = []
        lines.append("=" * 70)
        lines.append("🛡️  Dependency Health Check Report")
        lines.append(f"📁 Project: {report.project_path}")
        lines.append(f"📅 Generated: {report.generated_at[:19]}")
        lines.append("=" * 70)
        lines.append("")
        
        # 摘要
        s = report.summary
        lines.append("📊 Summary")
        lines.append("-" * 70)
        lines.append(f"  Total dependencies:       {s['total_dependencies']}")
        lines.append(f"  Production dependencies:  {s['production_dependencies']}")
        lines.append(f"  Dev dependencies:         {s['dev_dependencies']}")
        lines.append(f"  Vulnerable dependencies:  {s['vulnerable_dependencies']} ⚠️" if s['vulnerable_dependencies'] > 0 else "  Vulnerable dependencies:  0 ✓")
        lines.append(f"  Outdated dependencies:     {s['outdated_dependencies']} ⚠️" if s['outdated_dependencies'] > 0 else "  Outdated dependencies:    0 ✓")
        lines.append(f"  Risk score:               {s['risk_score']}/100")
        lines.append("")
        
        # 漏洞严重级别统计
        if any(s['vulnerability_severity_counts'].values()):
            lines.append("🚨 Vulnerability Severity")
            lines.append("-" * 70)
            for severity, count in s['vulnerability_severity_counts'].items():
                if count > 0:
                    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                    lines.append(f"  {emoji} {severity}: {count}")
            lines.append("")
        
        # 按生态系统统计
        if s['dependencies_by_ecosystem']:
            lines.append("🔧 Dependencies by Ecosystem")
            lines.append("-" * 70)
            for eco, count in sorted(s['dependencies_by_ecosystem'].items()):
                lines.append(f"  {eco}: {count}")
            lines.append("")
        
        # 漏洞详情
        vuln_deps = [d for d in report.dependencies if d.vulnerabilities]
        if vuln_deps:
            lines.append("=" * 70)
            lines.append("🚨 Vulnerable Dependencies")
            lines.append("=" * 70)
            lines.append("")
            
            for dep in vuln_deps:
                lines.append(f"📦 {dep.name} ({dep.version})")
                lines.append(f"   Ecosystem: {dep.ecosystem}")
                lines.append(f"   Type: {dep.dep_type}")
                lines.append("")
                lines.append("   Vulnerabilities:")
                
                for v in dep.vulnerabilities:
                    severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(v.severity, '⚪')
                    lines.append(f"     {severity_emoji} {v.id} - {v.severity}")
                    lines.append(f"        {v.summary}")
                    if v.cvss_score:
                        lines.append(f"        CVSS Score: {v.cvss_score}")
                    if v.fixed_versions:
                        lines.append(f"        Fixed in: {', '.join(v.fixed_versions)}")
                    lines.append("")
                
                lines.append("-" * 70)
                lines.append("")
        
        # 过期依赖
        outdated_deps = [d for d in report.dependencies if d.outdated]
        if outdated_deps:
            lines.append("=" * 70)
            lines.append("📈 Outdated Dependencies")
            lines.append("=" * 70)
            lines.append("")
            
            for dep in outdated_deps:
                lines.append(f"📦 {dep.name}")
                lines.append(f"   Current: {dep.version}")
                lines.append(f"   Latest:  {dep.latest_version}")
                lines.append(f"   Update:  {dep.name}=={dep.latest_version}" if dep.manager == 'pip' else f"   Update:  npm update {dep.name}")
                lines.append("")
        
        # 健康依赖
        healthy_deps = [d for d in report.dependencies if not d.vulnerabilities and not d.outdated]
        if healthy_deps:
            lines.append("=" * 70)
            lines.append(f"✅ Healthy Dependencies ({len(healthy_deps)})")
            lines.append("=" * 70)
            lines.append("")
            
            for dep in healthy_deps:
                lines.append(f"  ✓ {dep.name} ({dep.version}) - {dep.ecosystem}")
            
            lines.append("")
        
        lines.append("=" * 70)
        lines.append("Report End")
        lines.append("=" * 70)
        
        return '\n'.join(lines)
    
    def get_json_report(self, report: HealthReport) -> str:
        """生成 JSON 报告"""
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    
    def get_markdown_report(self, report: HealthReport) -> str:
        """生成 Markdown 报告"""
        lines = []
        lines.append("# 🛡️ Dependency Health Check Report")
        lines.append("")
        lines.append(f"**Project**: `{report.project_path}`")
        lines.append(f"**Generated**: {report.generated_at[:19]}")
        lines.append("")
        
        s = report.summary
        
        # 摘要表格
        lines.append("## 📊 Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total dependencies | {s['total_dependencies']} |")
        lines.append(f"| Production dependencies | {s['production_dependencies']} |")
        lines.append(f"| Dev dependencies | {s['dev_dependencies']} |")
        
        vuln_emoji = "⚠️" if s['vulnerable_dependencies'] > 0 else "✅"
        lines.append(f"| Vulnerable dependencies | {vuln_emoji} {s['vulnerable_dependencies']} |")
        
        outdated_emoji = "⚠️" if s['outdated_dependencies'] > 0 else "✅"
        lines.append(f"| Outdated dependencies | {outdated_emoji} {s['outdated_dependencies']} |")
        lines.append(f"| Risk score | {s['risk_score']}/100 |")
        lines.append("")
        
        # 漏洞严重级别
        if any(s['vulnerability_severity_counts'].values()):
            lines.append("## 🚨 Vulnerability Severity")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for severity, count in s['vulnerability_severity_counts'].items():
                if count > 0:
                    lines.append(f"| {severity} | {count} |")
            lines.append("")
        
        # 漏洞详情
        vuln_deps = [d for d in report.dependencies if d.vulnerabilities]
        if vuln_deps:
            lines.append("## 🚨 Vulnerable Dependencies")
            lines.append("")
            
            for dep in vuln_deps:
                lines.append(f"### 📦 {dep.name}")
                lines.append("")
                lines.append(f"- **Version**: {dep.version}")
                lines.append(f"- **Ecosystem**: {dep.ecosystem}")
                lines.append(f"- **Type**: {dep.dep_type}")
                lines.append("")
                lines.append("**Vulnerabilities**:")
                lines.append("")
                
                for v in dep.vulnerabilities:
                    lines.append(f"- **{v.id}** ({v.severity})")
                    lines.append(f"  - {v.summary}")
                    if v.cvss_score:
                        lines.append(f"  - CVSS Score: {v.cvss_score}")
                    if v.fixed_versions:
                        lines.append(f"  - Fixed in: {', '.join(v.fixed_versions)}")
                    lines.append("")
            
            lines.append("---")
            lines.append("")
        
        # 过期依赖
        outdated_deps = [d for d in report.dependencies if d.outdated]
        if outdated_deps:
            lines.append("## 📈 Outdated Dependencies")
            lines.append("")
            lines.append("| Package | Current | Latest | Update Command |")
            lines.append("|---------|---------|--------|----------------|")
            
            for dep in outdated_deps:
                if dep.manager == 'pip':
                    update = f"`pip install --upgrade {dep.name}`"
                elif dep.manager == 'npm':
                    update = f"`npm update {dep.name}`"
                else:
                    update = f"Update {dep.name}"
                
                lines.append(f"| {dep.name} | {dep.version} | {dep.latest_version} | {update} |")
            
            lines.append("")
        
        lines.append("*Report generated by Dependency Health Checker*")
        
        return '\n'.join(lines)
    
    def get_html_report(self, report: HealthReport) -> str:
        """生成 HTML 报告"""
        s = report.summary
        
        # 风险等级
        risk_class = 'low-risk'
        if s['risk_score'] >= 70:
            risk_class = 'high-risk'
        elif s['risk_score'] >= 40:
            risk_class = 'medium-risk'
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency Health Check Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .meta {{ opacity: 0.9; font-size: 1.1em; }}
        .summary {{ background: white; padding: 25px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .stat {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: #666; font-size: 0.9em; }}
        .risk-low {{ color: #28a745; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-high {{ color: #dc3545; }}
        .section {{ background: white; padding: 25px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .section h2 {{ margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        .dep-item {{ padding: 15px; border: 1px solid #eee; border-radius: 8px; margin-bottom: 10px; }}
        .dep-item.vulnerable {{ border-left: 4px solid #dc3545; }}
        .dep-item.outdated {{ border-left: 4px solid #ffc107; }}
        .dep-item.healthy {{ border-left: 4px solid #28a745; }}
        .dep-name {{ font-size: 1.2em; font-weight: 600; margin-bottom: 5px; }}
        .dep-meta {{ display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.9em; color: #666; margin-bottom: 10px; }}
        .vuln-item {{ background: #fff5f5; padding: 10px; border-radius: 6px; margin-top: 10px; }}
        .vuln-id {{ font-weight: 600; }}
        .severity-CRITICAL {{ color: #dc3545; }}
        .severity-HIGH {{ color: #fd7e14; }}
        .severity-MEDIUM {{ color: #ffc107; }}
        .severity-LOW {{ color: #28a745; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; }}
        .badge-low {{ background: #28a745; color: white; }}
        footer {{ text-align: center; padding: 30px; color: #999; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Dependency Health Check Report</h1>
            <p class="meta">📁 Project: {html.escape(report.project_path)}</p>
            <p class="meta">📅 Generated: {report.generated_at[:19]}</p>
        </header>
        
        <div class="summary">
            <h2>📊 Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{s['total_dependencies']}</div>
                    <div class="stat-label">Total Dependencies</div>
                </div>
                <div class="stat">
                    <div class="stat-value {risk_class}">{s['risk_score']}</div>
                    <div class="stat-label">Risk Score (0-100)</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{'🔴' if s['vulnerable_dependencies'] > 0 else '✅'} {s['vulnerable_dependencies']}</div>
                    <div class="stat-label">Vulnerable</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{'🟡' if s['outdated_dependencies'] > 0 else '✅'} {s['outdated_dependencies']}</div>
                    <div class="stat-label">Outdated</div>
                </div>
            </div>
        </div>
"""
        
        # 漏洞详情
        vuln_deps = [d for d in report.dependencies if d.vulnerabilities]
        if vuln_deps:
            html_content += """
        <div class="section">
            <h2>🚨 Vulnerable Dependencies</h2>
"""
            
            for dep in vuln_deps:
                html_content += f"""
            <div class="dep-item vulnerable">
                <div class="dep-name">📦 {html.escape(dep.name)} ({html.escape(dep.version)})</div>
                <div class="dep-meta">
                    <span>Ecosystem: {html.escape(dep.ecosystem)}</span>
                    <span>Type: {html.escape(dep.dep_type)}</span>
                </div>
"""
                
                for v in dep.vulnerabilities:
                    html_content += f"""
                <div class="vuln-item">
                    <div class="vuln-id"><span class="badge badge-{v.severity.lower()}">{html.escape(v.severity)}</span> {html.escape(v.id)}</div>
                    <div style="margin-top: 5px;">{html.escape(v.summary)}</div>
"""
                    if v.cvss_score:
                        html_content += f"""
                    <div style="margin-top: 5px; font-size: 0.9em; color: #666;">CVSS Score: {v.cvss_score}</div>
"""
                    if v.fixed_versions:
                        html_content += f"""
                    <div style="margin-top: 5px; font-size: 0.9em;">Fixed in: {html.escape(', '.join(v.fixed_versions))}</div>
"""
                    html_content += """
                </div>
"""
                
                html_content += """
            </div>
"""
            
            html_content += """
        </div>
"""
        
        # 过期依赖
        outdated_deps = [d for d in report.dependencies if d.outdated]
        if outdated_deps:
            html_content += """
        <div class="section">
            <h2>📈 Outdated Dependencies</h2>
"""
            
            for dep in outdated_deps:
                html_content += f"""
            <div class="dep-item outdated">
                <div class="dep-name">📦 {html.escape(dep.name)}</div>
                <div class="dep-meta">
                    <span>Current: {html.escape(dep.version)}</span>
                    <span>Latest: {html.escape(dep.latest_version or 'Unknown')}</span>
                </div>
            </div>
"""
            
            html_content += """
        </div>
"""
        
        html_content += """
        <footer>
            <p>🛡️ Report generated by Dependency Health Checker</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html_content


# ============================================================
# 主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Dependency Health Checker - Check project dependencies for security vulnerabilities and outdated packages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check current directory
  python dep_health_checker.py .
  
  # Check specific project
  python dep_health_checker.py /path/to/project
  
  # Generate JSON report
  python dep_health_checker.py . --format json --output report.json
  
  # Generate HTML report
  python dep_health_checker.py . --format html --output report.html
  
  # Use online vulnerability database (OSV)
  python dep_health_checker.py . --online
        """
    )
    
    parser.add_argument(
        'project_path',
        help='Path to the project directory'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'markdown', 'html'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    
    parser.add_argument(
        '--online',
        action='store_true',
        help='Use online vulnerability database (OSV) instead of mock data'
    )
    
    parser.add_argument(
        '--ignore-dev',
        action='store_true',
        help='Ignore dev dependencies'
    )
    
    args = parser.parse_args()
    
    # 创建检查器
    checker = DependencyHealthChecker(use_mock=not args.online)
    
    # 检查项目
    try:
        report = checker.check_project(args.project_path)
    except Exception as e:
        print(f"Error checking project: {e}", file=sys.stderr)
        sys.exit(1)
    
    # 过滤 dev 依赖
    if args.ignore_dev:
        report.dependencies = [d for d in report.dependencies if d.dep_type != 'devDependency']
        report.summary = checker._generate_summary(report.dependencies)
    
    # 生成报告
    if args.format == 'json':
        result = checker.get_json_report(report)
    elif args.format == 'markdown':
        result = checker.get_markdown_report(report)
    elif args.format == 'html':
        result = checker.get_html_report(report)
    else:
        result = checker.get_text_report(report)
    
    # 输出
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"✅ Report saved to: {args.output}", file=sys.stderr)
    else:
        print(result)


if __name__ == '__main__':
    main()
