"""公共工具函数"""

import re
import socket
from typing import Optional, List
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse


# ── URL 工具 ──

def normalize_url(url: str) -> str:
    """规范化 URL，自动补全协议"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def parse_url(url: str) -> dict:
    """解析 URL 返回各部分"""
    u = urlparse(normalize_url(url))
    return {
        "scheme": u.scheme,
        "host": u.hostname or "",
        "port": u.port or (443 if u.scheme == "https" else 80),
        "path": u.path or "/",
        "query": u.query,
        "fragment": u.fragment,
    }


def extract_params_from_url(url: str, params_str: str = "") -> List[str]:
    """从 URL 或参数字符串中提取参数列表。
    优先使用 params_str（逗号分隔），否则从 URL query 中自动提取。
    """
    test_params = [p.strip() for p in params_str.split(",") if p.strip()]
    if not test_params:
        parsed = urlparse(url)
        test_params = list(parse_qs(parsed.query).keys())
    return test_params


def build_url_with_param(url: str, param: str, value: str) -> str:
    """将参数设置到 URL 的 query string 中并返回新 URL。"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_qs))


# ── 参数构建 ──

def build_param_list(params_str: str) -> List[str]:
    """解析参数字符串 'a,b,c' 为列表"""
    if not params_str:
        return []
    return [p.strip() for p in params_str.split(",") if p.strip()]


# ── WAF 预检（消除各扫描工具的重复代码） ──

async def run_waf_precheck(
    url: str,
    waf_mode: str = "safe",
    request_delay: float = 0.5,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> List[str]:
    """执行 WAF 预检并以列表形式返回格式化输出行。
    如果 waf_mode == "off"，返回空列表。
    """
    from xuanmu_bb.data.waf import waf_precheck

    if waf_mode == "off":
        return []

    lines = []
    w = await waf_precheck(url, waf_mode=waf_mode, request_delay=request_delay,
                           proxy=proxy, cookie=cookie, auth_token=auth_token)
    waf_name = w.get("waf_name", "")
    waf_delay = w.get("delay", 0)
    if w["waf_detected"]:
        lines.append(f"[!] WAF 检测: {waf_name}  自动降速至 {waf_delay}s")
    for s in w.get("suggestions", []):
        lines.append(f"    绕过: {s}")
    return lines


# ── 域名 / IP 校验 ──

def is_valid_domain(domain: str) -> bool:
    """检查域名格式"""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain.strip()))


def is_valid_ip(ip: str) -> bool:
    """检查 IP 格式"""
    try:
        socket.inet_aton(ip.strip())
        return True
    except OSError:
        return False


def is_valid_host(target: str) -> bool:
    """检查是有效的域名或 IP"""
    target = target.strip()
    return is_valid_domain(target) or is_valid_ip(target)


# ── 端口解析 ──

def parse_ports(port_str: str) -> list[int]:
    """解析端口字符串，支持 80,443,8000-8010 格式"""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return sorted(set(ports))


# ── HTML 提取 ──

def extract_title(html: str) -> str:
    """从 HTML 中提取标题"""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""


def extract_forms(html: str) -> list[dict]:
    """从 HTML 中提取表单"""
    forms = []
    for m in re.finditer(
        r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        action = m.group(1)
        body = m.group(2)
        inputs = []
        for im in re.finditer(
            r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
        ):
            inputs.append(im.group(1))
        for im in re.finditer(
            r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
        ):
            inputs.append(im.group(1))
        for im in re.finditer(
            r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
        ):
            inputs.append(im.group(1))
        method_m = re.search(r'method=["\'](get|post)["\']', body, re.IGNORECASE)
        method = method_m.group(1).upper() if method_m else "GET"
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def extract_js_urls(html: str, base_url: str = "") -> list[str]:
    """提取 HTML 中的 JS 文件 URL"""
    urls = []
    for m in re.finditer(
        r'<script[^>]*src=["\']([^"\']*)["\']', html, re.IGNORECASE
    ):
        src = m.group(1)
        if src:
            urls.append(urljoin(base_url, src) if base_url else src)
    return urls


def extract_links(html: str, base_url: str = "") -> list[str]:
    """提取 HTML 中的所有链接"""
    links = []
    for m in re.finditer(
        r'<a[^>]*href=["\']([^"\']*)["\']', html, re.IGNORECASE
    ):
        href = m.group(1)
        if href and not href.startswith(("javascript:", "#", "mailto:")):
            links.append(urljoin(base_url, href) if base_url else href)
    return links


def truncate(text: str, max_len: int = 500) -> str:
    """截断文本"""
    return text[:max_len] + "..." if len(text) > max_len else text


# ── 结构化输出（ResultBuilder）──

import time as _time
from dataclasses import dataclass, field, asdict


class ResultBuilder:
    """统一的结构化扫描结果构建器。

    所有工具共用此格式，返回 dict 由 MCP 框架自动序列化为 JSON。
    """

    def __init__(self, tool_name: str, target: str):
        self.data = {
            "tool": tool_name,
            "target": target,
            "status": "no_findings",
            "summary": "",
            "findings": [],
            "waf": None,
            "metadata": {
                "duration_ms": 0,
                "requests_sent": 0,
                "params_tested": [],
            },
            "suggestions": [],
        }
        self._t0 = _time.monotonic()
        self._req_count = 0

    def set_waf(self, waf_name: str, suggestions: list):
        if waf_name:
            self.data["waf"] = {"detected": True, "name": waf_name, "suggestions": suggestions}
        else:
            self.data["waf"] = {"detected": False, "name": "", "suggestions": []}

    def inc_requests(self, n: int = 1):
        self._req_count += n

    def add_finding(self, finding: dict):
        """添加一个漏洞发现。
        finding 必须包含: param, payload, type, severity, evidence
        可选: verified, verified_by, status_code, length_diff, time_diff
        """
        self.data["findings"].append(finding)

    def add_suggestion(self, text: str):
        self.data["suggestions"].append(text)

    def set_params_tested(self, params: list):
        self.data["metadata"]["params_tested"] = params

    def finalize(self, status: str = None):
        """完成构建，设置状态和元数据。"""
        if status:
            self.data["status"] = status
        else:
            n = len(self.data["findings"])
            if n > 0:
                verified = sum(1 for f in self.data["findings"] if f.get("verified"))
                self.data["status"] = "confirmed" if verified > 0 else "suspicious"
            else:
                self.data["status"] = "no_findings"
        self.data["metadata"]["duration_ms"] = int((_time.monotonic() - self._t0) * 1000)
        self.data["metadata"]["requests_sent"] = self._req_count

        # 生成摘要
        n = len(self.data["findings"])
        if n == 0:
            self.data["summary"] = f"未检测到漏洞"
        else:
            verified = sum(1 for f in self.data["findings"] if f.get("verified"))
            by_severity = {}
            for f in self.data["findings"]:
                sev = f.get("severity", "INFO")
                by_severity[sev] = by_severity.get(sev, 0) + 1
            parts = [f"{c}个{v}" for v, c in by_severity.items()]
            self.data["summary"] = f"发现 {n} 个可疑点（{', '.join(parts)}），其中 {verified} 个已二次确认"

        return self.data


# ── 结构化 WAF 预检 ──

async def run_waf_precheck_structured(
    url: str,
    waf_mode: str = "safe",
    request_delay: float = 0.5,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> dict:
    """执行 WAF 预检，返回结构化 dict。"""
    if waf_mode == "off":
        return {"waf_name": "", "suggestions": [], "delay": request_delay}

    from xuanmu_bb.data.waf import waf_precheck
    w = await waf_precheck(url, waf_mode=waf_mode, request_delay=request_delay,
                           proxy=proxy, cookie=cookie, auth_token=auth_token)
    waf_name = w.get("waf_name", "") if w.get("waf_detected") else ""
    delay = w.get("delay", request_delay)
    suggestions = w.get("suggestions", [])
    return {"waf_name": waf_name, "suggestions": suggestions, "delay": delay}


# ── 合并自定义 Payload ──

def merge_payloads(builtin: list, custom_str: str = "", type_label: str = "custom") -> list:
    """将内置 payload 列表与用户自定义 payload 合并。
    builtin: 内置 payload 列表 (list of dicts with "payload" key)
    custom_str: 逗号分隔的自定义 payload 字符串
    """
    if not custom_str:
        return list(builtin)
    merged = list(builtin)
    for p in custom_str.split(","):
        p = p.strip()
        if p:
            merged.append({"payload": p, "type": type_label})
    return merged

