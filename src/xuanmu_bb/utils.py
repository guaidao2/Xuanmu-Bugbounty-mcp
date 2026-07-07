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
