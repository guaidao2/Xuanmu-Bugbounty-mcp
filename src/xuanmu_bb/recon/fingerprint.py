"""Web 指纹识别工具 — 三源合一：内置评分引擎 + 外置YAML + Wappalyzer"""

import os
import re
from typing import Optional

from ..client import HttpClient
from ..data import FINGERPRINTS as BUILTIN_FP, WAF_SIGNATURES
from ..utils import normalize_url, extract_title


def _load_yaml_fingerprints():
    """加载外置 YAML 指纹库"""
    yaml_path = os.path.join(os.path.dirname(__file__), "..", "data", "fingerprints.yaml")
    yaml_path = os.path.normpath(yaml_path)
    if not os.path.exists(yaml_path):
        return []
    try:
        import yaml
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def _score_engine(fp_list, headers, body):
    """通用评分引擎 — 同时处理内置和 YAML 指纹"""
    detected = []
    for fp in fp_list:
        score = 0
        signals = fp.get("signals", [])
        max_possible = sum(s.get("weight", s.get("w", 10)) for s in signals)
        versions = []

        for sig in signals:
            matched = False
            val = ""
            sig_type = sig.get("type", "")
            if sig_type == "header" or "hdr" in sig:
                key = sig.get("key", sig.get("hdr", ""))
                val = headers.get(key, "")
                pat = sig.get("pattern", sig.get("pat", ""))
                if pat and re.search(pat, val, re.IGNORECASE):
                    matched = True
            elif sig_type == "body" or "body" in sig:
                val = body
                pat = sig.get("pattern", sig.get("body", ""))
                if pat and re.search(pat, body, re.IGNORECASE):
                    matched = True

            if matched:
                score += sig.get("weight", sig.get("w", 10))
                # 版本提取
                ve = fp.get("version_extract", {})
                if ve:
                    ve_source = ve.get("source", "")
                    ve_pat = ve.get("pattern", "")
                    if ve_source == "header":
                        hdr_val = headers.get(ve.get("key", ""), "")
                        vm = re.search(ve_pat, hdr_val)
                        if vm:
                            versions.append(vm.group(1))
                    elif ve_source == "body":
                        vm = re.search(ve_pat, body)
                        if vm:
                            versions.append(vm.group(1))

        # 反向排除
        for neg in fp.get("negatives", []):
            neg_type = neg.get("type", "header")
            if neg_type == "header":
                key = neg.get("key", neg.get("hdr", ""))
                pat = neg.get("pattern", neg.get("pat", ""))
                if pat and re.search(pat, headers.get(key, ""), re.IGNORECASE):
                    score = 0
                    break

        min_score = fp.get("min_score", 30)
        if score >= min_score:
            ver_str = f" ({', '.join(versions)})" if versions else ""
            pct = int(score / max_possible * 100) if max_possible > 0 else 0
            conf = "高" if pct >= 80 else "中" if pct >= 50 else "低"
            detected.append((f"{fp['name']}{ver_str}", conf, score, max_possible))

    return detected


async def _wappalyzer_scan(url):
    """使用 Wappalyzer 库检测"""
    try:
        from Wappalyzer import Wappalyzer, WebPage
        import asyncio
        loop = asyncio.get_event_loop()
        wapp = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        # Wappalyzer 的 analyze 是同步的，需要在线程中运行
        result = await loop.run_in_executor(None, wapp.analyze, webpage)
        if result:
            return [(tech, "Wappalyzer", 0, 0) for tech in sorted(result)]
    except Exception:
        pass
    return []


async def bb_fingerprint(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    Web 指纹识别 — 三源合一：内置评分引擎 + 外置YAML + Wappalyzer

    检测流程:
    1. 内置评分引擎 — 多信号加权判定（Server/Cookie/Body）
    2. 外置 YAML 指纹库 — fingerprints.yaml 中的信号规则
    3. Wappalyzer — 开源指纹识别库协同判定

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        识别的技术栈、CMS、WAF 信息
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        resp = await client.get(url)
        headers = dict(resp.headers)
        body = resp.text
        status = resp.status_code

        results.append(f"[*] HTTP 状态码: {status}")
        results.append(f"[*] 页面标题: {extract_title(body)}")
        results.append(f"[*] 响应大小: {len(body):,} bytes")

        # ---- Server 头 ----
        server = headers.get("Server", "N/A")
        x_powered = headers.get("X-Powered-By", "")
        results.append(f"[*] Server: {server}")
        if x_powered:
            results.append(f"[*] X-Powered-By: {x_powered}")
        results.append("")

        # ============================================================
        # 三源合一指纹识别
        # ============================================================

        # 1. 内置评分引擎
        builtin_results = _score_engine(BUILTIN_FP, headers, body)

        # 2. 外置 YAML 指纹库
        yaml_fp = _load_yaml_fingerprints()
        yaml_results = _score_engine(yaml_fp, headers, body)

        # 3. Wappalyzer
        wapp_results = await _wappalyzer_scan(url)

        # 合并去重
        seen = set()
        merged = []

        for name, conf, score, max_s in builtin_results + yaml_results + wapp_results:
            # 取基本名称（去掉版本号）
            base_name = name.split(" (")[0]
            if base_name not in seen:
                seen.add(base_name)
                merged.append((name, conf, score if score > 0 else max_s, max_s))

        merged.sort(key=lambda x: -x[2] if x[2] > 0 else -x[3])

        if merged:
            results.append(f"[✓] 识别到 {len(merged)} 项技术栈:")
            for name, conf, score, max_s in merged:
                if conf in ("高", "中", "Wappalyzer"):
                    tag = f"[{conf}]"
                else:
                    tag = "[中]"
                if max_s > 0:
                    results.append(f"  {tag} {name} ({conf} {score}/{max_s})")
                else:
                    results.append(f"  {tag} {name}")
        else:
            results.append("[-] 未识别到已知技术栈")

        # ---- WAF 检测 ----
        results.append("")
        waf_detected = []
        for waf in WAF_SIGNATURES:
            matched = False
            for hdr, pattern in waf.get("headers", {}).items():
                val = headers.get(hdr, "")
                if re.search(pattern, val, re.IGNORECASE):
                    matched = True
                    break
            body_pattern = waf.get("body", "")
            if body_pattern and re.search(body_pattern, body, re.IGNORECASE):
                matched = True
            if matched:
                waf_detected.append(waf["name"])

        if waf_detected:
            results.append(f"[!] WAF 检测: 发现 {', '.join(waf_detected)}")
            results.append("  └─ 后续测试建议注意绕过")
            bypass_hints = {
                "Cloudflare": "尝试直接访问源站 IP，或使用特殊 UA/Headers",
                "阿里云 WAF": "尝试编码绕过、分块传输、HTTP 参数污染",
                "腾讯云 WAF": "尝试大小写混淆、双重 URL 编码",
                "安全狗": "尝试换行绕过、注释混淆",
                "ModSecurity": "尝试 CRLF 注入、协议违规绕过",
                "长亭 SafeLine": "尝试请求方法转换、参数变异",
            }
            for waf_name in waf_detected:
                hint = bypass_hints.get(waf_name)
                if hint:
                    results.append(f"    {waf_name} 绕过: {hint}")
        else:
            results.append("[*] WAF: 未检测到已知 WAF")

        # ---- 关键配置信息 ----
        results.append("")
        results.append("[*] 关键响应头:")
        important_headers = [
            "Set-Cookie", "X-Frame-Options", "X-Content-Type-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "Access-Control-Allow-Origin", "Location",
        ]
        for h in important_headers:
            if h in headers:
                results.append(f"  {h}: {headers[h][:200]}")

    except Exception as e:
        results.append(f"[!] 指纹识别失败: {e}")

    return "\n".join(results)
