"""Web 指纹识别工具 — 增强版：多引擎融合 + Favicon哈希 + 技术分类 + 隐含推导"""

import os
import re
import struct
import mmap
from typing import Optional

from ..client import HttpClient
from ..data.fingerprints_enhanced import ENHANCED_FINGERPRINTS, CATEGORIES, FAVICON_MAP as ENHANCED_FAVICON_MAP
from ..data.fingerprints_hub import HUB_FINGERPRINTS, HUB_FAVICON_MAP
from ..data.fingerprints import FINGERPRINTS as BUILTIN_FP, WAF_SIGNATURES
from ..data import FINGERPRINTS as DATA_FP
from ..utils import normalize_url, extract_title, ResultBuilder


# ============================================================
# Favicon Hash 计算 (MurmurHash3 32-bit — Shodan/EHole 格式)
# ============================================================

def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 32-bit (x86)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed
    rounded_end = (length & 0xFFFFFFFC)
    for i in range(0, rounded_end, 4):
        k1 = struct.unpack("<I", data[i:i + 4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded_end:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)
    signed = h1 - 4294967296 if h1 > 2147483647 else h1
    return signed


async def _compute_favicon_hash(client: HttpClient, base_url: str) -> Optional[int]:
    """下载 favicon 并计算 MMH3 哈希。"""
    try:
        favicon_url = base_url.rstrip("/") + "/favicon.ico"
        resp = await client.get(favicon_url, follow_redirects=True)
        if resp.status_code == 200 and len(resp.content) > 0:
            # Base64 编码后做 hash (与 Shodan/EHole 兼容)
            import base64
            encoded = base64.b64encode(resp.content)
            # 替换为 URL-safe 并去掉 padding（某些实现用标准 base64）
            # Shodan 使用标准 base64 带换行
            encoded_with_newlines = b"\n".join(
                encoded[i:i + 76] for i in range(0, len(encoded), 76)
            ) + b"\n"
            return _murmur3_32(encoded_with_newlines)
    except Exception:
        pass
    return None


# ============================================================
# 增强检测引擎
# ============================================================

def _detect_score_based(fp: dict, headers: dict, body: str, cookies: dict) -> tuple:
    """加权评分检测。返回 (name, version, score, max_score)。"""
    score = 0
    signals = fp.get("signals", [])
    max_possible = sum(s.get("w", 10) for s in signals)
    version = ""

    for sig in signals:
        matched = False
        if "hdr" in sig:
            key = sig["hdr"]
            val = headers.get(key, "")
            pat = sig.get("pat", "")
            if pat and re.search(pat, val, re.IGNORECASE):
                matched = True
        elif "body" in sig:
            pat = sig.get("body", "")
            if pat and re.search(pat, body, re.IGNORECASE):
                matched = True
        if matched:
            score += sig.get("w", 10)

    # 反向排除
    for neg in fp.get("negatives", []):
        if "hdr" in neg:
            key = neg["hdr"]
            pat = neg.get("pat", "")
            if pat and re.search(pat, headers.get(key, ""), re.IGNORECASE):
                score = 0
                break

    # 版本提取
    ve = fp.get("version_extract", {})
    if ve:
        source = ve.get("source", "body")
        if source == "header":
            hdr_val = headers.get(ve.get("key", ""), "")
            vm = re.search(ve["pat"], hdr_val)
            if vm: version = vm.group(1)
        elif source == "body":
            vm = re.search(ve["pat"], body)
            if vm: version = vm.group(1)
        elif source == "meta":
            vm = re.search(ve["pat"], body)
            if vm: version = vm.group(1)

    min_score = fp.get("min_score", 30)
    if score >= min_score:
        return (fp["name"], version, score, max_possible)
    return (None, "", 0, 0)


def _detect_keyword_and(fp: dict, body: str, headers: dict, cookies: dict) -> bool:
    """多关键词 AND 匹配（EHole 风格）——所有关键词需同时命中。"""
    keywords = fp.get("keywords", [])
    if not keywords:
        return False
    location = fp.get("location", "body")

    search_text = ""
    if location == "body":
        search_text = body
    elif location == "title":
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        search_text = m.group(1) if m else ""
    elif location == "header":
        search_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    elif location == "cookie":
        search_text = "\n".join(f"{k}={v}" for k, v in cookies.items())
    elif location == "meta":
        metas = re.findall(r'<meta[^>]+>', body, re.IGNORECASE)
        search_text = "\n".join(metas)

    return all(kw in search_text for kw in keywords)


def _extract_meta_generator(body: str) -> list:
    """从 <meta generator> 标签提取 CMS 和版本。"""
    results = []
    p = re.compile(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in p.finditer(body):
        content = m.group(1)
        results.append(content)
    return results


def _deduce_implies(detected_techs: set, fp_db: list) -> list:
    """推导隐含技术。"""
    added = []
    for name in list(detected_techs):
        for fp in fp_db:
            if fp.get("name") == name and fp.get("implies"):
                for implied in fp["implies"]:
                    if implied not in detected_techs:
                        detected_techs.add(implied)
                        added.append(implied)
    # 递归推导
    if added:
        more = _deduce_implies(detected_techs, fp_db)
        added.extend(more)
    return added


def _load_yaml_fingerprints():
    """加载外置 YAML 指纹库。"""
    try:
        from importlib.resources import files
        yaml_path = files("xuanmu_bb.data").joinpath("fingerprints.yaml")
        if yaml_path.is_file():
            import yaml
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
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


async def _wappalyzer_scan(url):
    """Wappalyzer 检测。"""
    try:
        from Wappalyzer import Wappalyzer, WebPage
        import asyncio
        loop = asyncio.get_event_loop()
        wapp = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        result = await loop.run_in_executor(None, wapp.analyze, webpage)
        if result:
            return sorted(result)
    except Exception:
        pass
    return []


# ============================================================
# 主检测函数
# ============================================================

async def bb_fingerprint(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None, auth_token: Optional[str] = None,
    timeout: int = 15,
) -> dict:
    """Web 指纹识别 — 增强版：Favicon哈希 + 多关键词AND + 分类 + 隐含推导。

    检测源:
    1. 增强指纹库 (Wappalyzer/EHole 风格，70+ 条)
    2. 外置 YAML 指纹库
    3. Wappalyzer 库
    4. Favicon 哈希匹配 (Shodan/EHole 风格)
    5. Meta Generator 提取
    6. 技术分类 + 隐含推导
    """
    url = normalize_url(url)
    rb = ResultBuilder("bb_fingerprint", url)

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    try:
        resp = await client.get(url)
        rb.inc_requests()
        headers = dict(resp.headers)
        body = resp.text
        status = resp.status_code

        # 解析 Cookie
        cookies = {}
        for c in resp.headers.get("Set-Cookie", "").split(","):
            c = c.strip()
            if "=" in c:
                k, v = c.split("=", 1)
                cookies[k.strip()] = v.split(";")[0].strip()
    except Exception as e:
        return rb.finalize("error")

    # 元数据
    rb.data["metadata"]["http_status"] = status
    rb.data["metadata"]["title"] = extract_title(body)
    rb.data["metadata"]["server"] = headers.get("Server", "")
    rb.data["metadata"]["content_type"] = headers.get("Content-Type", "")

    detected = {}  # name -> {category, version, confidence, source}

    # ── 合并所有指纹库 ──
    all_fingerprints = list(ENHANCED_FINGERPRINTS) + list(HUB_FINGERPRINTS)
    merged_favicon_map = dict(ENHANCED_FAVICON_MAP)
    merged_favicon_map.update(HUB_FAVICON_MAP)

    # ── 1. 增强指纹库 + Hub 指纹库检测 ──
    for fp in all_fingerprints:
        method = fp.get("method", "score")
        name = fp["name"]
        version = ""
        matched = False

        if method == "score":
            n, v, s, m = _detect_score_based(fp, headers, body, cookies)
            if n:
                matched = True
                version = v
        elif method == "keyword_and":
            if _detect_keyword_and(fp, body, headers, cookies):
                matched = True
                ve = fp.get("version_extract", {})
                if ve:
                    vm = re.search(ve["pat"], body)
                    if vm: version = vm.group(1)
        elif method == "favicon":
            pass  # favicon 检测在后面统一处理

        if matched:
            cat_ids = fp.get("cats", [])
            cat_names = [CATEGORIES.get(c, str(c)) for c in cat_ids]
            detected[name] = {
                "version": version,
                "categories": cat_names,
                "confidence": fp.get("confidence", "中"),
                "source": "enhanced_db",
            }

    # ── 2. 外置 YAML 指纹库 ──
    yaml_fp = _load_yaml_fingerprints()
    for fp in yaml_fp:
        score = 0
        signals = fp.get("signals", [])
        max_possible = sum(s.get("weight", s.get("w", 10)) for s in signals)
        for sig in signals:
            if sig.get("type") == "header":
                key = sig.get("key", "")
                pat = sig.get("pattern", "")
                if pat and re.search(pat, headers.get(key, ""), re.IGNORECASE):
                    score += sig.get("weight", 10)
            elif sig.get("type") == "body":
                pat = sig.get("pattern", "")
                if pat and re.search(pat, body, re.IGNORECASE):
                    score += sig.get("weight", 10)
        min_score = fp.get("min_score", 30)
        if score >= min_score and fp["name"] not in detected:
            detected[fp["name"]] = {
                "version": "",
                "categories": [],
                "confidence": "中",
                "source": "yaml_db",
            }

    # ── 3. Wappalyzer ──
    wapp_results = await _wappalyzer_scan(url)
    for tech in wapp_results:
        if tech not in detected:
            detected[tech] = {
                "version": "",
                "categories": [],
                "confidence": "Wappalyzer",
                "source": "wappalyzer",
            }

    # ── 4. Favicon 哈希匹配 ──
    favicon_hash = await _compute_favicon_hash(client, url)
    if favicon_hash is not None:
        rb.inc_requests()
        rb.data["metadata"]["favicon_hash"] = favicon_hash
        tech_name = merged_favicon_map.get(favicon_hash)
        if tech_name:
            # 没被其他方法检测到才追加
            already = any(k == tech_name for k in detected)
            if not already:
                detected[tech_name] = {
                    "version": "",
                    "categories": [],
                    "confidence": "favicon",
                    "source": "favicon_hash",
                }
            else:
                detected[tech_name]["confidence"] = detected[tech_name]["confidence"] + "+favicon"
        else:
            # 对内置指纹库也做 favicon 检测
            from ..data.fingerprints import FINGERPRINTS as FP
            for fp in FP:
                fh = fp.get("favicon_hash")
                if fh and fh == favicon_hash:
                    if fp["name"] not in detected:
                        detected[fp["name"]] = {
                            "version": "", "categories": [],
                            "confidence": "favicon", "source": "favicon_hash",
                        }

    # ── 5. Meta Generator 提取 ──
    meta_gens = _extract_meta_generator(body)
    for gen in meta_gens:
        rb.data["metadata"]["meta_generator"] = gen
        for fp in all_fingerprints:
            if fp["name"].lower() in gen.lower():
                if fp["name"] not in detected:
                    detected[fp["name"]] = {
                        "version": gen,
                        "categories": [CATEGORIES.get(c, str(c)) for c in fp.get("cats", [])],
                        "confidence": "meta",
                        "source": "meta_generator",
                    }

    # ── 6. 隐含技术推导 ──
    all_fp = all_fingerprints + yaml_fp
    detected_names = set(detected.keys())
    implied = _deduce_implies(detected_names, all_fp)
    for name in implied:
        if name not in detected:
            detected[name] = {
                "version": "",
                "categories": [],
                "confidence": "implied",
                "source": "logic_deduction",
            }

    # ── 7. WAF 检测 ──
    waf_list = []
    for waf in WAF_SIGNATURES:
        matched = False
        for hdr, pattern in waf.get("headers", {}).items():
            val = headers.get(hdr, "")
            if pattern and re.search(pattern, val, re.IGNORECASE):
                matched = True
                break
        body_pattern = waf.get("body", "")
        if body_pattern and re.search(body_pattern, body, re.IGNORECASE):
            matched = True
        if matched:
            waf_list.append({"name": waf["name"], "bypass": waf.get("bypass", "")})

    if waf_list:
        rb.data["waf"] = {"detected": True, "names": [w["name"] for w in waf_list],
                          "details": waf_list}
    else:
        rb.data["waf"] = {"detected": False, "names": [], "details": []}

    # ── 8. 构建分组输出 ──
    tech_by_category = {}
    for name, info in detected.items():
        cats = info.get("categories", [])
        if not cats:
            cats = ["未分类"]
        for cat in cats:
            if cat not in tech_by_category:
                tech_by_category[cat] = []
            tech_by_category[cat].append({
                "name": name,
                "version": info.get("version", ""),
                "confidence": info.get("confidence", ""),
                "source": info.get("source", ""),
            })

    rb.data["categories"] = tech_by_category
    rb.data["total_technologies"] = len(detected)

    # 摘要
    cat_summary = []
    for cat, techs in sorted(tech_by_category.items()):
        names = [t["name"] for t in techs]
        cat_summary.append(f"{cat}: {', '.join(names[:5])}")
    rb.data["summary"] = f"识别到 {len(detected)} 项技术栈 — " + "; ".join(cat_summary[:8])

    # 建议
    has_cms = any("CMS" in str(c) or "OA" in str(c) for c in tech_by_category)
    if has_cms:
        rb.add_suggestion("检测到 CMS/OA 系统，建议使用目录扫描进一步探测管理入口")
    if waf_list:
        rb.add_suggestion("检测到 WAF，后续扫描建议启用 waf_mode=safe 并降低并发")

    return rb.finalize("completed")
