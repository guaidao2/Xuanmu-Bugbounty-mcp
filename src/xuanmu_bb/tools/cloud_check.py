"""云服务安全检测 — S3/元数据/Cognito/Firebase"""

import re
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_cloud_check(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    云服务安全检测 — S3 公开访问 / 元数据 SSRF / 云配置泄露

    检测内容:
    1. S3 Bucket 公开列表检测
    2. 云元数据服务模拟 (SSRF 辅助)
    3. 前端云配置泄露 (Firebase / AWS Cognito / OSS)
    4. 已知云服务端点暴露

    Args:
        url: 目标 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        云服务安全检测结果
    """
    url = normalize_url(url)
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    results = []
    results.append(f"[*] 云服务安全检测: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # 1. S3 Bucket 检测
    results.append("[*] S3 Bucket 公开访问检测:")
    results.append("")
    s3_candidates = set()

    # 从域名推测 S3 bucket 名
    parts = domain.split(".")
    if len(parts) >= 2:
        main_domain = parts[-2] + "." + parts[-1]
        s3_candidates.add(f"{main_domain}.s3.amazonaws.com")
        s3_candidates.add(f"{main_domain}.s3-website-us-east-1.amazonaws.com")
        s3_candidates.add(f"{parts[0]}.s3.amazonaws.com")
        s3_candidates.add(f"{parts[0]}.s3-website-us-east-1.amazonaws.com")

    # 常用云存储命名
    for prefix in ["assets", "static", "media", "files", "uploads", "public", "cdn", "images", "backup", "data", "prod", "dev"]:
        s3_candidates.add(f"{prefix}.{main_domain}.s3.amazonaws.com")

    for bucket_url in sorted(s3_candidates)[:10]:
        try:
            resp = await client.get(f"https://{bucket_url}")
            body = resp.text
            if resp.status_code == 200:
                if "<ListBucketResult" in body or "<Contents>" in body:
                    results.append(f"  [! 公开可读] https://{bucket_url}")
                    results.append(f"      S3 Bucket 内容可公开列表!")
                elif resp.status_code == 200:
                    results.append(f"  [! 可访问] https://{bucket_url} (HTTP 200)")
            elif resp.status_code == 403:
                results.append(f"  [locked 禁止访问] https://{bucket_url} (403)")
        except Exception:
            pass

    results.append("")

    # 2. 云元数据服务 (SSRF 辅助)
    results.append("[*] 云元数据端点 (SSRF 辅助):")
    results.append("")
    metadata_endpoints = [
        ("AWS", "http://169.254.169.254/latest/meta-data/"),
        ("AWS IMDSv2", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
        ("阿里云", "http://100.100.100.200/latest/meta-data/"),
        ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("腾讯云", "http://metadata.tencentyun.com/latest/meta-data/"),
    ]
    results.append("  在 SSRF 漏洞中尝试以下端点读取云凭据:")
    for cloud_name, endpoint in metadata_endpoints:
        results.append(f"  -> [{cloud_name}] {endpoint}")
    results.append("")

    # 3. 前端页面云配置泄露检测
    results.append("[*] 前端云配置泄露检测:")
    results.append("")
    try:
        resp = await client.get(url, timeout=timeout)
        body = resp.text

        cloud_leaks = []
        patterns = [
            ("Firebase API Key", r'(?i)(AIza[0-9A-Za-z_-]{35})'),
            ("Firebase Auth Domain", r'(?i)([a-zA-Z0-9-]+\.firebaseapp\.com)'),
            ("AWS Cognito", r'(?i)([a-zA-Z0-9-_]+\.amazoncognito\.com)'),
            ("AWS User Pool", r'(?i)(us-east-1_[a-zA-Z0-9]+)'),
            ("阿里云 OSS Bucket", r'(?i)([a-zA-Z0-9.-]+\.oss-[a-z]+-aliyuncs\.com)'),
            ("Stripe Public Key", r'(?i)(pk_live_[0-9a-zA-Z]+|pk_test_[0-9a-zA-Z]+)'),
            ("Google Maps API Key", r'(?i)(AIza[0-9A-Za-z_-]{35})'),
            ("Mapbox Token", r'(?i)(pk\.eyJ[a-zA-Z0-9_-]{30,})'),
        ]

        for name, pattern in patterns:
            for m in re.finditer(pattern, body):
                val = m.group(0)
                masked = val[:20] + "****" + val[-10:] if len(val) > 35 else val
                cloud_leaks.append((name, masked))

        if cloud_leaks:
            results.append(f"  [!] 发现 {len(cloud_leaks)} 个云配置泄露:")
            for name, val in cloud_leaks[:8]:
                results.append(f"    [!] [{name}] {val}")
        else:
            results.append("  [-] 页面中未发现云配置泄露")
    except Exception as e:
        results.append(f"  [!] 检测失败: {e}")

    results.append("")
    results.append("[*] 安全建议:")
    results.append("  [+] S3 Bucket 应配置阻止公开访问")
    results.append("  [+] 云元数据服务需启用 IMDSv2 并限制访问")
    results.append("  [+] 前端代码中不应硬编码云服务凭据")
    results.append("  [+] 使用环境变量或 Secrets Manager 管理密钥")

    return "\n".join(results)
