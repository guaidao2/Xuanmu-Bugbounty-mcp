"""子域名接管检测工具"""

import dns.asyncresolver
from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


# 常见可接管的云服务
TAKEOVER_SERVICES = {
    # CNAME 包含的关键词 → 服务名称
    "cloudfront.net": "AWS CloudFront",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure Web App",
    "trafficmanager.net": "Azure Traffic Manager",
    "azureedge.net": "Azure CDN",
    "cloudapp.net": "Azure Cloud Service",
    "herokudns.com": "Heroku",
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku SSL",
    "github.io": "GitHub Pages",
    "pantheonsite.io": "Pantheon",
    "squarespace.com": "Squarespace",
    "unbouncepages.com": "Unbounce",
    "surge.sh": "Surge",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "cdn.shopify.com": "Shopify CDN",
    "wordpress.com": "WordPress.com",
    "wpengine.com": "WP Engine",
    "fastly.net": "Fastly",
    "zendesk.com": "Zendesk",
    "zendesk.eu": "Zendesk EU",
    "statuspage.io": "Atlassian StatusPage",
    "bitbucket.io": "Bitbucket Pages",
    "readme.io": "ReadMe.io",
    "cargocollective.com": "Cargo",
    "fly.io": "Fly.io",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "pages.dev": "Cloudflare Pages",
    "framer.app": "Framer",
    "notion.site": "Notion",
    "helpscoutdocs.com": "Help Scout",
    "render.com": "Render",
    "firebaseapp.com": "Firebase",
    "web.app": "Firebase",
    "pages.github.com": "GitHub Pages",
    "aftership.com": "AfterShip",
    "campaign-archive.com": "Mailchimp",
    "desk.com": "Desk.com",
    "teamwork.com": "Teamwork",
    "tilda.ws": "Tilda",
    "zapier.com": "Zapier",
    "worksites.net": "Worksites",
    "aha.io": "Aha!",
    "helpshift.com": "Helpshift",
    "intercom.com": "Intercom",
    "intercom.io": "Intercom",
    "simplebooklet.com": "Simplebooklet",
}


async def bb_takeover(
    domain: str,
    proxy: Optional[str] = None,
    timeout: int = 10, auth_token: Optional[str] = None,
) -> str:
    """
    子域名接管检测 — DNS CNAME 分析 + HTTP 响应验证

    检测逻辑:
    1. 查询目标域名的 CNAME 记录
    2. 匹配已知的云服务域名模式
    3. 发送 HTTP 请求验证是否返回 404/NXDOMAIN 特征

    Args:
        domain: 目标域名（如 sub.example.com）
        proxy: 代理地址（可选）
        timeout: 超时秒数（默认 10）

    Returns:
        子域名接管风险分析结果
    """
    domain = domain.strip().lower()
    results = []
    results.append(f"[*] 子域名接管检测目标: {domain}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, auth_token=auth_token)

    # 1. DNS CNAME 查询
    cname = ""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = await resolver.resolve(domain, "CNAME")
        cname = str(answers[0]).rstrip(".").lower()
        results.append(f"[*] CNAME: {domain} → {cname}")
    except Exception:
        results.append("[*] 无 CNAME 记录（可能 A 记录直连 IP）")
        # 有 A 记录就不存在接管风险
        try:
            resolver = dns.asyncresolver.Resolver()
            answers = await resolver.resolve(domain, "A")
            ips = [str(r) for r in answers]
            results.append(f"[*] A 记录 IP: {', '.join(ips)}")
            results.append("[+] A 记录存在 — 无接管风险")
            return "\n".join(results)
        except Exception:
            results.append("[!] 域名无任何 DNS 记录 — 存在接管风险！")
            results.append("")
            results.append("[!] DNS 记录完全不存在，可直接注册")
            return "\n".join(results)

    if not cname:
        results.append("[+] 无 CNAME — 无接管风险")
        return "\n".join(results)

    # 2. CNAME 匹配已知服务
    matched_service = None
    for pattern, service_name in TAKEOVER_SERVICES.items():
        if pattern in cname:
            matched_service = service_name
            results.append(f"[!] CNAME 指向已知云服务: {service_name}")
            break

    if not matched_service:
        results.append(f"[*] CNAME 指向: {cname}")
        results.append("[*] 未匹配到已知接管模式（但仍建议手动检查）")
        return "\n".join(results)

    # 3. HTTP 验证 — 发送请求检查是否返回 404/NXDOMAIN 特征
    results.append("")
    results.append("[*] HTTP 验证（通过 HTTPS 和 HTTP）:")

    for scheme in ["https", "http"]:
        try:
            test_url = f"{scheme}://{domain}"
            resp = await client.get(test_url, follow_redirects=False)
            status = resp.status_code
            body_preview = resp.text[:300].replace("\n", " ")

            # 接管特征
            takeover_indicators = {
                "AWS S3": ["NoSuchBucket", "does not exist", "404 Not Found"],
                "AWS CloudFront": ["BadRequest", "CloudFront", "The request could not be satisfied"],
                "Azure": ["404 Not Found", "The web app you have attempted to reach"],
                "Heroku": ["No such app", "Heroku | No such app"],
                "GitHub Pages": ["404", "There isn't a GitHub Pages site here"],
                "Shopify": ["Sorry, this shop is currently unavailable"],
                "Netlify": ["Not Found - Request ID:", "Page Not Found"],
                "Vercel": ["404: NOT_FOUND", "The page could not be found"],
                "Firebase": ["404", "Project not found"],
                "Fastly": ["Fastly error", "domain does not exist"],
                "WordPress.com": ["Domain does not exist", "Site not found"],
                "Cloudflare Pages": ["404 Not Found", "page not found"],
                "Notion": ["Notion – The all-in-one workspace", "获取中"],
            }

            indicators = takeover_indicators.get(matched_service, [])
            for indicator in indicators:
                if indicator.lower() in body_preview.lower():
                    results.append(f"  [{status}] {scheme}://{domain}")
                    results.append(f"    → 发现接管特征: '{indicator}'")
                    results.append(f"    [!] {matched_service} 子域名可接管！")
                    break
            else:
                results.append(f"  [{status}] {scheme}://{domain} — 未匹配到接管特征")
        except Exception as e:
            results.append(f"  [-] {scheme}://{domain} — 请求失败: {str(e)[:60]}")

    # 验证建议
    results.append("")
    if any("可接管" in r for r in results):
        results.append("[!] 结论: 该子域名被弃用且可被接管！")
        results.append(f"    → 在 {matched_service} 上注册同名资源即可完成接管")
    else:
        results.append("[*] 结论: HTTP 验证未发现接管特征，但建议参考以下手动验证:")
        results.append(f"    curl -I https://{domain}")
        results.append(f"    curl -I http://{domain}")

    return "\n".join(results)
