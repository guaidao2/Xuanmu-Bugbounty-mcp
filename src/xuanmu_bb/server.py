"""Xuanmu Bug Bounty MCP — 主入口"""

import os
import sys

# 支持直接 python server.py 运行：将 src 目录加入 sys.path
# 这样 pip install 和直接运行两种方式都能工作
_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from mcp.server.fastmcp import FastMCP

# ── Recon ──
from xuanmu_bb.recon.ping import bb_ping
from xuanmu_bb.recon.port_scan import bb_port_scan
from xuanmu_bb.recon.subdomain import bb_subdomain
from xuanmu_bb.recon.fingerprint import bb_fingerprint
from xuanmu_bb.recon.dir_scan import bb_dir_scan

# ── Vuln Core ──
from xuanmu_bb.vuln.sqli import bb_sqli
from xuanmu_bb.vuln.xss import bb_xss
from xuanmu_bb.vuln.ssti import bb_ssti
from xuanmu_bb.vuln.cmdi import bb_cmdi
from xuanmu_bb.vuln.ssrf import bb_ssrf
from xuanmu_bb.vuln.cors import bb_cors
from xuanmu_bb.vuln.open_redirect import bb_open_redirect
from xuanmu_bb.vuln.file_upload import bb_file_upload

from xuanmu_bb.vuln.nosqli import bb_nosqli

# ── Vuln Enhanced ──
from xuanmu_bb.vuln.csrf import bb_csrf
from xuanmu_bb.vuln.xxe import bb_xxe
from xuanmu_bb.vuln.lfi import bb_lfi
from xuanmu_bb.vuln.host_inject import bb_host_inject
from xuanmu_bb.vuln.takeover import bb_takeover
from xuanmu_bb.vuln.race import bb_race

# ── Auth ──
from xuanmu_bb.auth.jwt_tool import bb_jwt_decode, bb_jwt_analyze, bb_jwt_crack, bb_jwt_attack
from xuanmu_bb.auth.graphql import bb_graphql

# ── Extract ──
from xuanmu_bb.extract.url_extract import bb_extract
from xuanmu_bb.extract.secret_detect import bb_secrets
from xuanmu_bb.extract.headers import bb_headers
from xuanmu_bb.extract.param_discover import bb_param_discover
from xuanmu_bb.extract.js_analyze import bb_js_analyze

# ── Tools ──
from xuanmu_bb.tools.payload_factory import bb_payload
from xuanmu_bb.tools.report import bb_report
from xuanmu_bb.tools.request import bb_send
from xuanmu_bb.tools.oob import bb_oob
from xuanmu_bb.tools.idor import bb_idor
from xuanmu_bb.tools.session import bb_session
from xuanmu_bb.tools.cloud_check import bb_cloud_check
from xuanmu_bb.tools.waf_check import bb_waf_check
from xuanmu_bb.tools.summary import bb_summary

# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP("Xuanmu-BugBounty-mcp")

# ╔══════════════════════════════════════════════════════════════╗
# ║  侦察模块 (Reconnaissance)                                   ║
# ╚══════════════════════════════════════════════════════════════╝


@mcp.tool(name="bb_ping", description="存活探测 — TCP + HTTP 双重检测目标是否存活")
async def tool_ping(target: str, timeout: int = 5, proxy: str = None, auth_token: str = None) -> str:
    return await bb_ping(target, timeout=timeout, proxy=proxy, auth_token=auth_token)


@mcp.tool(name="bb_port_scan", description="端口扫描 — TCP Connect 方式，支持 Top100/自定义端口范围")
async def tool_port_scan(target: str, ports: str = "top100", timeout: int = 3, concurrent: int = 200) -> str:
    return await bb_port_scan(target, ports=ports, timeout=timeout, concurrent=concurrent)


@mcp.tool(name="bb_subdomain", description="子域名枚举 — DNS 批量解析 + 自定义字典")
async def tool_subdomain(domain: str, wordlist: str = None, concurrent: int = 50) -> str:
    return await bb_subdomain(domain, wordlist=wordlist, concurrent=concurrent)


@mcp.tool(name="bb_fingerprint", description="Web 指纹识别 — 技术栈/CMS/WAF 识别 + 绕过建议")
async def tool_fingerprint(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_fingerprint(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_dir_scan", description="目录/文件爆破 — 内置 150+ 敏感路径字典")
async def tool_dir_scan(url: str, wordlist: str = None, status_filter: str = "200,301,302,307,308,401,403,405,500",
                        concurrent: int = 30, timeout: int = 10, proxy: str = None, cookie: str = None, auth_token: str = None,
                        waf_mode: str = "safe", max_retries_on_block: int = 3, request_delay: float = 0.5) -> str:
    return await bb_dir_scan(url, wordlist=wordlist, status_filter=status_filter,
                             concurrent=concurrent, timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token,
                             waf_mode=waf_mode, max_retries_on_block=max_retries_on_block, request_delay=request_delay)


# ╔══════════════════════════════════════════════════════════════╗
# ║  漏洞检测模块 (Vulnerability Detection)                      ║
# ╚══════════════════════════════════════════════════════════════╝


@mcp.tool(name="bb_nosqli", description="NoSQL 注入检测 — MongoDB \$ne/\$gt/\$regex 等 Payload")
async def tool_nosqli(url: str, params: str = "", method: str = "GET",
                      proxy: str = None, cookie: str = None, auth_token: str = None,
                      timeout: int = 15, body: str = "") -> str:
    return await bb_nosqli(url, params=params, method=method,
                           proxy=proxy, cookie=cookie, auth_token=auth_token, timeout=timeout, body=body)


@mcp.tool(name="bb_sqli", description="SQL 注入检测 — 报错/布尔/时间盲注三种模式")
async def tool_sqli(url: str, params: str = "", method: str = "GET",
                    proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15, delay: float = 0.5,
                    body: str = "") -> str:
    return await bb_sqli(url, params=params, method=method,
                         proxy=proxy, cookie=cookie, timeout=timeout, delay=delay, auth_token=auth_token, body=body)


@mcp.tool(name="bb_xss", description="XSS 检测 — 反射型 XSS，多种上下文/事件/属性 Payload")
async def tool_xss(url: str, params: str = "", method: str = "GET",
                   proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15,
                   body: str = "") -> str:
    return await bb_xss(url, params=params, method=method, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token, body=body)


@mcp.tool(name="bb_ssti", description="SSTI 模板注入检测 — Jinja2/Twig/FreeMarker/Velocity/ERB/Smarty")
async def tool_ssti(url: str, params: str = "", method: str = "GET",
                    proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15,
                    body: str = "") -> str:
    return await bb_ssti(url, params=params, method=method, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token, body=body)


@mcp.tool(name="bb_cmdi", description="命令注入检测 — 时间盲注 + 输出回显")
async def tool_cmdi(url: str, params: str = "", method: str = "GET",
                    proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15,
                    body: str = "") -> str:
    return await bb_cmdi(url, params=params, method=method, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token, body=body)


@mcp.tool(name="bb_ssrf", description="SSRF 检测 — 内网地址探测 + 协议转换 + OOB 提示")
async def tool_ssrf(url: str, params: str = "", method: str = "GET",
                    proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 10,
                    body: str = "") -> str:
    return await bb_ssrf(url, params=params, method=method, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token, body=body)


@mcp.tool(name="bb_cors", description="CORS 跨域检测 — 12 种 Origin 反射测试 + 预检请求 + 凭据配置分析")
async def tool_cors(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 10) -> str:
    return await bb_cors(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_open_redirect", description="开放重定向检测 — 多种跳转测试 + 常见参数名扫描")
async def tool_open_redirect(url: str, params: str = "",
                             proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 10) -> str:
    return await bb_open_redirect(url, params=params, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_file_upload", description="文件上传绕过检测 — 扩展名/MIME/双扩展名/截断/.htaccess/SVG")
async def tool_file_upload(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_file_upload(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_csrf", description="CSRF 检测 — 表单 Token 分析 + Cookie SameSite + Referer/Origin 校验")
async def tool_csrf(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_csrf(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_xxe", description="XXE 检测 — 经典/Blind OOB/XInclude/SVG 多 Payload 测试")
async def tool_xxe(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15,
                    body: str = "", content_type: str = "application/xml") -> str:
    return await bb_xxe(url, proxy=proxy, cookie=cookie, timeout=timeout, body=body, content_type=content_type, auth_token=auth_token)


@mcp.tool(name="bb_lfi", description="LFI 路径遍历检测 — 多种遍历/PHP filter 测试")
async def tool_lfi(url: str, params: str = "", method: str = "GET",
                   proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15,
                   body: str = "") -> str:
    return await bb_lfi(url, params=params, method=method, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token, body=body)


@mcp.tool(name="bb_host_inject", description="Host 头注入检测 — Host 覆盖/XFH/Forwarded/重复 Host 等 9 种测试")
async def tool_host_inject(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_host_inject(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_takeover", description="子域名接管检测 — DNS CNAME 分析 + 50+ 云服务模式匹配 + HTTP 验证")
async def tool_takeover(domain: str, proxy: str = None, timeout: int = 10, auth_token: str = None) -> str:
    return await bb_takeover(domain, proxy=proxy, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_race", description="条件竞争检测 — 并发请求分析 + 响应差异检测")
async def tool_race(url: str, method: str = "POST", data: str = None, body: str = None, concurrent: int = 20,
                    proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_race(url, method=method, data=data, body=body, concurrent=concurrent,
                         proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


# ╔══════════════════════════════════════════════════════════════╗
# ║  认证安全模块 (Authentication Security)                       ║
# ╚══════════════════════════════════════════════════════════════╝


@mcp.tool(name="bb_jwt_decode", description="JWT 解码 — 解析 Header/Payload（不验证签名）")
async def tool_jwt_decode(token: str) -> str:
    return await bb_jwt_decode(token)


@mcp.tool(name="bb_jwt_analyze", description="JWT 安全分析 — 完整分析报告（解码 + 漏洞检测 + 攻击建议）")
async def tool_jwt_analyze(token: str) -> str:
    return await bb_jwt_analyze(token)


@mcp.tool(name="bb_jwt_crack", description="JWT 暴力破解 — 尝试破解 HMAC 密钥，不传 wordlist 则自动使用内置 Top 100+ 弱密钥字典")
async def tool_jwt_crack(token: str, wordlist: str = "") -> str:
    return await bb_jwt_crack(token, wordlist=wordlist)


@mcp.tool(name="bb_jwt_attack", description="JWT 攻击 — None 签名/KID 注入/算法混淆 (RS256→HS256)")
async def tool_jwt_attack(token: str, mode: str = "none", payload_override: str = None, public_key: str = "", verify_url: str = None) -> str:
    return await bb_jwt_attack(token, mode=mode, payload_override=payload_override, public_key=public_key, verify_url=verify_url)


@mcp.tool(name="bb_graphql", description="GraphQL 安全扫描 — Introspection/批量查询/深度递归/Schema 提取")
async def tool_graphql(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_graphql(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


# ╔══════════════════════════════════════════════════════════════╗
# ║  信息提取模块 (Information Extraction)                        ║
# ╚══════════════════════════════════════════════════════════════╝


@mcp.tool(name="bb_extract", description="URL/Endpoint 提取 — 从 HTML 和 JS 中提取链接、API 端点")
async def tool_extract(url: str, depth: int = 1, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_extract(url, depth=depth, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_secrets", description="敏感信息泄露检测 — 检测 Key/Token/密码/内网地址/注释泄露等 20 种模式")
async def tool_secrets(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15, check_js: bool = True) -> str:
    return await bb_secrets(url, proxy=proxy, cookie=cookie, timeout=timeout, check_js=check_js, auth_token=auth_token)


@mcp.tool(name="bb_headers", description="安全头审计 — 检查 8 项安全响应头 + 评分 + 修复建议")
async def tool_headers(url: str, proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 15) -> str:
    return await bb_headers(url, proxy=proxy, cookie=cookie, timeout=timeout, auth_token=auth_token)


@mcp.tool(name="bb_param_discover", description="参数自动发现 — 从页面/API/JS 中提取表单参数/查询参数/JSON 字段/JS 变量")
async def tool_param_discover(url: str, depth: int = 1, proxy: str = None, cookie: str = None,
                               auth_token: str = None, timeout: int = 15) -> str:
    return await bb_param_discover(url, depth=depth, proxy=proxy, cookie=cookie,
                                   auth_token=auth_token, timeout=timeout)


@mcp.tool(name="bb_js_analyze", description="JS 深度分析 — 提取 API 路由/Sourcemap/硬编码密钥/SPA 路由/WebSocket 端点/云配置")
async def tool_js_analyze(url: str, proxy: str = None, cookie: str = None,
                          auth_token: str = None, timeout: int = 15) -> str:
    return await bb_js_analyze(url, proxy=proxy, cookie=cookie,
                               auth_token=auth_token, timeout=timeout)


# ╔══════════════════════════════════════════════════════════════╗
# ║  工具模块 (Utilities)                                         ║
# ╚══════════════════════════════════════════════════════════════╝


@mcp.tool(name="bb_payload", description="Payload 工厂 — 生成 XSS/SQLi/SSTI/SSRF 等 9 类 Payload，支持 6 种编码变体")
async def tool_payload(vuln_type: str = "xss", encode: str = "raw", count: int = 10) -> str:
    return await bb_payload(vuln_type=vuln_type, encode=encode, count=count)


@mcp.tool(name="bb_report", description="漏洞报告生成 — 生成结构化 SRC 格式 Markdown 报告")
async def tool_report(vuln_type: str = "", target: str = "", param: str = "",
                      payload: str = "", impact: str = "", detail: str = "", poc: str = "") -> str:
    return await bb_report(vuln_type=vuln_type, target=target, param=param,
                           payload=payload, impact=impact, detail=detail, poc=poc)


@mcp.tool(name="bb_send", description="手工 HTTP 发包 — 自定义方法/头/Body 发送请求，支持完整请求响应查看")
async def tool_send(url: str, method: str = "GET", headers: str = None, body: str = None,
                    content_type: str = None, follow_redirects: bool = True,
                    proxy: str = None, cookie: str = None, auth_token: str = None, timeout: int = 30) -> str:
    return await bb_send(url, method=method, headers=headers, body=body,
                         content_type=content_type, follow_redirects=follow_redirects,
                         proxy=proxy, cookie=cookie, auth_token=auth_token, timeout=timeout)


@mcp.tool(name="bb_oob", description="OOB 外带检测辅助 — 生成回调标识/Payload 建议，用于 Blind SSRF/XXE/RCE 验证")
async def tool_oob(mode: str = "generate", callback_url: str = None) -> str:
    return await bb_oob(mode=mode, callback_url=callback_url)


@mcp.tool(name="bb_idor", description="IDOR 越权检测 — 双 Token 对比 + 序号枚举，检测水平/垂直越权")
async def tool_idor(url: str, token_owner: str = "", token_attacker: str = "",
                    cookie_owner: str = "", cookie_attacker: str = "",
                    method: str = "GET", param: str = "",
                    range_start: int = 1, range_end: int = 10,
                    proxy: str = None, timeout: int = 15) -> str:
    return await bb_idor(url, token_owner=token_owner, token_attacker=token_attacker,
                         cookie_owner=cookie_owner, cookie_attacker=cookie_attacker,
                         method=method, param=param,
                         range_start=range_start, range_end=range_end,
                         proxy=proxy, timeout=timeout)


@mcp.tool(name="bb_session", description="多步骤流程测试 — 自动保持 Cookie + 链式请求，用于测试业务流漏洞")
async def tool_session(steps: str, proxy: str = None, timeout: int = 30) -> str:
    return await bb_session(steps=steps, proxy=proxy, timeout=timeout)


@mcp.tool(name="bb_cloud_check", description="云服务安全检测 — S3 公开访问 / 元数据 SSRF / 云配置泄露")
async def tool_cloud_check(url: str, proxy: str = None, cookie: str = None,
                           auth_token: str = None, timeout: int = 15) -> str:
    return await bb_cloud_check(url, proxy=proxy, cookie=cookie,
                                auth_token=auth_token, timeout=timeout)


@mcp.tool(name="bb_summary", description="扫描报告聚合 — 汇总资产发现与漏洞，生成结构化报告")
async def tool_summary(url: str = "", findings: str = None) -> str:
    return await bb_summary(url=url, findings=findings)


@mcp.tool(name="bb_waf_check", description="WAF 指纹识别 — 检测 Cloudflare/阿里云/腾讯云等 14 种 WAF + 绕过建议 + 推荐扫描设置")
async def tool_waf_check(url: str, proxy: str = None, cookie: str = None,
                         auth_token: str = None, timeout: int = 15) -> str:
    return await bb_waf_check(url, proxy=proxy, cookie=cookie,
                              auth_token=auth_token, timeout=timeout)


# ╔══════════════════════════════════════════════════════════════╗
# ║  启动入口                                                     ║
# ╚══════════════════════════════════════════════════════════════╝


def main():
    """启动 Xuanmu Bug Bounty MCP 服务器（stdio 模式）"""
    mcp.run()


if __name__ == "__main__":
    main()
