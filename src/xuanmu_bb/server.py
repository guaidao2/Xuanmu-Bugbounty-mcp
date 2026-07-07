"""Xuanmu Bug Bounty MCP — 主入口（注册表模式）"""

import os
import sys

# 支持直接 python server.py 运行：将 src 目录加入 sys.path
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


# ============================================================
# 工具注册表 — 每个条目 (name, description, handler_fn)
# 新增工具只需在此列表添加一行
# ============================================================

TOOL_REGISTRY = [
    # ── 侦察模块 ──
    ("bb_ping",           "存活探测 — TCP + HTTP 双重检测目标是否存活",                  bb_ping),
    ("bb_port_scan",      "端口扫描 — TCP Connect 方式，支持 Top100/自定义端口范围",        bb_port_scan),
    ("bb_subdomain",      "子域名枚举 — DNS 批量解析 + 自定义字典",                        bb_subdomain),
    ("bb_fingerprint",    "Web 指纹识别 — 技术栈/CMS/WAF 识别 + 绕过建议",                 bb_fingerprint),
    ("bb_dir_scan",       "目录/文件爆破 — 内置 150+ 敏感路径字典",                        bb_dir_scan),

    # ── 漏洞检测模块 ──
    ("bb_sqli",           "SQL 注入检测 — 报错/布尔/时间盲注三种模式",                     bb_sqli),
    ("bb_nosqli",         "NoSQL 注入检测 — MongoDB $ne/$gt/$regex 等 Payload",           bb_nosqli),
    ("bb_xss",            "XSS 检测 — 反射型 XSS，多种上下文/事件/属性 Payload",            bb_xss),
    ("bb_ssti",           "SSTI 模板注入检测 — Jinja2/Twig/FreeMarker/Velocity/ERB/Smarty", bb_ssti),
    ("bb_cmdi",           "命令注入检测 — 时间盲注 + 输出回显",                             bb_cmdi),
    ("bb_ssrf",           "SSRF 检测 — 内网地址探测 + 协议转换 + OOB 提示",                bb_ssrf),
    ("bb_cors",           "CORS 跨域检测 — 12 种 Origin 反射测试 + 预检请求 + 凭据配置分析", bb_cors),
    ("bb_open_redirect",  "开放重定向检测 — 多种跳转测试 + 常见参数名扫描",                 bb_open_redirect),
    ("bb_file_upload",    "文件上传绕过检测 — 扩展名/MIME/双扩展名/截断/.htaccess/SVG",     bb_file_upload),
    ("bb_csrf",           "CSRF 检测 — 表单 Token 分析 + Cookie SameSite + Referer/Origin 校验", bb_csrf),
    ("bb_xxe",            "XXE 检测 — 经典/Blind OOB/XInclude/SVG 多 Payload 测试",        bb_xxe),
    ("bb_lfi",            "LFI 路径遍历检测 — 多种遍历/PHP filter 测试",                    bb_lfi),
    ("bb_host_inject",    "Host 头注入检测 — Host 覆盖/XFH/Forwarded/重复 Host 等 9 种测试", bb_host_inject),
    ("bb_takeover",       "子域名接管检测 — DNS CNAME 分析 + 50+ 云服务模式匹配 + HTTP 验证", bb_takeover),
    ("bb_race",           "条件竞争检测 — 并发请求分析 + 响应差异检测",                     bb_race),

    # ── 认证安全模块 ──
    ("bb_jwt_decode",     "JWT 解码 — 解析 Header/Payload（不验证签名）",                  bb_jwt_decode),
    ("bb_jwt_analyze",    "JWT 安全分析 — 完整分析报告（解码 + 漏洞检测 + 攻击建议）",      bb_jwt_analyze),
    ("bb_jwt_crack",      "JWT 暴力破解 — 尝试破解 HMAC 密钥，不传 wordlist 则自动使用内置 Top 100+ 弱密钥字典", bb_jwt_crack),
    ("bb_jwt_attack",     "JWT 攻击 — None 签名/KID 注入/算法混淆 (RS256->HS256)",         bb_jwt_attack),
    ("bb_graphql",        "GraphQL 安全扫描 — Introspection/批量查询/深度递归/Schema 提取", bb_graphql),

    # ── 信息提取模块 ──
    ("bb_extract",        "URL/Endpoint 提取 — 从 HTML 和 JS 中提取链接、API 端点",        bb_extract),
    ("bb_secrets",        "敏感信息泄露检测 — 检测 Key/Token/密码/内网地址/注释泄露等 20 种模式", bb_secrets),
    ("bb_headers",        "安全头审计 — 检查 8 项安全响应头 + 评分 + 修复建议",              bb_headers),
    ("bb_param_discover", "参数自动发现 — 从页面/API/JS 中提取表单参数/查询参数/JSON 字段/JS 变量", bb_param_discover),
    ("bb_js_analyze",     "JS 深度分析 — 提取 API 路由/Sourcemap/硬编码密钥/SPA 路由/WebSocket 端点/云配置", bb_js_analyze),

    # ── 工具模块 ──
    ("bb_payload",        "Payload 工厂 — 生成 XSS/SQLi/SSTI/SSRF 等 9 类 Payload，支持 6 种编码变体", bb_payload),
    ("bb_report",         "漏洞报告生成 — 生成结构化 SRC 格式 Markdown 报告",                bb_report),
    ("bb_send",           "手工 HTTP 发包 — 自定义方法/头/Body 发送请求，支持完整请求响应查看", bb_send),
    ("bb_oob",            "OOB 外带检测辅助 — 生成回调标识/Payload 建议，用于 Blind SSRF/XXE/RCE 验证", bb_oob),
    ("bb_idor",           "IDOR 越权检测 — 双 Token 对比 + 序号枚举，检测水平/垂直越权",      bb_idor),
    ("bb_session",        "多步骤流程测试 — 自动保持 Cookie + 链式请求，用于测试业务流漏洞",   bb_session),
    ("bb_cloud_check",    "云服务安全检测 — S3 公开访问 / 元数据 SSRF / 云配置泄露",         bb_cloud_check),
    ("bb_waf_check",      "WAF 指纹识别 — 检测 Cloudflare/阿里云/腾讯云等 14 种 WAF + 绕过建议 + 推荐扫描设置", bb_waf_check),
    ("bb_summary",        "扫描报告聚合 — 汇总资产发现与漏洞，生成结构化报告",                bb_summary),
]


# 自动注册所有工具
for name, desc, handler in TOOL_REGISTRY:
    mcp.tool(name=name, description=desc)(handler)


# ============================================================
# 启动入口
# ============================================================

def main():
    """启动 Xuanmu Bug Bounty MCP 服务器（stdio 模式）"""
    mcp.run()


if __name__ == "__main__":
    main()
