"""文件上传检测工具"""

from typing import Optional

from ..client import HttpClient
from ..utils import normalize_url


async def bb_file_upload(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    文件上传检测 — 检查上传接口及绕过方式

    Args:
        url: 上传接口 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        文件上传配置分析结果
    """
    url = normalize_url(url)
    results = []
    results.append(f"[*] 文件上传检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie)

    # 1. 获取页面，分析表单
    try:
        resp = await client.get(url)
        body = resp.text

        import re
        forms = []
        for m in re.finditer(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*enctype=["\']multipart/form-data["\'][^>]*>(.*?)</form>',
            body, re.IGNORECASE | re.DOTALL,
        ):
            forms.append({"action": m.group(1), "type": "multipart"})
        for m in re.finditer(
            r'<input[^>]*type=["\']file["\'][^>]*>', body, re.IGNORECASE,
        ):
            results.append("[✓] 发现文件上传表单")

        if not forms:
            # 检查是否有文件上传相关的 JS
            if re.search(r'(upload|file|import|attachment)', body, re.IGNORECASE):
                results.append("[*] 页面包含文件上传相关关键词（可能通过 JS/AJAX 上传）")

    except Exception as e:
        results.append(f"[!] 页面获取失败: {e}")
        results.append("")

    # 2. 尝试各种文件上传绕过
    results.append("[*] 文件上传绕过检测:")
    results.append("")

    test_files = [
        ("test.php", "<?php echo 1;?>", "application/x-php"),
        ("test.php5", "<?php echo 1;?>", "application/x-php"),
        ("test.phtml", "<?php echo 1;?>", "text/html"),
        ("test.jsp", '<%=1%>', "text/plain"),
        ("test.asp", '<%Response.Write("1")%>', "text/plain"),
        ("test.aspx", '<%@Page Language="C#"%><%=1%>', "text/plain"),
        ("test.jpg", "<?php echo 1;?>", "image/jpeg"),
        ("test.jpg.php", "<?php echo 1;?>", "image/jpeg"),
        ("test.php.jpg", "<?php echo 1;?>", "image/jpeg"),
        ("test.php;.jpg", "<?php echo 1;?>", "image/jpeg"),
        ("test.php%00.jpg", "<?php echo 1;?>", "image/jpeg"),
        ("test.php\x00.jpg", "<?php echo 1;?>", "image/jpeg"),
        ("test.asp;.jpg", "test", "image/jpeg"),
        ("test.cer", "test", "image/jpeg"),
        ("test.asa", "test", "image/jpeg"),
        ("test.htaccess", "AddType application/x-httpd-php .jpg", "text/plain"),
        ("test.svg", '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
    ]

    for filename, content, content_type in test_files[:5]:  # 只试前5个避免过多请求
        try:
            files = {"file": (filename, content, content_type)}
            resp = await client.post(url, data=files)
            status = resp.status_code
            if status in (200, 201, 302):
                results.append(f"  [{status}] {filename} ({content_type}) — 可能上传成功")
        except Exception:
            pass

    results.append("")
    results.append("[*] 常见绕过方式（手动验证）:")
    results.append("  ──────────────────────────────────────")
    results.append("  1. Content-Type 修改: image/jpeg, text/plain")
    results.append("  2. 双扩展名: shell.php.jpg, shell.jpg.php")
    results.append("  3. 特殊字符: shell.php%00.jpg, shell.php;.jpg")
    results.append("  4. .htaccess 上传: 先上传 .htaccess 再传图片马")
    results.append("  5. 大小写绕过: shell.PhP, shell.Asp")
    results.append("  6. 截断上传: shell.php%00.jpg (仅 PHP < 5.3.4)")
    results.append("  7. SVG 文件: XSS via SVG 上传")

    return "\n".join(results)
