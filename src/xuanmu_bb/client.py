"""自定义 HTTP 客户端 — 支持代理/Cookie/反封/UA轮换"""

import asyncio
import random
from typing import Optional

import httpx

# 常见浏览器 User-Agent 池
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]


class HttpClient:
    """支持反封策略的 HTTP 客户端"""

    def __init__(
        self,
        proxy: Optional[str] = None,
        cookie: Optional[str] = None,
        headers: Optional[dict] = None,
        timeout: int = 15,
        delay: float = 0,
        random_ua: bool = True,
        verify_ssl: bool = False,
        auth_token: Optional[str] = None,
        auth_header: Optional[str] = None,
    ):
        self.proxy = proxy
        self.cookie = cookie
        self.custom_headers = headers or {}
        self.timeout = timeout
        self.delay = delay
        self.random_ua = random_ua
        self.verify_ssl = verify_ssl
        self.auth_token = auth_token
        self.auth_header = auth_header or "Authorization"
        self._last_request_time = 0.0

    def _build_client(self) -> httpx.AsyncClient:
        """构建 httpx 异步客户端"""
        headers = dict(self.custom_headers)
        if self.random_ua and "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        if self.cookie and "Cookie" not in headers:
            headers["Cookie"] = self.cookie
        if self.auth_token and self.auth_header not in headers:
            headers[self.auth_header] = f"Bearer {self.auth_token}"

        client_kwargs = dict(
            headers=headers,
            timeout=httpx.Timeout(timeout=self.timeout),
            follow_redirects=True,
            verify=self.verify_ssl,
        )
        if self.proxy:
            client_kwargs["proxies"] = self.proxy

        return httpx.AsyncClient(**client_kwargs)

    async def _rate_limit(self):
        """请求频率控制"""
        if self.delay <= 0:
            return
        elapsed = time() - self._last_request_time
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json_data: Optional[dict] = None,
        files: Optional[dict] = None,
        headers: Optional[dict] = None,
        follow_redirects: bool = True,
        **kwargs,
    ) -> httpx.Response:
        """发送 HTTP 请求"""
        await self._rate_limit()
        async with self._build_client() as client:
            resp = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                content=data,
                json=json_data,
                files=files,
                headers=headers,
                follow_redirects=follow_redirects,
                **kwargs,
            )
            self._last_request_time = time()
            return resp

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def options(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)


# 为了在 async 中使用 time()
from time import time
