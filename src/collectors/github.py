"""GitHub 公开仓库泄露扫描器

搜索 GitHub 上可能意外泄露的密钥、密码、配置文件等。
仅使用 GitHub 公开搜索 API，不涉及任何非公开数据。
"""

import requests
import base64
from src.collectors.base import BaseCollector
from src.utils.helpers import logger, text_fingerprint


class GitHubCollector(BaseCollector):
    """扫描 GitHub 公开仓库中的潜在敏感信息泄露"""

    SEARCH_API = "https://api.github.com/search/code"

    def __init__(self, config: dict):
        super().__init__(config)
        self.queries = config.get("search_queries", [
            "password OR secret OR token OR api_key filename:.env",
            "BEGIN RSA PRIVATE KEY",
        ])
        self.results_per_query = config.get("results_per_query", 10)
        self.token = config.get("token", "")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ThreatIntel-Agent/1.0"
        })
        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"

    def collect(self, **kwargs) -> list[dict]:
        items = []

        for query in self.queries:
            try:
                params = {
                    "q": query,
                    "per_page": self.results_per_query,
                    "sort": "indexed",
                    "order": "desc"
                }
                resp = self.session.get(self.SEARCH_API, params=params, timeout=30)

                if resp.status_code == 403:
                    logger.warning(f"[GitHubCollector] API 限流（无 Token 时限额很低），跳过查询: {query[:50]}")
                    continue
                if resp.status_code == 422:
                    logger.warning(f"[GitHubCollector] 查询格式错误: {query[:50]}")
                    continue

                resp.raise_for_status()
                data = resp.json()

                for item in data.get("items", []):
                    repo = item.get("repository", {}).get("full_name", "unknown")
                    path = item.get("path", "unknown")
                    html_url = item.get("html_url", "")
                    git_url = item.get("git_url", "")

                    title = f"[泄露风险] {repo}/{path}"
                    summary = f"在 GitHub 仓库 {repo} 中发现可能包含敏感信息的文件: {path}"

                    items.append({
                        "id": f"github-{item.get('sha', '')[:16]}",
                        "source": "GitHub-Leak-Scan",
                        "title": title,
                        "summary": summary,
                        "content": f"Repository: {repo}\nFile: {path}\nURL: {html_url}\nQuery: {query}",
                        "url": html_url,
                        "published": "",
                        "fingerprint": text_fingerprint(f"{repo}:{path}"),
                        "raw": {
                            "repository": repo,
                            "path": path,
                            "query": query,
                            "score": item.get("score", 0)
                        }
                    })

                # GitHub API 有分页，但简版只取第一页
                logger.info(f"[GitHubCollector] 查询 '{query[:40]}...': {len(data.get('items', []))} 结果")

            except requests.RequestException as e:
                logger.error(f"[GitHubCollector] 搜索失败: {e}")
                continue

        return items
