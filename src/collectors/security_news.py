"""国际安全新闻 RSS 采集器（The Hacker News, Krebs on Security 等）"""

import feedparser
import requests
import random
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from src.collectors.base import BaseCollector
from src.utils.helpers import logger, text_fingerprint


class SecurityNewsCollector(BaseCollector):
    """采集国际安全新闻源（增强错误处理和超时配置）"""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    ]

    def __init__(self, config: dict):
        super().__init__(config)
        self.sources = config.get("sources", [
            {"name": "The Hacker News", "rss": "https://feeds.feedburner.com/TheHackersNews"},
            {"name": "Krebs on Security", "rss": "https://krebsonsecurity.com/feed/"},
        ])
        self.max_articles = config.get("max_articles", 10)
        self.timeout = config.get("timeout", 30)

    def collect(self, **kwargs) -> list[dict]:
        items = []

        for source in self.sources:
            name = source.get("name", "Unknown")
            rss_url = source.get("rss", "")

            if not rss_url:
                continue

            try:
                # 设置请求头（模拟浏览器）
                headers = {
                    "User-Agent": random.choice(self.USER_AGENTS),
                    "Accept": "application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
                    "Connection": "keep-alive",
                }
                
                # 先获取内容
                resp = requests.get(rss_url, headers=headers, timeout=self.timeout)
                resp.encoding = "utf-8"
                
                # 使用 feedparser 解析
                feed = feedparser.parse(resp.content)

                if feed.bozo:
                    logger.warning(f"[SecurityNews] {name} RSS 解析警告: {feed.bozo_exception}")

                entries = feed.entries[:self.max_articles]

                for entry in entries:
                    title = entry.get("title", "Untitled")
                    link = entry.get("link", "")
                    summary_raw = entry.get("summary", entry.get("description", ""))
                    summary = re.sub(r'<[^>]+>', '', summary_raw).strip()[:500]
                    published = entry.get("published", "")

                    try:
                        pub_dt = parsedate_to_datetime(published)
                        published_iso = pub_dt.isoformat()
                    except Exception:
                        published_iso = published or datetime.now().isoformat()

                    items.append({
                        "id": f"news-{hash(link)}",
                        "source": name,
                        "title": title,
                        "summary": summary[:300],
                        "content": f"Source: {name}\nTitle: {title}\nURL: {link}\n\n{summary}",
                        "url": link,
                        "published": published_iso,
                        "fingerprint": text_fingerprint(name + title),
                        "raw": {"source_name": name, "link": link}
                    })

                logger.info(f"[SecurityNews] {name}: {len(entries)} 篇")

            except requests.exceptions.Timeout:
                logger.warning(f"[SecurityNews] {name} 连接超时，跳过此数据源")
            except requests.exceptions.RequestException as e:
                logger.warning(f"[SecurityNews] {name} 请求失败: {e}，跳过此数据源")
            except Exception as e:
                logger.error(f"[SecurityNews] {name} 采集失败: {e}")

        return items
