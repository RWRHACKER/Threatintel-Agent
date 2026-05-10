"""FreeBuf 安全社区 RSS 采集器（增强版）"""

import feedparser
import requests
import random
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from bs4 import BeautifulSoup
from src.collectors.base import BaseCollector
from src.utils.helpers import logger, text_fingerprint


class FreeBufCollector(BaseCollector):
    """采集 FreeBuf 安全社区最新文章（支持备用数据源和页面抓取）"""

    # 备用数据源列表
    BACKUP_RSS_URLS = [
        "https://www.freebuf.com/feed",
        "https://www.freebuf.com/articles/feed",
        "https://www.freebuf.com/news/feed",
    ]
    
    # 页面抓取备用方案
    PAGE_URLS = [
        "https://www.freebuf.com/news",
        "https://www.freebuf.com/articles",
        "https://www.freebuf.com/vuls",
    ]
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/121.0",
    ]

    def __init__(self, config: dict):
        super().__init__(config)
        self.rss_url = config.get("rss_url", "https://www.freebuf.com/feed")
        self.max_articles = config.get("max_articles", 15)
        self.backup_urls = self.BACKUP_RSS_URLS
        self.page_urls = self.PAGE_URLS

    def collect(self, **kwargs) -> list[dict]:
        items = []
        
        # 1. 尝试 RSS 数据源
        items = self._try_rss_sources()
        
        # 2. 如果 RSS 失败，尝试页面抓取
        if len(items) == 0:
            logger.info("[FreeBufCollector] RSS 全部失败，尝试页面抓取")
            items = self._try_page_scraping()
        
        logger.info(f"[FreeBufCollector] 采集完成: {len(items)} 条")
        return items
    
    def _try_rss_sources(self) -> list[dict]:
        """尝试所有 RSS 数据源"""
        items = []
        urls_to_try = [self.rss_url] + self.backup_urls
        
        for url in urls_to_try:
            if len(items) >= self.max_articles:
                break
                
            try:
                headers = {
                    "User-Agent": random.choice(self.USER_AGENTS),
                    "Accept": "application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Connection": "keep-alive",
                }
                
                resp = requests.get(url, headers=headers, timeout=30)
                resp.encoding = "utf-8"
                
                feed = feedparser.parse(resp.content)

                if feed.bozo:
                    logger.warning(f"[FreeBufCollector] RSS 解析警告 ({url}): {feed.bozo_exception}")
                    continue

                entries = feed.entries[:self.max_articles - len(items)]
                
                for entry in entries:
                    items.append(self._parse_rss_entry(entry))
                
                if entries:
                    logger.info(f"[FreeBufCollector] 从 RSS {url} 获取 {len(entries)} 篇文章")

            except Exception as e:
                logger.debug(f"[FreeBufCollector] 从 RSS {url} 采集失败: {e}")
                continue
        
        return items
    
    def _parse_rss_entry(self, entry) -> dict:
        """解析 RSS 条目"""
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

        return {
            "id": f"freebuf-{text_fingerprint(link)}",
            "source": "FreeBuf",
            "title": title,
            "summary": summary[:300],
            "content": f"Title: {title}\nSource: FreeBuf\nURL: {link}\n\n{summary}",
            "url": link,
            "published": published_iso,
            "fingerprint": text_fingerprint(title + (summary or "")[:200]),
            "raw": {
                "link": link,
                "tags": [t.get("term", "") for t in entry.get("tags", [])]
            }
        }
    
    def _try_page_scraping(self) -> list[dict]:
        """尝试页面抓取作为备用方案"""
        items = []
        seen_urls = set()
        
        for page_url in self.page_urls:
            if len(items) >= self.max_articles:
                break
                
            try:
                headers = {
                    "User-Agent": random.choice(self.USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Connection": "keep-alive",
                    "Referer": "https://www.freebuf.com/",
                }
                
                resp = requests.get(page_url, headers=headers, timeout=30)
                resp.encoding = "utf-8"
                
                soup = BeautifulSoup(resp.text, "html.parser")
                
                # 查找文章列表
                articles = []
                
                # 尝试多种可能的选择器
                selectors = [
                    "article.article-item",
                    "div.article-list li",
                    "div.news-list a",
                    "div.left-content article",
                    "div.content article",
                ]
                
                for selector in selectors:
                    articles = soup.select(selector)
                    if articles:
                        break
                
                if not articles:
                    # 最后尝试找所有带 href 的链接
                    articles = soup.find_all("a", href=re.compile(r'^/article/\d+'))
                
                for article in articles[:self.max_articles - len(items)]:
                    try:
                        # 提取链接
                        if hasattr(article, 'get'):
                            link = article.get("href", "")
                        else:
                            link_tag = article.find("a")
                            link = link_tag.get("href", "") if link_tag else ""
                            
                        if not link or link in seen_urls:
                            continue
                        
                        # 补全链接
                        if link.startswith("/"):
                            link = "https://www.freebuf.com" + link
                        
                        seen_urls.add(link)
                        
                        # 提取标题
                        title_tag = article.find("h2") or article.find("h3") or article.find("h4")
                        if title_tag:
                            title = title_tag.get_text(strip=True)
                        else:
                            title = article.get_text(strip=True)[:50]
                        
                        # 提取摘要
                        summary_tag = article.find("p") or article.find("div", class_="summary")
                        summary = summary_tag.get_text(strip=True)[:300] if summary_tag else title
                        
                        items.append({
                            "id": f"freebuf-{text_fingerprint(link)}",
                            "source": "FreeBuf",
                            "title": title,
                            "summary": summary[:300],
                            "content": f"Title: {title}\nSource: FreeBuf\nURL: {link}\n\n{summary}",
                            "url": link,
                            "published": datetime.now().isoformat(),
                            "fingerprint": text_fingerprint(title + summary[:200]),
                            "raw": {"link": link}
                        })
                    
                    except Exception as e:
                        logger.debug(f"[FreeBufCollector] 解析文章失败: {e}")
                        continue
                
                if articles:
                    logger.info(f"[FreeBufCollector] 从页面 {page_url} 获取 {min(len(articles), self.max_articles - len(items))} 篇文章")

            except Exception as e:
                logger.warning(f"[FreeBufCollector] 页面抓取失败 ({page_url}): {e}")
                continue
        
        return items
