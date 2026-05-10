"""CNVD 中国国家信息安全漏洞库采集器

采集 CNVD 公开漏洞信息，包括高危漏洞、厂商公告等。
使用 Playwright 绕过 Cloudflare 反爬机制。
"""

import requests
import random
import time
from datetime import datetime
from bs4 import BeautifulSoup
from src.collectors.base import BaseCollector
from src.utils.helpers import logger, text_fingerprint, now_iso


class CNVDCollector(BaseCollector):
    """CNVD 漏洞库采集器（使用 Playwright 绕过反爬）"""

    BASE_URL = "https://www.cnvd.org.cn"
    VULN_LIST_URL = "https://www.cnvd.org.cn/flaw/list.htm"

    # 随机 User-Agent 池
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/121.0",
    ]

    def __init__(self, config: dict):
        super().__init__(config)
        self.max_pages = config.get("max_pages", 2)
        self.keywords = config.get("keywords", [])
        # 反爬配置
        self.request_delay_min = config.get("request_delay_min", 3)
        self.request_delay_max = config.get("request_delay_max", 8)
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 15)
        # Playwright 配置
        self.use_playwright = config.get("use_playwright", True)
        self.playwright_timeout = config.get("playwright_timeout", 60000)
        
        self.session = self._create_session()

    def _create_session(self):
        """创建带反爬配置的会话"""
        session = requests.Session()
        
        session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
        })
        
        return session

    def _random_delay(self):
        """随机延迟，避免被封"""
        delay = random.uniform(self.request_delay_min, self.request_delay_max)
        logger.debug(f"[CNVDCollector] 随机延迟 {delay:.2f} 秒")
        time.sleep(delay)

    def _rotate_user_agent(self):
        """轮换 User-Agent"""
        self.session.headers["User-Agent"] = random.choice(self.USER_AGENTS)

    def _request_with_retry(self, url, params=None, max_retries=None):
        """带重试的请求"""
        retries = max_retries or self.max_retries
        
        for attempt in range(retries):
            try:
                self._rotate_user_agent()
                self._random_delay()
                
                resp = self.session.get(url, params=params, timeout=30)
                resp.encoding = "utf-8"
                
                # 检查是否被封禁
                if resp.status_code == 403:
                    logger.warning(f"[CNVDCollector] 第 {attempt+1} 次请求被拒绝，重试中...")
                    if attempt < retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
                        continue
                    else:
                        raise Exception("CNVD 访问被拒绝，请稍后重试")
                
                resp.raise_for_status()
                return resp
                
            except requests.RequestException as e:
                logger.warning(f"[CNVDCollector] 请求失败 ({attempt+1}/{retries}): {e}")
                if attempt < retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                    continue
                raise
        
        raise Exception(f"请求失败，已重试 {retries} 次")

    def _fetch_with_playwright(self, url: str) -> str:
        """使用 Playwright 获取页面内容（绕过 Cloudflare）"""
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
            
            with sync_playwright() as p:
                # 使用 Firefox 浏览器（更不容易被检测）
                browser = p.firefox.launch(headless=True)
                context = browser.new_context(
                    user_agent=random.choice(self.USER_AGENTS),
                    viewport={"width": 1920, "height": 1080},
                    locale="zh-CN",
                    extra_http_headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                    }
                )
                page = context.new_page()
                
                # 增加超时时间
                page.set_default_timeout(self.playwright_timeout)
                
                # 导航到页面
                page.goto(url, wait_until="networkidle")
                
                # 等待 Cloudflare 验证完成（增加等待时间）
                page.wait_for_timeout(8000)
                
                # 检查是否有 JavaScript 重定向
                # 尝试执行页面上的 go() 函数来通过验证
                try:
                    page.evaluate("if (typeof go === 'function') { go(); }")
                    page.wait_for_timeout(5000)
                except Exception:
                    pass  # 如果没有 go 函数或执行失败，忽略
                
                # 再次等待网络空闲
                page.wait_for_load_state("networkidle")
                
                # 获取页面内容
                content = page.content()
                
                # 检查是否还是 Cloudflare 挑战页面
                if "cloudflare" in content.lower() or "challenge" in content.lower():
                    logger.warning("[CNVDCollector] 页面仍被 Cloudflare 拦截")
                
                browser.close()
                return content
                
        except PlaywrightTimeoutError:
            logger.error(f"[CNVDCollector] Playwright 超时")
            return ""
        except Exception as e:
            logger.error(f"[CNVDCollector] Playwright 访问失败: {e}")
            return ""

    def collect(self, **kwargs) -> list[dict]:
        items = []
        use_playwright = self.use_playwright
        
        # 如果配置了使用 Playwright，尝试用它来获取页面
        if use_playwright:
            logger.info("[CNVDCollector] 使用 Playwright 模式采集")
            return self._collect_with_playwright(kwargs.get("keyword", ""))
        
        # 否则使用传统方式
        return self._collect_with_requests(kwargs.get("keyword", ""))

    def _collect_with_playwright(self, keyword: str = "") -> list[dict]:
        """使用 Playwright 采集"""
        items = []
        
        for page_num in range(1, self.max_pages + 1):
            try:
                url = f"{self.VULN_LIST_URL}?pageNo={page_num}"
                if keyword:
                    url += f"&keyword={keyword}"
                
                logger.info(f"[CNVDCollector] Playwright 采集第 {page_num} 页: {url}")
                
                content = self._fetch_with_playwright(url)
                
                if not content:
                    logger.warning(f"[CNVDCollector] 第 {page_num} 页获取失败")
                    continue
                
                soup = BeautifulSoup(content, "html.parser")
                table = soup.find("table", class_="list_table")
                
                if not table:
                    logger.warning(f"[CNVDCollector] 第 {page_num} 页未找到漏洞列表")
                    continue

                rows = table.find_all("tr")[1:]  # 跳过表头
                
                for row in rows:
                    try:
                        cells = row.find_all("td")
                        if len(cells) < 5:
                            continue

                        title_cell = cells[1]
                        link = title_cell.find("a")
                        if not link:
                            continue

                        cnvd_id = cells[0].get_text(strip=True)
                        title = link.get_text(strip=True)
                        url = self.BASE_URL + link["href"]
                        severity = cells[2].get_text(strip=True)
                        cve_id = cells[3].get_text(strip=True)
                        publish_date = cells[4].get_text(strip=True)

                        # 获取详情（带延迟）
                        self._random_delay()
                        detail = self._get_vuln_detail_with_playwright(url)

                        items.append({
                            "id": f"cnvd-{cnvd_id}",
                            "source": "CNVD",
                            "title": title,
                            "summary": detail.get("summary", title),
                            "content": detail.get("content", ""),
                            "url": url,
                            "published": publish_date,
                            "fingerprint": text_fingerprint(f"{cnvd_id}:{title}"),
                            "raw": {
                                "cnvd_id": cnvd_id,
                                "cve_id": cve_id,
                                "severity": severity,
                                "detail": detail
                            }
                        })

                    except Exception as e:
                        logger.error(f"[CNVDCollector] 解析漏洞条目失败: {e}")
                        continue

                logger.info(f"[CNVDCollector] 第 {page_num} 页: {len(rows)} 条漏洞")

            except Exception as e:
                logger.error(f"[CNVDCollector] 请求失败: {e}")
                continue

        return items

    def _get_vuln_detail_with_playwright(self, url: str) -> dict:
        """使用 Playwright 获取漏洞详情"""
        try:
            content = self._fetch_with_playwright(url)
            if not content:
                return {}
            
            soup = BeautifulSoup(content, "html.parser")
            detail = {}
            
            info_table = soup.find("table", class_="detail_xq")
            if info_table:
                rows = info_table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) >= 2:
                        key = cols[0].get_text(strip=True).replace("：", "")
                        value = cols[1].get_text(strip=True)
                        detail[key] = value

            desc_div = soup.find("div", id="vul_detail")
            if desc_div:
                detail["content"] = desc_div.get_text(strip=True)[:2000]

            summary = detail.get("漏洞描述", detail.get("漏洞简介", ""))
            if summary:
                detail["summary"] = summary[:500]

            return detail

        except Exception as e:
            logger.debug(f"[CNVDCollector] 获取详情失败: {e}")
            return {}

    def _collect_with_requests(self, keyword: str = "") -> list[dict]:
        """使用 requests 采集（备用模式）"""
        items = []

        for page in range(1, self.max_pages + 1):
            try:
                params = {
                    "pageNo": page,
                    "keyword": keyword
                }
                resp = self._request_with_retry(self.VULN_LIST_URL, params=params)
                
                if resp.status_code != 200:
                    logger.warning(f"[CNVDCollector] 请求失败: {resp.status_code}")
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                table = soup.find("table", class_="list_table")
                
                if not table:
                    logger.warning(f"[CNVDCollector] 未找到漏洞列表")
                    continue

                rows = table.find_all("tr")[1:]  # 跳过表头
                
                for row in rows:
                    try:
                        cells = row.find_all("td")
                        if len(cells) < 5:
                            continue

                        title_cell = cells[1]
                        link = title_cell.find("a")
                        if not link:
                            continue

                        cnvd_id = cells[0].get_text(strip=True)
                        title = link.get_text(strip=True)
                        url = self.BASE_URL + link["href"]
                        severity = cells[2].get_text(strip=True)
                        cve_id = cells[3].get_text(strip=True)
                        publish_date = cells[4].get_text(strip=True)

                        detail = self._get_vuln_detail(url)

                        items.append({
                            "id": f"cnvd-{cnvd_id}",
                            "source": "CNVD",
                            "title": title,
                            "summary": detail.get("summary", title),
                            "content": detail.get("content", ""),
                            "url": url,
                            "published": publish_date,
                            "fingerprint": text_fingerprint(f"{cnvd_id}:{title}"),
                            "raw": {
                                "cnvd_id": cnvd_id,
                                "cve_id": cve_id,
                                "severity": severity,
                                "detail": detail
                            }
                        })

                    except Exception as e:
                        logger.error(f"[CNVDCollector] 解析漏洞条目失败: {e}")
                        continue

                logger.info(f"[CNVDCollector] 第 {page} 页: {len(rows)} 条漏洞")

            except Exception as e:
                logger.error(f"[CNVDCollector] 请求失败: {e}")
                continue

        return items

    def _get_vuln_detail(self, url: str) -> dict:
        """获取漏洞详情（带反爬）"""
        try:
            resp = self._request_with_retry(url, max_retries=2)
            soup = BeautifulSoup(resp.text, "html.parser")

            detail = {}
            info_table = soup.find("table", class_="detail_xq")
            
            if info_table:
                rows = info_table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) >= 2:
                        key = cols[0].get_text(strip=True).replace("：", "")
                        value = cols[1].get_text(strip=True)
                        detail[key] = value

            desc_div = soup.find("div", id="vul_detail")
            if desc_div:
                detail["content"] = desc_div.get_text(strip=True)[:2000]

            summary = detail.get("漏洞描述", detail.get("漏洞简介", ""))
            if summary:
                detail["summary"] = summary[:500]

            return detail

        except Exception as e:
            logger.debug(f"[CNVDCollector] 获取详情失败: {e}")
            return {}
