"""CVE/NVD 漏洞数据库采集器"""

import requests
from datetime import datetime, timedelta
from src.collectors.base import BaseCollector
from src.utils.helpers import logger, text_fingerprint


class CVECollector(BaseCollector):
    """从 NVD API 采集最新 CVE 漏洞信息"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.results_per_page = config.get("results_per_page", 20)
        self.max_pages = config.get("max_pages", 2)
        # 默认拉最近7天的
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ThreatIntel-Agent/1.0"
        })

    def collect(self, keyword: str = None, days: int = 7, **kwargs) -> list[dict]:
        """
        采集 CVE 数据
        :param keyword: 关键词过滤（在描述中搜索），为空则获取最新
        :param days: 拉取最近 N 天
        """
        items = []
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": self.results_per_page,
        }

        if keyword:
            params["keywordSearch"] = keyword

        for page in range(self.max_pages):
            params["startIndex"] = page * self.results_per_page
            try:
                resp = self.session.get(self.base_url, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                for vuln in vulns:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "UNKNOWN")

                    # 提取描述
                    descriptions = cve.get("descriptions", [])
                    desc_en = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc_en = d.get("value", "")
                            break

                    # 提取 CVSS 评分
                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [])
                    cvss_v30 = metrics.get("cvssMetricV30", [])
                    cvss_v2 = metrics.get("cvssMetricV2", [])

                    cvss_score = None
                    cvss_severity = "UNKNOWN"
                    cvss_vector = ""
                    for cvss_list in [cvss_v31, cvss_v30, cvss_v2]:
                        if cvss_list:
                            cdata = cvss_list[0].get("cvssData", {})
                            cvss_score = cdata.get("baseScore")
                            cvss_severity = cdata.get("baseSeverity", cvss_list[0].get("baseSeverity", "UNKNOWN"))
                            cvss_vector = cdata.get("vectorString", "")
                            break

                    # 提取发布时间
                    published = cve.get("published", "")

                    # 提取参考链接
                    references = cve.get("references", [])
                    ref_urls = [r.get("url", "") for r in references[:5]]

                    title = f"{cve_id} — {desc_en[:120]}..." if len(desc_en) > 120 else f"{cve_id} — {desc_en}"

                    items.append({
                        "id": cve_id,
                        "source": "CVE-NVD",
                        "title": title,
                        "summary": desc_en[:300],
                        "content": f"CVE: {cve_id}\nCVSS: {cvss_score} ({cvss_severity})\nVector: {cvss_vector}\nDescription: {desc_en}\nReferences: {', '.join(ref_urls)}",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "published": published,
                        "fingerprint": text_fingerprint(cve_id + desc_en[:200]),
                        "raw": {
                            "cvss_score": cvss_score,
                            "cvss_severity": cvss_severity,
                            "cvss_vector": cvss_vector,
                            "references": ref_urls
                        }
                    })

                # 如果返回的不够一页，说明没更多了
                if len(vulns) < self.results_per_page:
                    break

            except requests.RequestException as e:
                logger.error(f"[CVECollector] API 请求失败: {e}")
                break

        return items
