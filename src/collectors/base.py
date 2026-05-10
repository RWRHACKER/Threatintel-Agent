"""采集器基类"""

from abc import ABC, abstractmethod
from src.utils.helpers import logger, cache_get, cache_set, cache_is_fresh, text_fingerprint, now_iso


class BaseCollector(ABC):
    """所有采集器的基类"""

    def __init__(self, config: dict):
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = config.get("enabled", True)
        self.cache_ttl = config.get("cache_ttl", 3600)

    @abstractmethod
    def collect(self, **kwargs) -> list[dict]:
        """
        执行采集，返回标准化条目列表。
        每个条目: {
            "id": str,           # 唯一标识
            "source": str,       # 来源名称
            "title": str,        # 标题
            "summary": str,      # 摘要
            "content": str,      # 原始内容（供 LLM 分析）
            "url": str,          # 来源 URL
            "published": str,    # 发布时间 ISO
            "collected_at": str, # 采集时间 ISO
            "fingerprint": str,  # 指纹
            "raw": dict          # 原始数据
        }
        """
        pass

    def _normalize(self, item: dict) -> dict:
        """补全缺失字段，确保结构一致"""
        defaults = {
            "id": item.get("id", ""),
            "source": item.get("source", self.name),
            "title": item.get("title", "Untitled"),
            "summary": item.get("summary", ""),
            "content": item.get("content", item.get("summary", "")),
            "url": item.get("url", ""),
            "published": item.get("published", now_iso()),
            "collected_at": now_iso(),
            "fingerprint": item.get("fingerprint", text_fingerprint(
                item.get("title", "") + item.get("summary", "")
            )),
            "raw": item.get("raw", {})
        }
        return defaults

    def collect_with_cache(self, cache_prefix: str, **kwargs) -> list[dict]:
        """带缓存的采集"""
        if not self.enabled:
            logger.info(f"[{self.name}] 已禁用，跳过")
            return []

        import hashlib
        # 缓存键需要包含影响数据的参数（如 days、keyword）
        cache_key_str = f"{cache_prefix}"
        if "days" in kwargs:
            cache_key_str += f"_days={kwargs['days']}"
        if "keyword" in kwargs and kwargs["keyword"]:
            cache_key_str += f"_keyword={kwargs['keyword']}"
        cache_k = hashlib.md5(cache_key_str.encode()).hexdigest()

        if cache_is_fresh(cache_k, self.cache_ttl):
            cached = cache_get(cache_k)
            if cached and "items" in cached:
                logger.info(f"[{self.name}] 使用缓存 ({len(cached['items'])} 条)")
                return cached["items"]

        logger.info(f"[{self.name}] 开始采集...")
        try:
            items = self.collect(**kwargs)
            items = [self._normalize(i) for i in items]
            cache_set(cache_k, {"items": items})
            logger.info(f"[{self.name}] 采集完成: {len(items)} 条")
            return items
        except Exception as e:
            logger.error(f"[{self.name}] 采集失败: {e}")
            # 有缓存就用缓存
            cached = cache_get(cache_k)
            if cached and "items" in cached:
                logger.warning(f"[{self.name}] 降级使用过期缓存")
                return cached["items"]
            return []
