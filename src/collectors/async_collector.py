"""异步采集器：并发执行多个采集源"""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils.helpers import logger
from src.collectors import COLLECTOR_MAP


class AsyncCollector:
    """异步并发采集器"""

    def __init__(self, config: dict, max_workers: int = 5):
        self.config = config
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def collect_all_async(self, source: str, keyword: str = None, days: int = 7, no_cache: bool = False) -> list[dict]:
        """异步并发采集所有数据源"""
        all_items = []
        collector_configs = self.config.get("collectors", {})

        def patch_config(cfg, no_cache):
            if no_cache:
                cfg = cfg.copy()
                cfg["cache_ttl"] = 0
            return cfg

        sources_to_collect = []
        if source == "all":
            sources_to_collect = list(COLLECTOR_MAP.keys())
        else:
            sources_to_collect = [source]

        # 准备任务
        futures = []
        for source_name in sources_to_collect:
            collector_class = COLLECTOR_MAP.get(source_name)
            if not collector_class:
                logger.warning(f"未知采集源: {source_name}")
                continue

            cfg = patch_config(collector_configs.get(source_name, {}), no_cache)
            collector = collector_class(cfg)

            # 提交到线程池
            future = self.executor.submit(
                self._collect_source,
                collector,
                source_name,
                keyword,
                days
            )
            futures.append((source_name, future))

        # 收集结果
        for source_name, future in futures:
            try:
                items = future.result(timeout=120)  # 2分钟超时
                all_items.extend(items)
                logger.info(f"✅ [{source_name}] 采集完成: {len(items)} 条")
            except TimeoutError:
                logger.error(f"⏰ [{source_name}] 采集超时")
            except Exception as e:
                logger.error(f"❌ [{source_name}] 采集失败: {e}")

        logger.info(f"📊 并发采集完成: 共 {len(all_items)} 条原始条目")
        return all_items

    def _collect_source(self, collector, source_name: str, keyword: str, days: int) -> list[dict]:
        """单个数据源采集（在子线程中执行）"""
        try:
            return collector.collect_with_cache(source_name, keyword=keyword, days=days)
        except Exception as e:
            logger.error(f"[{source_name}] 采集异常: {e}")
            return []

    def shutdown(self):
        """关闭线程池"""
        self.executor.shutdown(wait=True)


def collect_all_async(config: dict, source: str, keyword: str = None, days: int = 7, no_cache: bool = False) -> list[dict]:
    """便捷函数：异步采集"""
    collector = AsyncCollector(config)
    try:
        return collector.collect_all_async(source, keyword, days, no_cache)
    finally:
        collector.shutdown()