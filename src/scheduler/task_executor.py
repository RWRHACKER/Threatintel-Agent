"""定时任务执行器：抽离任务逻辑，避免循环引用"""

from src.utils.helpers import logger, load_config
from src.collectors.async_collector import collect_all_async
from src.analyzers import ThreatAnalyzer
from src.reporters import Reporter
from src.storage import DatabaseManager
from src.alerts import AlertManager


def execute_scheduled_task(source: str, keyword: str = None, alert: bool = False, save_db: bool = True):
    """执行定时任务（独立模块，避免循环引用）"""
    try:
        task_config = load_config()
        logger.info(f"[ScheduledTask] 开始定时采集: source={source}, keyword={keyword}")

        # 采集（直接使用异步采集）
        items = collect_all_async(task_config, source=source, keyword=keyword)

        if not items:
            logger.info("[ScheduledTask] 未采集到情报")
            return

        # 分析
        analyzer = ThreatAnalyzer(task_config)
        analyzed_items = analyzer.analyze(items)

        # 保存到数据库
        if save_db:
            db_manager = DatabaseManager()
            db_manager.save_intel(analyzed_items)
            db_manager.close()

        # 生成报告
        reporter = Reporter(task_config.get("reporter", {}))
        result = reporter.generate(analyzed_items, metadata={"query": keyword or "scheduled"})

        # 发送告警
        if alert:
            alert_manager = AlertManager(task_config.get("alerts", {}))
            alert_manager.send_alerts(analyzed_items, report_path=result.get("markdown_path"))

        logger.info("[ScheduledTask] 定时任务完成")

    except Exception as e:
        logger.error(f"[ScheduledTask] 任务执行失败: {e}")