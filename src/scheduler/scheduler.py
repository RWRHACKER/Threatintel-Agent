"""定时任务调度器：支持 cron 表达式"""

import time
import threading
from datetime import datetime
from croniter import croniter
from src.utils.helpers import logger
from src.scheduler.task_executor import execute_scheduled_task


class TaskScheduler:
    """定时任务调度器"""

    def __init__(self):
        self.tasks = []
        self.running = False
        self.thread = None

    def add_task(self, cron_expr: str, task_func, *args, **kwargs):
        """添加定时任务"""
        try:
            cron = croniter(cron_expr, datetime.now())
            next_run = cron.get_next(datetime)
            self.tasks.append({
                "cron": cron,
                "expr": cron_expr,
                "func": task_func,
                "args": args,
                "kwargs": kwargs,
                "next_run": next_run,
                "last_run": None
            })
            logger.info(f"[Scheduler] 添加定时任务: {cron_expr}")
            return True
        except Exception as e:
            logger.error(f"[Scheduler] 无效的 cron 表达式 '{cron_expr}': {e}")
            return False

    def start(self):
        """启动调度器"""
        if self.running:
            logger.warning("[Scheduler] 调度器已在运行")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("[Scheduler] 定时任务调度器已启动")

    def stop(self):
        """停止调度器"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("[Scheduler] 定时任务调度器已停止")

    def _run(self):
        """调度器主循环"""
        while self.running:
            now = datetime.now()
            
            for task in self.tasks:
                if task["next_run"] <= now:
                    self._execute_task(task)
                    # 计算下次运行时间
                    task["next_run"] = task["cron"].get_next(datetime)

            # 每秒检查一次
            time.sleep(1)

    def _execute_task(self, task):
        """执行定时任务"""
        logger.info(f"[Scheduler] 执行任务: {task['expr']}")
        try:
            task["func"](*task["args"], **task["kwargs"])
            task["last_run"] = datetime.now()
            logger.info(f"[Scheduler] 任务执行成功: {task['expr']}")
        except Exception as e:
            logger.error(f"[Scheduler] 任务执行失败 {task['expr']}: {e}")

    def get_status(self):
        """获取调度器状态"""
        return {
            "running": self.running,
            "task_count": len(self.tasks),
            "tasks": [{
                "expr": t["expr"],
                "next_run": t["next_run"].isoformat() if t["next_run"] else None,
                "last_run": t["last_run"].isoformat() if t["last_run"] else None
            } for t in self.tasks]
        }


def run_scheduled_tasks(config: dict):
    """运行定时任务"""
    scheduler = TaskScheduler()

    # 从配置读取定时任务
    schedules = config.get("scheduler", {}).get("tasks", [])
    
    for schedule in schedules:
        cron_expr = schedule.get("cron")
        source = schedule.get("source", "all")
        keyword = schedule.get("keyword")
        alert = schedule.get("alert", False)
        save_db = schedule.get("save_db", True)

        if not cron_expr:
            continue

        # 使用独立的任务执行器，避免循环引用
        scheduler.add_task(
            cron_expr,
            execute_scheduled_task,
            source=source,
            keyword=keyword,
            alert=alert,
            save_db=save_db
        )

    if scheduler.tasks:
        scheduler.start()
        # 保持主进程运行
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            scheduler.stop()
    else:
        logger.warning("[Scheduler] 未配置定时任务")


if __name__ == "__main__":
    # 示例配置
    test_config = {
        "scheduler": {
            "tasks": [
                {
                    "cron": "0 * * * *",  # 每小时
                    "source": "cve",
                    "alert": True,
                    "save_db": True
                },
                {
                    "cron": "0 0 * * *",  # 每天凌晨
                    "source": "all",
                    "alert": True,
                    "save_db": True
                }
            ]
        }
    }
    run_scheduled_tasks(test_config)