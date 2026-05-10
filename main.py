#!/usr/bin/env python3
"""
ThreatIntel Agent — 黑灰产/威胁情报聚合分析 Agent
主入口：CLI 命令行工具
"""

import sys
import os
import time
import argparse
from pathlib import Path

# 将项目根目录加入 sys.path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# 加载 .env
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from src.utils.helpers import logger, load_config, now_iso
from src.collectors import COLLECTOR_MAP
from src.collectors.async_collector import collect_all_async
from src.analyzers import ThreatAnalyzer, AssetImpactAnalyzer
from src.reporters import Reporter
from src.storage import DatabaseManager
from src.alerts import AlertManager


def build_parser():
    parser = argparse.ArgumentParser(
        description="🛡️ ThreatIntel Agent — 威胁情报聚合分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --auto                          # 全源自动采集+分析
  python main.py --source cve --keyword apache   # 仅 CVE 源，关键词过滤
  python main.py --source github                 # 仅扫描 GitHub 泄露
  python main.py --source cnvd                   # 仅 CNVD 漏洞库
  python main.py --query "高危漏洞"               # LLM 辅助搜索
  python main.py --output json                   # 输出 JSON 格式
  python main.py --no-cache                      # 跳过缓存强制刷新
  python main.py --alert                         # 启用告警通知
  python main.py --save-db                       # 保存到数据库
  python main.py --scheduler                     # 启动定时任务
  python main.py --api                           # 启动 API 服务
        """
    )
    parser.add_argument("--auto", action="store_true", help="自动模式：启用所有采集源")
    parser.add_argument("--source", choices=["cve", "github", "freebuf", "news", "cnvd", "all"],
                        default="all", help="指定采集源 (默认 all)")
    parser.add_argument("--keyword", "-k", type=str, help="关键词过滤")
    parser.add_argument("--query", "-q", type=str, help="自然语言查询 (LLM辅助)")
    parser.add_argument("--output", "-o", choices=["markdown", "json", "both"],
                        default="both", help="输出格式")
    parser.add_argument("--no-cache", action="store_true", help="跳过缓存，强制重新采集")
    parser.add_argument("--days", type=int, default=7, help="CVE 回看天数 (默认7)")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    parser.add_argument("--alert", action="store_true", help="启用告警通知")
    parser.add_argument("--save-db", action="store_true", help="保存结果到数据库")
    parser.add_argument("--scheduler", action="store_true", help="启动定时任务调度器")
    parser.add_argument("--api", action="store_true", help="启动 RESTful API 服务")
    return parser


def collect_all(config: dict, source: str, keyword: str = None, days: int = 7, no_cache: bool = False) -> list[dict]:
    """执行采集（异步并发模式）"""
    logger.info(f"🚀 开始并发采集: source={source}, keyword={keyword}")
    start_time = time.time()
    
    items = collect_all_async(config, source, keyword, days, no_cache)
    
    elapsed = time.time() - start_time
    logger.info(f"⏱️ 采集耗时: {elapsed:.2f} 秒")
    
    return items


def run_analysis(config, args):
    """执行单次分析任务"""
    raw_count = 0

    # 初始化数据库（如果启用）
    db_manager = None
    if args.save_db:
        db_manager = DatabaseManager()
        logger.info("[Database] 已连接")

    # ── 1. 采集阶段 ──
    logger.info("=" * 50)
    logger.info("🔍 阶段1: 情报采集")
    logger.info("=" * 50)

    items = collect_all(
        config,
        source=args.source if not args.auto else "all",
        keyword=args.keyword,
        days=args.days,
        no_cache=args.no_cache
    )
    raw_count = len(items)

    if not items:
        logger.warning("😕 未采集到任何情报条目")
        print("\n💡 建议:")
        print("  - 检查网络连接")
        print("  - 尝试 --no-cache 强制刷新")
        print("  - 用 --source cve 缩小范围测试")
        if db_manager:
            db_manager.close()
        return

    # ── 2. 分析阶段 ──
    logger.info("=" * 50)
    logger.info("🧠 阶段2: 威胁分析")
    logger.info("=" * 50)

    analyzer = ThreatAnalyzer(config)
    analyzed_items = analyzer.analyze(items)

    if not analyzed_items:
        logger.error("❌ 分析阶段失败")
        if db_manager:
            db_manager.close()
        return

    # 资产影响评估
    if db_manager:
        assets = db_manager.get_assets()
        if assets:
            logger.info(f"📦 正在评估 {len(assets)} 个资产的受影响情况...")
            impact_analyzer = AssetImpactAnalyzer(config.get("analyzers", {}).get("asset_impact", {}))
            analyzed_items = impact_analyzer.analyze_impact(analyzed_items, assets)

    # 统计威胁分布
    threat_dist = {}
    for item in analyzed_items:
        level = item.get("threat_level", "INFO")
        threat_dist[level] = threat_dist.get(level, 0) + 1

    logger.info(f"📊 威胁分布: {threat_dist}")

    # ── 3. 数据库存储 ──
    if args.save_db and db_manager:
        logger.info("=" * 50)
        logger.info("💾 阶段3: 数据持久化")
        logger.info("=" * 50)
        
        saved = db_manager.save_intel(analyzed_items)
        logger.info(f"✅ 已保存 {saved} 条情报到数据库")

    # ── 4. 报告阶段 ──
    logger.info("=" * 50)
    logger.info("📝 阶段4: 报告生成")
    logger.info("=" * 50)

    reporter_config = config.get("reporter", {})
    reporter_config["formats"] = ["markdown"] if args.output == "markdown" else \
                                  ["json"] if args.output == "json" else ["markdown", "json"]
    reporter = Reporter(reporter_config)

    result = reporter.generate(analyzed_items, metadata={
        "raw_count": raw_count,
        "used_llm": analyzer.client is not None,
        "query": args.query or args.keyword or "auto"
    })

    # ── 5. 告警阶段 ──
    if args.alert:
        logger.info("=" * 50)
        logger.info("🔔 阶段5: 告警通知")
        logger.info("=" * 50)

        alert_config = config.get("alerts", {})
        alert_manager = AlertManager(alert_config)
        alert_manager.send_alerts(analyzed_items, report_path=result.get("markdown_path"))

    # 关闭数据库连接
    if db_manager:
        db_manager.close()

    # ── 输出摘要 ──
    print("\n" + "=" * 50)
    print("✅ 分析完成!")
    print("=" * 50)
    summary = result.get("summary", {})
    print(f"""
📊 情报摘要:
  - 原始采集: {raw_count} 条
  - 去重后:   {summary.get('total', 0)} 条
  - 🔴 严重:  {summary.get('critical', 0)}
  - 🟠 高危:  {summary.get('high', 0)}
  - 🟡 中危:  {summary.get('medium', 0)}
  - 🟢 低危:  {summary.get('low', 0)}
  - 🔵 信息:  {summary.get('info', 0)}
""")

    if result.get("markdown_path"):
        print(f"📄 Markdown 报告: {result['markdown_path']}")
    if result.get("json_path"):
        print(f"📦 JSON 报告:     {result['json_path']}")

    print("\n🐮 ThreatIntel Agent 任务完成! 定期运行获取持续情报监控。")


def main():
    parser = build_parser()
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════╗
║     🛡️  ThreatIntel Agent v2.0.0            ║
║     威胁情报聚合分析 — 增强版                 ║
╚══════════════════════════════════════════════╝
""")

    if args.verbose:
        import logging
        logging.getLogger("threatintel").handlers[0].setLevel(logging.DEBUG)

    # 加载配置
    config = load_config()

    # 启动定时任务
    if args.scheduler:
        from src.scheduler import run_scheduled_tasks
        logger.info("[Scheduler] 启动定时任务调度器...")
        run_scheduled_tasks(config)
        return

    # 启动 API 服务
    if args.api:
        from src.api import run_api
        api_config = config.get("api", {})
        host = api_config.get("host", "0.0.0.0")
        port = api_config.get("port", 8000)
        logger.info(f"[API] 启动 RESTful API 服务...")
        run_api(host=host, port=port)
        return

    # 执行单次分析
    run_analysis(config, args)


if __name__ == "__main__":
    main()