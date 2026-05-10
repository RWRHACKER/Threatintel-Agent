"""CrewAI 多 Agent 协作编排

Orchestrator → [Collector Agents] → Analyzer Agent → Reporter Agent

注意：简版中我们不需要强制依赖 CrewAI 运行，可以用直接调用链。
CrewAI 编排作为可选功能，保留此文件用于后续升级。
"""

from src.utils.helpers import logger


def create_crew(config: dict):
    """
    创建 CrewAI 编排（可选功能）

    当前简版使用直接调用链：collect → analyze → report
    此函数保留用于后续升级为完整多 Agent 协作模式
    """
    try:
        from crewai import Agent, Task, Crew, Process

        llm_config = config.get("llm", {})
        verbose = config.get("agent", {}).get("verbose", True)

        # ── Collector Agent ──
        collector_agent = Agent(
            role="威胁情报采集专家",
            goal="从多个公开数据源采集最新的安全威胁情报",
            backstory="""你是一名资深的安全情报采集专家，擅长从 CVE 漏洞库、
            GitHub 公开仓库、安全社区论坛等多个渠道自动化采集威胁情报。
            你确保采集到的每一条情报都有可靠的来源和完整的上下文。""",
            verbose=verbose,
            allow_delegation=False,
            llm=llm_config
        )

        # ── Analyzer Agent ──
        analyzer_agent = Agent(
            role="威胁情报分析专家",
            goal="对采集到的情报进行威胁评级、关联分析和影响评估",
            backstory="""你是一名资深威胁情报分析师，拥有10年安全运营经验。
            你能快速判断一条情报的真实威胁等级，识别误报，关联多个情报源，
            评估对组织的实际影响，并给出可操作的处置建议。""",
            verbose=verbose,
            allow_delegation=False,
            llm=llm_config
        )

        # ── Reporter Agent ──
        reporter_agent = Agent(
            role="安全报告撰写专家",
            goal="将分析结果整理成结构清晰、可操作的安全报告",
            backstory="""你是一名专业的安全报告撰写人，擅长将复杂的技术信息
            转化为管理层和安全团队都能理解的报告。你的报告结构清晰、
            重点突出、建议可落地。""",
            verbose=verbose,
            allow_delegation=False,
            llm=llm_config
        )

        # ── 任务定义 ──
        collect_task = Task(
            description="从配置的多个情报源采集最新的威胁数据",
            agent=collector_agent,
            expected_output="结构化的威胁情报条目列表"
        )

        analyze_task = Task(
            description="分析采集到的情报，评定威胁等级，识别关联",
            agent=analyzer_agent,
            expected_output="包含威胁评级和研判意见的分析结果"
        )

        report_task = Task(
            description="生成威胁情报报告",
            agent=reporter_agent,
            expected_output="格式化的 Markdown 和 JSON 报告"
        )

        crew = Crew(
            agents=[collector_agent, analyzer_agent, reporter_agent],
            tasks=[collect_task, analyze_task, report_task],
            process=Process.sequential,
            verbose=verbose
        )

        logger.info("[Crew] CrewAI 编排创建成功")
        return crew

    except ImportError:
        logger.warning("[Crew] CrewAI 未安装或导入失败，使用直接调用模式")
        return None
    except Exception as e:
        logger.error(f"[Crew] 创建失败: {e}")
        return None
