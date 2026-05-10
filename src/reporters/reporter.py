"""报告生成器：Markdown + JSON 格式输出，支持索引归档"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from src.utils.helpers import logger, REPORT_DIR, now_date, now_iso

# ── Markdown 报告模板 ──
MARKDOWN_TEMPLATE = """# 🛡️ 威胁情报报告 — {date}

> 自动生成于 {generated_at}
> 分析引擎: {engine}

---

## 📋 概览

| 指标 | 数值 |
|------|------|
| 采集源数 | {source_count} |
| 原始条目 | {raw_count} |
| 去重后 | {dedup_count} |
| 🔴 严重 | {critical_count} |
| 🟠 高危 | {high_count} |
| 🟡 中危 | {medium_count} |
| 🟢 低危 | {low_count} |
| 🔵 信息 | {info_count} |

---

## 🔴 严重威胁

{critical_section}

---

## 🟠 高危威胁

{high_section}

---

## 🟡 中危威胁

{medium_section}

---

## 🟢 低危 & 信息

{low_section}

---

## 📊 来源分布

{source_distribution}

---

## 🔧 采集源详情

{source_details}

---

*报告由 ThreatIntel Agent 自动生成 | {generated_at}*
"""

ITEM_TEMPLATE = """### {title}

## 📋 基本信息

| 字段 | 内容 |
|------|------|
| **来源** | {source} |
| **威胁等级** | {threat_level} |
| **置信度** | {confidence} |
| **处置优先级** | {urgency} |
| **可操作** | {is_actionable} |

{chinese_analysis}

🔗 [查看原文]({url})

---

"""


class Reporter:
    """生成 Markdown 和 JSON 格式的威胁情报报告，支持索引归档"""

    def __init__(self, config: dict):
        self.config = config
        self.output_dir = Path(config.get("output_dir", REPORT_DIR))
        self.formats = config.get("formats", ["markdown", "json"])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # 创建归档目录结构
        self._init_archive_structure()

    def _init_archive_structure(self):
        """初始化归档目录结构"""
        # 按年月归档
        archive_dir = self.output_dir / "archive"
        archive_dir.mkdir(exist_ok=True)
        logger.info(f"[Reporter] 归档目录: {archive_dir}")

    def generate(self, items: list[dict], metadata: dict | None = None) -> dict:
        """
        生成报告
        :param items: 分析后的条目列表
        :param metadata: 元数据（采集源数量、耗时等）
        :return: {"markdown_path": ..., "json_path": ..., "summary": ...}
        """
        if not items:
            logger.warning("[Reporter] 无条目，不生成报告")
            return {}

        metadata = metadata or {}
        date_str = now_date()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        current_month = datetime.now().strftime("%Y/%m")

        # 按威胁等级分组
        groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for item in items:
            level = item.get("threat_level", "INFO")
            if level not in groups:
                level = "INFO"
            groups[level].append(item)

        # 来源分布统计
        source_stats = {}
        for item in items:
            src = item.get("source", "Unknown")
            source_stats[src] = source_stats.get(src, 0) + 1
        source_dist_lines = []
        for src, count in sorted(source_stats.items(), key=lambda x: -x[1]):
            source_dist_lines.append(f"| {src} | {count} |")
        source_distribution = "| 来源 | 数量 |\n|------|------|\n" + "\n".join(source_dist_lines)

        # 来源详情
        source_detail_lines = []
        for src, count in sorted(source_stats.items(), key=lambda x: -x[1]):
            critical_in_src = sum(1 for i in items if i.get("source") == src and i.get("threat_level") == "CRITICAL")
            high_in_src = sum(1 for i in items if i.get("source") == src and i.get("threat_level") == "HIGH")
            source_detail_lines.append(
                f"- **{src}**: {count} 条（🔴{critical_in_src} 🟠{high_in_src}）"
            )
        source_details = "\n".join(source_detail_lines)

        # 生成漏洞核心信息
        def generate_core_info(item: dict) -> str:
            """生成漏洞核心信息部分"""
            raw = item.get("raw", {})
            detail = raw.get("detail", {})
            lines = []
            
            # 漏洞类型（优先从detail获取，否则推断）
            vuln_type = detail.get("漏洞类型") or self._infer_vuln_type(item)
            lines.append(f"- **漏洞类型**: {vuln_type}")
            
            # 漏洞名称/标题
            title = item.get("title", "")
            if title:
                lines.append(f"- **漏洞名称**: {title}")
            
            # 影响产品/组件
            affected_entities = item.get("affected_entities", [])
            if affected_entities:
                lines.append(f"- **影响产品**: {', '.join(affected_entities)}")
            elif detail.get("影响产品"):
                lines.append(f"- **影响产品**: {detail['影响产品']}")
            elif raw.get("product"):
                lines.append(f"- **影响产品**: {raw['product']}")
            
            # 版本范围
            version_range = self._extract_version_range(item)
            if version_range:
                lines.append(f"- **影响版本**: {version_range}")
            elif detail.get("影响版本"):
                lines.append(f"- **影响版本**: {detail['影响版本']}")
            elif raw.get("version"):
                lines.append(f"- **影响版本**: {raw['version']}")
            
            # CVSS 评分
            cvss_score = raw.get("cvss_score") or detail.get("CVSS评分") or detail.get("cvss_score")
            cvss_severity = raw.get("cvss_severity") or detail.get("CVSS等级")
            if cvss_score:
                lines.append(f"- **CVSS评分**: {cvss_score} ({cvss_severity or '未指定'})")
            
            # CNVD 编号
            cnvd_id = raw.get("cnvd_id") or detail.get("CNVD编号") or detail.get("cnvd_id")
            if cnvd_id:
                lines.append(f"- **CNVD编号**: {cnvd_id}")
            
            # CVE 编号
            cve_id = raw.get("cve_id") or raw.get("id", "") or detail.get("CVE编号") or detail.get("cve_id")
            if cve_id and ("cve-" in cve_id.lower() or cve_id.startswith("CVE-")):
                lines.append(f"- **CVE编号**: {cve_id}")
            
            # 厂商信息
            vendor = raw.get("vendor") or detail.get("厂商")
            if vendor:
                lines.append(f"- **厂商**: {vendor}")
            
            # 漏洞状态
            status = raw.get("status") or detail.get("漏洞状态") or detail.get("状态")
            if status:
                lines.append(f"- **漏洞状态**: {status}")
            
            # 发布时间
            publish_time = raw.get("publish_time") or detail.get("发布时间")
            if publish_time:
                lines.append(f"- **发布时间**: {publish_time}")
            
            # 危害等级说明
            threat_level = item.get("threat_level", "INFO")
            level_desc = self._get_threat_level_desc(threat_level)
            lines.append(f"- **危害等级说明**: {level_desc}")
            
            return "\n".join(lines) if lines else "_暂无详细信息_"

        # 生成技术分析
        def generate_technical_analysis(item: dict) -> str:
            """生成技术分析部分"""
            raw = item.get("raw", {})
            detail = raw.get("detail", {})
            summary = item.get("summary", "")
            content = item.get("content", "")
            lines = []
            
            # 漏洞描述（优先使用detail中的中文描述）
            cnvd_desc = detail.get("漏洞描述") or detail.get("描述")
            if cnvd_desc:
                lines.append(f"**漏洞描述**:\n{cnvd_desc[:800]}")
            elif summary:
                lines.append(f"**漏洞描述**:\n{summary[:800]}")
            elif content:
                lines.append(f"**漏洞描述**:\n{content[:800]}")
            
            # 技术细节
            tech_details = []
            if detail.get("漏洞类型"):
                tech_details.append(f"- 漏洞类型: {detail['漏洞类型']}")
            if detail.get("危害类型"):
                tech_details.append(f"- 危害类型: {detail['危害类型']}")
            if detail.get("攻击类型"):
                tech_details.append(f"- 攻击类型: {detail['攻击类型']}")
            if detail.get("攻击向量"):
                tech_details.append(f"- 攻击向量: {detail['攻击向量']}")
            if detail.get("参考链接"):
                tech_details.append(f"- 参考链接: {detail['参考链接'][:200]}")
            
            # 从raw获取更多技术细节
            if raw.get("attack_vector"):
                tech_details.append(f"- 攻击向量: {raw['attack_vector']}")
            if raw.get("exploit_type"):
                tech_details.append(f"- 利用类型: {raw['exploit_type']}")
            
            if tech_details:
                lines.append(f"\n**技术细节**:\n{chr(10).join(tech_details)}")
            
            # 攻击向量推断（如果没有明确信息）
            if not (detail.get("攻击向量") or raw.get("attack_vector")):
                attack_vector = self._infer_attack_vector(item)
                if attack_vector:
                    lines.append(f"\n**攻击向量**: {attack_vector}")
            
            # 利用条件
            exploit_conditions = self._infer_exploit_conditions(item)
            if exploit_conditions:
                lines.append(f"\n**利用条件**: {exploit_conditions}")
            
            # 漏洞原理
            vuln_principle = self._infer_vuln_principle(item)
            if vuln_principle:
                lines.append(f"\n**漏洞原理**: {vuln_principle}")
            
            return "\n".join(lines) if lines else "_暂无技术分析信息_"

        # 生成潜在影响
        def generate_potential_impact(item: dict) -> str:
            """生成潜在影响部分 - 根据漏洞类型生成差异化描述"""
            threat_level = item.get("threat_level", "INFO")
            vuln_type = self._infer_vuln_type(item)
            affected_entities = item.get("affected_entities", []) or []
            lines = []
            
            # 根据漏洞类型生成具体的影响描述
            impact_by_type = self._get_impact_by_vuln_type(vuln_type, threat_level)
            if impact_by_type:
                lines.append(f"- {impact_by_type}")
            
            # 业务影响评估（根据漏洞类型和威胁等级）
            business_impact = self._infer_business_impact(item)
            if business_impact:
                lines.append(f"- {business_impact}")
            
            # 数据风险
            data_risk = self._infer_data_risk(item)
            if data_risk:
                lines.append(f"- {data_risk}")
            
            # 系统风险
            system_risk = self._infer_system_risk(item)
            if system_risk:
                lines.append(f"- {system_risk}")
            
            # 影响范围
            if affected_entities:
                lines.append(f"- **直接影响组件**: {', '.join(affected_entities)}")
            elif item.get("title"):
                # 从标题提取产品信息
                product_match = re.search(r"(Apache|Spring|Nginx|Tomcat|MySQL|Oracle|Microsoft|VMware|Docker|Kubernetes)", item["title"])
                if product_match:
                    lines.append(f"- **可能影响**: {product_match.group(1)} 相关产品")
            
            # 风险等级对应的影响描述
            impact_desc = self._get_impact_description(vuln_type, threat_level)
            if impact_desc:
                lines.append(f"- **风险等级影响**: {impact_desc}")
            
            return "\n".join(lines) if lines else "_暂无潜在影响评估_"

        # 生成各等级内容
        def render_section(level: str, emoji: str) -> str:
            items_list = groups.get(level, [])
            if not items_list:
                return f"_暂无{self._get_level_cn_name(level)}级别的威胁_\n"
            parts = []
            for item in items_list:
                # 使用新方法生成中文分析
                chinese_analysis = self._build_chinese_analysis(item, level)

                parts.append(ITEM_TEMPLATE.format(
                    title=item.get("title", "Untitled"),
                    source=item.get("source", ""),
                    threat_level=f"{emoji} {self._get_level_cn_name(level)}",
                    confidence=f"{item.get('confidence', 0):.0%}",
                    urgency=item.get("urgency", "持续关注"),
                    is_actionable="✅ 是" if item.get("is_actionable") else "❌ 否",
                    chinese_analysis=chinese_analysis,
                    url=item.get("url", "#")
                ))
            return "".join(parts)

        # 填充模板
        engine = "LLM (DEEPSEEK)" if metadata.get("used_llm") else "规则引擎"
        markdown_content = MARKDOWN_TEMPLATE.format(
            date=date_str,
            generated_at=now_iso(),
            engine=engine,
            source_count=len(source_stats),
            raw_count=metadata.get("raw_count", len(items)),
            dedup_count=len(items),
            critical_count=len(groups["CRITICAL"]),
            high_count=len(groups["HIGH"]),
            medium_count=len(groups["MEDIUM"]),
            low_count=len(groups["LOW"]),
            info_count=len(groups["INFO"]),
            overall_summary="",
            critical_section=render_section("CRITICAL", "🔴"),
            high_section=render_section("HIGH", "🟠"),
            medium_section=render_section("MEDIUM", "🟡"),
            low_section=render_section("LOW", "🟢") + "\n\n" + render_section("INFO", "🔵"),
            source_distribution=source_distribution,
            source_details=source_details
        )

        result = {}

        # 创建年月归档目录
        archive_month_dir = self.output_dir / "archive" / current_month
        archive_month_dir.mkdir(parents=True, exist_ok=True)

        # 写入 Markdown
        if "markdown" in self.formats:
            md_path = archive_month_dir / f"report_{date_str}_{timestamp}.md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            
            # 创建快捷方式到最新报告（Windows 无管理员权限用文本文件替代）
            latest_md = self.output_dir / "latest_report.md"
            try:
                if latest_md.exists() or latest_md.is_symlink():
                    latest_md.unlink()
                latest_md.symlink_to(md_path)
            except OSError:
                # Windows 无管理员权限时降级为写一个文本指针
                with open(latest_md, "w", encoding="utf-8") as lf:
                    lf.write(f"# 最新报告\n\n路径: {md_path}\n时间: {now_iso()}\n")
            
            result["markdown_path"] = str(md_path)
            logger.info(f"[Reporter] Markdown 报告: {md_path}")

        # 写入 JSON
        if "json" in self.formats:
            json_path = archive_month_dir / f"report_{date_str}_{timestamp}.json"
            json_content = {
                "metadata": {
                    "date": date_str,
                    "generated_at": now_iso(),
                    "engine": engine,
                    "source_count": len(source_stats),
                    "total_items": len(items),
                    **{k: len(v) for k, v in groups.items()}
                },
                "items": items
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_content, f, ensure_ascii=False, indent=2)
            
            # 创建快捷方式到最新 JSON（Windows 无管理员权限用文本文件替代）
            latest_json = self.output_dir / "latest_report.json"
            try:
                if latest_json.exists() or latest_json.is_symlink():
                    latest_json.unlink()
                latest_json.symlink_to(json_path)
            except OSError:
                # 降级写入指针文件
                with open(latest_json, "w", encoding="utf-8") as lf:
                    json.dump({"path": str(json_path), "time": now_iso()}, lf, ensure_ascii=False, indent=2)
            
            result["json_path"] = str(json_path)
            logger.info(f"[Reporter] JSON 报告: {json_path}")

        # 更新索引
        self._update_index(date_str, timestamp, result, groups, source_stats, engine)

        # 返回摘要
        result["summary"] = {
            "total": len(items),
            "critical": len(groups["CRITICAL"]),
            "high": len(groups["HIGH"]),
            "medium": len(groups["MEDIUM"]),
            "low": len(groups["LOW"]),
            "info": len(groups["INFO"]),
            "sources": source_stats
        }

        return result

    def _update_index(self, date_str: str, timestamp: str, result: dict, groups: dict, source_stats: dict, engine: str):
        """更新报告索引文件"""
        index_path = self.output_dir / "report_index.json"
        
        # 读取现有索引
        if index_path.exists():
            with open(index_path, "r", encoding="utf-8") as f:
                index = json.load(f)
        else:
            index = {
                "reports": [],
                "stats": {
                    "total_reports": 0,
                    "total_critical": 0,
                    "total_high": 0,
                    "total_medium": 0,
                    "total_low": 0,
                    "total_info": 0
                }
            }

        # 添加新报告记录
        report_entry = {
            "date": date_str,
            "timestamp": timestamp,
            "datetime": now_iso(),
            "engine": engine,
            "markdown_path": result.get("markdown_path", ""),
            "json_path": result.get("json_path", ""),
            "source_count": len(source_stats),
            "total_items": sum(len(v) for v in groups.values()),
            "critical": len(groups["CRITICAL"]),
            "high": len(groups["HIGH"]),
            "medium": len(groups["MEDIUM"]),
            "low": len(groups["LOW"]),
            "info": len(groups["INFO"]),
            "sources": source_stats
        }
        
        index["reports"].insert(0, report_entry)
        
        # 保持索引最多100条记录
        if len(index["reports"]) > 100:
            index["reports"] = index["reports"][:100]

        # 更新统计
        index["stats"]["total_reports"] = len(index["reports"])
        index["stats"]["total_critical"] += len(groups["CRITICAL"])
        index["stats"]["total_high"] += len(groups["HIGH"])
        index["stats"]["total_medium"] += len(groups["MEDIUM"])
        index["stats"]["total_low"] += len(groups["LOW"])
        index["stats"]["total_info"] += len(groups["INFO"])

        # 写入索引
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, ensure_ascii=False, indent=2)
        
        logger.info(f"[Reporter] 索引已更新: {index_path}")

    def get_report_index(self) -> dict:
        """获取报告索引"""
        index_path = self.output_dir / "report_index.json"
        if index_path.exists():
            with open(index_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"reports": [], "stats": {}}

    def list_reports(self, days: int = 7) -> list[dict]:
        """列出最近N天的报告"""
        index = self.get_report_index()
        if not index.get("reports"):
            return []
        
        cutoff_date = (datetime.now() - datetime.timedelta(days=days)).date()
        return [
            report for report in index["reports"]
            if datetime.strptime(report["date"], "%Y-%m-%d").date() >= cutoff_date
        ]

    # ── 辅助方法：漏洞信息提取与分析 ──
    
    def _get_level_cn_name(self, level: str) -> str:
        """获取威胁等级中文名称"""
        level_names = {
            "CRITICAL": "严重",
            "HIGH": "高危",
            "MEDIUM": "中危",
            "LOW": "低危",
            "INFO": "信息"
        }
        return level_names.get(level, level)

    def _infer_vuln_type(self, item: dict) -> str:
        """根据标题和摘要推断漏洞类型"""
        title = item.get("title", "").lower()
        summary = item.get("summary", "").lower()
        text = title + " " + summary
        
        vuln_types = {
            "远程代码执行": ["rce", "remote code execution", "远程代码执行", "任意代码执行", "代码执行漏洞"],
            "命令注入": ["命令注入", "command injection", "os command", "命令执行"],
            "SQL注入": ["sql注入", "sql injection", "sql注入漏洞", "数据库注入"],
            "XSS跨站脚本": ["xss", "跨站脚本", "cross-site scripting", "跨站脚本攻击"],
            "CSRF跨站请求伪造": ["csrf", "跨站请求伪造", "cross-site request forgery"],
            "反序列化漏洞": ["反序列化", "deserialization", "序列化漏洞"],
            "SSRF服务端请求伪造": ["ssrf", "服务端请求伪造", "server-side request forgery"],
            "路径遍历": ["路径遍历", "path traversal", "目录遍历", "directory traversal", "文件读取"],
            "文件上传漏洞": ["文件上传", "file upload", "恶意文件上传"],
            "认证绕过": ["认证绕过", "authentication bypass", "未授权访问", "越权访问"],
            "权限提升": ["权限提升", "privilege escalation", "提权", "权限升级", "本地提权"],
            "信息泄露": ["信息泄露", "information disclosure", "数据泄露", "敏感信息"],
            "拒绝服务": ["拒绝服务", "denial of service", "dos", "ddos"],
            "配置错误": ["配置错误", "配置漏洞", "不安全配置", "默认配置"],
            "弱口令": ["弱口令", "weak password", "默认密码", "密码泄露"],
            "密钥泄露": ["密钥泄露", "secret leak", "token泄露", "credentials", "api密钥"],
            "缓冲区溢出": ["缓冲区溢出", "buffer overflow", "栈溢出", "堆溢出"],
            "逻辑漏洞": ["逻辑漏洞", "业务逻辑", "逻辑缺陷"],
            "XML外部实体注入": ["xxe", "xml external entity", "xml注入"],
            "模板注入": ["模板注入", "template injection", "ssti"],
        }
        
        for vuln_type, keywords in vuln_types.items():
            for kw in keywords:
                if kw.lower() in text:
                    return vuln_type
        
        return "未知类型"

    def _build_chinese_analysis(self, item: dict, level: str) -> str:
        """构建中文分析内容，整合漏洞核心信息、技术分析、潜在影响和处置建议"""
        raw = item.get("raw", {})
        detail = raw.get("detail", {})
        
        # 优先使用 LLM 生成的完整分析结果（reasoning 包含完整内容时）
        reasoning = item.get("reasoning", "")
        
        # 检查是否是完整的 LLM 分析（包含中文分析内容）
        has_full_analysis = False
        if reasoning:
            # 如果 reasoning 包含中文分析内容（有多个段落或足够长），则使用它
            # 规则引擎的 reasoning 通常很短（如"关键词: rce"），LLM 生成的通常很长
            if len(reasoning) > 100 or "\n" in reasoning or "##" in reasoning:
                has_full_analysis = True
        
        if has_full_analysis:
            return reasoning
        
        # 检查是否有 LLM 生成的中文分析字段
        vuln_desc = item.get("vuln_description_cn", "")
        potential_impact = item.get("potential_impact_cn", "")
        recommendations_cn = item.get("recommended_actions_cn", "")
        
        if vuln_desc or potential_impact or recommendations_cn:
            parts = []
            
            # 漏洞核心信息
            core_info = self._build_core_info(item)
            if core_info:
                parts.append(f"## 🔍 漏洞核心信息\n\n{core_info}")
            
            # LLM 生成的技术分析（中文）
            if vuln_desc:
                parts.append(f"## 📊 技术分析\n\n{vuln_desc}")
            else:
                tech_analysis = self._build_technical_analysis(item)
                if tech_analysis:
                    parts.append(f"## 📊 技术分析\n\n{tech_analysis}")
            
            # LLM 生成的潜在影响（中文）
            if potential_impact:
                parts.append(f"## ⚠️ 潜在影响\n\n{potential_impact}")
            else:
                impact = self._build_potential_impact(item, level)
                if impact:
                    parts.append(f"## ⚠️ 潜在影响\n\n{impact}")
            
            # LLM 生成的处置建议（中文）
            if recommendations_cn:
                parts.append(f"## ✅ 处置建议\n\n{recommendations_cn}")
            else:
                recommendations = self._build_recommendations(item, level)
                if recommendations:
                    parts.append(f"## ✅ 处置建议\n\n{recommendations}")
            
            return "\n\n".join(parts)
        
        # 构建各部分内容（降级到规则引擎）
        parts = []
        
        # 漏洞核心信息
        core_info = self._build_core_info(item)
        if core_info:
            parts.append(f"## 🔍 漏洞核心信息\n\n{core_info}")
        
        # 技术分析
        tech_analysis = self._build_technical_analysis(item)
        if tech_analysis:
            parts.append(f"## 📊 技术分析\n\n{tech_analysis}")
        
        # 潜在影响
        potential_impact = self._build_potential_impact(item, level)
        if potential_impact:
            parts.append(f"## ⚠️ 潜在影响\n\n{potential_impact}")
        
        # 处置建议
        recommendations = self._build_recommendations(item, level)
        if recommendations:
            parts.append(f"## ✅ 处置建议\n\n{recommendations}")
        
        return "\n\n".join(parts) if parts else "_暂无分析信息_"

    def _build_core_info(self, item: dict) -> str:
        """构建漏洞核心信息"""
        raw = item.get("raw", {})
        detail = raw.get("detail", {})
        lines = []
        
        # 漏洞类型（优先从detail获取，否则推断）
        vuln_type = detail.get("漏洞类型") or self._infer_vuln_type(item)
        lines.append(f"- **漏洞类型**: {vuln_type}")
        
        # 影响产品/组件
        affected_entities = item.get("affected_entities", [])
        if affected_entities:
            lines.append(f"- **影响产品**: {', '.join(affected_entities)}")
        elif detail.get("影响产品"):
            lines.append(f"- **影响产品**: {detail['影响产品']}")
        elif raw.get("product"):
            lines.append(f"- **影响产品**: {raw['product']}")
        
        # 版本范围
        version_range = self._extract_version_range(item)
        if version_range:
            lines.append(f"- **影响版本**: {version_range}")
        elif detail.get("影响版本"):
            lines.append(f"- **影响版本**: {detail['影响版本']}")
        elif raw.get("version"):
            lines.append(f"- **影响版本**: {raw['version']}")
        
        # CVSS 评分
        cvss_score = raw.get("cvss_score") or detail.get("CVSS评分") or detail.get("cvss_score")
        cvss_severity = raw.get("cvss_severity") or detail.get("CVSS等级")
        if cvss_score:
            lines.append(f"- **CVSS评分**: {cvss_score} ({cvss_severity or '未指定'})")
        
        # CNVD 编号
        cnvd_id = raw.get("cnvd_id") or detail.get("CNVD编号") or detail.get("cnvd_id")
        if cnvd_id:
            lines.append(f"- **CNVD编号**: {cnvd_id}")
        
        # CVE 编号
        cve_id = raw.get("cve_id") or raw.get("id", "") or detail.get("CVE编号") or detail.get("cve_id")
        if cve_id and ("cve-" in cve_id.lower() or cve_id.startswith("CVE-")):
            lines.append(f"- **CVE编号**: {cve_id}")
        
        # 厂商信息
        vendor = raw.get("vendor") or detail.get("厂商")
        if vendor:
            lines.append(f"- **厂商**: {vendor}")
        
        # 漏洞状态
        status = raw.get("status") or detail.get("漏洞状态") or detail.get("状态")
        if status:
            lines.append(f"- **漏洞状态**: {status}")
        
        # 发布时间
        publish_time = raw.get("publish_time") or detail.get("发布时间")
        if publish_time:
            lines.append(f"- **发布时间**: {publish_time}")
        
        # 危害等级说明
        threat_level = item.get("threat_level", "INFO")
        level_desc = self._get_threat_level_desc(threat_level)
        lines.append(f"- **危害等级说明**: {level_desc}")
        
        return "\n".join(lines) if lines else ""

    def _build_technical_analysis(self, item: dict) -> str:
        """构建技术分析内容"""
        raw = item.get("raw", {})
        detail = raw.get("detail", {})
        summary = item.get("summary", "")
        content = item.get("content", "")
        lines = []
        
        # 漏洞描述（优先使用detail中的中文描述）
        cnvd_desc = detail.get("漏洞描述") or detail.get("描述")
        if cnvd_desc:
            lines.append(f"**漏洞描述**:\n{cnvd_desc[:800]}")
        elif summary:
            lines.append(f"**漏洞描述**:\n{summary[:800]}")
        elif content:
            lines.append(f"**漏洞描述**:\n{content[:800]}")
        
        # 技术细节
        tech_details = []
        if detail.get("漏洞类型"):
            tech_details.append(f"- 漏洞类型: {detail['漏洞类型']}")
        if detail.get("危害类型"):
            tech_details.append(f"- 危害类型: {detail['危害类型']}")
        if detail.get("攻击类型"):
            tech_details.append(f"- 攻击类型: {detail['攻击类型']}")
        if detail.get("攻击向量"):
            tech_details.append(f"- 攻击向量: {detail['攻击向量']}")
        if detail.get("参考链接"):
            tech_details.append(f"- 参考链接: {detail['参考链接'][:200]}")
        
        if raw.get("attack_vector"):
            tech_details.append(f"- 攻击向量: {raw['attack_vector']}")
        if raw.get("exploit_type"):
            tech_details.append(f"- 利用类型: {raw['exploit_type']}")
        
        if tech_details:
            lines.append(f"\n**技术细节**:\n{chr(10).join(tech_details)}")
        
        # 攻击向量推断
        if not (detail.get("攻击向量") or raw.get("attack_vector")):
            attack_vector = self._infer_attack_vector(item)
            if attack_vector:
                lines.append(f"\n**攻击向量**: {attack_vector}")
        
        # 利用条件
        exploit_conditions = self._infer_exploit_conditions(item)
        if exploit_conditions:
            lines.append(f"\n**利用条件**: {exploit_conditions}")
        
        # 漏洞原理
        vuln_principle = self._infer_vuln_principle(item)
        if vuln_principle:
            lines.append(f"\n**漏洞原理**: {vuln_principle}")
        
        return "\n".join(lines) if lines else ""

    def _build_potential_impact(self, item: dict, level: str) -> str:
        """构建潜在影响内容"""
        threat_level = item.get("threat_level", "INFO")
        vuln_type = self._infer_vuln_type(item)
        affected_entities = item.get("affected_entities", []) or []
        lines = []
        
        # 根据漏洞类型生成具体的影响描述
        impact_by_type = self._get_impact_by_vuln_type(vuln_type, threat_level)
        if impact_by_type:
            lines.append(f"- {impact_by_type}")
        
        # 业务影响评估
        business_impact = self._infer_business_impact(item)
        if business_impact:
            lines.append(f"- {business_impact}")
        
        # 数据风险
        data_risk = self._infer_data_risk(item)
        if data_risk:
            lines.append(f"- {data_risk}")
        
        # 系统风险
        system_risk = self._infer_system_risk(item)
        if system_risk:
            lines.append(f"- {system_risk}")
        
        # 影响范围
        if affected_entities:
            lines.append(f"- **直接影响组件**: {', '.join(affected_entities)}")
        elif item.get("title"):
            product_match = re.search(r"(Apache|Spring|Nginx|Tomcat|MySQL|Oracle|Microsoft|VMware|Docker|Kubernetes)", item["title"])
            if product_match:
                lines.append(f"- **可能影响**: {product_match.group(1)} 相关产品")
        
        # 风险等级对应的影响描述
        impact_desc = self._get_impact_description(vuln_type, threat_level)
        if impact_desc:
            lines.append(f"- **风险等级影响**: {impact_desc}")
        
        return "\n".join(lines) if lines else ""

    def _build_recommendations(self, item: dict, level: str) -> str:
        """构建处置建议内容"""
        # 优先使用 LLM 生成的建议
        if item.get("recommended_actions"):
            return "\n".join(f"- {a}" for a in item["recommended_actions"])
        
        # 根据漏洞类型生成针对性建议
        vuln_type = self._infer_vuln_type(item)
        return self._generate_specific_recommendations(vuln_type, level)

    def _extract_version_range(self, item: dict) -> str:
        """从标题和摘要中提取版本范围"""
        title = item.get("title", "")
        summary = item.get("summary", "")
        text = title + " " + summary
        
        # 匹配版本范围模式
        patterns = [
            r"(\d+\.\d+(\.\d+)?)\s*[~-]\s*(\d+\.\d+(\.\d+)?)",  # 1.0 ~ 2.0 或 1.0-2.0
            r"(\d+\.\d+(\.\d+)?)\s*to\s*(\d+\.\d+(\.\d+)?)",     # 1.0 to 2.0
            r"(?:version|versions?)\s*(\d+\.\d+(\.\d+)?)",        # version 1.0
            r"(?:affects|impacted)\s*(\d+\.\d+(\.\d+)?)",         # affects 1.0
            r"(\d+\.\d+(\.\d+)?)\s*(?:and below|以下)",            # 1.0 以下
            r"(?:<=|<)\s*(\d+\.\d+(\.\d+)?)",                    # <= 1.0
            r"(\d+\.\d+(\.\d+)?)\s*(?:之前|before)",              # 1.0 之前
            r"(?:低于|less than)\s*(\d+\.\d+(\.\d+)?)",          # 低于 1.0
        ]
        
        results = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if match[0]:
                    results.append(match[0])
        
        if results:
            return ", ".join(set(results))
        return ""

    def _get_threat_level_desc(self, level: str) -> str:
        """获取威胁等级描述"""
        level_descriptions = {
            "CRITICAL": "严重威胁，可能是0day漏洞或正在被大规模利用的高危漏洞，需要立即处置",
            "HIGH": "高危威胁，CVSS评分≥7.0的漏洞或重大安全事件，需要24小时内处置",
            "MEDIUM": "中危威胁，CVSS评分4.0-6.9的漏洞或可疑活动，需要本周内处置",
            "LOW": "低危威胁，CVSS评分0.1-3.9的漏洞或理论攻击面，持续关注即可",
            "INFO": "信息性内容，安全科普或公告，无需处置"
        }
        return level_descriptions.get(level, "未定义")

    def _infer_attack_vector(self, item: dict) -> str:
        """推断攻击向量"""
        title = item.get("title", "").lower()
        summary = item.get("summary", "").lower()
        text = title + " " + summary
        
        if any(kw in text for kw in ["远程", "remote", "网络", "无需认证"]):
            return "远程攻击 - 攻击者可通过网络远程利用此漏洞，无需物理接触目标系统"
        elif any(kw in text for kw in ["本地", "local", "本地提权", "本地攻击"]):
            return "本地攻击 - 需要攻击者已获得目标系统的本地访问权限"
        elif any(kw in text for kw in ["社会工程", "钓鱼", "社工", "诱骗"]):
            return "社会工程 - 需要诱使受害者执行特定操作才能触发"
        else:
            return "网络攻击 - 通过网络协议发起攻击"

    def _infer_exploit_conditions(self, item: dict) -> str:
        """推断利用条件"""
        title = item.get("title", "").lower()
        summary = item.get("summary", "").lower()
        text = title + " " + summary
        
        conditions = []
        
        if any(kw in text for kw in ["无需认证", "未授权", "unauthenticated", "未登录"]):
            conditions.append("无需身份认证")
        if any(kw in text for kw in ["无需交互", "被动", "passive", "自动触发"]):
            conditions.append("无需用户交互")
        if any(kw in text for kw in ["需要认证", "authenticated", "登录后"]):
            conditions.append("需要有效用户凭证")
        if any(kw in text for kw in ["特定条件", "特定场景", "特定配置"]):
            conditions.append("需要满足特定触发条件")
        if any(kw in text for kw in ["管理员", "admin", "root"]):
            conditions.append("需要管理员权限")
        
        if conditions:
            return "需要满足以下条件: " + " → ".join(conditions)
        return "标准利用条件"

    def _infer_vuln_principle(self, item: dict) -> str:
        """推断漏洞原理"""
        vuln_type = self._infer_vuln_type(item)
        
        principles = {
            "远程代码执行": "攻击者通过构造恶意输入，使目标系统执行非预期的代码。常见于用户输入未正确过滤导致命令执行或代码注入。",
            "SQL注入": "攻击者通过在输入中插入SQL语句，使数据库执行非预期的查询操作，可能导致数据泄露或篡改。",
            "XSS跨站脚本": "攻击者注入恶意脚本代码到网页中，当其他用户访问时执行，可窃取cookie或劫持会话。",
            "CSRF跨站请求伪造": "攻击者诱导用户在已认证的情况下执行非预期的操作，利用用户身份进行恶意请求。",
            "反序列化漏洞": "攻击者通过构造恶意序列化数据，在反序列化过程中触发代码执行，实现远程控制。",
            "SSRF服务端请求伪造": "攻击者诱导服务器发起非预期的请求，可访问内网资源或攻击内部系统。",
            "路径遍历": "攻击者通过../等特殊字符绕过路径限制，访问服务器上的任意文件，可能导致敏感信息泄露。",
            "文件上传漏洞": "攻击者上传恶意文件（如webshell）到服务器，获取服务器控制权。",
            "认证绕过": "攻击者通过各种手段绕过身份认证机制，获取未授权的系统访问权限。",
            "权限提升": "攻击者从低权限账户提升到高权限账户，获取系统管理员级别的访问权限。",
            "信息泄露": "系统未正确保护敏感信息，导致攻击者可获取不应公开的数据。",
            "拒绝服务": "攻击者通过大量请求或恶意操作使系统资源耗尽，导致服务不可用。",
            "命令注入": "攻击者在输入中插入系统命令，使服务器执行非预期的操作系统命令。",
            "缓冲区溢出": "攻击者通过超出缓冲区边界的输入覆盖内存，可能导致程序崩溃或代码执行。",
        }
        
        return principles.get(vuln_type, "")

    def _infer_business_impact(self, item: dict) -> str:
        """推断业务影响"""
        threat_level = item.get("threat_level", "INFO")
        vuln_type = self._infer_vuln_type(item)
        affected_entities = item.get("affected_entities", [])
        
        impact_map = {
            "CRITICAL": {
                "远程代码执行": "核心业务系统可能被完全控制，导致业务瘫痪、数据泄露和重大经济损失",
                "SQL注入": "数据库可能被攻破，导致核心业务数据泄露、篡改或删除",
                "反序列化漏洞": "应用服务器可能被完全控制，影响所有依赖该服务的业务",
                "SSRF服务端请求伪造": "内网资源可能被暴露，导致内部系统全面沦陷",
                "默认": "业务严重受损 - 核心系统可能被入侵，导致大规模数据泄露或业务中断"
            },
            "HIGH": {
                "XSS跨站脚本": "用户会话可能被劫持，导致用户数据泄露和账户安全风险",
                "CSRF跨站请求伪造": "用户可能被诱导执行恶意操作，导致业务数据异常",
                "文件上传漏洞": "服务器可能被植入恶意代码，影响业务服务可用性",
                "认证绕过": "未授权用户可能访问敏感功能，导致权限滥用和数据泄露",
                "默认": "业务受到影响 - 部分服务可能中断或数据可能泄露"
            },
            "MEDIUM": {
                "路径遍历": "敏感文件可能被读取，导致配置信息或业务数据泄露",
                "信息泄露": "非敏感但重要的业务信息可能被公开",
                "配置错误": "系统可能存在安全隐患，增加被攻击的风险",
                "默认": "业务轻微影响 - 次要功能可能异常或信息可能泄露"
            },
            "LOW": {
                "弱口令": "账户可能被暴力破解，导致个别用户数据风险",
                "默认": "业务影响有限 - 主要为安全风险提示，实际业务影响较小"
            }
        }
        
        level_map = impact_map.get(threat_level, {})
        impact = level_map.get(vuln_type, level_map.get("默认", ""))
        
        if affected_entities and impact:
            return f"**业务影响**: {impact}（影响组件: {', '.join(affected_entities)}）"
        elif impact:
            return f"**业务影响**: {impact}"
        return ""

    def _infer_data_risk(self, item: dict) -> str:
        """推断数据风险"""
        title = item.get("title", "").lower()
        summary = item.get("summary", "").lower()
        text = title + " " + summary
        
        if any(kw in text for kw in ["敏感数据", "password", "secret", "token", "密钥", "凭证", "api密钥"]):
            return "**数据泄露风险**: 可能导致敏感数据（密码、密钥、API凭证等）泄露，影响用户账户安全"
        elif any(kw in text for kw in ["数据库", "database", "sql", "数据篡改"]):
            return "**数据库风险**: 可能导致数据库被非法访问、数据被篡改或删除，影响业务数据完整性"
        elif any(kw in text for kw in ["隐私", "personal", "个人信息", "用户数据"]):
            return "**隐私风险**: 可能导致用户个人信息泄露，违反《个人信息保护法》等合规要求"
        elif any(kw in text for kw in ["财务", "金融", "money", "payment"]):
            return "**财务风险**: 可能导致财务数据泄露或资金安全受到威胁"
        else:
            return ""

    def _infer_system_risk(self, item: dict) -> str:
        """推断系统风险"""
        title = item.get("title", "").lower()
        summary = item.get("summary", "").lower()
        text = title + " " + summary
        vuln_type = self._infer_vuln_type(item)
        
        risks = []
        
        if vuln_type == "远程代码执行" or any(kw in text for kw in ["远程代码执行", "rce", "代码执行"]):
            risks.append("远程代码执行 - 攻击者可在目标系统上执行任意代码，完全控制服务器")
        if vuln_type == "权限提升" or any(kw in text for kw in ["权限提升", "提权", "privilege escalation"]):
            risks.append("权限提升 - 攻击者可获取更高系统权限，访问受限资源")
        if vuln_type == "拒绝服务" or any(kw in text for kw in ["拒绝服务", "dos", "ddos"]):
            risks.append("拒绝服务 - 系统可能被攻击导致服务不可用，影响业务连续性")
        if any(kw in text for kw in ["后门", "backdoor", "持久化", "植入"]):
            risks.append("持久化威胁 - 攻击者可能植入后门实现长期控制")
        if vuln_type == "反序列化漏洞" or any(kw in text for kw in ["反序列化"]):
            risks.append("反序列化攻击 - 攻击者可通过恶意序列化数据触发代码执行")
        if vuln_type == "SSRF服务端请求伪造" or any(kw in text for kw in ["ssrf", "内网"]):
            risks.append("内网穿透 - 攻击者可通过SSRF访问内网资源，扩大攻击面")
        
        if risks:
            return "**系统安全风险**: " + "；".join(risks)
        return ""

    def _get_impact_by_vuln_type(self, vuln_type: str, threat_level: str) -> str:
        """根据漏洞类型生成具体的影响描述"""
        impact_by_type = {
            "远程代码执行": {
                "CRITICAL": "攻击者可远程执行任意代码，完全控制目标系统，可能导致数据泄露、系统瘫痪或成为攻击跳板",
                "HIGH": "攻击者可远程执行代码，获取系统控制权，对业务运营造成严重威胁",
                "MEDIUM": "代码执行能力受限，但仍可能导致系统被入侵"
            },
            "SQL注入": {
                "CRITICAL": "数据库可能被完全攻破，导致核心业务数据泄露、篡改或删除，影响业务正常运行",
                "HIGH": "数据库可能被非法访问，敏感数据可能泄露",
                "MEDIUM": "可能获取部分数据库信息，存在数据泄露风险"
            },
            "XSS跨站脚本": {
                "CRITICAL": "可能导致大规模用户会话劫持，窃取大量用户凭证",
                "HIGH": "用户浏览器可能被劫持，导致账户安全风险",
                "MEDIUM": "可能窃取个别用户信息，影响用户信任"
            },
            "CSRF跨站请求伪造": {
                "CRITICAL": "可能导致用户执行非预期的敏感操作，如转账、删除数据等",
                "HIGH": "用户可能被诱导执行恶意操作，影响业务数据完整性",
                "MEDIUM": "可能导致用户执行非敏感操作，影响业务正常流程"
            },
            "反序列化漏洞": {
                "CRITICAL": "攻击者可通过恶意序列化数据完全控制服务器，风险极高",
                "HIGH": "可能导致远程代码执行，服务器安全性受到严重威胁"
            },
            "SSRF服务端请求伪造": {
                "CRITICAL": "攻击者可访问内网资源，可能导致内网系统全面沦陷",
                "HIGH": "可能暴露内网服务，增加攻击面",
                "MEDIUM": "可能访问受限资源，获取敏感信息"
            },
            "路径遍历": {
                "CRITICAL": "可读取任意系统文件，可能泄露敏感配置和数据",
                "HIGH": "可能读取敏感文件，泄露系统信息",
                "MEDIUM": "可能读取非敏感文件，获取系统结构信息"
            },
            "文件上传漏洞": {
                "CRITICAL": "可上传恶意文件获取服务器控制权，风险极高",
                "HIGH": "可能上传webshell，获取系统访问权限",
                "MEDIUM": "可能上传恶意文件，但执行受限"
            },
            "认证绕过": {
                "CRITICAL": "攻击者可绕过认证直接访问敏感功能，权限完全失效",
                "HIGH": "未授权用户可访问受限功能，权限控制失效",
                "MEDIUM": "可能绕过部分认证机制，获取非敏感功能访问权限"
            },
            "权限提升": {
                "CRITICAL": "普通用户可提升至管理员权限，完全控制系统",
                "HIGH": "低权限用户可获取更高权限，访问受限资源",
                "MEDIUM": "权限边界被突破，存在越权访问风险"
            },
            "信息泄露": {
                "CRITICAL": "大规模敏感数据泄露，影响用户隐私和企业声誉",
                "HIGH": "敏感信息暴露，可能被用于进一步攻击",
                "MEDIUM": "非敏感但有用的信息泄露，增加攻击面"
            },
            "拒绝服务": {
                "CRITICAL": "核心业务服务可能完全中断，造成重大经济损失",
                "HIGH": "部分服务可能中断，影响业务连续性",
                "MEDIUM": "服务性能下降，用户体验受影响"
            },
            "命令注入": {
                "CRITICAL": "攻击者可执行任意系统命令，完全控制服务器",
                "HIGH": "可执行系统命令，获取系统控制权",
                "MEDIUM": "命令执行能力受限，但仍存在安全风险"
            },
            "缓冲区溢出": {
                "CRITICAL": "可能导致程序崩溃或远程代码执行，系统安全性严重受损",
                "HIGH": "可能被利用执行恶意代码，系统面临被入侵风险"
            },
        }
        
        level_map = impact_by_type.get(vuln_type, {})
        return level_map.get(threat_level, "")

    def _get_impact_description(self, vuln_type: str, level: str) -> str:
        """获取风险等级对应的影响描述（差异化版本）"""
        base_descriptions = {
            "CRITICAL": "需立即响应 - 系统面临严重威胁，可能导致核心业务中断和大规模数据泄露",
            "HIGH": "需24小时内响应 - 系统存在高危风险，可能导致敏感数据泄露或服务中断",
            "MEDIUM": "需本周内评估 - 系统存在安全隐患，可能导致信息泄露或功能异常",
            "LOW": "持续关注即可 - 风险较低，主要为安全提示，实际影响有限"
        }
        return base_descriptions.get(level, "")

    def _generate_specific_recommendations(self, vuln_type: str, level: str) -> str:
        """根据漏洞类型生成针对性的处置建议"""
        recommendations_by_type = {
            "远程代码执行": [
                "立即检查受影响系统是否使用存在漏洞的组件",
                "立即应用官方安全补丁或升级到安全版本",
                "临时修复：限制网络访问，禁用不必要的服务和端口",
                "加强入侵检测，监控异常进程和网络连接",
                "评估是否已有攻击发生，检查系统日志"
            ],
            "SQL注入": [
                "检查所有用户输入点，确保使用参数化查询或预编译语句",
                "实施输入验证和输出编码，过滤特殊字符",
                "最小化数据库用户权限，避免使用超级用户连接数据库",
                "定期审计数据库访问日志，检测异常查询",
                "考虑使用Web应用防火墙(WAF)进行防护"
            ],
            "XSS跨站脚本": [
                "对所有用户输入进行严格过滤和转义",
                "实施内容安全策略(CSP)限制脚本执行",
                "使用HttpOnly和Secure标志保护cookie",
                "对输出进行HTML编码，防止脚本注入",
                "定期扫描代码中的XSS漏洞"
            ],
            "CSRF跨站请求伪造": [
                "实施CSRF Token验证机制",
                "检查请求来源，验证Referer头",
                "对敏感操作要求二次验证",
                "使用SameSite cookie属性",
                "实施请求签名验证"
            ],
            "反序列化漏洞": [
                "立即升级存在漏洞的序列化库版本",
                "禁用不必要的反序列化功能",
                "实施反序列化白名单验证",
                "使用安全的序列化格式（如JSON替代Java序列化）",
                "隔离反序列化操作，限制其权限"
            ],
            "SSRF服务端请求伪造": [
                "实施URL白名单验证，限制可访问的地址",
                "禁止访问内网IP地址和本地服务",
                "使用DNS解析验证，防止DNS重绑定攻击",
                "限制请求协议（如只允许HTTP/HTTPS）",
                "记录所有出站请求，监控异常访问"
            ],
            "路径遍历": [
                "对用户输入的路径进行规范化处理",
                "实施路径白名单验证，限制访问目录",
                "禁止使用../等特殊字符",
                "使用绝对路径访问文件，避免相对路径",
                "设置文件访问权限，最小化可读范围"
            ],
            "文件上传漏洞": [
                "验证文件类型（检查文件头和扩展名）",
                "限制上传文件大小和数量",
                "将上传文件存储在非Web可访问目录",
                "对文件名进行随机化处理，避免路径遍历",
                "禁止执行上传目录中的脚本文件"
            ],
            "认证绕过": [
                "审查认证逻辑，修复身份验证漏洞",
                "实施多因素认证(MFA)增强安全性",
                "加强会话管理，定期轮换会话令牌",
                "记录所有认证失败尝试，检测暴力破解",
                "实施账户锁定策略"
            ],
            "权限提升": [
                "审查权限配置，实施最小权限原则",
                "定期审计用户权限，移除不必要的权限",
                "实施权限变更审批流程",
                "监控权限提升操作，检测异常行为",
                "使用特权账户管理(PAM)解决方案"
            ],
            "信息泄露": [
                "审查系统日志和错误信息，避免暴露敏感数据",
                "实施数据脱敏，保护敏感信息",
                "限制日志级别，生产环境禁用DEBUG模式",
                "加密存储敏感配置信息",
                "审查API响应，移除不必要的字段"
            ],
            "拒绝服务": [
                "实施流量限制和速率控制",
                "配置DDoS防护方案",
                "优化系统性能，增加资源容量",
                "实施流量清洗，过滤恶意请求",
                "制定应急响应计划，准备故障转移方案"
            ],
            "命令注入": [
                "禁止直接执行用户输入的命令",
                "使用安全的API替代命令执行",
                "对用户输入进行严格验证和过滤",
                "使用白名单限制允许的命令和参数",
                "最小化执行命令的用户权限"
            ],
            "缓冲区溢出": [
                "升级到修复漏洞的软件版本",
                "启用编译器的安全选项（如ASLR、DEP）",
                "使用安全的编程语言和库",
                "实施代码审计，修复内存安全问题",
                "使用模糊测试发现潜在漏洞"
            ],
            "弱口令": [
                "强制实施强密码策略",
                "实施定期密码更换要求",
                "禁止使用默认密码",
                "实施账户锁定策略防止暴力破解",
                "推广使用密码管理器"
            ],
            "密钥泄露": [
                "立即轮换泄露的密钥和凭证",
                "审查密钥管理流程，实施安全存储",
                "使用密钥管理服务(KMS)集中管理密钥",
                "实施密钥轮换策略",
                "审计密钥访问日志，检测异常使用"
            ],
            "配置错误": [
                "审查系统配置，修复不安全的默认配置",
                "禁用不必要的服务和端口",
                "实施安全基线配置标准",
                "定期扫描配置漏洞",
                "使用配置管理工具确保一致性"
            ],
            "XML外部实体注入": [
                "禁用DTD处理或限制外部实体访问",
                "使用安全的XML解析库",
                "验证XML输入，拒绝恶意实体引用",
                "升级到最新版本的XML解析器",
                "限制XML文档大小"
            ],
            "模板注入": [
                "避免直接渲染用户输入的模板",
                "使用安全的模板引擎配置",
                "实施模板路径白名单",
                "对模板变量进行严格验证",
                "使用沙箱环境隔离模板执行"
            ],
        }
        
        # 获取针对特定漏洞类型的建议
        type_recommendations = recommendations_by_type.get(vuln_type, [])
        
        if type_recommendations:
            # 根据威胁等级调整建议数量和紧急程度
            if level == "CRITICAL":
                return "\n".join(f"- {r}" for r in type_recommendations[:5])
            elif level == "HIGH":
                return "\n".join(f"- {r}" for r in type_recommendations[:4])
            elif level == "MEDIUM":
                return "\n".join(f"- {r}" for r in type_recommendations[:3])
            else:
                return "\n".join(f"- {r}" for r in type_recommendations[:2])
        else:
            # 默认建议
            default_recommendations = {
                "CRITICAL": [
                    "立即评估受影响系统是否存在该漏洞",
                    "立即应用官方安全补丁或临时修复措施",
                    "加强网络监控，检测是否已有攻击发生",
                    "如有必要，临时关闭受影响服务或限制访问",
                    "通知相关业务和安全团队进行应急响应"
                ],
                "HIGH": [
                    "评估受影响系统范围和业务影响",
                    "制定补丁更新计划并尽快实施",
                    "加强日志监控，关注异常活动",
                    "考虑启用相关安全防护规则"
                ],
                "MEDIUM": [
                    "纳入常规安全更新计划",
                    "评估业务影响和修复优先级",
                    "考虑是否需要临时缓解措施"
                ],
                "LOW": [
                    "持续关注漏洞动态",
                    "纳入定期安全审查范围",
                    "无需立即采取紧急措施"
                ]
            }
            return "\n".join(f"- {r}" for r in default_recommendations.get(level, []))