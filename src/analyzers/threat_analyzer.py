"""威胁情报分析器：LLM 驱动的威胁研判、评级、关联分析"""

import json
import os
from src.utils.helpers import logger, deduplicate_items


class ThreatAnalyzer:
    """使用 LLM 对采集到的情报条目进行分析评级"""

    # 分析 Prompt 模板（中文详细分析版）
    ANALYSIS_PROMPT = """你是一名资深威胁情报分析师。请分析以下安全情报条目，为每条评定威胁等级并用中文撰写详细的技术分析报告。

## 威胁等级定义
- CRITICAL: 正在被大规模利用的高危漏洞、生产环境密钥泄露、0day漏洞
- HIGH: 高危漏洞(CVSS≥7.0)、重大安全事件、针对性攻击活动
- MEDIUM: 中危漏洞、可疑活动、需要关注的安全动态
- LOW: 低危漏洞、一般性安全新闻、理论攻击面
- INFO: 纯信息性内容、安全科普、无直接威胁

## 需要分析的条目
{items_text}

## 输出要求
请以 JSON 格式输出分析结果。**每条必须包含用中文撰写的详细技术分析、潜在影响和处置建议**，格式如下:
```json
{{
  "analyses": [
    {{
      "id": "原始条目ID",
      "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": 0.0-1.0,
      "reasoning": "简短研判理由(1-2句中文)",
      "vuln_description_cn": "中文漏洞描述与技术分析（2-4段,150-400字）：包括漏洞原理、利用方式、攻击面、受影响版本等。如果原始信息是英文标题/摘要，请翻译并扩展成详细的中文技术分析。对 CVE 漏洞要说明其成因和利用条件；对 GitHub 泄露要说明泄露了什么类型的信息及可能后果；对安全新闻要提炼关键事实。",
      "potential_impact_cn": "中文潜在影响评估（1-2段,80-200字）：分析该漏洞/事件可能造成的实际危害，包括受影响系统范围、攻击者利用后的后果、业务影响等",
      "recommended_actions_cn": "中文处置建议（3-5条列表）：具体、可操作的修复和缓解措施，按优先级排列。包括补丁升级、配置加固、监控检测、应急响应等具体步骤",
      "affected_entities": ["受影响的系统/组织/人群"],
      "recommended_actions": ["简短建议标签（英文）"],
      "tags": ["标签1", "标签2"],
      "is_actionable": true/false,
      "urgency": "立即处置|24小时内|本周内|持续关注|无需处置"
    }}
  ],
  "overall_summary": "整体态势摘要(2-3句中文)"
}}
```

**重要**: vuln_description_cn、potential_impact_cn、recommended_actions_cn 三个字段必须填写实质性内容，不能省略或写"暂无信息"。
    """

    def __init__(self, config: dict):
        self.config = config
        self.llm_config = config.get("llm", {})
        self.threat_levels = config.get("analyzers", {}).get("threat_levels",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.dedup_threshold = config.get("analyzers", {}).get("dedup_threshold", 0.85)
        # 分批处理配置
        self.batch_size = self.llm_config.get("batch_size", 10)
        self.max_items = self.llm_config.get("max_items", 100)

        # 初始化 OpenAI 兼容客户端（支持 OpenAI / DeepSeek 等任何兼容 API）
        try:
            from openai import OpenAI
            provider = self.llm_config.get("provider", "openai").lower()
            
            # 按 provider 确定 api_key / base_url / model
            if provider == "deepseek":
                api_key = self.llm_config.get("api_key") or os.getenv("DEEPSEEK_API_KEY")
                base_url = self.llm_config.get("api_base") or os.getenv("DEEPSEEK_API_BASE") or "https://api.deepseek.com/v1"
                self.model = self.llm_config.get("model", "deepseek-chat")
            else:
                # openai 或任何 OpenAI 兼容服务
                api_key = self.llm_config.get("api_key") or os.getenv("OPENAI_API_KEY")
                base_url = self.llm_config.get("api_base") or os.getenv("OPENAI_API_BASE")
                self.model = self.llm_config.get("model", "gpt-4o-mini")
            
            if not api_key:
                logger.warning(f"[ThreatAnalyzer] 未配置 {provider.upper()}_API_KEY，将使用规则引擎降级分析")
                self.client = None
            else:
                self.client = OpenAI(api_key=api_key, base_url=base_url)
                logger.info(f"[ThreatAnalyzer] LLM 客户端初始化成功 (provider={provider}, model={self.model})")
        except Exception as e:
            logger.warning(f"[ThreatAnalyzer] LLM 初始化失败，将使用规则引擎: {e}")
            self.client = None

        # 防止 _model 未定义
        if not hasattr(self, 'model'):
            self.model = self.llm_config.get("model", "gpt-4o-mini")

    def analyze(self, items: list[dict]) -> list[dict]:
        """对采集条目进行威胁分析"""
        if not items:
            logger.info("[ThreatAnalyzer] 无条目需要分析")
            return []

        # 先去重
        items = deduplicate_items(items)
        logger.info(f"[ThreatAnalyzer] 去重后待分析: {len(items)} 条")

        # 限制最大分析数量
        if len(items) > self.max_items:
            logger.warning(f"[ThreatAnalyzer] 条目数量 {len(items)} 超过最大限制 {self.max_items}，截断处理")
            items = items[:self.max_items]

        # 有 LLM 时先探测一下是否可用，不可用直接走规则引擎
        if self.client and not self._check_llm_available():
            logger.warning("[ThreatAnalyzer] LLM 不可用（quota耗尽/网络问题），自动降级到规则引擎")
            self.client = None  # 标记不可用，避免后续重试

        if self.client:
            return self._analyze_with_llm(items)
        else:
            return self._analyze_with_rules(items)

    def _check_llm_available(self) -> bool:
        """探测 LLM 是否可用（发送极小请求）"""
        try:
            timeout = self.llm_config.get("timeout", 30)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
                timeout=timeout
            )
            return True
        except Exception as e:
            error_str = str(e)
            if "insufficient_quota" in error_str or "429" in error_str:
                logger.warning(f"[ThreatAnalyzer] LLM quota 检测: 余额不足")
            else:
                logger.warning(f"[ThreatAnalyzer] LLM 连通性检测失败: {e}")
            return False

    def _analyze_with_llm(self, items: list[dict]) -> list[dict]:
        """使用 LLM 进行分析（支持并发分批处理）"""
        total_count = len(items)
        
        if total_count <= self.batch_size:
            # 单批处理
            return self._analyze_batch(items)
        
        # 分批处理
        num_batches = (total_count + self.batch_size - 1) // self.batch_size
        logger.info(f"[ThreatAnalyzer] 分批分析: {total_count} 条 → {num_batches} 批")
        
        # 检查是否启用并发
        concurrent_requests = self.llm_config.get("concurrent_requests", 1)
        
        if concurrent_requests > 1 and num_batches > 1:
            return self._analyze_concurrent(items)
        else:
            return self._analyze_sequential(items)
    
    def _analyze_sequential(self, items: list[dict]) -> list[dict]:
        """顺序分批分析"""
        total_count = len(items)
        all_results = []
        overall_summaries = []
        
        for i in range(0, total_count, self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_num = (i // self.batch_size) + 1
            logger.info(f"[ThreatAnalyzer] 处理第 {batch_num} 批: {len(batch)} 条")
            
            try:
                batch_results = self._analyze_batch(batch)
                all_results.extend(batch_results)
                
                if batch_results and "_overall_summary" in batch_results[0]:
                    overall_summaries.append(batch_results[0]["_overall_summary"])
            except Exception as e:
                logger.error(f"[ThreatAnalyzer] 第 {batch_num} 批分析失败: {e}")
                batch_results = self._analyze_with_rules(batch)
                all_results.extend(batch_results)
        
        if overall_summaries and all_results:
            all_results[0]["_overall_summary"] = "\n".join(overall_summaries)
        
        return all_results
    
    def _analyze_concurrent(self, items: list[dict]) -> list[dict]:
        """并发分批分析"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        total_count = len(items)
        concurrent_requests = self.llm_config.get("concurrent_requests", 3)
        
        # 准备批次
        batches = []
        for i in range(0, total_count, self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_num = (i // self.batch_size) + 1
            batches.append((batch_num, batch))
        
        logger.info(f"[ThreatAnalyzer] 并发分析: {len(batches)} 批, 并发数: {concurrent_requests}")
        
        all_results = []
        overall_summaries = []
        futures = {}
        
        # 使用线程池并发处理
        with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
            # 提交所有批次
            for batch_num, batch in batches:
                future = executor.submit(self._analyze_batch_with_fallback, batch_num, batch)
                futures[future] = batch_num
            
            # 收集结果
            for future in as_completed(futures):
                batch_num = futures[future]
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)
                    
                    if batch_results and "_overall_summary" in batch_results[0]:
                        overall_summaries.append(batch_results[0]["_overall_summary"])
                except Exception as e:
                    logger.error(f"[ThreatAnalyzer] 并发批 {batch_num} 失败: {e}")
        
        # 按原始顺序排序
        all_results.sort(key=lambda x: x.get('id', ''))
        
        if overall_summaries and all_results:
            all_results[0]["_overall_summary"] = "\n".join(overall_summaries)
        
        return all_results
    
    def _analyze_batch_with_fallback(self, batch_num: int, batch: list[dict]) -> list[dict]:
        """分析单批并带有降级处理（用于并发）"""
        logger.info(f"[ThreatAnalyzer] 并发处理批 {batch_num}: {len(batch)} 条")
        try:
            return self._analyze_batch(batch)
        except Exception as e:
            logger.warning(f"[ThreatAnalyzer] 批 {batch_num} LLM分析失败，降级到规则引擎: {e}")
            return self._analyze_with_rules(batch)

    def _analyze_batch(self, items: list[dict]) -> list[dict]:
        """分析单批条目"""
        # 构建输入文本
        items_text_parts = []
        for i, item in enumerate(items):
            items_text_parts.append(
                f"--- 条目 {i+1} ---\n"
                f"ID: {item.get('id', '')}\n"
                f"来源: {item.get('source', '')}\n"
                f"标题: {item.get('title', '')}\n"
                f"摘要: {item.get('summary', '')}\n"
                f"CVSS评分: {item.get('raw', {}).get('cvss_score', 'N/A')}\n"
                f"CVSS等级: {item.get('raw', {}).get('cvss_severity', 'N/A')}\n"
            )
        items_text = "\n".join(items_text_parts)

        prompt = self.ANALYSIS_PROMPT.format(items_text=items_text)

        try:
            timeout = self.llm_config.get("timeout", 30)
            logger.info(f"[ThreatAnalyzer] 调用 LLM 分析 {len(items)} 条情报...")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一名资深威胁情报分析师，请用 JSON 格式输出分析结果。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.llm_config.get("temperature", 0.3),
                max_tokens=self.llm_config.get("max_tokens", 4096),
                timeout=timeout,
            )
            content = response.choices[0].message.content.strip()

            # 尝试提取 JSON
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            result = json.loads(content)
            analyses = result.get("analyses", [])

            # 合并回原始条目
            return self._merge_analyses(items, analyses, result.get("overall_summary", ""))

        except json.JSONDecodeError as e:
            logger.error(f"[ThreatAnalyzer] LLM 返回的 JSON 解析失败: {e}")
            logger.debug(f"原始输出: {content[:500]}...")
            return self._analyze_with_rules(items)
        except Exception as e:
            logger.error(f"[ThreatAnalyzer] LLM 分析失败: {e}")
            return self._analyze_with_rules(items)

    def _analyze_with_rules(self, items: list[dict]) -> list[dict]:
        """基于规则的降级分析（无需 LLM）"""
        logger.info(f"[ThreatAnalyzer] 使用规则引擎分析 {len(items)} 条情报")

        # 威胁关键词规则
        critical_keywords = [
            "0day", "零日漏洞", "远程代码执行", "rce", "remote code execution",
            "命令注入", "command injection", "反序列化", "deserialization",
            "任意代码执行", "arbitrary code execution", "提权", "权限提升",
            "privilege escalation", "未授权访问", "unauthorized access",
            "大规模利用", "mass exploitation", "在野利用", "active exploitation",
            "供应链攻击", "supply chain attack", "apt", "高级持续性威胁",
            "生产环境", "production", "敏感信息泄露", "敏感数据泄露"
        ]
        
        high_keywords = [
            "sql注入", "sql injection", "认证绕过", "authentication bypass",
            "文件上传", "file upload", "路径遍历", "path traversal",
            "目录遍历", "directory traversal", "ssrf", "服务端请求伪造",
            "server-side request forgery", "xxe", "xml外部实体",
            "xml external entity", "反序列化漏洞", "deserialization vulnerability",
            "本地提权", "local privilege escalation", "密码泄露", "password leak",
            "密钥泄露", "secret leak", "token泄露", "token exposure",
            "配置泄露", "configuration exposure", "git泄露", "git exposure"
        ]
        
        medium_keywords = [
            "xss", "跨站脚本", "cross-site scripting", "csrf",
            "跨站请求伪造", "cross-site request forgery", "信息泄露",
            "information disclosure", "拒绝服务", "denial of service", "dos",
            "ddos", "分布式拒绝服务", "弱口令", "weak password",
            "默认密码", "default credential", "不安全配置", "insecure configuration",
            "敏感信息", "sensitive information", "日志泄露", "log exposure"
        ]
        
        low_keywords = [
            "安全更新", "security update", "补丁发布", "patch release",
            "安全公告", "security advisory", "漏洞通报", "vulnerability report",
            "安全研究", "security research", "安全分析", "security analysis"
        ]

        for item in items:
            raw = item.get("raw", {})
            summary = item.get("summary", "").lower()
            title = item.get("title", "").lower()
            source = item.get("source", "")
            content = item.get("content", "").lower()
            text = title + " " + summary + " " + content

            level = "INFO"
            reasoning = []
            tags = ["rule-based"]

            # ── 规则 1: CVSS 评分（优先级最高）──
            cvss_score = raw.get("cvss_score")
            if cvss_score is not None:
                try:
                    score = float(cvss_score)
                    if score >= 9.0:
                        level = "CRITICAL"
                        reasoning.append(f"CVSS评分 {score}")
                    elif score >= 7.0:
                        level = "HIGH"
                        reasoning.append(f"CVSS评分 {score}")
                    elif score >= 4.0:
                        level = "MEDIUM"
                        reasoning.append(f"CVSS评分 {score}")
                    else:
                        level = "LOW"
                        reasoning.append(f"CVSS评分 {score}")
                except (ValueError, TypeError):
                    pass

            # ── 规则 2: CNVD 严重级别 ──
            if level == "INFO":
                cnvd_severity = raw.get("detail", {}).get("severity", "").lower()
                if cnvd_severity:
                    if "高危" in cnvd_severity or "critical" in cnvd_severity:
                        level = "HIGH"
                        reasoning.append(f"CNVD级别: {cnvd_severity}")
                    elif "中危" in cnvd_severity or "medium" in cnvd_severity:
                        level = "MEDIUM"
                        reasoning.append(f"CNVD级别: {cnvd_severity}")

            # ── 规则 3: 关键词匹配 ──
            if level == "INFO":
                # 检测 CRITICAL 级别关键词
                for kw in critical_keywords:
                    if kw.lower() in text:
                        level = "CRITICAL"
                        reasoning.append(f"关键词: {kw}")
                        tags.append(kw)
                        break
                
                # 检测 HIGH 级别关键词
                if level == "INFO":
                    for kw in high_keywords:
                        if kw.lower() in text:
                            level = "HIGH"
                            reasoning.append(f"关键词: {kw}")
                            tags.append(kw)
                            break
                
                # 检测 MEDIUM 级别关键词
                if level == "INFO":
                    for kw in medium_keywords:
                        if kw.lower() in text:
                            level = "MEDIUM"
                            reasoning.append(f"关键词: {kw}")
                            tags.append(kw)
                            break
                
                # 检测 LOW 级别关键词
                if level == "INFO":
                    for kw in low_keywords:
                        if kw.lower() in text:
                            level = "LOW"
                            reasoning.append(f"关键词: {kw}")
                            tags.append(kw)
                            break

            # ── 规则 4: 来源特定规则 ──
            if level == "INFO":
                if source == "GitHub-Leak-Scan":
                    level = "HIGH"
                    reasoning.append("GitHub敏感信息泄露")
                    tags.append("github-leak")
                elif source == "CNVD":
                    level = "MEDIUM"
                    reasoning.append("CNVD漏洞通报")
                    tags.append("cnvd")

            # ── 规则 5: 特殊标记检测 ──
            if level in ("CRITICAL", "HIGH"):
                if any(marker in text for marker in ["紧急", "urgent", "critical", "高危"]):
                    tags.append("urgent")

            # 计算置信度
            confidence = 0.5 + (len(reasoning) * 0.1)
            confidence = min(confidence, 0.9)

            item["threat_level"] = level
            item["confidence"] = round(confidence, 2)
            item["reasoning"] = "; ".join(reasoning) if reasoning else f"基于规则自动研判: {level}"
            item["affected_entities"] = self._extract_affected_entities(title, summary)
            item["recommended_actions"] = self._generate_recommendations(level, title, summary)
            item["tags"] = list(set(tags))
            item["is_actionable"] = level in ("CRITICAL", "HIGH")
            item["urgency"] = {
                "CRITICAL": "立即处置",
                "HIGH": "24小时内",
                "MEDIUM": "本周内",
                "LOW": "持续关注",
                "INFO": "无需处置"
            }.get(level, "持续关注")
            # 规则引擎降级：中文分析字段留空（报告中会显示「规则引擎降级，暂无 LLM 分析」）
            item["vuln_description_cn"] = ""
            item["potential_impact_cn"] = ""
            item["recommended_actions_cn"] = ""

        return items

    def _extract_affected_entities(self, title: str, summary: str) -> list[str]:
        """从标题和摘要中提取受影响实体"""
        entities = []
        text = title + " " + summary
        
        # 常见软件/产品关键词
        products = ["apache", "nginx", "mysql", "redis", "mongodb", "docker",
                    "kubernetes", "jenkins", "wordpress", "drupal",
                    "tomcat", "spring", "struts", "django", "flask",
                    "windows", "linux", "android", "ios", "macos"]
        
        for product in products:
            if product.lower() in text.lower():
                entities.append(product.capitalize())
        
        return entities[:5]

    def _generate_recommendations(self, level: str, title: str, summary: str) -> list[str]:
        """根据威胁级别生成建议措施"""
        recommendations = []
        
        if level == "CRITICAL":
            recommendations = [
                "立即评估受影响系统",
                "尽快应用安全补丁",
                "监控异常访问行为",
                "临时禁用受影响功能"
            ]
        elif level == "HIGH":
            recommendations = [
                "评估受影响范围",
                "计划安全更新",
                "加强监控告警"
            ]
        elif level == "MEDIUM":
            recommendations = [
                "纳入常规安全更新计划",
                "评估业务影响"
            ]
        
        return recommendations

    def _merge_analyses(self, items: list[dict], analyses: list[dict], overall_summary: str) -> list[dict]:
        """将 LLM 分析结果合并回原始条目"""
        analysis_map = {a.get("id", ""): a for a in analyses}

        for item in items:
            aid = item.get("id", "")
            analysis = analysis_map.get(aid, {})

            item["threat_level"] = analysis.get("threat_level", "INFO")
            item["confidence"] = analysis.get("confidence", 0.5)
            item["reasoning"] = analysis.get("reasoning", "")
            item["affected_entities"] = analysis.get("affected_entities", [])
            item["recommended_actions"] = analysis.get("recommended_actions", [])
            item["tags"] = analysis.get("tags", [])
            item["is_actionable"] = analysis.get("is_actionable", False)
            item["urgency"] = analysis.get("urgency", "持续关注")
            # 新增：LLM 生成的中文详细分析
            item["vuln_description_cn"] = analysis.get("vuln_description_cn", "")
            item["potential_impact_cn"] = analysis.get("potential_impact_cn", "")
            item["recommended_actions_cn"] = analysis.get("recommended_actions_cn", "")

        # 把 overall_summary 挂到第一个条目上
        if items:
            items[0]["_overall_summary"] = overall_summary

        return items