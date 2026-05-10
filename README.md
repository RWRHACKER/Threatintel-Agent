# ThreatIntel Agent — 威胁情报聚合分析平台

自动采集公开安全情报源（CVE漏洞、GitHub泄露、安全新闻），用 LLM 驱动多 Agent 协作（采集→分析→报告），输出结构化威胁情报报告。
核心特性：
• 多源异步并发采集：CVE、GitHub 泄露、The Hacker News 等
• LLM 中文深度分析：每条漏洞产出 150-400 字中文技术分析
• 智能降级：LLM 不可用时自动切换规则引擎，7×24 可用
• 批量并发处理：降低 API 成本
• MD5 去重 + 智能缓存
• 多渠道告警：邮件/钉钉/企业微信
• RESTful API + 定时调度
## 🚀 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置 API Key
cp .env.example .env
# 编辑 .env，填入 DEEPSEEK_API_KEY（推荐使用 DeepSeek v4-flash）

# 3. 运行
python main.py --auto                            # 全源采集+分析（推荐）
python main.py --query "最近的高危漏洞"           # LLM 辅助查询
python main.py --source cve --keyword apache     # 指定源+关键词
python main.py --source github                   # 仅检查 GitHub 泄露
python main.py --output json                     # JSON 格式输出
python main.py --no-cache                        # 强制刷新缓存
```

## ⚡ 性能优化特性

| 优化项 | 说明 | 效果 |
|--------|------|------|
| **异步并发采集** | 使用 ThreadPoolExecutor 并行采集多数据源 | 采集速度提升 3-5x |
| **LLM 批量处理** | 支持批量分析，减少 API 调用次数 | 分析效率提升 2-3x |
| **智能缓存** | 基于指纹的去重和结果缓存 | 重复请求秒级响应 |
| **降级机制** | LLM 不可用时自动切换规则引擎 | 保证服务可用性 |

## 📁 项目结构

```
threatintel-agent/
├── main.py                  # CLI 入口
├── config/
│   └── default.yaml         # 默认配置（采集源、LLM 参数等）
├── src/
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py          # 采集器基类
│   │   ├── async_collector.py # 异步并发采集器
│   │   ├── cve.py           # CVE/NVD 漏洞采集
│   │   ├── github.py        # GitHub 敏感信息泄露扫描
│   │   ├── freebuf.py       # FreeBuf 安全社区（暂禁用）
│   │   ├── cnvd.py          # CNVD 漏洞库（暂禁用，需申请 API）
│   │   └── security_news.py # 国际安全新闻（The Hacker News 等）
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── threat_analyzer.py  # LLM 威胁分析+评级（支持 DeepSeek）
│   │   └── asset_impact_analyzer.py # 资产影响评估
│   ├── reporters/
│   │   ├── __init__.py
│   │   └── reporter.py      # Markdown/JSON 报告生成（含中文分析）
│   ├── scheduler/
│   │   ├── __init__.py
│   │   ├── scheduler.py     # 定时任务调度
│   │   └── task_executor.py # 任务执行器（避免循环引用）
│   ├── storage/
│   │   ├── __init__.py
│   │   └── database.py      # SQLite 数据库存储
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── alert_manager.py # 告警通知（邮件/钉钉/企业微信）
│   ├── api/
│   │   ├── __init__.py
│   │   └── api.py            # RESTful API 服务
│   └── utils/
│       ├── __init__.py
│       └── helpers.py       # 缓存/日志/去重等工具函数
├── data/
│   ├── reports/
│   │   ├── archive/         # 历史报告归档（按年月）
│   │   └── report_index.json # 报告索引
│   └── cache/               # API 响应缓存
└── tests/
```

## 🧠 架构设计

```
用户输入 → CLI / API / 定时任务
              │
              ▼
        ┌─────────────┐
        │  Orchestrator │  ← 任务编排与调度
        └──────┬──────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
 Collector  Collector  Collector   ← 异步并行采集
  (CVE)    (GitHub)   (SecurityNews)
    │          │          │
    └──────────┼──────────┘
               ▼
        ┌─────────────┐
        │   Analyzer  │  ← LLM 分析 + 规则引擎降级
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │   Reporter  │  ← 生成报告 + 数据库存储 + 告警
        └─────────────┘
```

## 🔧 支持的数据源

| 数据源 | 状态 | 说明 |
|--------|------|------|
| **CVE-NVD** | ✅ 正常 | 美国国家漏洞数据库 |
| **GitHub Search** | ✅ 正常 | 敏感信息泄露检测 |
| **Security News** | ✅ 正常 | The Hacker News、Krebs on Security |
| **FreeBuf** | ⏳ 暂禁用 | RSS 源不稳定，待修复 |
| **CNVD** | ⏳ 暂禁用 | 需要申请官方 API |

## 📊 输出报告示例

生成的报告包含完整的中文技术分析：

```markdown
# 🛡️ 威胁情报报告 — 2026-05-10

## 📋 概览
| 指标 | 数值 |
|------|------|
| 采集源数 | 3 |
| 原始条目 | 80 |
| 🔴 严重 | 7 |
| 🟠 高危 | 16 |

## 🔴 严重威胁

### CVE-2026-42368 — GeoVision 权限提升漏洞

#### 📋 基本信息
| 字段 | 内容 |
|------|------|
| **威胁等级** | 🔴 严重 |
| **CVSS** | 9.8 |
| **处置优先级** | 立即处置 |

#### 🔍 漏洞核心信息
- **漏洞类型**: 认证绕过 + 权限提升
- **影响产品**: GeoVision LPC2011/LPC2211 固件
- **受影响版本**: 1.10

#### 📊 技术分析
漏洞位于 Web 接口的 CGI 功能中，由于权限检查不足，攻击者可直接执行特权操作（添加管理员、修改配置等）。

#### ⚠️ 潜在影响
未授权攻击者可完全控制受影响设备，获取监控视频、修改系统配置。

#### ✅ 处置建议
1. 立即升级固件到最新版本
2. 限制设备管理接口访问 IP
3. 启用额外认证机制
```

## ⚙️ 配置说明

编辑 `config/default.yaml` 可调整：

```yaml
# LLM 配置（推荐使用 DeepSeek）
llm:
  provider: deepseek          # openai | deepseek
  model: deepseek-v4-flash    # 模型名称
  api_base: https://api.deepseek.com/v1
  temperature: 0.3
  batch_size: 15              # 批量分析大小
  concurrent_requests: 5      # 并发请求数

# 采集源配置
collectors:
  cve:
    enabled: true
    results_per_page: 20
  github:
    enabled: true
    search_queries:
      - "password OR secret OR token filename:.env"

# 报告配置
reporter:
  output_dir: data/reports
  formats:
    - markdown
    - json
```

## 📡 API 服务

启动 RESTful API 服务：

```bash
python main.py --api
```

访问 `http://localhost:8000/docs` 查看接口文档。

## ⏰ 定时任务

启用定时任务：

```bash
python main.py --scheduler
```

配置文件中定义的定时任务：
- 每小时检查 CVE 漏洞
- 每天凌晨执行全量采集
- 每6小时检查 GitHub 泄露

## 📝 注意事项

⚠️ **合规声明**: 本项目仅采集公开可访问的数据源，不涉及暗网、社工库等灰色地带。所有采集行为遵守目标网站的 robots.txt 和使用条款。

⚠️ **安全建议**: 建议将报告存储在安全位置，敏感信息如 API Key 应通过环境变量配置。

## 📄 License

MIT License
