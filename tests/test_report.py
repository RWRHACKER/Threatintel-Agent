#!/usr/bin/env python3
"""测试报告生成器改进"""

from src.reporters.reporter import Reporter

# 创建报告生成器
r = Reporter({'output_dir': 'reports', 'formats': ['markdown', 'json']})

# 测试数据
sample_items = [
    {
        'title': 'Apache Log4j 远程代码执行漏洞(CVE-2021-44228)',
        'source': 'CNVD',
        'threat_level': 'CRITICAL',
        'confidence': 0.95,
        'urgency': '立即处置',
        'is_actionable': True,
        'summary': 'Apache Log4j是Apache软件基金会的一个Java日志库。攻击者可以通过构造恶意请求，触发Log4j的JNDI功能，从而在目标服务器上执行任意代码。该漏洞影响使用Log4j 2.0至2.14.1版本的应用程序，攻击者无需认证即可远程利用此漏洞。',
        'content': '该漏洞是由于Log4j库在处理JNDI Lookup时没有正确验证用户输入导致的。攻击者可以通过在日志消息中注入恶意JNDI引用，使服务器连接到恶意LDAP服务器并执行任意代码。',
        'url': 'https://cnvd.org.cn',
        'raw': {
            'cvss_score': '9.8',
            'cvss_severity': 'CRITICAL',
            'cnvd_id': 'CNVD-2021-95914',
            'cve_id': 'CVE-2021-44228',
            'vendor': 'Apache',
            'status': '已公开',
            'publish_time': '2021-12-09',
            'detail': {
                '漏洞类型': '远程代码执行',
                '危害类型': '代码执行',
                '攻击类型': '远程攻击',
                '攻击向量': '网络',
                '漏洞描述': 'Apache Log4j是Apache软件基金会的一个Java日志库。攻击者可以通过构造恶意请求，触发Log4j的JNDI功能，从而在目标服务器上执行任意代码。该漏洞影响使用Log4j 2.0至2.14.1版本的应用程序，攻击者无需认证即可远程利用此漏洞执行任意代码。'
            }
        },
        'affected_entities': ['Apache Log4j', 'Elasticsearch', 'Solr', 'Kafka']
    },
    {
        'title': 'Spring Boot 路径遍历漏洞',
        'source': 'FreeBuf',
        'threat_level': 'HIGH',
        'confidence': 0.85,
        'urgency': '尽快处置',
        'is_actionable': True,
        'summary': 'Spring Boot应用存在路径遍历漏洞，攻击者可以通过构造恶意URL访问服务器上的任意文件。该漏洞影响Spring Boot 2.6.x版本，攻击者可以通过../等特殊字符绕过路径限制。',
        'content': '该漏洞是由于Spring Boot在处理静态资源请求时没有正确过滤路径字符导致的。攻击者可以通过构造类似../的路径来访问Web根目录之外的文件。',
        'url': 'https://www.freebuf.com',
        'raw': {
            'cvss_score': '7.5',
            'cvss_severity': 'HIGH',
            'vendor': 'Spring',
            'status': '已修复',
            'detail': {
                '漏洞类型': '路径遍历',
                '危害类型': '信息泄露',
                '攻击类型': '远程攻击'
            }
        }
    },
    {
        'title': 'WordPress XSS跨站脚本漏洞',
        'source': 'FreeBuf',
        'threat_level': 'MEDIUM',
        'confidence': 0.75,
        'urgency': '计划处置',
        'is_actionable': True,
        'summary': 'WordPress存在跨站脚本漏洞，攻击者可以通过评论功能注入恶意脚本，当管理员查看评论时执行。',
        'content': '该漏洞存在于评论处理模块，用户提交的评论内容没有经过正确的HTML转义处理。',
        'url': 'https://www.freebuf.com',
        'raw': {
            'cvss_score': '5.4',
            'cvss_severity': 'MEDIUM',
            'vendor': 'WordPress',
            'status': '已修复'
        }
    }
]

# 生成报告
result = r.generate(sample_items, {'used_llm': True, 'raw_count': 3})
print('报告生成成功:', result)