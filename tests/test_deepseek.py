#!/usr/bin/env python3
"""测试 DeepSeek API 连接"""

import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 测试 DeepSeek API
try:
    from openai import OpenAI
    
    api_key = os.getenv("DEEPSEEK_API_KEY")
    base_url = os.getenv("DEEPSEEK_API_BASE") or "https://api.deepseek.com/v1"
    
    print(f"API Key: {api_key[:10]}...")
    print(f"Base URL: {base_url}")
    
    client = OpenAI(api_key=api_key, base_url=base_url)
    
    # 发送测试请求
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "user", "content": "用中文分析一下CVE-2021-44228 Log4j漏洞的技术原理和潜在影响"}
        ],
        max_tokens=500,
        temperature=0.3,
        timeout=30
    )
    
    content = response.choices[0].message.content
    print("\n✅ DeepSeek API 响应成功!")
    print("=" * 50)
    print(content)
    
except Exception as e:
    print(f"\n❌ DeepSeek API 调用失败: {e}")
    import traceback
    traceback.print_exc()