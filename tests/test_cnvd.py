"""测试 CNVD 网站访问"""

import requests
import time

def test_cnvd_access():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    session = requests.Session()
    session.headers.update(headers)
    
    # 尝试访问主页
    print("尝试访问 CNVD 主页...")
    try:
        r = session.get('https://www.cnvd.org.cn/', timeout=30)
        print(f"状态码: {r.status_code}")
        print(f"内容长度: {len(r.text)}")
        print(f"前500字符:\n{r.text[:500]}")
        print("\n" + "="*50)
    except Exception as e:
        print(f"访问失败: {e}")
        return
    
    # 尝试访问漏洞列表
    print("\n尝试访问漏洞列表...")
    try:
        time.sleep(3)  # 延迟
        r = session.get('https://www.cnvd.org.cn/flaw/list.htm?pageNo=1', timeout=30)
        print(f"状态码: {r.status_code}")
        print(f"内容长度: {len(r.text)}")
        print(f"前1000字符:\n{r.text[:1000]}")
    except Exception as e:
        print(f"访问失败: {e}")

if __name__ == "__main__":
    test_cnvd_access()
