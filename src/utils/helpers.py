"""工具函数：缓存、日志、去重、配置加载"""

import json
import hashlib
import logging
import time
import os
from pathlib import Path
from datetime import datetime
import yaml


# ── 路径 ──────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"
REPORT_DIR = DATA_DIR / "reports"
CONFIG_DIR = PROJECT_ROOT / "config"

# 确保目录存在
CACHE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ── 日志 ──────────────────────────────────────────────
def setup_logger(name: str = "threatintel") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # 控制台 handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(ch)

    # 文件 handler
    log_file = DATA_DIR / "run.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
    ))
    logger.addHandler(fh)

    return logger


logger = setup_logger()


# ── 配置加载 ──────────────────────────────────────────
def load_config() -> dict:
    """加载 YAML 配置，环境变量可覆盖"""
    # 加载 .env 文件
    try:
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
    except ImportError:
        pass
    
    config_file = CONFIG_DIR / "default.yaml"
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    else:
        config = {}

    # 环境变量覆盖 LLM 配置
    if os.getenv("OPENAI_API_KEY"):
        config.setdefault("llm", {})["api_key"] = os.getenv("OPENAI_API_KEY")
    if os.getenv("OPENAI_API_BASE"):
        config.setdefault("llm", {})["api_base"] = os.getenv("OPENAI_API_BASE")
    
    # DeepSeek API 配置（优先级高于 OpenAI）
    if os.getenv("DEEPSEEK_API_KEY"):
        config.setdefault("llm", {})["api_key"] = os.getenv("DEEPSEEK_API_KEY")
    if os.getenv("DEEPSEEK_API_BASE"):
        config.setdefault("llm", {})["api_base"] = os.getenv("DEEPSEEK_API_BASE")
    
    if os.getenv("GITHUB_TOKEN"):
        config.setdefault("collectors", {}).setdefault("github", {})["token"] = os.getenv("GITHUB_TOKEN")

    return config


# ── 缓存 ──────────────────────────────────────────────
def cache_key(prefix: str, *args) -> str:
    """生成缓存键"""
    raw = f"{prefix}:{':'.join(str(a) for a in args)}"
    return hashlib.md5(raw.encode()).hexdigest()


def cache_get(key: str) -> dict | None:
    """读取缓存"""
    cache_file = CACHE_DIR / f"{key}.json"
    if not cache_file.exists():
        return None
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return None


def cache_set(key: str, data: dict):
    """写入缓存"""
    cache_file = CACHE_DIR / f"{key}.json"
    data["_cached_at"] = datetime.now().isoformat()
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def cache_is_fresh(key: str, ttl_seconds: int) -> bool:
    """检查缓存是否新鲜"""
    data = cache_get(key)
    if not data or "_cached_at" not in data:
        return False
    cached_time = datetime.fromisoformat(data["_cached_at"])
    return (datetime.now() - cached_time).total_seconds() < ttl_seconds


# ── 去重 ──────────────────────────────────────────────
def text_fingerprint(text: str) -> str:
    """文本指纹，用于去重"""
    # 取前200字符 + 后100字符做指纹
    clean = text.strip().lower()[:500]
    return hashlib.md5(clean.encode()).hexdigest()


def deduplicate_items(items: list[dict], key_field: str = "fingerprint") -> list[dict]:
    """按指纹去重，保留第一次出现的"""
    seen = set()
    result = []
    for item in items:
        fp = item.get(key_field, text_fingerprint(str(item)))
        if fp not in seen:
            seen.add(fp)
            result.append(item)
    return result


# ── 时间 ──────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now().isoformat()


def now_date() -> str:
    return datetime.now().strftime("%Y-%m-%d")
