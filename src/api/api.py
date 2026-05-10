"""RESTful API 服务：基于 FastAPI"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from src.storage import DatabaseManager
from src.collectors import COLLECTOR_MAP
from src.analyzers import ThreatAnalyzer, AssetImpactAnalyzer
from src.reporters import Reporter
from src.utils.helpers import load_config, logger

app = FastAPI(
    title="ThreatIntel Agent API",
    description="威胁情报聚合分析 API",
    version="2.0.0"
)

# 全局配置
config = load_config()

class IntelItem(BaseModel):
    """威胁情报条目模型"""
    id: str
    source: str
    title: str
    summary: str
    url: Optional[str] = None
    published: Optional[str] = None
    threat_level: Optional[str] = "INFO"
    confidence: Optional[float] = 0.5
    reasoning: Optional[str] = None
    affected_entities: Optional[List[str]] = []
    recommended_actions: Optional[List[str]] = []
    tags: Optional[List[str]] = []
    is_actionable: Optional[bool] = False
    urgency: Optional[str] = "持续关注"

class AssetItem(BaseModel):
    """资产条目模型"""
    name: str
    type: Optional[str] = None
    version: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    description: Optional[str] = None
    criticality: Optional[str] = "medium"

class AnalysisRequest(BaseModel):
    """分析请求模型"""
    source: Optional[str] = "all"
    keyword: Optional[str] = None
    days: Optional[int] = 7

@app.get("/")
async def root():
    """健康检查"""
    return {"status": "running", "service": "ThreatIntel Agent API"}

@app.get("/api/v1/intel", response_model=List[IntelItem])
async def get_intel(
    threat_level: Optional[str] = None,
    limit: Optional[int] = 50,
    offset: Optional[int] = 0
):
    """获取威胁情报列表"""
    try:
        db = DatabaseManager()
        if threat_level:
            items = db.get_intel_by_level(threat_level)
        else:
            items = db.get_recent_intel(limit + offset)
        
        db.close()
        return items[offset:offset + limit]
    except Exception as e:
        logger.error(f"[API] 获取情报失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/intel/{intel_id}", response_model=IntelItem)
async def get_intel_by_id(intel_id: str):
    """获取单条威胁情报"""
    try:
        db = DatabaseManager()
        items = db.get_intel_by_level(None)  # 获取所有
        db.close()
        
        for item in items:
            if item["id"] == intel_id:
                return item
        
        raise HTTPException(status_code=404, detail="情报不存在")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[API] 获取情报失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze", response_model=Dict[str, Any])
async def analyze_intel(request: AnalysisRequest):
    """执行威胁情报采集与分析"""
    try:
        # 采集
        items = []
        sources = [request.source] if request.source != "all" else list(COLLECTOR_MAP.keys())
        
        for source_name in sources:
            collector_class = COLLECTOR_MAP.get(source_name)
            if collector_class:
                cfg = config.get("collectors", {}).get(source_name, {})
                collector = collector_class(cfg)
                items.extend(collector.collect_with_cache(source_name, keyword=request.keyword, days=request.days))
        
        if not items:
            return {"status": "success", "data": [], "summary": {"total": 0}}
        
        # 分析
        analyzer = ThreatAnalyzer(config)
        analyzed_items = analyzer.analyze(items)
        
        # 资产影响评估
        db = DatabaseManager()
        assets = db.get_assets()
        if assets:
            impact_analyzer = AssetImpactAnalyzer(config.get("analyzers", {}).get("asset_impact", {}))
            analyzed_items = impact_analyzer.analyze_impact(analyzed_items, assets)
        
        # 保存到数据库
        db.save_intel(analyzed_items)
        db.close()
        
        # 统计
        summary = {
            "total": len(analyzed_items),
            "critical": sum(1 for i in analyzed_items if i.get("threat_level") == "CRITICAL"),
            "high": sum(1 for i in analyzed_items if i.get("threat_level") == "HIGH"),
            "medium": sum(1 for i in analyzed_items if i.get("threat_level") == "MEDIUM"),
            "low": sum(1 for i in analyzed_items if i.get("threat_level") == "LOW"),
            "info": sum(1 for i in analyzed_items if i.get("threat_level") == "INFO"),
            "with_impact": sum(1 for i in analyzed_items if i.get("has_impact", False))
        }
        
        return {"status": "success", "data": analyzed_items, "summary": summary}
    
    except Exception as e:
        logger.error(f"[API] 分析失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/high-threat", response_model=List[IntelItem])
async def get_high_threat(hours: Optional[int] = 24):
    """获取最近N小时内的高威胁情报"""
    try:
        db = DatabaseManager()
        items = db.get_high_threat_intel(hours)
        db.close()
        return items
    except Exception as e:
        logger.error(f"[API] 获取高威胁情报失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/assets", response_model=List[AssetItem])
async def get_assets():
    """获取所有资产列表"""
    try:
        db = DatabaseManager()
        assets = db.get_assets()
        db.close()
        return assets
    except Exception as e:
        logger.error(f"[API] 获取资产失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/assets", response_model=Dict[str, Any])
async def add_asset(asset: AssetItem):
    """添加资产"""
    try:
        db = DatabaseManager()
        asset_dict = asset.dict()
        asset_id = db.save_asset(asset_dict)
        db.close()
        return {"status": "success", "asset_id": asset_id}
    except Exception as e:
        logger.error(f"[API] 添加资产失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}

def run_api(host: str = "0.0.0.0", port: int = 8000):
    """启动 API 服务"""
    import uvicorn
    logger.info(f"[API] 启动服务: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_api()