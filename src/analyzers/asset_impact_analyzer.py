"""资产影响评估分析器

分析威胁情报对自有资产的影响，判断哪些资产可能受到威胁。
"""

import re
from src.utils.helpers import logger


class AssetImpactAnalyzer:
    """资产影响评估分析器"""

    def __init__(self, config: dict):
        self.config = config
        self.threshold = config.get("impact_threshold", 0.7)

    def analyze_impact(self, intel_items: list[dict], assets: list[dict]) -> list[dict]:
        """分析威胁情报对资产的影响"""
        if not assets:
            logger.info("[AssetImpactAnalyzer] 未配置资产，跳过影响评估")
            return intel_items

        for item in intel_items:
            affected_assets = self._find_affected_assets(item, assets)
            item["impacted_assets"] = affected_assets
            item["has_impact"] = len(affected_assets) > 0
            if affected_assets:
                item["impact_score"] = self._calculate_impact_score(item, affected_assets)
            else:
                item["impact_score"] = 0.0

        return intel_items

    def _find_affected_assets(self, intel: dict, assets: list[dict]) -> list[dict]:
        """找出受影响的资产"""
        affected = []
        intel_text = f"{intel.get('title', '')} {intel.get('summary', '')} {intel.get('content', '')}".lower()

        for asset in assets:
            if self._is_asset_affected(intel, asset, intel_text):
                affected.append({
                    "asset_id": asset.get("id"),
                    "name": asset.get("name"),
                    "type": asset.get("type"),
                    "version": asset.get("version"),
                    "risk_level": self._determine_risk_level(intel, asset)
                })

        return affected

    def _is_asset_affected(self, intel: dict, asset: dict, intel_text: str) -> bool:
        """判断单个资产是否受影响"""
        asset_name = asset.get("name", "").lower()
        asset_type = asset.get("type", "").lower()
        asset_version = asset.get("version", "").lower()

        # 检查产品名称匹配
        if asset_name and asset_name in intel_text:
            return True

        # 检查类型匹配（如 Apache、nginx、Windows 等）
        if asset_type and asset_type in intel_text:
            # 检查版本是否在受影响范围内
            if asset_version:
                return self._is_version_affected(intel, asset_version)
            return True

        # 检查已知受影响产品列表
        affected_entities = intel.get("affected_entities", [])
        for entity in affected_entities:
            if entity.lower() in asset_name or entity.lower() in asset_type:
                return True

        return False

    def _is_version_affected(self, intel: dict, asset_version: str) -> bool:
        """判断版本是否在受影响范围内"""
        summary = intel.get("summary", "").lower()
        title = intel.get("title", "").lower()
        text = f"{title} {summary}"

        # 提取版本范围信息
        version_patterns = [
            r"(\d+\.\d+(\.\d+)?)\s*[~-]\s*(\d+\.\d+(\.\d+)?)",  # 1.0 ~ 2.0
            r"(\d+\.\d+(\.\d+)?)\s*to\s*(\d+\.\d+(\.\d+)?)",     # 1.0 to 2.0
            r"(?:version|versions?)\s*(\d+\.\d+(\.\d+)?)",        # version 1.0
            r"(?:affects|impacted)\s*(\d+\.\d+(\.\d+)?)",         # affects 1.0
        ]

        for pattern in version_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if match[0] in asset_version:
                    return True

        return False

    def _determine_risk_level(self, intel: dict, asset: dict) -> str:
        """确定资产受影响的风险等级"""
        threat_level = intel.get("threat_level", "INFO")
        asset_criticality = asset.get("criticality", "medium")

        # 根据威胁级别和资产重要性确定风险
        if threat_level == "CRITICAL":
            if asset_criticality == "high":
                return "critical"
            return "high"
        elif threat_level == "HIGH":
            if asset_criticality == "high":
                return "high"
            return "medium"
        elif threat_level == "MEDIUM":
            return "medium"
        else:
            return "low"

    def _calculate_impact_score(self, intel: dict, affected_assets: list[dict]) -> float:
        """计算影响评分"""
        threat_level_weights = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.5,
            "LOW": 0.2,
            "INFO": 0.0
        }

        asset_criticality_weights = {
            "high": 1.0,
            "medium": 0.6,
            "low": 0.3
        }

        base_weight = threat_level_weights.get(intel.get("threat_level"), 0.5)
        total_score = 0.0

        for asset in affected_assets:
            criticality = asset.get("criticality", "medium")
            asset_weight = asset_criticality_weights.get(criticality, 0.6)
            total_score += base_weight * asset_weight

        # 归一化
        if affected_assets:
            total_score /= len(affected_assets)

        return round(total_score, 2)
