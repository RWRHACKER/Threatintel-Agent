"""SQLite 数据库管理器"""

import sqlite3
import json
import os
from datetime import datetime
from src.utils.helpers import logger, DATA_DIR


class DatabaseManager:
    """SQLite 数据库管理器，用于存储威胁情报"""

    def __init__(self, db_name: str = "threatintel.db"):
        self.db_path = os.path.join(DATA_DIR, db_name)
        self.conn = None
        self._connect()
        self._create_tables()

    def _connect(self):
        """连接数据库"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"[DatabaseManager] 连接数据库: {self.db_path}")
        except Exception as e:
            logger.error(f"[DatabaseManager] 数据库连接失败: {e}")
            raise

    def _create_tables(self):
        """创建数据表"""
        try:
            cursor = self.conn.cursor()

            # 威胁情报表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT,
                    content TEXT,
                    url TEXT,
                    published TEXT,
                    collected_at TEXT NOT NULL,
                    fingerprint TEXT UNIQUE,
                    threat_level TEXT DEFAULT 'INFO',
                    confidence REAL DEFAULT 0.5,
                    reasoning TEXT,
                    affected_entities TEXT,
                    recommended_actions TEXT,
                    tags TEXT,
                    is_actionable INTEGER DEFAULT 0,
                    urgency TEXT DEFAULT '持续关注',
                    raw TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 告警记录表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intel_id TEXT,
                    channel TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    message TEXT,
                    sent_at TEXT,
                    error TEXT,
                    FOREIGN KEY (intel_id) REFERENCES threat_intel(id)
                )
            """)

            # 资产表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT,
                    version TEXT,
                    ip_address TEXT,
                    hostname TEXT,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 情报-资产关联表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS intel_asset_mapping (
                    intel_id TEXT,
                    asset_id INTEGER,
                    risk_level TEXT DEFAULT 'unknown',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (intel_id, asset_id),
                    FOREIGN KEY (intel_id) REFERENCES threat_intel(id),
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            """)

            self.conn.commit()
            logger.info("[DatabaseManager] 数据表创建完成")

        except Exception as e:
            logger.error(f"[DatabaseManager] 创建表失败: {e}")
            self.conn.rollback()

    def save_intel(self, items: list[dict]) -> int:
        """保存威胁情报条目"""
        if not items:
            return 0

        cursor = self.conn.cursor()
        saved_count = 0
        updated_count = 0

        for item in items:
            try:
                # 检查是否已存在
                cursor.execute("SELECT id FROM threat_intel WHERE fingerprint = ?",
                            (item.get("fingerprint"),))
                exists = cursor.fetchone()

                item_data = {
                    "id": item.get("id"),
                    "source": item.get("source"),
                    "title": item.get("title"),
                    "summary": item.get("summary"),
                    "content": item.get("content"),
                    "url": item.get("url"),
                    "published": item.get("published"),
                    "collected_at": item.get("collected_at", datetime.now().isoformat()),
                    "fingerprint": item.get("fingerprint"),
                    "threat_level": item.get("threat_level", "INFO"),
                    "confidence": item.get("confidence", 0.5),
                    "reasoning": item.get("reasoning"),
                    "affected_entities": json.dumps(item.get("affected_entities", [])),
                    "recommended_actions": json.dumps(item.get("recommended_actions", [])),
                    "tags": json.dumps(item.get("tags", [])),
                    "is_actionable": 1 if item.get("is_actionable", False) else 0,
                    "urgency": item.get("urgency", "持续关注"),
                    "raw": json.dumps(item.get("raw", {}))
                }

                if exists:
                    # 更新现有记录
                    cursor.execute("""
                        UPDATE threat_intel SET
                            source=?, title=?, summary=?, content=?, url=?,
                            published=?, collected_at=?, threat_level=?,
                            confidence=?, reasoning=?, affected_entities=?,
                            recommended_actions=?, tags=?, is_actionable=?,
                            urgency=?, raw=?, updated_at=?
                        WHERE fingerprint=?
                    """, (
                        item_data["source"], item_data["title"], item_data["summary"],
                        item_data["content"], item_data["url"], item_data["published"],
                        item_data["collected_at"], item_data["threat_level"],
                        item_data["confidence"], item_data["reasoning"],
                        item_data["affected_entities"], item_data["recommended_actions"],
                        item_data["tags"], item_data["is_actionable"], item_data["urgency"],
                        item_data["raw"], datetime.now().isoformat(), item_data["fingerprint"]
                    ))
                    updated_count += 1
                else:
                    # 插入新记录
                    cursor.execute("""
                        INSERT INTO threat_intel (
                            id, source, title, summary, content, url,
                            published, collected_at, fingerprint, threat_level,
                            confidence, reasoning, affected_entities,
                            recommended_actions, tags, is_actionable, urgency, raw
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        item_data["id"], item_data["source"], item_data["title"],
                        item_data["summary"], item_data["content"], item_data["url"],
                        item_data["published"], item_data["collected_at"],
                        item_data["fingerprint"], item_data["threat_level"],
                        item_data["confidence"], item_data["reasoning"],
                        item_data["affected_entities"], item_data["recommended_actions"],
                        item_data["tags"], item_data["is_actionable"],
                        item_data["urgency"], item_data["raw"]
                    ))
                    saved_count += 1

            except Exception as e:
                logger.error(f"[DatabaseManager] 保存情报失败 {item.get('id')}: {e}")
                self.conn.rollback()

        self.conn.commit()
        logger.info(f"[DatabaseManager] 保存完成: 新增 {saved_count} 条, 更新 {updated_count} 条")
        return saved_count + updated_count

    def get_intel_by_level(self, threat_level: str = None) -> list[dict]:
        """按威胁级别查询情报"""
        cursor = self.conn.cursor()
        
        if threat_level:
            cursor.execute("SELECT * FROM threat_intel WHERE threat_level = ? ORDER BY collected_at DESC",
                        (threat_level,))
        else:
            cursor.execute("SELECT * FROM threat_intel ORDER BY collected_at DESC")

        return self._rows_to_dict(cursor.fetchall())

    def get_intel_since(self, since_date: str) -> list[dict]:
        """获取指定日期之后的情报"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM threat_intel WHERE collected_at >= ? ORDER BY collected_at DESC",
                    (since_date,))
        return self._rows_to_dict(cursor.fetchall())

    def get_recent_intel(self, limit: int = 50) -> list[dict]:
        """获取最近的情报"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM threat_intel ORDER BY collected_at DESC LIMIT ?", (limit,))
        return self._rows_to_dict(cursor.fetchall())

    def get_high_threat_intel(self, hours: int = 24) -> list[dict]:
        """获取最近N小时内的高威胁情报"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM threat_intel 
            WHERE threat_level IN ('CRITICAL', 'HIGH') 
              AND collected_at >= datetime('now', '-{} hours')
            ORDER BY collected_at DESC
        """.format(hours))
        return self._rows_to_dict(cursor.fetchall())

    def save_asset(self, asset: dict) -> int:
        """保存资产信息"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO assets (name, type, version, ip_address, hostname, description, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            asset.get("name"),
            asset.get("type"),
            asset.get("version"),
            asset.get("ip_address"),
            asset.get("hostname"),
            asset.get("description"),
            datetime.now().isoformat()
        ))
        
        self.conn.commit()
        return cursor.lastrowid

    def get_assets(self) -> list[dict]:
        """获取所有资产"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM assets ORDER BY name")
        return self._rows_to_dict(cursor.fetchall())

    def save_intel_asset_mapping(self, intel_id: str, asset_id: int, risk_level: str = "unknown"):
        """保存情报与资产的关联"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO intel_asset_mapping (intel_id, asset_id, risk_level, created_at)
            VALUES (?, ?, ?, ?)
        """, (intel_id, asset_id, risk_level, datetime.now().isoformat()))
        
        self.conn.commit()

    def get_affected_assets(self, intel_id: str) -> list[dict]:
        """获取受某情报影响的资产"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT a.*, iam.risk_level 
            FROM assets a 
            JOIN intel_asset_mapping iam ON a.id = iam.asset_id 
            WHERE iam.intel_id = ?
        """, (intel_id,))
        return self._rows_to_dict(cursor.fetchall())

    def _rows_to_dict(self, rows) -> list[dict]:
        """将数据库行转换为字典"""
        result = []
        for row in rows:
            item = dict(row)
            # 解析JSON字段
            for field in ["affected_entities", "recommended_actions", "tags", "raw"]:
                if item.get(field):
                    try:
                        item[field] = json.loads(item[field])
                    except json.JSONDecodeError:
                        pass
            result.append(item)
        return result

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            logger.info("[DatabaseManager] 数据库连接已关闭")
