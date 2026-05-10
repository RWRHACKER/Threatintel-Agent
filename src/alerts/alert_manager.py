"""告警管理器：支持多种告警渠道"""

import json
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.utils.helpers import logger


class AlertManager:
    """告警管理器，支持邮件、钉钉、企业微信告警"""

    def __init__(self, config: dict):
        self.config = config
        self.enabled_channels = config.get("enabled_channels", [])
        self.email_config = config.get("email", {})
        self.dingtalk_config = config.get("dingtalk", {})
        self.wecom_config = config.get("wecom", {})

    def send_alerts(self, items: list[dict], report_path: str = None):
        """发送告警通知"""
        if not items:
            logger.info("[AlertManager] 无高威胁情报需要告警")
            return

        # 过滤高威胁级别
        high_threat_items = [
            item for item in items
            if item.get("threat_level") in ("CRITICAL", "HIGH")
        ]

        if not high_threat_items:
            logger.info("[AlertManager] 无 CRITICAL/HIGH 级别威胁，跳过告警")
            return

        logger.info(f"[AlertManager] 准备向 {len(self.enabled_channels)} 个渠道发送告警，共 {len(high_threat_items)} 条高威胁情报")

        # 构建告警消息
        message = self._build_message(high_threat_items, report_path)

        # 发送到各个渠道
        if "email" in self.enabled_channels:
            self._send_email(message, high_threat_items)
        if "dingtalk" in self.enabled_channels:
            self._send_dingtalk(message)
        if "wecom" in self.enabled_channels:
            self._send_wecom(message)

    def _build_message(self, items: list[dict], report_path: str = None) -> str:
        """构建告警消息内容"""
        lines = ["🔴 【威胁情报告警】"]
        lines.append("=" * 50)
        
        for item in items:
            lines.append(f"\n📌 {item.get('threat_level', 'UNKNOWN')}")
            lines.append(f"标题: {item.get('title', '')}")
            lines.append(f"来源: {item.get('source', '')}")
            lines.append(f"严重程度: {item.get('threat_level', '')}")
            lines.append(f"置信度: {item.get('confidence', 0):.2f}")
            lines.append(f"研判: {item.get('reasoning', '')}")
            lines.append(f"URL: {item.get('url', '')}")
            if item.get('recommended_actions'):
                lines.append(f"建议: {' | '.join(item.get('recommended_actions', []))}")

        if report_path:
            lines.append(f"\n📄 完整报告: {report_path}")

        lines.append("\n⚠️ 请及时评估并采取相应措施")
        return "\n".join(lines)

    def _send_email(self, message: str, items: list[dict]):
        """发送邮件告警"""
        try:
            smtp_server = self.email_config.get("smtp_server")
            smtp_port = self.email_config.get("smtp_port", 587)
            smtp_user = self.email_config.get("smtp_user")
            smtp_password = self.email_config.get("smtp_password")
            to_emails = self.email_config.get("to_emails", [])

            if not all([smtp_server, smtp_user, smtp_password, to_emails]):
                logger.warning("[AlertManager] 邮件配置不完整，跳过邮件告警")
                return

            msg = MIMEMultipart()
            msg['From'] = smtp_user
            msg['To'] = ", ".join(to_emails)
            msg['Subject'] = f"🔴 威胁情报告警 - {len(items)} 条高威胁"

            msg.attach(MIMEText(message, 'plain', 'utf-8'))

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, to_emails, msg.as_string())

            logger.info(f"[AlertManager] 邮件告警已发送到 {len(to_emails)} 个收件人")

        except Exception as e:
            logger.error(f"[AlertManager] 邮件发送失败: {e}")

    def _send_dingtalk(self, message: str):
        """发送钉钉告警"""
        try:
            webhook_url = self.dingtalk_config.get("webhook_url")
            if not webhook_url:
                logger.warning("[AlertManager] 钉钉 Webhook URL 未配置")
                return

            headers = {"Content-Type": "application/json;charset=utf-8"}
            data = {
                "msgtype": "text",
                "text": {
                    "content": message
                }
            }

            resp = requests.post(webhook_url, headers=headers, data=json.dumps(data), timeout=10)
            resp.raise_for_status()
            logger.info("[AlertManager] 钉钉告警发送成功")

        except Exception as e:
            logger.error(f"[AlertManager] 钉钉告警发送失败: {e}")

    def _send_wecom(self, message: str):
        """发送企业微信告警"""
        try:
            webhook_url = self.wecom_config.get("webhook_url")
            if not webhook_url:
                logger.warning("[AlertManager] 企微 Webhook URL 未配置")
                return

            headers = {"Content-Type": "application/json;charset=utf-8"}
            data = {
                "msgtype": "text",
                "text": {
                    "content": message
                }
            }

            resp = requests.post(webhook_url, headers=headers, data=json.dumps(data), timeout=10)
            resp.raise_for_status()
            logger.info("[AlertManager] 企微告警发送成功")

        except Exception as e:
            logger.error(f"[AlertManager] 企微告警发送失败: {e}")
