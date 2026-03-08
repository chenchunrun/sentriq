# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Notification Service - Sends notifications via multiple channels."""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import ResponseMeta, SuccessResponse
from shared.utils import Config, get_logger

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None
consumer: MessageConsumer = None
publisher: MessagePublisher = None


class NotificationChannel(str, Enum):
    """Notification channels."""

    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    WEBHOOK = "webhook"
    IN_APP = "in_app"
    DINGTALK = "dingtalk"
    WECHAT_WORK = "wechat_work"
    TEAMS = "teams"
    WEBEX = "webex"
    PAGERDUTY = "pagerduty"


class NotificationPriority(str, Enum):
    """Notification priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


def priority_to_severity(priority: NotificationPriority) -> str:
    mapping = {
        NotificationPriority.LOW: "low",
        NotificationPriority.NORMAL: "medium",
        NotificationPriority.HIGH: "high",
        NotificationPriority.URGENT: "critical",
    }
    return mapping.get(priority, "medium")


async def persist_notification(
    recipient: str,
    subject: str,
    message: str,
    channel: NotificationChannel,
    priority: NotificationPriority,
    link: Optional[str] = None,
):
    """Persist notification record to database."""
    async with db_manager.get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO notifications (notification_id, title, message, type, severity, link, user_id)
                VALUES (:notification_id, :title, :message, :type, :severity, :link, :user_id)
                """
            ),
            {
                "notification_id": f"notif-{uuid.uuid4()}",
                "title": subject or "Notification",
                "message": message,
                "type": channel.value,
                "severity": priority_to_severity(priority),
                "link": link,
                "user_id": recipient,
            },
        )
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, consumer, publisher

    logger.info("Starting Notification service...")

    # Initialize database
    import os
    await init_database(
        database_url=config.database_url,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        echo=config.debug,
    )
    db_manager = get_database_manager()

    # Initialize messaging
    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "notifications.send")
    await consumer.connect()

    # Start consuming notification requests
    asyncio.create_task(consume_notifications())

    logger.info("Notification service started successfully")

    yield

    # Cleanup
    await consumer.close()
    await publisher.close()
    await close_database()
    logger.info("Notification service stopped")


app = FastAPI(
    title="Notification Service",
    description="Sends notifications via multiple channels",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Notification channel implementations


async def send_email(
    recipient: str, subject: str, body: str, html_body: Optional[str] = None
) -> Dict[str, Any]:
    """Send email notification."""
    try:
        # TODO: Integrate with email service (SendGrid, AWS SES, SMTP)
        logger.info(f"Sending email to {recipient}: {subject}")

        # Mock implementation
        await asyncio.sleep(0.5)

        return {
            "success": True,
            "channel": "email",
            "recipient": recipient,
            "message_id": f"email-{uuid.uuid4()}",
        }

    except Exception as e:
        logger.error(f"Failed to send email: {e}", exc_info=True)
        return {"success": False, "channel": "email", "error": str(e)}


async def send_slack(
    webhook_url: str, message: str, channel: Optional[str] = None, username: Optional[str] = None
) -> Dict[str, Any]:
    """Send Slack notification."""
    try:
        payload = {"text": message, "username": username or "Security Triage Bot"}

        if channel:
            payload["channel"] = channel

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()

        logger.info(f"Slack message sent to {channel or 'default channel'}")

        return {"success": True, "channel": "slack", "webhook_url": webhook_url}

    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}", exc_info=True)
        return {"success": False, "channel": "slack", "error": str(e)}


async def send_webhook(
    webhook_url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Send webhook notification."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url, json=payload, headers=headers or {}, timeout=10.0
            )
            response.raise_for_status()

        logger.info(f"Webhook sent to {webhook_url}")

        return {
            "success": True,
            "channel": "webhook",
            "webhook_url": webhook_url,
            "status_code": response.status_code,
        }

    except Exception as e:
        logger.error(f"Failed to send webhook: {e}", exc_info=True)
        return {"success": False, "channel": "webhook", "error": str(e)}


async def send_dingtalk(
    webhook_url: str, message: str, at_mobiles: Optional[List[str]] = None, at_all: bool = False
) -> Dict[str, Any]:
    """Send DingTalk notification."""
    try:
        payload = {
            "msgtype": "text",
            "text": {
                "content": message,
            },
            "at": {
                "atMobiles": at_mobiles or [],
                "isAtAll": at_all,
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()

        logger.info(f"DingTalk message sent")

        return {"success": True, "channel": "dingtalk", "webhook_url": webhook_url}

    except Exception as e:
        logger.error(f"Failed to send DingTalk message: {e}", exc_info=True)
        return {"success": False, "channel": "dingtalk", "error": str(e)}


async def send_wechat_work(
    webhook_url: str, message: str, mentioned_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Send WeChat Work notification."""
    try:
        payload = {
            "msgtype": "text",
            "text": {
                "content": message,
                "mentioned_list": mentioned_list or [],
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()

        logger.info(f"WeChat Work message sent")

        return {"success": True, "channel": "wechat_work", "webhook_url": webhook_url}

    except Exception as e:
        logger.error(f"Failed to send WeChat Work message: {e}", exc_info=True)
        return {"success": False, "channel": "wechat_work", "error": str(e)}


async def send_teams(webhook_url: str, title: str, message: str, summary: Optional[str] = None) -> Dict[str, Any]:
    """Send Microsoft Teams notification."""
    try:
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": summary or title,
            "themeColor": "0078D7",
            "title": title,
            "text": message,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()

        logger.info(f"Teams message sent")

        return {"success": True, "channel": "teams", "webhook_url": webhook_url}

    except Exception as e:
        logger.error(f"Failed to send Teams message: {e}", exc_info=True)
        return {"success": False, "channel": "teams", "error": str(e)}


async def send_pagerduty(
    api_key: str, routing_key: str, event_action: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Send PagerDuty notification."""
    try:
        pd_payload = {
            "routing_key": routing_key,
            "event_action": event_action,
            "payload": payload,
        }

        headers = {"Authorization": f"Token token={api_key}"}
        url = "https://events.pagerduty.com/v2/enqueue"

        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=pd_payload, headers=headers, timeout=10.0)
            response.raise_for_status()

        logger.info(f"PagerDuty event sent")

        return {"success": True, "channel": "pagerduty"}

    except Exception as e:
        logger.error(f"Failed to send PagerDuty event: {e}", exc_info=True)
        return {"success": False, "channel": "pagerduty", "error": str(e)}


async def send_notification(
    channel: NotificationChannel,
    recipient: str,
    subject: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Send notification via specified channel."""
    try:
        await persist_notification(
            recipient=recipient,
            subject=subject,
            message=message,
            channel=channel,
            priority=priority,
            link=(data or {}).get("link"),
        )

        if channel == NotificationChannel.EMAIL:
            return await send_email(recipient, subject, message)

        elif channel == NotificationChannel.SLACK:
            return await send_slack(recipient, message)

        elif channel == NotificationChannel.WEBHOOK:
            return await send_webhook(recipient, data or {"message": message, "subject": subject})

        elif channel == NotificationChannel.SMS:
            logger.info(f"SMS notification to {recipient}: {message}")
            return {"success": True, "channel": "sms"}

        elif channel == NotificationChannel.IN_APP:
            logger.info(f"In-app notification for {recipient}: {message}")
            return {"success": True, "channel": "in_app"}

        elif channel == NotificationChannel.DINGTALK:
            at_mobiles = data.get("at_mobiles") if data else None
            at_all = data.get("at_all", False) if data else False
            return await send_dingtalk(recipient, message, at_mobiles, at_all)

        elif channel == NotificationChannel.WECHAT_WORK:
            mentioned_list = data.get("mentioned_list") if data else None
            return await send_wechat_work(recipient, message, mentioned_list)

        elif channel == NotificationChannel.TEAMS:
            return await send_teams(recipient, subject, message)

        elif channel == NotificationChannel.PAGERDUTY:
            pd_data = data or {}
            return await send_pagerduty(
                api_key=pd_data.get("api_key", ""),
                routing_key=pd_data.get("routing_key", ""),
                event_action=pd_data.get("event_action", "trigger"),
                payload=pd_data.get("payload", {"summary": message}),
            )

        else:
            raise ValueError(f"Unsupported channel: {channel}")

    except Exception as e:
        logger.error(f"Failed to send notification: {e}", exc_info=True)
        return {"success": False, "channel": channel.value, "error": str(e)}


async def consume_notifications():
    """Consume notification requests from message queue."""

    async def process_message(message: dict):
        try:
            payload = message["payload"]
            channel = NotificationChannel(payload.get("channel", "email"))
            recipient = payload.get("recipient")
            subject = payload.get("subject", "")
            message_text = payload.get("message", "")
            priority = NotificationPriority(payload.get("priority", "normal"))
            data = payload.get("data")

            if not recipient or not message_text:
                logger.error("Missing required fields in notification message")
                return

            # Send notification
            result = await send_notification(
                channel, recipient, subject, message_text, priority, data
            )

            if result.get("success"):
                logger.info(f"Notification sent successfully via {channel.value}")
            else:
                logger.error(f"Notification failed: {result.get('error')}")

        except Exception as e:
            logger.error(f"Failed to process notification: {e}", exc_info=True)

    await consumer.consume(process_message)


# API Endpoints


@app.post("/api/v1/notifications/send", response_model=Dict[str, Any])
async def send_notification_api(
    channel: NotificationChannel,
    recipient: str,
    subject: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    data: Optional[Dict[str, Any]] = None,
    background_tasks: BackgroundTasks = None,
):
    """
    Send notification via API.

    Args:
        channel: Notification channel
        recipient: Recipient address/webhook URL
        subject: Notification subject/title
        message: Notification message body
        priority: Notification priority
        data: Additional data for the notification
    """
    try:
        # Send notification
        result = await send_notification(channel, recipient, subject, message, priority, data)

        return {
            "success": result.get("success", False),
            "data": result,
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to send notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to send notification: {str(e)}")


@app.post("/api/v1/notifications/broadcast", response_model=Dict[str, Any])
async def broadcast_notification(
    channel: NotificationChannel,
    recipients: List[str],
    subject: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    background_tasks: BackgroundTasks = None,
):
    """Broadcast notification to multiple recipients."""
    try:
        results = []

        for recipient in recipients:
            result = await send_notification(channel, recipient, subject, message, priority)
            results.append(result)

        successful = sum(1 for r in results if r.get("success"))
        total = len(results)

        return {
            "success": successful > 0,
            "data": {
                "total": total,
                "successful": successful,
                "failed": total - successful,
                "results": results,
            },
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to broadcast notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to broadcast notification: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "notification-service",
        "timestamp": datetime.utcnow().isoformat(),
        "channels": [c.value for c in NotificationChannel],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
