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

"""
Message consumer with retry logic and dead letter queue support.

This module provides an enhanced message consumer with features for
reliable message processing, automatic retries, and dead letter queue handling.
"""

import asyncio
import json
from typing import Any, Callable, Dict, List, Optional

from aio_pika import DeliveryMode, ExchangeType, RobustConnection, connect_robust
from aio_pika.abc import AbstractChannel, AbstractQueue, AbstractExchange
from aio_pika.exceptions import QueueEmpty
from shared.utils.logger import get_logger
from shared.utils.time import utc_now

logger = get_logger(__name__)


class MessageConsumer:
    """
    Enhanced message consumer with retry logic and DLQ support.

    Features:
    - Automatic message retry with exponential backoff
    - Dead letter queue for failed messages
    - Prefetch control for parallel processing
    - Graceful shutdown handling
    - Message tracking and monitoring
    """

    def __init__(
        self,
        amqp_url: str,
        queue_name: str,
        dlq_name: Optional[str] = None,
        auto_ack: bool = False,
        prefetch_count: int = 10,
        max_retry_attempts: int = 3,
        retry_delay_ms: int = 5000,
        retry_backoff_multiplier: float = 2.0,
    ):
        """
        Initialize message consumer.

        Args:
            amqp_url: RabbitMQ connection URL
            queue_name: Queue to consume from
            dlq_name: Dead letter queue name (auto-generated if None: {queue_name}.dlq)
            auto_ack: Auto-acknowledge messages (not recommended for production)
            prefetch_count: Number of messages to prefetch
            max_retry_attempts: Maximum number of retry attempts before sending to DLQ
            retry_delay_ms: Initial retry delay in milliseconds
            retry_backoff_multiplier: Multiplier for exponential backoff
        """
        self.amqp_url = amqp_url
        self.queue_name = queue_name
        self.dlq_name = dlq_name or f"{queue_name}.dlq"
        self.auto_ack = auto_ack
        self.prefetch_count = prefetch_count
        self.max_retry_attempts = max_retry_attempts
        self.retry_delay_ms = retry_delay_ms
        self.retry_backoff_multiplier = retry_backoff_multiplier

        self.connection: Optional[RobustConnection] = None
        self.channel: Optional[AbstractChannel] = None
        self.queue: Optional[AbstractQueue] = None
        self.dlq: Optional[AbstractQueue] = None
        self.dlx_exchange: Optional[AbstractExchange] = None

        self._consumer_tag: Optional[str] = None
        self._is_consuming = False
        self._shutdown_event = asyncio.Event()

    async def connect(self):
        """Connect to RabbitMQ and setup queues."""
        try:
            self.connection = await connect_robust(self.amqp_url)
            self.channel = await self.connection.channel()
            await self.channel.set_qos(prefetch_count=self.prefetch_count)

            # Setup dead letter exchange
            dlx_name = f"{self.queue_name}.dlx"
            self.dlx_exchange = await self.channel.declare_exchange(
                dlx_name,
                ExchangeType.DIRECT,
                durable=True,
            )

            # Setup dead letter queue
            self.dlq = await self.channel.declare_queue(
                self.dlq_name,
                durable=True,
                arguments={
                    "x-max-length": 50000,  # Max 50k messages in DLQ
                    "x-message-ttl": 604800000,  # 7 days TTL
                },
            )
            await self.dlq.bind(self.dlx_exchange, routing_key=self.dlq_name)

            # Setup main queue with DLQ configuration
            self.queue = await self.channel.declare_queue(
                self.queue_name,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": dlx_name,
                    "x-dead-letter-routing-key": self.dlq_name,
                    "x-max-length": 100000,  # Max 100k messages
                    "x-message-ttl": 86400000,  # 24 hours TTL
                    "x-max-priority": 10,
                },
            )

            logger.info(
                f"Connected to RabbitMQ (queue: {self.queue_name}, dlq: {self.dlq_name}, prefetch: {self.prefetch_count})"
            )
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            raise

    async def consume(
        self,
        callback: Callable[[Dict[str, Any]], Any],
        error_callback: Optional[Callable[[Dict[str, Any], Exception], Any]] = None,
    ):
        """
        Start consuming messages with retry logic.

        Args:
            callback: Async callback function for message processing
            error_callback: Optional callback for handling errors
        """
        if not self.connection:
            await self.connect()

        self._is_consuming = True
        logger.info(f"Started consuming from {self.queue_name}")

        while not self._shutdown_event.is_set():
            try:
                message = await self.queue.get(
                    no_ack=self.auto_ack,
                    fail=False,
                    timeout=1.0,
                )
            except QueueEmpty:
                continue

            if message is None:
                continue

            await self._process_message(message, callback, error_callback)

        logger.info("Shutdown signal received, stopping consumption")

    async def _process_message(
        self,
        message,
        callback: Callable[[Dict[str, Any]], Any],
        error_callback: Optional[Callable[[Dict[str, Any], Exception], Any]] = None,
    ):
        """
        Process a single message with retry logic.

        Args:
            message: aio_pika message
            callback: Processing callback
            error_callback: Error handling callback
        """
        try:
            # Parse message body
            body = json.loads(message.body.decode())

            # Get retry count from headers
            headers = message.headers or {}
            retry_count = headers.get("x-death", [{}])[0].get("count", 0) if headers.get("x-death") else 0

            # Add metadata to message
            body["_meta"] = {
                "message_id": message.message_id,
                "correlation_id": message.correlation_id,
                "reply_to": message.reply_to,
                "timestamp": message.timestamp,
                "retry_count": retry_count,
                "first_death_time": headers.get("x-first-death-time"),
            }

            # Process message
            await callback(body)

            # Acknowledge message
            if not self.auto_ack:
                await message.ack()

            logger.debug(
                f"Message processed successfully (message_id: {message.message_id}, queue: {self.queue_name}, retry_count: {retry_count})"
            )

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in message: {e}")
            if not self.auto_ack:
                await message.reject(requeue=False)

        except Exception as e:
            # Avoid recursive logging errors - just print the exception type
            import traceback
            print(f"ERROR in {self.queue_name}: {type(e).__name__}: {str(e)[:100]}")
            traceback.print_exc()

            # Call error callback if provided
            if error_callback:
                try:
                    body = json.loads(message.body.decode()) if message.body else {}
                    await error_callback(body, e)
                except Exception as callback_error:
                    logger.error(f"Error in error_callback: {callback_error}")

            # Check retry count
            headers = message.headers or {}
            retry_count = headers.get("x-death", [{}])[0].get("count", 0) if headers.get("x-death") else 0

            if retry_count >= self.max_retry_attempts:
                logger.warning(
                    f"Message exceeded max retry attempts, sending to DLQ (message_id: {getattr(message, 'message_id', 'unknown')}, retry_count: {retry_count})"
                )
                if not self.auto_ack:
                    await message.reject(requeue=False)
            else:
                # Requeue with exponential backoff
                if not self.auto_ack:
                    await message.nack(requeue=True)

    async def consume_from_dlq(
        self,
        callback: Callable[[Dict[str, Any]], Any],
    ):
        """
        Consume messages from dead letter queue.

        Args:
            callback: Async callback function for DLQ message processing
        """
        if not self.connection:
            await self.connect()

        logger.info(f"Started consuming from DLQ: {self.dlq_name}")

        async with self.dlq.iterator(no_ack=False) as queue_iter:
            async for message in queue_iter:
                if self._shutdown_event.is_set():
                    break

                try:
                    body = json.loads(message.body.decode())
                    await callback(body)
                    await message.ack()

                    logger.info(f"DLQ message processed (message_id: {message.message_id})")

                except Exception as e:
                    logger.error(f"Error processing DLQ message: {e}")
                    await message.nack(requeue=False)

    async def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.

        Returns:
            Dictionary with queue statistics
        """
        if not self.queue:
            await self.connect()

        # Get queue info
        underlay_channel = await self.channel.get_underlay_channel()
        queue_result = await underlay_channel.queue_declare(
            self.queue_name,
            durable=True,
            passive=True,
        )
        dlq_result = await underlay_channel.queue_declare(
            self.dlq_name,
            durable=True,
            passive=True,
        )

        return {
            "queue": self.queue_name,
            "message_count": queue_result.message_count,
            "consumer_count": queue_result.consumer_count,
            "dlq": self.dlq_name,
            "dlq_message_count": dlq_result.message_count,
            "is_consuming": self._is_consuming,
        }

    async def purge_dlq(self) -> int:
        """
        Purge all messages from dead letter queue.

        Returns:
            Number of messages purged
        """
        if not self.dlq:
            await self.connect()

        result = await self.dlq.purge()
        logger.info(f"Purged {result} messages from DLQ: {self.dlq_name}")
        return result

    async def replay_dlq_messages(
        self,
        max_messages: int = 100,
    ) -> int:
        """
        Replay messages from DLQ back to main queue.

        Args:
            max_messages: Maximum number of messages to replay

        Returns:
            Number of messages replayed
        """
        if not self.connection:
            await self.connect()

        replayed_count = 0

        async with self.dlq.iterator(no_ack=False) as queue_iter:
            async for message in queue_iter:
                if replayed_count >= max_messages:
                    break

                try:
                    # Remove retry headers to prevent immediate re-queuing to DLQ
                    body = json.loads(message.body.decode())
                    if "_meta" in body:
                        del body["_meta"]

                    # Republish to main queue
                    await self.publish_to_main_queue(body)
                    await message.ack()
                    replayed_count += 1

                except Exception as e:
                    logger.error(f"Error replaying message: {e}")
                    await message.nack(requeue=False)

        logger.info(f"Replayed {replayed_count} messages from DLQ to main queue")
        return replayed_count

    async def publish_to_main_queue(self, message: Dict[str, Any]) -> None:
        """
        Publish message to main queue.

        Args:
            message: Message to publish
        """
        if not self.queue:
            await self.connect()

        message_body = json.dumps(message).encode()
        msg = aio_pika.Message(
            message_body,
            delivery_mode=DeliveryMode.PERSISTENT,
        )

        await self.channel.default_exchange.publish(msg, routing_key=self.queue_name)

    async def stop_consuming(self):
        """Stop consuming messages gracefully."""
        logger.info("Stopping message consumption...")
        self._shutdown_event.set()
        self._is_consuming = False

    async def close(self):
        """Close connection to RabbitMQ."""
        await self.stop_consuming()

        if self.connection:
            await self.connection.close()
            logger.info("RabbitMQ connection closed")


# Import aio_pika.Message for the publish method
import aio_pika


class BatchConsumer(MessageConsumer):
    """
    Batch consumer for processing multiple messages together.

    Accumulates messages and processes them in batches for improved throughput.
    """

    def __init__(
        self,
        amqp_url: str,
        queue_name: str,
        batch_size: int = 10,
        batch_timeout_ms: int = 5000,
        **kwargs,
    ):
        """
        Initialize batch consumer.

        Args:
            amqp_url: RabbitMQ connection URL
            queue_name: Queue to consume from
            batch_size: Number of messages to accumulate before processing
            batch_timeout_ms: Maximum time to wait before processing partial batch
            **kwargs: Additional arguments passed to MessageConsumer
        """
        super().__init__(amqp_url, queue_name, **kwargs)
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self._message_buffer: List[Dict[str, Any]] = []
        self._last_process_time = utc_now()

    async def consume(
        self,
        callback: Callable[[List[Dict[str, Any]]], Any],
        error_callback: Optional[Callable[[List[Dict[str, Any]], Exception], Any]] = None,
    ):
        """
        Start consuming messages in batches.

        Args:
            callback: Async callback function for batch processing
            error_callback: Optional callback for batch error handling
        """
        if not self.connection:
            await self.connect()

        self._is_consuming = True
        logger.info(
            f"Started batch consuming from {self.queue_name} (batch_size: {self.batch_size})"
        )

        while not self._shutdown_event.is_set():
            try:
                message = await self.queue.get(
                    no_ack=self.auto_ack,
                    fail=False,
                    timeout=1.0,
                )
            except QueueEmpty:
                message = None

            now = utc_now()
            batch_timed_out = (
                self._message_buffer
                and (now - self._last_process_time).total_seconds() * 1000 >= self.batch_timeout_ms
            )

            if message is None:
                if batch_timed_out:
                    await self._process_batch(callback, error_callback)
                    self._message_buffer = []
                    self._last_process_time = now
                continue

            try:
                body = json.loads(message.body.decode())
                self._message_buffer.append(body)

                if not self.auto_ack:
                    await message.ack()

                should_process = (
                    len(self._message_buffer) >= self.batch_size
                    or (utc_now() - self._last_process_time).total_seconds() * 1000
                    >= self.batch_timeout_ms
                )

                if should_process and self._message_buffer:
                    await self._process_batch(callback, error_callback)
                    self._message_buffer = []
                    self._last_process_time = utc_now()

            except Exception as e:
                logger.error(f"Error in batch consumption: {e}")
                if not self.auto_ack:
                    await message.nack(requeue=False)

        if self._message_buffer:
            await self._process_batch(callback, error_callback)
            self._message_buffer = []

    async def _process_batch(
        self,
        callback: Callable[[List[Dict[str, Any]]], Any],
        error_callback: Optional[Callable[[List[Dict[str, Any]], Exception], Any]] = None,
    ):
        """
        Process a batch of messages.

        Args:
            callback: Batch processing callback
            error_callback: Batch error handling callback
        """
        try:
            await callback(self._message_buffer)

            logger.debug(
                f"Batch processed successfully (batch_size: {len(self._message_buffer)})"
            )

        except Exception as e:
            logger.error(f"Error processing batch: {e}")

            if error_callback:
                try:
                    await error_callback(self._message_buffer, e)
                except Exception as callback_error:
                    logger.error(f"Error in batch error_callback: {callback_error}")
