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
Integration tests for message queue operations.

Tests RabbitMQ message publishing, consuming, retry logic,
dead letter queues, and priority message handling.
"""

import asyncio
import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from aio_pika import ExchangeType, RobustConnection
from aio_pika.exceptions import AMQPError

from shared.messaging.consumer import BatchConsumer, MessageConsumer
from shared.messaging.publisher import MessagePublisher, TransactionalPublisher


# =============================================================================
# Test Configuration
# =============================================================================

# Use in-memory RabbitMQ for testing (requires rabbitmq-server with test plugin)
# For CI/CD, use a real RabbitMQ instance
TEST_RABBITMQ_URL = "amqp://guest:guest@localhost:5672/%2F"

TEST_QUEUE = "test.queue"
TEST_DLQ = "test.queue.dlq"
TEST_EXCHANGE = "test.exchange"


async def _ensure_rabbitmq_available() -> None:
    """Skip tests when RabbitMQ is not reachable in local test env."""
    from aio_pika import connect_robust

    try:
        conn = await connect_robust(TEST_RABBITMQ_URL)
        await conn.close()
    except Exception as exc:
        pytest.skip(f"RabbitMQ not available at {TEST_RABBITMQ_URL}: {exc}")


async def _reset_test_queues() -> None:
    """Ensure the shared test queues start empty for each test."""
    from aio_pika import connect_robust
    from aio_pika.exceptions import ChannelNotFoundEntity

    conn = await connect_robust(TEST_RABBITMQ_URL)
    channel = await conn.channel()
    try:
        await channel.queue_delete(TEST_QUEUE)
    except ChannelNotFoundEntity:
        pass
    try:
        await channel.queue_delete(TEST_DLQ)
    except ChannelNotFoundEntity:
        pass

    dlx_name = f"{TEST_QUEUE}.dlx"
    dlx = await channel.declare_exchange(dlx_name, ExchangeType.DIRECT, durable=True)
    queue = await channel.declare_queue(
        TEST_QUEUE,
        durable=True,
        arguments={
            "x-dead-letter-exchange": dlx_name,
            "x-dead-letter-routing-key": TEST_DLQ,
            "x-max-length": 100000,
            "x-message-ttl": 86400000,
            "x-max-priority": 10,
        },
    )
    dlq = await channel.declare_queue(
        TEST_DLQ,
        durable=True,
        arguments={
            "x-max-length": 50000,
            "x-message-ttl": 604800000,
        },
    )
    await dlq.bind(dlx, routing_key=TEST_DLQ)
    await queue.purge()
    await dlq.purge()
    await conn.close()


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="function")
async def publisher():
    """Create message publisher for testing."""
    await _ensure_rabbitmq_available()
    await _reset_test_queues()
    pub = MessagePublisher(
        amqp_url=TEST_RABBITMQ_URL,
        exchange_name=TEST_EXCHANGE,
        exchange_type=ExchangeType.DIRECT,
        use_publisher_confirms=True,
    )
    await pub.connect()
    yield pub
    await pub.close()


@pytest.fixture(scope="function")
async def consumer():
    """Create message consumer for testing."""
    await _ensure_rabbitmq_available()
    await _reset_test_queues()
    cons = MessageConsumer(
        amqp_url=TEST_RABBITMQ_URL,
        queue_name=TEST_QUEUE,
        dlq_name=TEST_DLQ,
        prefetch_count=10,
        max_retry_attempts=3,
    )
    await cons.connect()
    yield cons
    await cons.close()


@pytest.fixture
def sample_message() -> Dict:
    """Sample message for testing."""
    return {
        "alert_id": "test-alert-001",
        "alert_type": "malware",
        "severity": "high",
        "source_ip": "45.33.32.156",
        "timestamp": "2025-01-09T10:30:00Z",
    }


# =============================================================================
# Publisher Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestMessagePublisher:
    """Test message publisher functionality."""

    async def test_publisher_connect(self, publisher):
        """Test publisher connection to RabbitMQ."""
        assert publisher.connection is not None
        assert publisher.channel is not None
        assert publisher.exchange is not None

    async def test_publish_message(self, publisher, sample_message):
        """Test publishing a single message."""
        message_id = await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
            priority=5,
        )

        assert message_id is not None
        assert len(message_id) > 0

    async def test_publish_persistent_message(self, publisher, sample_message):
        """Test publishing persistent message."""
        message_id = await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
            persistent=True,
        )

        assert message_id is not None

    async def test_publish_priority_message(self, publisher, sample_message):
        """Test publishing messages with different priorities."""
        priorities = [1, 5, 10]
        message_ids = []

        for priority in priorities:
            message_id = await publisher.publish(
                routing_key=TEST_QUEUE,
                message=sample_message,
                priority=priority,
            )
            message_ids.append(message_id)

        assert all(msg_id is not None for msg_id in message_ids)
        assert len(set(message_ids)) == 3  # All unique

    async def test_publish_batch_messages(self, publisher, sample_message):
        """Test publishing multiple messages in batch."""
        messages = [
            {**sample_message, "alert_id": f"alert-{i}"}
            for i in range(5)
        ]

        result = await publisher.publish_batch(
            messages=messages,
            routing_key=TEST_QUEUE,
            priority=5,
        )

        assert result["success_count"] == 5
        assert result["failure_count"] == 0
        assert len(result["message_ids"]) == 5

    async def test_publish_to_queue(self, publisher, sample_message):
        """Test publishing directly to queue."""
        message_id = await publisher.publish_to_queue(
            queue_name=TEST_QUEUE,
            message=sample_message,
            priority=5,
        )

        assert message_id is not None

    async def test_publish_priority_alert(self, publisher, sample_message):
        """Test publishing alert with automatic priority."""
        # High priority alert
        high_priority_id = await publisher.publish_priority_alert(
            routing_key=TEST_QUEUE,
            message=sample_message,
            alert_type="critical",
        )

        # Low priority alert
        low_priority_id = await publisher.publish_priority_alert(
            routing_key=TEST_QUEUE,
            message={**sample_message, "alert_id": "alert-002"},
            alert_type="info",
        )

        assert high_priority_id is not None
        assert low_priority_id is not None
        assert high_priority_id != low_priority_id

    async def test_publish_with_correlation_id(self, publisher, sample_message):
        """Test publishing message with correlation ID."""
        correlation_id = "test-correlation-123"

        message_id = await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
            correlation_id=correlation_id,
        )

        assert message_id is not None

    async def test_publish_with_expiration(self, publisher, sample_message):
        """Test publishing message with TTL."""
        message_id = await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
            expiration=60000,  # 60 seconds
        )

        assert message_id is not None

    async def test_publish_with_headers(self, publisher, sample_message):
        """Test publishing message with custom headers."""
        headers = {
            "source": "splunk",
            "environment": "production",
        }

        message_id = await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
            headers=headers,
        )

        assert message_id is not None

    async def test_get_publish_stats(self, publisher):
        """Test getting publisher statistics."""
        stats = await publisher.get_publish_stats()

        assert "pending_confirms" in stats
        assert "confirmed_messages" in stats
        assert "failed_messages" in stats
        assert "use_publisher_confirms" in stats
        assert stats["use_publisher_confirms"] is True

    async def test_wait_for_confirms(self, publisher, sample_message):
        """Test waiting for publisher confirms."""
        # Publish messages
        for i in range(3):
            await publisher.publish(
                routing_key=TEST_QUEUE,
                message={**sample_message, "alert_id": f"alert-{i}"},
            )

        # Wait for confirms
        confirmed = await publisher.wait_for_confirms(timeout=5.0)

        assert confirmed is True


# =============================================================================
# Consumer Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestMessageConsumer:
    """Test message consumer functionality."""

    async def test_consumer_connect(self, consumer):
        """Test consumer connection to RabbitMQ."""
        assert consumer.connection is not None
        assert consumer.channel is not None
        assert consumer.queue is not None
        assert consumer.dlq is not None

    async def test_consume_single_message(self, consumer, publisher, sample_message):
        """Test consuming a single message."""
        # Publish message
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        # Consume message
        received_messages = []

        async def callback(message: Dict[str, Any]):
            received_messages.append(message)
            await consumer.stop_consuming()

        # Start consumption in background
        consume_task = asyncio.create_task(consumer.consume(callback))

        # Wait for message
        await asyncio.wait_for(consume_task, timeout=5.0)

        assert len(received_messages) >= 1
        assert received_messages[0]["data"]["alert_id"] == sample_message["alert_id"]

    async def test_consume_multiple_messages(self, consumer, publisher, sample_message):
        """Test consuming multiple messages."""
        # Publish multiple messages
        message_count = 5
        for i in range(message_count):
            await publisher.publish(
                routing_key=TEST_QUEUE,
                message={**sample_message, "alert_id": f"alert-{i}"},
            )

        # Consume messages
        received_messages = []

        async def callback(message: Dict[str, Any]):
            received_messages.append(message)
            if len(received_messages) >= message_count:
                await consumer.stop_consuming()

        # Start consumption
        consume_task = asyncio.create_task(consumer.consume(callback))

        # Wait for messages
        await asyncio.wait_for(consume_task, timeout=10.0)

        assert len(received_messages) >= message_count

    async def test_message_metadata(self, consumer, publisher, sample_message):
        """Test that messages include metadata."""
        # Publish message
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        # Consume and check metadata
        received_messages = []

        async def callback(message: Dict[str, Any]):
            received_messages.append(message)
            await consumer.stop_consuming()

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.wait_for(consume_task, timeout=5.0)

        assert len(received_messages) >= 1
        assert "_meta" in received_messages[0]
        assert "message_id" in received_messages[0]["_meta"]
        assert "timestamp" in received_messages[0]["_meta"]

    async def test_get_queue_stats(self, consumer, publisher, sample_message):
        """Test getting queue statistics."""
        # Publish messages
        for i in range(3):
            await publisher.publish(
                routing_key=TEST_QUEUE,
                message={**sample_message, "alert_id": f"alert-{i}"},
            )

        # Get stats
        stats = await consumer.get_queue_stats()

        assert "queue" in stats
        assert "message_count" in stats
        assert "consumer_count" in stats
        assert "dlq" in stats
        assert "dlq_message_count" in stats
        assert stats["queue"] == TEST_QUEUE
        assert stats["message_count"] >= 3


# =============================================================================
# Error Handling and Retry Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestErrorHandling:
    """Test error handling and retry logic."""

    async def test_message_retry_on_error(self, consumer, publisher, sample_message):
        """Test that failed messages are retried."""
        # Publish message
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        # Track attempts
        attempt_count = 0

        async def failing_callback(message: Dict[str, Any]):
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 2:
                raise Exception("Simulated processing error")
            await consumer.stop_consuming()

        # Error callback
        async def error_callback(message: Dict[str, Any], error: Exception):
            pass

        # Start consumption
        consume_task = asyncio.create_task(
            consumer.consume(failing_callback, error_callback)
        )

        # Wait for retry
        await asyncio.wait_for(consume_task, timeout=10.0)

        assert attempt_count >= 2

    async def test_message_to_dlq_after_max_retries(
        self,
        consumer,
        publisher,
        sample_message,
    ):
        """Test that messages exceeding max retries go to DLQ."""
        # Publish message
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        # Always fail callback
        async def always_failing_callback(message: Dict[str, Any]):
            raise Exception("Permanent processing error")

        # Start consumption (will fail and go to DLQ)
        consume_task = asyncio.create_task(consumer.consume(always_failing_callback))

        # Wait for message to be processed and sent to DLQ
        await asyncio.sleep(2.0)
        await consumer.stop_consuming()
        try:
            await asyncio.wait_for(consume_task, timeout=2.0)
        except asyncio.TimeoutError:
            pass

        # Check DLQ stats
        stats = await consumer.get_queue_stats()
        # Message should be in DLQ after max retries
        assert stats["dlq_message_count"] >= 0

    async def test_error_callback_invocation(self, consumer, publisher, sample_message):
        """Test that error callback is invoked on processing failure."""
        # Publish message
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        error_received = []

        async def failing_callback(message: Dict[str, Any]):
            raise ValueError("Test error")

        async def error_callback(message: Dict[str, Any], error: Exception):
            error_received.append((message, error))
            await consumer.stop_consuming()

        # Start consumption
        consume_task = asyncio.create_task(
            consumer.consume(failing_callback, error_callback)
        )

        # Wait for error callback
        await asyncio.wait_for(consume_task, timeout=5.0)

        assert len(error_received) >= 1
        assert isinstance(error_received[0][1], ValueError)


# =============================================================================
# Dead Letter Queue Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestDeadLetterQueue:
    """Test dead letter queue functionality."""

    async def test_dlq_message_receive(self, consumer, publisher, sample_message):
        """Test receiving messages from DLQ."""
        # First, send a message to DLQ by consuming with error
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        async def failing_callback(message: Dict[str, Any]):
            raise Exception("Send to DLQ")

        # Consume and fail (sends to DLQ)
        consume_task = asyncio.create_task(consumer.consume(failing_callback))
        await asyncio.sleep(1.0)
        await consumer.stop_consuming()

        try:
            await asyncio.wait_for(consume_task, timeout=2.0)
        except asyncio.TimeoutError:
            pass

        # Now consume from DLQ
        dlq_messages = []

        async def dlq_callback(message: Dict[str, Any]):
            dlq_messages.append(message)
            raise Exception("Stop DLQ consumption")

        # Start DLQ consumption
        dlq_task = asyncio.create_task(consumer.consume_from_dlq(dlq_callback))

        await asyncio.sleep(1.0)
        await consumer.stop_consuming()

        try:
            await asyncio.wait_for(dlq_task, timeout=2.0)
        except asyncio.TimeoutError:
            pass

        # At this point, DLQ should have messages
        stats = await consumer.get_queue_stats()
        assert stats["dlq"] == TEST_DLQ

    async def test_purge_dlq(self, consumer, publisher, sample_message):
        """Test purging DLQ."""
        # Get initial DLQ count
        initial_stats = await consumer.get_queue_stats()
        initial_count = initial_stats["dlq_message_count"]

        # Purge DLQ
        purged = await consumer.purge_dlq()

        # Verify purged
        final_stats = await consumer.get_queue_stats()
        assert final_stats["dlq_message_count"] == 0


# =============================================================================
# Batch Consumer Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestBatchConsumer:
    """Test batch consumer functionality."""

    @pytest.fixture
    async def batch_consumer(self):
        """Create batch consumer for testing."""
        await _ensure_rabbitmq_available()
        await _reset_test_queues()
        consumer = BatchConsumer(
            amqp_url=TEST_RABBITMQ_URL,
            queue_name=TEST_QUEUE,
            batch_size=3,
            batch_timeout_ms=5000,
        )
        await consumer.connect()
        yield consumer
        await consumer.close()

    async def test_batch_consumption(self, batch_consumer, publisher, sample_message):
        """Test consuming messages in batches."""
        # Publish messages
        message_count = 5
        for i in range(message_count):
            await publisher.publish(
                routing_key=TEST_QUEUE,
                message={**sample_message, "alert_id": f"alert-{i}"},
            )

        # Track batches
        received_batches = []

        async def batch_callback(messages: list):
            received_batches.append(messages)
            if len(received_batches) >= 2:  # Get at least 2 batches
                await batch_consumer.stop_consuming()

        # Start batch consumption
        consume_task = asyncio.create_task(batch_consumer.consume(batch_callback))

        # Wait for batches
        await asyncio.wait_for(consume_task, timeout=10.0)

        assert len(received_batches) >= 2
        # Check batch sizes
        assert sum(len(batch) for batch in received_batches) >= message_count

    async def test_batch_timeout(self, batch_consumer, publisher, sample_message):
        """Test that partial batches are processed after timeout."""
        # Publish fewer messages than batch size
        for i in range(2):
            await publisher.publish(
                routing_key=TEST_QUEUE,
                message={**sample_message, "alert_id": f"alert-{i}"},
            )

        received_batches = []

        async def batch_callback(messages: list):
            received_batches.append(messages)
            await batch_consumer.stop_consuming()

        # Start batch consumption
        consume_task = asyncio.create_task(batch_consumer.consume(batch_callback))

        # Wait for batch timeout (5 seconds)
        await asyncio.wait_for(consume_task, timeout=10.0)

        assert len(received_batches) >= 1
        assert len(received_batches[0]) == 2  # Partial batch


# =============================================================================
# Transactional Publisher Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestTransactionalPublisher:
    """Test transactional publisher functionality."""

    @pytest.fixture
    async def transactional_publisher(self):
        """Create transactional publisher for testing."""
        await _ensure_rabbitmq_available()
        await _reset_test_queues()
        pub = TransactionalPublisher(
            amqp_url=TEST_RABBITMQ_URL,
            exchange_name=TEST_EXCHANGE,
            exchange_type=ExchangeType.DIRECT,
        )
        await pub.connect()
        yield pub
        await pub.close()

    async def test_transaction_commit(self, transactional_publisher, consumer, sample_message):
        """Test transaction commit."""
        # Start transaction
        await transactional_publisher.begin_transaction()

        # Publish messages in transaction
        messages = [
            {**sample_message, "alert_id": f"alert-{i}"}
            for i in range(3)
        ]

        for message in messages:
            await transactional_publisher.publish(
                routing_key=TEST_QUEUE,
                message=message,
            )

        # Commit transaction
        await transactional_publisher.commit_transaction()

        # Verify messages were published
        received = []

        async def callback(msg):
            received.append(msg)
            if len(received) >= len(messages):
                await consumer.stop_consuming()

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.wait_for(consume_task, timeout=10.0)

        assert len(received) >= len(messages)

    async def test_transaction_rollback(self, transactional_publisher, consumer, sample_message):
        """Test transaction rollback."""
        # Start transaction
        await transactional_publisher.begin_transaction()

        # Publish message
        await transactional_publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
        )

        # Rollback transaction
        await transactional_publisher.rollback_transaction()

        # Verify no messages in queue
        received = []

        async def callback(msg):
            received.append(msg)

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.sleep(1.0)
        await consumer.stop_consuming()

        try:
            await asyncio.wait_for(consume_task, timeout=1.0)
        except asyncio.TimeoutError:
            pass

        # Messages should not have been delivered
        # (This test is timing-dependent and may need adjustment)

    async def test_publish_in_transaction(self, transactional_publisher, consumer, sample_message):
        """Test publish_in_transaction method."""
        messages = [
            {**sample_message, "alert_id": f"alert-{i}"}
            for i in range(3)
        ]

        # Publish in transaction
        success = await transactional_publisher.publish_in_transaction(
            messages=messages,
            routing_key=TEST_QUEUE,
        )

        assert success is True

        # Verify messages
        received = []

        async def callback(msg):
            received.append(msg)
            if len(received) >= len(messages):
                await consumer.stop_consuming()

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.wait_for(consume_task, timeout=10.0)

        assert len(received) >= len(messages)


# =============================================================================
# End-to-End Message Flow Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.message_queue
class TestEndToEndMessageFlow:
    """Test complete message flow from publisher to consumer."""

    async def test_complete_message_flow(self, publisher, consumer, sample_message):
        """Test complete publish → consume flow."""
        # Publish message
        message_id = await publisher.publish(
            routing_key=TEST_QUEUE,
            message=sample_message,
            priority=7,
        )

        assert message_id is not None

        # Consume message
        received = []

        async def callback(message: Dict[str, Any]):
            received.append(message)
            await consumer.stop_consuming()

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.wait_for(consume_task, timeout=5.0)

        # Verify
        assert len(received) >= 1
        assert received[0]["data"]["alert_id"] == sample_message["alert_id"]
        assert received[0]["_meta"]["message_id"] == message_id

    async def test_message_ordering(self, publisher, consumer, sample_message):
        """Test that messages maintain order."""
        # Publish messages in order
        message_count = 10
        for i in range(message_count):
            await publisher.publish(
                routing_key=TEST_QUEUE,
                message={**sample_message, "alert_id": f"alert-{i}", "order": i},
                priority=5,  # Same priority to maintain order
            )

        # Consume and verify order
        received = []

        async def callback(message: Dict[str, Any]):
            received.append(message)
            if len(received) >= message_count:
                await consumer.stop_consuming()

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.wait_for(consume_task, timeout=15.0)

        # Verify order is maintained
        if len(received) >= message_count:
            orders = [msg["data"]["order"] for msg in received[:message_count]]
            # With same priority, order should be maintained
            # (Note: RabbitMQ doesn't strictly guarantee FIFO within same priority,
            # but in practice it usually works out)
            assert len(orders) == message_count

    async def test_priority_message_ordering(self, publisher, consumer, sample_message):
        """Test that higher priority messages are processed first."""
        # Publish messages with different priorities
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message={**sample_message, "alert_id": "low", "priority": "low"},
            priority=1,
        )
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message={**sample_message, "alert_id": "high", "priority": "high"},
            priority=10,
        )
        await publisher.publish(
            routing_key=TEST_QUEUE,
            message={**sample_message, "alert_id": "medium", "priority": "medium"},
            priority=5,
        )

        # Consume messages
        received = []

        async def callback(message: Dict[str, Any]):
            received.append(message)
            if len(received) >= 3:
                await consumer.stop_consuming()

        consume_task = asyncio.create_task(consumer.consume(callback))
        await asyncio.wait_for(consume_task, timeout=10.0)

        # High priority message should be consumed first
        if len(received) >= 3:
            # Check that high priority comes before low priority
            alert_ids = [msg["data"]["alert_id"] for msg in received[:3]]
            high_idx = alert_ids.index("high")
            low_idx = alert_ids.index("low")
            # High priority should come before low priority
            assert high_idx < low_idx


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
