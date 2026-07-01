import json
import logging
import os
import socket
import time
from typing import Any
from urllib.parse import quote, urlparse

logger = logging.getLogger("queue_manager")

def build_rabbitmq_url() -> str:
    direct_url = os.getenv("RABBITMQ_URL")
    if direct_url:
        return direct_url

    user = os.getenv("RABBITMQ_DEFAULT_USER", "lexledger")
    password = os.getenv("RABBITMQ_DEFAULT_PASS") or os.getenv("LEXLEDGER_RABBITMQ_PASSWORD")
    host = os.getenv("RABBITMQ_HOST", "localhost")
    port = os.getenv("RABBITMQ_PORT", "5672")

    if password is None:
        logger.warning(
            "RABBITMQ_URL/RABBITMQ_DEFAULT_PASS is not set; using insecure guest RabbitMQ credentials."
        )
        return "amqp://guest:guest@localhost:5672/"

    return f"amqp://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}/"


RABBITMQ_URL = build_rabbitmq_url()
VOTE_QUEUE = "vote_queue"
RABBITMQ_STATUS_CACHE_SECONDS = float(os.getenv("LEXLEDGER_RABBITMQ_STATUS_CACHE_SECONDS", "15"))
_rabbitmq_status_cache: tuple[float, bool] | None = None

def is_rabbitmq_online() -> bool:
    """Checks if RabbitMQ is reachable and the pika library is installed."""
    global _rabbitmq_status_cache

    now = time.monotonic()
    if _rabbitmq_status_cache is not None:
        checked_at, status = _rabbitmq_status_cache
        if now - checked_at < RABBITMQ_STATUS_CACHE_SECONDS:
            return status

    parsed_url = urlparse(RABBITMQ_URL)
    host = parsed_url.hostname or "localhost"
    port = parsed_url.port or 5672
    try:
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except OSError:
        _rabbitmq_status_cache = (now, False)
        return False

    try:
        import pika
        # Short timeout to prevent blocking startup
        parameters = pika.URLParameters(RABBITMQ_URL)
        parameters.connection_attempts = 1
        parameters.retry_delay = 1
        connection = pika.BlockingConnection(parameters)
        connection.close()
        _rabbitmq_status_cache = (now, True)
        return True
    except Exception:
        _rabbitmq_status_cache = (now, False)
        return False

def publish_vote(proposal_id: int, user_id: int, vote_id: int) -> bool:
    """Publishes a vote message to the RabbitMQ queue."""
    message = {
        "proposal_id": proposal_id,
        "user_id": user_id,
        "vote_id": vote_id
    }
    
    try:
        import pika
        parameters = pika.URLParameters(RABBITMQ_URL)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue=VOTE_QUEUE, durable=True)
        channel.basic_publish(
            exchange="",
            routing_key=VOTE_QUEUE,
            body=json.dumps(message),
            properties=pika.BasicProperties(
                delivery_mode=2  # Make message persistent
            )
        )
        connection.close()
        logger.info(f"[QueueManager] Published vote for proposal {proposal_id} to queue.")
        return True
    except Exception as e:
        logger.warning(f"[QueueManager] RabbitMQ publish failed: {e}. Falling back to sync tally.")
        return False

def start_rabbitmq_consumer():
    """Starts the RabbitMQ consumer loop in a background thread."""
    try:
        import pika
    except ImportError:
        logger.error("[QueueManager] pika library not installed. Consumer cannot start.")
        return

    logger.info("[QueueManager] Starting background RabbitMQ vote consumer thread...")
    while True:
        try:
            parameters = pika.URLParameters(RABBITMQ_URL)
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            channel.queue_declare(queue=VOTE_QUEUE, durable=True)
            
            # Prefetch count = 1 to distribute load evenly
            channel.basic_qos(prefetch_count=1)

            def callback(ch, method, properties, body):
                try:
                    data = json.loads(body)
                    proposal_id = data["proposal_id"]
                    logger.info(f"[QueueManager] Processing vote from queue for proposal {proposal_id}")
                    
                    # Dynamically import to avoid circular dependency
                    from .main import tally_proposal
                    tally_proposal(proposal_id)
                    
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                except Exception as ex:
                    logger.error(f"[QueueManager] Error processing queue message: {ex}")
                    # Re-queue on failure
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

            channel.basic_consume(queue=VOTE_QUEUE, on_message_callback=callback)
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError:
            logger.warning("[QueueManager] RabbitMQ connection lost. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"[QueueManager] Consumer encountered unexpected error: {e}")
            time.sleep(5)
