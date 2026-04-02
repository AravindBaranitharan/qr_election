import os
from gunicorn.config import Config


class CustomConfig(Config):
    # Render dynamically injects PORT; fallback keeps local run simple.
    bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"

    # 15 concurrent users target on a single free instance.
    workers = int(os.getenv("WEB_CONCURRENCY", "1"))
    worker_class = "gthread"
    threads = int(os.getenv("GUNICORN_THREADS", "15"))

    # Your requested worker timeout.
    worker_timeout = int(os.getenv("GUNICORN_WORKER_TIMEOUT", "180"))
    timeout = worker_timeout

    graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
    keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))


# Gunicorn consumes module-level settings from this file.
bind = CustomConfig.bind
workers = CustomConfig.workers
worker_class = CustomConfig.worker_class
threads = CustomConfig.threads
timeout = CustomConfig.timeout
graceful_timeout = CustomConfig.graceful_timeout
keepalive = CustomConfig.keepalive
