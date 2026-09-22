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

# Triage Engine Service - Dockerfile
# AI Security Triage Engine: System 1 (Laya) + Decision Plane + System 2 (Investigation Agent)
#
# NOTE: the MLX runtime (laya-mlx) is Apple-Silicon-only and is NOT installed in
# this image. Inside Linux containers the fast provider falls back to the
# deterministic RuleProvider (fail-safe, requirement §41) unless LAYA_RUNTIME=torch
# and the upstream `laya` package are installed at deploy time.

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/services:/app \
    TRIAGE_ENGINE_DB=/app/data/triage_engine.db

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources || true
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc curl && \
    rm -rf /var/lib/apt/lists/*

COPY ./services/triage_engine/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY ./services/triage_engine /app/services/triage_engine
COPY ./data /app/data

RUN useradd -m -u 1001 appuser && \
    mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser

EXPOSE 8009

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8009/health || exit 1

CMD ["python", "services/triage_engine/main.py"]
