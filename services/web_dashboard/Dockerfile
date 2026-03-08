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

# =============================================================================
# Stage 1: Build React Frontend
# =============================================================================
FROM node:20-alpine AS frontend-builder

# Build context is project root (./)
WORKDIR /frontend

# Copy frontend package files from project root
COPY ./services/web_dashboard/package.json ./

# Install dependencies (npm install instead of ci since no package-lock.json exists)
RUN npm config set registry https://registry.npmmirror.com && \
    npm config set fetch-retries 3 && \
    npm config set fetch-retry-mintimeout 10000 && \
    npm config set fetch-retry-maxtimeout 60000 && \
    npm install

# Copy frontend source from project root
COPY ./services/web_dashboard ./

# Build frontend
RUN npm run build

# =============================================================================
# Stage 2: Build Backend and Serve Frontend
# =============================================================================
FROM python:3.11-slim

WORKDIR /app

# Use China mirrors for faster downloads
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources || \
    sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources || \
    sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources

# Install system dependencies with retry logic
RUN for i in 1 2 3; do \
    apt-get update && apt-get install -y --fix-missing \
        gcc \
        g++ \
        curl \
        && rm -rf /var/lib/apt/lists/* && break || sleep 10; \
    done

# Install Python dependencies (from project root)
COPY ./services/web_dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared module (parent directory relative to build context)
COPY ./services/shared /app/shared

# Copy backend code (current directory)
COPY ./services/web_dashboard /app/services/web_dashboard

# Copy built frontend from stage 1
COPY --from=frontend-builder /frontend/dist /app/static

# Create non-root user
RUN useradd -m -u 1000 triage && \
    chown -R triage:triage /app
USER triage

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Set PYTHONPATH to include /app for shared module imports
ENV PYTHONPATH=/app

# Start FastAPI backend
CMD ["python", "services/web_dashboard/main.py"]
