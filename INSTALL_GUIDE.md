# 📦 安装指南

本指南覆盖公开仓库中的两条路径：原型 CLI（`src/` + `main.py`）和 Web 前端（`services/web_dashboard/`）。

## 前置条件

- Python 3.11+ 和 `pip`
- 一个 OpenAI 兼容的 LLM API 密钥（通义千问 Qwen、OpenAI、DeepSeek 等）
- （仅前端需要）Node.js >=20 <25

## 原型 CLI 安装

### 步骤 1：安装 Python 依赖

```bash
cd sentriq
pip3 install -r requirements.txt
```

如果遇到版本冲突：

```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt --upgrade
```

建议使用虚拟环境：

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 步骤 2：创建 .env 文件

```bash
cp .env.example .env
```

编辑 `.env`，填入你的 API 密钥：

```bash
LLM_API_KEY=sk-your-key
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1   # 以 Qwen 为例
```

注意格式：`LLM_API_KEY=sk-xxx`，不要加引号。

### 步骤 3：运行

```bash
# 使用 4 条示例告警测试
python3 main.py --sample

# 交互式模式
python3 main.py --interactive

# 批量处理
python3 main.py --file data/sample_alerts.json
```

运行结果输出到 `logs/triage_result_*.json`，运行日志在 `logs/triage.log`。

## Web 前端安装（可选）

```bash
cd services/web_dashboard
npm install
npm run dev     # Vite 开发服务器
npm run build   # 生产构建，输出到 dist/
```

Node 版本要求 `>=20 <25`（Vite 5 / Rollup 4 在更高版本上会挂起），详见 `services/web_dashboard/README.md`。

## 微服务源码（可选）

`services/` 下的每个服务都是独立的 FastAPI 应用，各自带有 `requirements.txt`，可以单独安装运行：

```bash
cd services/<service_name>
pip3 install -r requirements.txt
python3 main.py
```

服务间依赖 PostgreSQL、Redis、RabbitMQ、ChromaDB 等基础设施，并通过 `services/shared/` 共享库（models、database、messaging、auth）协作。多服务部署编排文件（docker-compose、k8s/helm）不在公开仓库中。

## 故障排除

### 问题 1：pip install 失败

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 问题 2：Python 版本太旧

```bash
python3 --version   # 需要 3.11+
# macOS
brew install python@3.11
```

### 问题 3：ImportError / Module Not Found

```bash
# 确保在仓库根目录运行
cd sentriq
python3 main.py --sample

# 检查依赖是否安装
pip3 list | grep langchain
pip3 install langchain langchain-openai langchain-community
```

### 问题 4：API 连接失败

```bash
# 检查 .env 配置，确认密钥格式正确、无引号
cat .env
```

详细错误信息见 `logs/triage.log`。

## 验证安装

```bash
python3 -c "
import sys
print('Python version:', sys.version)

import langchain
print('LangChain:', langchain.__version__)

import openai
print('OpenAI:', openai.__version__)

import pydantic
print('Pydantic:', pydantic.__version__)
"
```

四个包都能正常打印版本号即安装成功。

---

**快速开始（3 个命令）**：

```bash
cd sentriq
pip3 install -r requirements.txt
python3 main.py --sample
```
