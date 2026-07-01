"""集中式配置：全部从环境变量读取，便于在不同客户环境部署。"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- Wazuh Server API ----
    wazuh_api_url: str = "https://wazuh.manager:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = "MyS3cr37P450r.*-"

    # ---- Wazuh Indexer (OpenSearch) ----
    indexer_url: str = "https://wazuh.indexer:9200"
    indexer_user: str = "admin"
    indexer_password: str = "SecretPassword"
    alerts_index: str = "wazuh-alerts-*"
    vuln_index: str = "wazuh-states-vulnerabilities-*"  # Wazuh 4.8+ 漏洞结果索引

    # 自签证书环境下默认不校验 TLS（生产可换成挂载 CA 后置 True）
    verify_tls: bool = False

    # ---- PostgreSQL（AI 结论/趋势/报表历史） ----
    database_url: str = "postgresql+psycopg2://sentinel:sentinel@db:5432/sentinel"

    # ---- GuizangAI 对接点 ----
    # 留空 => Mock 模式：返回模拟分析结果，保证无 GuizangAI 时全链路可跑通
    guizangai_base_url: str = ""
    # 接口风格：openai（/v1/chat/completions，LM Studio/vLLM/llama.cpp/Ollama 都兼容，默认）
    #          | ollama（/api/chat）| custom_sse（现有 /chat SSE）
    guizangai_api_style: str = "openai"
    guizangai_model: str = "qwen2.5:3b"        # 模型名；Ollama 用其底层模型标签
    guizangai_api_key: str = ""                # OpenAI 兼容接口如需鉴权则填（Bearer）
    guizangai_chat_path: str = ""              # 可选：自定义请求路径，覆盖该风格的默认路径
    guizangai_timeout_seconds: int = 60
    guizangai_max_new_tokens: int = 1024
    guizangai_temperature: float = 0.4
    guizangai_num_ctx: int = 4096
    guizangai_keep_alive: str = "30m"
    guizangai_num_gpu: int = 999
    guizangai_analysis_concurrency: int = 1
    guizangai_analysis_cache_ttl_seconds: int = 600
    guizangai_advice_cache_ttl_seconds: int = 3600

    # ---- 发送给 GuizangAI 的原始日志（全量信息） ----
    # True => 把原始告警明细(整条 _source)随摘要一起发给模型；False => 仅发聚合摘要
    guizangai_send_raw_logs: bool = True
    # 单次最多取多少条原始告警，防止超出模型上下文窗口；设 0 表示取上限(1万条)
    guizangai_raw_logs_max: int = 80
    # 留空=整条日志全部字段；可填逗号分隔字段名只取关心的字段(裁剪体积)
    guizangai_raw_logs_fields: str = "timestamp,agent.name,rule.level,rule.description,rule.groups,rule.mitre.id,syscheck.path,syscheck.event,data.srcip,location"

    # 兼容 sentinel-installer-2 中的通用 AI_* 环境变量和旧 ai_client.py。
    ai_base_url: str = ""
    ai_api_style: str = "openai"
    ai_model: str = "qwen2.5:7b"
    ai_api_key: str = ""
    ai_chat_path: str = ""
    ai_timeout_seconds: int = 60
    ai_max_new_tokens: int = 1024
    ai_temperature: float = 0.4
    ai_num_ctx: int = 4096
    ai_keep_alive: str = "30m"
    ai_num_gpu: int = 999
    ai_send_raw_logs: bool = True
    ai_raw_logs_max: int = 200
    ai_raw_logs_fields: str = ""

    # ---- 分析调度 ----
    analysis_interval_minutes: float = 1.0  # 定时分析周期，支持 0.5 表示 30 秒
    summary_window: str = "now-24h"      # 聚合时间窗

    # ---- 高危问题生命周期追踪（发现→清除） ----
    issue_min_level: int = 12
    issue_window: str = "now-30d"
    issue_reconcile_minutes: int = 2

    # ---- 仪表盘登录鉴权 ----
    auth_secret: str = "guizang-sentinel-secret-change-me"  # 令牌签名密钥，生产建议改成随机长字符串
    auth_token_ttl_hours: int = 12                         # 登录令牌有效期
    default_admin_user: str = "testadmin"                    # 首次启动自动创建的默认账号
    default_admin_password: str = "testpass"                 # 默认密码（登录后请尽快修改）

    # ---- 其它 ----
    cors_origins: str = "http://localhost:8080,http://127.0.0.1:8080"
    timezone: str = "Asia/Shanghai"


settings = Settings()
