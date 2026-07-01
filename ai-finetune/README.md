# GuizangAI 微调数据工作区

这个目录用于准备后续真正模型微调所需的数据、来源清单和脚本。当前项目里的 AI 主要负责：

- 根据 Wazuh 聚合摘要生成安全态势、告警归并、合规建议。
- 根据单条漏洞或告警生成可执行处置建议和 runbook。
- 将告警描述改写成适合仪表盘展示的简洁说明。

因此训练数据必须围绕这些任务，不建议混入泛泛的聊天语料、攻击教学或和终端安全无关的数据。

## 推荐目录

```text
ai-finetune/
  data/
    raw/              # 原始外部数据或本地导出数据，不直接训练
    processed/        # 清洗、脱敏、人工复核后的 JSONL
    train.example.jsonl
  schemas/
    guizangai-sft-record.schema.json
  scripts/
    export_wazuh_alerts_to_jsonl.py
    validate_jsonl.py
    fetch_public_sources.py
    train_lora.py
  SOURCES.md
```

## 样本格式

每条训练样本使用 JSONL，一行一个对象：

```json
{"task":"alert_advice","instruction":"根据这条 Wazuh 告警生成中文处置建议和 runbook。","input":{"alert":{"rule":{"level":12,"description":"sshd brute force attempt"}}},"expected_output":{"summary":"检测到 SSH 暴力破解风险。","steps":["确认来源 IP 和目标账号。"],"runbook":[]},"source":"local_wazuh","review_status":"reviewed"}
```

关键要求：

- `expected_output` 必须经过人工复核后才能进入 `processed/train.jsonl`。
- 本地客户数据进入训练前必须脱敏：设备名、IP、用户名、路径、域名、哈希、业务名称。
- 外部公开数据只作为种子数据或知识增强，最终仍要用本系统的真实告警和人工修正来对齐输出风格。

## 基本流程

1. 从 Wazuh 或 PostgreSQL 导出本地样本到 `data/raw/`。
2. 用公开来源补充告警类型、漏洞优先级、ATT&CK 技术和处置 Playbook。
3. 脱敏并转换为统一 JSONL。
4. 人工复核 `expected_output`。
5. 运行校验脚本。
6. 生成 `data/processed/train.jsonl` 和 `data/processed/val.jsonl` 后再进入 LoRA/QLoRA 微调。

## LoRA / QLoRA 微调

先在独立训练环境安装依赖：

```bash
pip install "torch" "transformers>=4.44" "datasets" "accelerate" "peft" "trl"
# 需要 QLoRA 4-bit 时再装：
pip install "bitsandbytes"
```

先做 dry-run，确认样本能被转换成 Qwen chat 模板：

```bash
python3 ai-finetune/scripts/train_lora.py \
  --train-file ai-finetune/data/processed/train.jsonl \
  --dry-run
```

普通 LoRA：

```bash
python3 ai-finetune/scripts/train_lora.py \
  --train-file ai-finetune/data/processed/train.jsonl \
  --output-dir ai-finetune/out/qwen2.5-guizangai-lora \
  --model-name Qwen/Qwen2.5-3B-Instruct
```

QLoRA 4-bit：

```bash
python3 ai-finetune/scripts/train_lora.py \
  --train-file ai-finetune/data/processed/train.jsonl \
  --output-dir ai-finetune/out/qwen2.5-guizangai-qlora \
  --model-name Qwen/Qwen2.5-3B-Instruct \
  --use-4bit
```

当前 `processed/train.jsonl` 只有少量示例，只能验证训练流程，不能训练出有效模型。真正微调建议至少准备数百条已脱敏、已人工复核的样本，并保留约 10% 到 `data/processed/val.jsonl`。

训练产物是 LoRA adapter，不是完整模型。后续可以用 `peft` 合并到基座模型，或在推理服务里以 adapter 方式加载；如果要给 Ollama 使用，还需要额外走合并、转换和量化到 GGUF 的流程。
