# 数据目录说明

不要把未脱敏的客户数据提交或打包给第三方。

- `raw/`：原始导出数据，例如 Wazuh `alerts.json`、公开数据集下载结果、数据库导出结果。
- `processed/`：已清洗、脱敏、人工复核后的训练/验证 JSONL。
- `train.example.jsonl`：格式样例，不用于正式训练。

建议文件命名：

```text
raw/wazuh-alerts-2026-06.jsonl
raw/cisa-kev.json
raw/mitre-attack-enterprise.json
processed/train.jsonl
processed/val.jsonl
```
