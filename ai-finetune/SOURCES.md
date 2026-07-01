# 训练数据来源清单

本清单只收录和当前 GuizangAI 职责直接相关的数据：Wazuh 告警分析、漏洞优先级、ATT&CK 技术解释、检测规则说明、事件响应 runbook。任何来源进入训练前都必须确认许可证、脱敏和人工复核。

## 最优先：本项目真实数据

### Wazuh alerts.json

- 地址：部署后的 Wazuh Manager 容器内 `/var/ossec/logs/alerts/alerts.json`
- 用途：训练 `alert_advice`、`alert_description`、`alert_triage`
- 优点：字段结构和本系统完全一致，最贴近真实效果
- 风险：含设备名、IP、用户、路径、命令，必须脱敏
- 处理方式：

```bash
python ai-finetune/scripts/export_wazuh_alerts_to_jsonl.py \
  /path/to/alerts.json \
  ai-finetune/data/raw/wazuh-alerts-seed.jsonl
```

生成结果只是 `needs_review` 种子数据，必须人工补充 `expected_output`。

### PostgreSQL 分析快照

- 表：`analysis_snapshots`、`metric_snapshots`
- 用途：训练 `overview`、`alert_triage`、`compliance`
- 优点：包含本系统已经生成过的 AI 结构化输出
- 风险：如果输出未经人工修正，只能当弱标签，不能直接作为高质量训练集
- 建议：导出后让管理员修正为“老板能看懂、IT 能执行”的标准答案。

## 高相关公开数据

### Hugging Face: kholil-lil/wazuh-alerts

- URL: https://huggingface.co/datasets/kholil-lil/wazuh-alerts
- 类型：Wazuh 安全告警数据，JSON / Parquet
- 适合任务：`alert_triage`、`alert_advice`、告警字段理解
- 使用建议：作为 Wazuh schema 和告警类型扩充，不要直接把原始告警当回答。

### Hugging Face: acezxn/event_correlation_wazuh

- URL: https://huggingface.co/datasets/acezxn/event_correlation_wazuh
- 类型：Wazuh 事件关联数据，包含告警描述和响应文本
- 适合任务：`alert_triage`、`alert_advice`
- 使用建议：适合做“告警上下文 -> 分析说明/处置建议”的种子，但需要统一成 GuizangAI 的 JSON 输出格式。

### AIT Alert Data Set

- URL: https://doi.org/10.5281/zenodo.8263180
- 类型：多场景攻击链告警数据，包含 Wazuh、Suricata、AMiner JSON 告警和攻击阶段标签
- 适合任务：`alert_triage`、攻击链归并、告警降噪
- 使用建议：适合训练“多条告警归并成少数问题类别”，比单条告警更贴近仪表盘里的 `alert_triage`。

### Incident Response Playbooks

- URL: https://huggingface.co/datasets/AYI-NEDJIMI/incident-response-playbooks
- 类型：NIST 800-61 风格事件响应 Playbook，JSONL
- 适合任务：`alert_advice`、`vuln_advice`
- 使用建议：只抽取防守处置结构，例如 check / contain / remediate / verify / rollback，输出时要改写成本项目 runbook schema。

### Incident_Response_Playbook_Dataset

- URL: https://huggingface.co/datasets/darkknight25/Incident_Response_Playbook_Dataset
- 类型：结构化事件响应 Playbook，含 MITRE ATT&CK tactic/technique
- 适合任务：`alert_advice`
- 使用建议：用于补充不同攻击类型的处置步骤，但必须过滤掉红队执行细节和不适合终端管理员执行的内容。

## 权威知识源，适合增强和标注

### MITRE ATT&CK STIX

- URL: https://github.com/mitre-attack/attack-stix-data
- 类型：ATT&CK 技术、战术、缓解措施、检测策略，STIX 2.1 JSON
- 适合任务：解释 `rule.mitre.id`、生成处置建议中的原因和验证项
- 拉取方式：

```bash
python ai-finetune/scripts/fetch_public_sources.py ai-finetune/data/raw/public
```

### CISA Known Exploited Vulnerabilities

- URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- GitHub: https://github.com/cisagov/kev-data
- 类型：已确认被利用漏洞，含 `cveID`、厂商、产品、描述、requiredAction、是否被勒索利用
- 适合任务：`vuln_advice`、漏洞优先级、修复建议
- 使用建议：遇到 KEV CVE 时提高优先级，训练输出中明确“已被利用，应优先修复”。

### SigmaHQ/sigma

- URL: https://github.com/SigmaHQ/sigma
- 类型：SIEM 检测规则，YAML
- 适合任务：告警解释、规则分类、检测逻辑说明
- 使用建议：把 rule title / description / tags / falsepositives 转成“为什么触发、误报如何排查”的辅助样本。

## 可选大规模安全语料

### CyberLLMInstruct

- URL: https://arxiv.org/html/2503.09334v1
- 类型：网络安全 instruction-response 对
- 适合任务：安全问答泛化
- 使用建议：只筛选防守、处置、分析类内容；不要混入攻击执行、恶意脚本生成等不适合产品形态的数据。

## 不建议直接用于训练

- `simulate-wazuh-attack.sh`：它是制造测试告警的脚本，不是训练集。可以用它触发 Wazuh 产生样本，再从 `alerts.json` 导出。
- 未复核的 AI 输出：可能有幻觉或命令不匹配操作系统，只能作为待审草稿。
- 原始客户日志：必须脱敏、授权、隔离存储。

## 进入训练集前的筛选标准

1. 和当前任务有关：态势总结、告警归并、漏洞处置、告警说明。
2. 输出必须是项目需要的 JSON schema。
3. 处置步骤必须偏防守，不能包含攻击教学或破坏性操作。
4. 命令必须匹配目标系统：Windows / macOS / Linux。
5. 修改系统状态的命令必须带确认、回滚或验证步骤。
6. 人工复核后 `review_status` 才能从 `needs_review` 改成 `reviewed`。
