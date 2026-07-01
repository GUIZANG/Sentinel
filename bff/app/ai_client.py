"""AI 适配器 —— ★ 对接点预留 ★

本文件是与 AI 推理服务的唯一耦合点。部署 AI 的机器上的 Cursor
只需按 docs/AI_INTEGRATION.md 校对这里的请求/响应格式即可完成最终对接。

两种模式：
  1) Mock 模式（AI_BASE_URL 为空）：返回规则化的模拟结论，保证全链路可跑通。
  2) HTTP 模式（配置了 AI_BASE_URL）：调用真实 AI 后端。

无论哪种模式，analyze() 的契约不变：
    输入  = (task_key, summary_dict)
    输出  = dict（与 prompts.PRESET_TASKS[task_key]['schema'] 对应的 JSON）
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import settings
from .prompts import PRESET_TASKS, SYSTEM_PERSONA

log = logging.getLogger("ai")


# 最近一次「预设分析」推理的性能快照（供仪表盘 AI 推理性能卡片读取）。
_PERF: dict[str, Any] = {
    "enabled": False,
    "api_style": None,
    "model": None,
    "task": None,
    "input_tokens": None,
    "output_tokens": None,
    "tokens_per_sec": None,
    "duration_ms": None,
    "sent_logs": 0,
    "last_refresh": None,
    "last_error": None,
}


def ai_perf() -> dict[str, Any]:
    """返回最近一次推理的性能快照（只读副本）。"""
    return dict(_PERF)


def _est_tokens(s: str | None) -> int:
    """粗略估算 token 数（约 4 字符/token），仅在后端未返回 usage 时兜底。"""
    return max(1, round(len(s) / 4)) if s else 0


class AiClient:
    def __init__(self) -> None:
        self.base_url = settings.ai_base_url.rstrip("/")
        self.enabled = bool(self.base_url)
        self._last_meta: dict[str, Any] = {}  # 每次 _call 后由实现填入 token/耗时

    # ------------------------------------------------------------------ 对外接口
    async def analyze(
        self,
        task_key: str,
        summary: dict[str, Any],
        raw_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        task = PRESET_TASKS[task_key]
        if not self.enabled:
            res = _mock_result(task_key, summary)
            self._record_perf(task_key, "", json.dumps(res, ensure_ascii=False), 0.0, raw_events,
                              error="未配置远端模型端点（Mock 模式）")
            return res

        prompt = self._build_prompt(task, summary, raw_events)
        self._last_meta = {}
        start = time.perf_counter()
        try:
            raw = await self._call(prompt)
            elapsed = time.perf_counter() - start
            parsed = _extract_json(raw)
            if parsed is None:
                self._record_perf(task_key, prompt, raw, elapsed, raw_events, error="无法解析模型输出")
                return {"_error": "无法解析模型输出", "_raw": raw[:500], **_mock_result(task_key, summary)}
            parsed["_source"] = "ai"
            self._record_perf(task_key, prompt, raw, elapsed, raw_events, error=None)
            return parsed
        except Exception as e:  # 失败兜底为 mock，保证仪表盘不空
            self._record_perf(task_key, prompt, "", time.perf_counter() - start, raw_events, error=str(e))
            return {"_error": str(e), **_mock_result(task_key, summary)}

    def _record_perf(self, task: str, prompt: str, output: str, elapsed: float,
                     raw_events: list[dict] | None, error: str | None) -> None:
        meta = self._last_meta or {}
        in_tok = meta.get("input_tokens") or _est_tokens(prompt)
        out_tok = meta.get("output_tokens") or _est_tokens(output)
        gen = meta.get("gen_seconds") or elapsed or None
        tps = round(out_tok / gen, 2) if (out_tok and gen) else None
        _PERF.clear()
        _PERF.update({
            "enabled": self.enabled,
            "api_style": (settings.ai_api_style or "openai") if self.enabled else "mock",
            "model": settings.ai_model,
            "task": task,
            "input_tokens": in_tok or None,
            "output_tokens": out_tok or None,
            "tokens_per_sec": tps,
            "duration_ms": round(elapsed * 1000) if elapsed else None,
            "sent_logs": len(raw_events or []),
            "last_refresh": datetime.now(timezone.utc).isoformat(),
            "last_error": error,
        })

    # ------------------------------------------------------------------ 按需处理建议（漏洞 / 告警）
    async def advise(self, kind: str, context: dict[str, Any], lang: str = "zh",
                     debug: bool = False) -> dict[str, Any]:
        """针对单条漏洞或告警，生成可操作的处置建议。lang: zh / en。

        debug=True 时在返回里附带 `_debug`（发送的 context / 完整 prompt / 模型原始返回 /
        耗时 / token），便于在前端或日志中校验 AI 究竟收到与产出了什么。
        """
        prompt = _build_advice_prompt(kind, context, lang)
        log.info("[advise] kind=%s lang=%s enabled=%s context=%s",
                 kind, lang, self.enabled, json.dumps(context, ensure_ascii=False))

        def _wrap(res: dict[str, Any], raw: str | None, elapsed: float, err: str | None) -> dict[str, Any]:
            if debug:
                res["_debug"] = {
                    "kind": kind,
                    "lang": lang,
                    "enabled": self.enabled,
                    "api_style": (settings.ai_api_style or "openai") if self.enabled else "mock",
                    "model": settings.ai_model if self.enabled else None,
                    "context": context,
                    "prompt": prompt,
                    "raw": raw,
                    "duration_ms": round(elapsed * 1000) if elapsed else 0,
                    "input_tokens": (self._last_meta or {}).get("input_tokens"),
                    "output_tokens": (self._last_meta or {}).get("output_tokens"),
                    "error": err,
                }
            return res

        # 未接入 AI：规则化兜底（仍回传将要发送的 prompt 供核对）
        if not self.enabled:
            res = _mock_advice(kind, context, lang)
            return _wrap(res, None, 0.0, "未配置远端模型端点（Mock 模式）")

        self._last_meta = {}
        start = time.perf_counter()
        try:
            # 处置建议使用专用、语言中立的系统人设：输出语言完全由提示词里的
            # 动态语言指令决定（避免全局人设把输出固定成中文）。
            raw = await self._call(prompt, system=ADVICE_SYSTEM)
            elapsed = time.perf_counter() - start
            log.info("[advise] raw_response=%s", (raw or "")[:2000])
            parsed = _extract_json(raw)
            if parsed is None:
                res = {"_error": "无法解析模型输出", **_mock_advice(kind, context, lang)}
                return _wrap(res, raw, elapsed, "无法解析模型输出")
            parsed["_source"] = "ai"
            return _wrap(parsed, raw, elapsed, None)
        except Exception as e:
            log.warning("[advise] call failed: %s", e)
            res = {"_error": str(e), **_mock_advice(kind, context, lang)}
            return _wrap(res, None, time.perf_counter() - start, str(e))

    # ------------------------------------------------------------------ 告警危害分析（详情用）
    async def analyze_harm(self, context: dict[str, Any], lang: str = "zh") -> dict[str, Any]:
        """针对单条告警，分析其可能造成的危害（分条罗列）+ 受影响范围 + 风险等级。
        与处置建议互补：建议讲“怎么修”，这里讲“有什么危害”。"""
        prompt = _build_harm_prompt(context, lang)
        log.info("[harm] lang=%s enabled=%s desc=%s", lang, self.enabled,
                 str(context.get("description"))[:120])
        if not self.enabled:
            return _mock_harm(context, lang)
        try:
            raw = await self._call(prompt, system=ADVICE_SYSTEM)
            parsed = _extract_json(raw)
            if parsed is None:
                return {"_error": "无法解析模型输出", **_mock_harm(context, lang)}
            parsed["_source"] = "ai"
            return parsed
        except Exception as e:
            log.warning("[harm] call failed: %s", e)
            return {"_error": str(e), **_mock_harm(context, lang)}

    # ------------------------------------------------------------------ 结论翻译（多语言切换用）
    async def translate(self, obj: dict[str, Any], lang: str) -> dict[str, Any]:
        """把一段结构化结论(JSON)的字符串值翻译到目标语言，键与结构保持不变。

        无 AI 时无法翻译，原样返回（前端会回退到原语言显示）。
        """
        if not self.enabled or not isinstance(obj, dict):
            return obj
        target = {"en": "English", "zh": "Simplified Chinese"}.get(lang, lang)
        prompt = (
            f"Translate ALL string values in the following JSON into {target}. "
            "Keep every key, the JSON structure, arrays and numbers exactly unchanged. "
            "Do not add or remove fields. Return ONLY the JSON object.\n\n"
            + json.dumps(obj, ensure_ascii=False)
        )
        try:
            raw = await self._call(prompt)
            parsed = _extract_json(raw)
            if not isinstance(parsed, dict):
                return obj
            parsed["_source"] = obj.get("_source", "ai")
            return parsed
        except Exception:
            return obj

    # ------------------------------------------------------------------ 内部
    def _build_prompt(self, task: dict, summary: dict, raw_events: list[dict] | None = None) -> str:
        parts = [
            task["instruction"],
            # 预设分析统一生成中文底稿；其它语言由 overview 接口按需翻译并缓存。
            "所有输出必须是简体中文。",
            "",
            "【数据摘要】",
            json.dumps(summary, ensure_ascii=False),
        ]
        if raw_events:
            parts += [
                "",
                f"【原始日志全量明细 共 {len(raw_events)} 条】",
                json.dumps(raw_events, ensure_ascii=False),
            ]
        parts += [
            "",
            "【只返回如下结构的 JSON】",
            json.dumps(task["schema"], ensure_ascii=False),
        ]
        return "\n".join(parts)

    async def _call(self, message: str, system: str | None = None) -> str:
        """调用 AI 后端 —— 按 AI_API_STYLE 选择实现。

        system：系统消息，默认用预设分析人设；处置建议等场景可传入自己的人设，
        避免全局人设里的语言/任务设定干扰（如把输出语言固定成中文）。

        多数情况【只改 .env、不用改代码】：
          - openai（默认）：LM Studio / vLLM / llama.cpp / Ollama(/v1) 等 OpenAI 兼容服务
          - ollama        ：Ollama 原生 /api/chat
          - custom_sse    ：现有 /chat + SSE 流式后端（与 AIWebProvider 同源）
        若是更特殊的私有接口，只需在本类里加一个 _call_xxx 并在此分发。
        """
        system = system or SYSTEM_PERSONA
        style = (settings.ai_api_style or "openai").lower()
        if style == "ollama":
            return await self._call_ollama(message, system)
        if style in ("custom_sse", "custom", "sse"):
            return await self._call_custom_sse(message, system)
        return await self._call_openai(message, system)

    async def _call_openai(self, message: str, system: str = SYSTEM_PERSONA) -> str:
        url = self.base_url + (settings.ai_chat_path or "/v1/chat/completions")
        headers = {"Authorization": f"Bearer {settings.ai_api_key}"} if settings.ai_api_key else {}
        payload = {
            "model": settings.ai_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": message},
            ],
            "temperature": settings.ai_temperature,
            "max_tokens": settings.ai_max_new_tokens,
            "stream": False,
        }
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=settings.ai_timeout_seconds) as c:
            r = await c.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
            usage = data.get("usage") or {}
            self._last_meta = {
                "input_tokens": usage.get("prompt_tokens"),
                "output_tokens": usage.get("completion_tokens"),
                "gen_seconds": None,
            }
            return data["choices"][0]["message"]["content"]

    async def _call_ollama(self, message: str, system: str = SYSTEM_PERSONA) -> str:
        url = self.base_url + (settings.ai_chat_path or "/api/chat")
        payload = {
            "model": settings.ai_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": message},
            ],
            "format": "json",
            "stream": False,
            # keep_alive：模型常驻，避免每次重新加载（这是单次延迟最大的来源之一）
            "keep_alive": settings.ai_keep_alive,
            "options": {
                "temperature": settings.ai_temperature,
                "num_predict": settings.ai_max_new_tokens,  # 限制输出长度，避免无谓的长生成
                "num_ctx": settings.ai_num_ctx,             # 显式上下文窗口，防止 prompt 被默认 2048 静默截断
            },
        }
        async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as c:
            r = await c.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            eval_dur = data.get("eval_duration")  # 纳秒
            self._last_meta = {
                "input_tokens": data.get("prompt_eval_count"),
                "output_tokens": data.get("eval_count"),
                "gen_seconds": (eval_dur / 1e9) if eval_dur else None,
            }
            return data.get("message", {}).get("content", "")

    async def _call_custom_sse(self, message: str, system: str = SYSTEM_PERSONA) -> str:
        url = self.base_url + (settings.ai_chat_path or "/chat")
        payload = {
            "message": message,
            "persona": system,
            "max_new_tokens": settings.ai_max_new_tokens,
            "temperature": settings.ai_temperature,
            "top_p": 0.9,
        }
        text_parts: list[str] = []
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=settings.ai_timeout_seconds) as c:
            async with c.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    try:
                        obj = json.loads(data)
                        if obj.get("text"):
                            text_parts.append(obj["text"])
                    except json.JSONDecodeError:
                        continue
        return "".join(text_parts)


def _extract_json(text: str) -> dict | None:
    """从模型输出中尽量稳健地抠出第一个 JSON 对象。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


# ---------------------------------------------------------------------- Mock
def _mock_result(task_key: str, summary: dict) -> dict[str, Any]:
    """无 AI 时的规则化模拟结论（基于真实摘要数字，便于演示全链路）。"""
    alerts = summary.get("alerts", {})
    sev = alerts.get("by_severity", {})
    eps = summary.get("endpoints", {})
    high = int(sev.get("high", 0)) + int(sev.get("critical", 0))
    total = int(alerts.get("total", 0))

    if task_key == "overview":
        if high > 0:
            level, score = "警告", min(85, 50 + high)
        elif total > 200:
            level, score = "关注", 40
        else:
            level, score = "安全", 18
        return {
            "_source": "mock",
            "risk_level": level,
            "risk_score": score,
            "headline": f"{eps.get('active', 0)}台在线 · {high}条高危待处理",
            "summary": (
                f"过去 {summary.get('window','24h')} 内共 {total} 条告警，其中高危 {high} 条。"
                f"在线设备 {eps.get('active',0)}/{eps.get('total',0)} 台，整体处于「{level}」状态。"
            ),
            "top_actions": _mock_actions(summary),
        }
    if task_key == "alert_triage":
        groups = alerts.get("by_group", {})
        clusters = []
        for cat, cnt in list(groups.items())[:4]:
            clusters.append({"category": cat, "count": cnt, "meaning": _group_meaning(cat),
                             "severity": "高" if cat in ("rootcheck",) else "中"})
        return {"_source": "mock", "clusters": clusters}
    if task_key == "compliance":
        comp = summary.get("compliance", {})
        worst, worst_score = None, 101
        for name, c in comp.items():
            s = c.get("score") or 100
            if s < worst_score:
                worst, worst_score = name, s
        return {
            "_source": "mock",
            "worst_endpoint": worst or "—",
            "worst_score": worst_score if worst else 0,
            "recommendations": ["关闭未加密远程访问", "开启磁盘加密(BitLocker/FileVault)", "及时安装系统补丁"],
        }
    return {"_source": "mock"}


def _mock_actions(summary: dict) -> list[str]:
    actions = []
    comp = summary.get("compliance", {})
    for name, c in comp.items():
        if (c.get("score") or 100) < 50:
            actions.append(f"加固 {name}（合规仅 {c.get('score')} 分）")
    if not actions:
        actions.append("保持当前防护，定期复查")
    return actions[:3]


# ---------------------------------------------------------------------- 处置建议
ADVICE_SCHEMA = {
    "summary": "一句话风险概述",
    "steps": ["可操作的处置步骤，3-5 条，每条不超过 40 字"],
    "impact": "影响范围/危害的简短说明",
    "priority": "处置优先级：immediate / soon / scheduled 之一",
}

# 各语言的 schema 字段说明：示例若用中文会诱导模型输出中文，故按语言切换。
ADVICE_SCHEMA_BY_LANG = {
    "zh": ADVICE_SCHEMA,
    "en": {
        "summary": "one-sentence risk summary",
        "steps": ["actionable remediation steps, 3-5 items, each under 40 words"],
        "impact": "brief description of the impact / severity",
        "priority": "one of: immediate / soon / scheduled",
    },
}

# 告警危害分析 schema（详情弹窗用）：危害分条 + 受影响范围 + 风险等级
HARM_SCHEMA_BY_LANG = {
    "zh": {
        "summary": "一句话说明这条告警的核心风险",
        "harms": ["可能造成的具体危害，3-5 条，每条不超过 40 字"],
        "affected": ["受影响的资产/文件/账户/服务（结合原始日志，可为空）"],
        "risk_level": "风险等级：严重 / 高 / 中 / 低 之一",
    },
    "en": {
        "summary": "one-sentence core risk of this alert",
        "harms": ["specific potential harms, 3-5 items, each under 40 words"],
        "affected": ["impacted assets/files/accounts/services (from the raw log, may be empty)"],
        "risk_level": "one of: Critical / High / Medium / Low",
    },
}


# 处置建议专用系统人设：语言中立，严格遵循用户提示词中指定的输出语言。
ADVICE_SYSTEM = (
    "You are an enterprise endpoint security expert. Follow the user's instruction "
    "exactly, including the requested OUTPUT LANGUAGE. Return only one JSON object, "
    "with no extra text."
)

# 输出语言指令：随所选语言动态切换。后续适配更多语言只需在此追加一项。
ADVICE_LANG_DIRECTIVE = {
    "zh": "所有输出必须是简体中文。",
    "en": "All output must be in English.",
}


def _build_advice_prompt(kind: str, context: dict[str, Any], lang: str) -> str:
    persona = (
        "You are an enterprise endpoint security expert. Based on the single "
        "vulnerability or alert below, give concise, actionable remediation advice "
        "for an IT administrator."
        if lang == "en"
        else
        "你是一名企业终端安全专家。请基于下面这一条漏洞或告警，给出简洁、可操作的"
        "处置建议，面向 IT 管理员。"
    )
    # 追加与所选语言对应的输出语言要求（未知语言回退英文）。
    persona += ADVICE_LANG_DIRECTIVE.get(lang, ADVICE_LANG_DIRECTIVE["en"])
    kind_label = {
        "vuln": "vulnerability" if lang == "en" else "漏洞",
        "alert": "security alert" if lang == "en" else "安全告警",
    }.get(kind, kind)
    parts = [
        persona,
        "",
        (f"Type: {kind_label}" if lang == "en" else f"类型：{kind_label}"),
        (f"Details: {json.dumps(context, ensure_ascii=False)}"
         if lang == "en" else f"明细：{json.dumps(context, ensure_ascii=False)}"),
        "",
        ("Return ONLY a JSON object with this structure:" if lang == "en"
         else "只返回如下结构的 JSON 对象，不要任何额外文字："),
        json.dumps(ADVICE_SCHEMA_BY_LANG.get(lang, ADVICE_SCHEMA_BY_LANG["en"]), ensure_ascii=False),
    ]
    return "\n".join(parts)


def _mock_advice(kind: str, context: dict[str, Any], lang: str) -> dict[str, Any]:
    """无 AI 时的规则化处置建议（中英双语），保证按钮可用、可演示。"""
    sev = str(context.get("severity") or "").lower()
    level = int(context.get("level") or 0)
    high = sev in ("critical", "high") or level >= 12
    priority = "immediate" if high else ("soon" if (sev == "medium" or level >= 7) else "scheduled")

    if kind == "vuln":
        cve = context.get("cve") or "该漏洞"
        pkg = context.get("package") or "受影响组件"
        if lang == "en":
            return {
                "_source": "mock",
                "summary": f"{pkg} is affected by {cve}; upgrade to a fixed version as soon as possible.",
                "steps": [
                    f"Confirm the installed version of {pkg} and the affected range",
                    f"Apply the official patch / upgrade {pkg} to the fixed version",
                    "If no patch is available, restrict network exposure as a mitigation",
                    "Re-scan to verify the vulnerability is cleared",
                ],
                "impact": f"Attackers may exploit {cve} to compromise the device.",
                "priority": priority,
            }
        return {
            "_source": "mock",
            "summary": f"{pkg} 存在 {cve}，建议尽快升级到已修复版本。",
            "steps": [
                f"确认 {pkg} 的当前版本与受影响范围",
                f"安装官方补丁 / 将 {pkg} 升级到修复版本",
                "若暂无补丁，先限制该组件的网络暴露面作为缓解",
                "处理后重新扫描，确认漏洞已消除",
            ],
            "impact": f"攻击者可能利用 {cve} 危害该设备。",
            "priority": priority,
        }

    # alert
    desc = context.get("description") or "该告警"
    if lang == "en":
        return {
            "_source": "mock",
            "summary": f"Investigate the alert: {desc}.",
            "steps": [
                "Confirm whether the action on the affected device was authorized",
                "Check related accounts / processes / files for anomalies",
                "Reset credentials or isolate the device if malicious",
                "Keep monitoring whether the alert recurs",
            ],
            "impact": "May indicate intrusion, brute force, or unauthorized change.",
            "priority": priority,
        }
    return {
        "_source": "mock",
        "summary": f"建议核查该告警：{desc}。",
        "steps": [
            "确认相关设备上的操作是否为授权行为",
            "排查关联的账户 / 进程 / 文件是否异常",
            "如确认为恶意，重置凭据或隔离该设备",
            "持续观察该告警是否反复出现",
        ],
        "impact": "可能涉及入侵、爆破或未授权变更。",
        "priority": priority,
    }


def _build_harm_prompt(context: dict[str, Any], lang: str) -> str:
    persona = (
        "You are an enterprise endpoint security expert. Based on the security alert "
        "and its raw log below, analyse the potential HARM it may cause in detail "
        "(list them), and which assets/files/accounts are affected."
        if lang == "en"
        else
        "你是一名企业终端安全专家。请基于下面这条安全告警及其原始日志，"
        "详细分析它可能造成的危害（分条罗列），以及受影响的资产/文件/账户。"
    )
    persona += ADVICE_LANG_DIRECTIVE.get(lang, ADVICE_LANG_DIRECTIVE["en"])
    parts = [
        persona,
        "",
        (f"Alert & raw log: {json.dumps(context, ensure_ascii=False)}"
         if lang == "en" else f"告警与原始日志：{json.dumps(context, ensure_ascii=False)}"),
        "",
        ("Return ONLY a JSON object with this structure:" if lang == "en"
         else "只返回如下结构的 JSON 对象，不要任何额外文字："),
        json.dumps(HARM_SCHEMA_BY_LANG.get(lang, HARM_SCHEMA_BY_LANG["en"]), ensure_ascii=False),
    ]
    return "\n".join(parts)


def _mock_harm(context: dict[str, Any], lang: str) -> dict[str, Any]:
    """无 AI 时的规则化危害分析，保证详情弹窗可用、可演示。"""
    level = int(context.get("level") or 0)
    risk_zh = "严重" if level >= 15 else "高" if level >= 12 else "中" if level >= 7 else "低"
    risk_en = "Critical" if level >= 15 else "High" if level >= 12 else "Medium" if level >= 7 else "Low"
    files = context.get("affected_files") or []
    if lang == "en":
        return {
            "_source": "mock",
            "summary": "This alert indicates a security configuration or activity risk that needs review.",
            "harms": [
                "May weaken the device's security posture and increase attack surface",
                "Could lead to unauthorized access or data exposure if exploited",
                "May indicate non-compliance with the security baseline",
            ],
            "affected": files or ["the affected device's security configuration"],
            "risk_level": risk_en,
        }
    return {
        "_source": "mock",
        "summary": "该告警反映存在需关注的安全配置或行为风险。",
        "harms": [
            "可能削弱设备安全基线、扩大被攻击面",
            "若被利用，可能导致未授权访问或数据泄露",
            "可能表明系统未达到安全合规要求",
        ],
        "affected": files or ["该设备的安全配置"],
        "risk_level": risk_zh,
    }


def _group_meaning(group: str) -> str:
    return {
        "sca": "安全基线检查未达标项",
        "syscheck": "关键文件被改动",
        "rootcheck": "主机异常/可疑行为",
        "windows": "Windows 系统事件",
        "ossec": "Agent 自身/系统级事件",
        "authentication": "登录认证相关",
        "sudo": "提权操作",
    }.get(group, "安全事件")


ai_client = AiClient()
