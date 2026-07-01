"""GuizangAI 客户端：集中管理 Ollama/OpenAI 兼容调用。"""

from __future__ import annotations

import json
import logging
import re
import time
import hashlib
import datetime as dt
from typing import Any
from collections.abc import AsyncIterator

import httpx

from ..config import settings
from ..db import GuizangAICache, SessionLocal
from .advice import build_advice_prompt, clean_advice_steps, steps_are_too_generic
from .mock import mock_advice, mock_result
from .prompts import PRESET_TASKS, SYSTEM_PERSONA
from .text_cleaning import clean_text, extract_json, steps_conflict_with_target_os

log = logging.getLogger("guizangai")


class GuizangAIClient:
    def __init__(self) -> None:
        self.base_url = settings.guizangai_base_url.rstrip("/")
        self.enabled = bool(self.base_url)

    async def analyze(
        self,
        task_key: str,
        summary: dict[str, Any],
        raw_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        task = PRESET_TASKS[task_key]
        if not self.enabled:
            return mock_result(task_key, summary)

        prompt = _build_sft_prompt(task_key, summary, raw_events) or self._build_prompt(task, summary, raw_events)
        try:
            raw, perf = await self._call(prompt)
            if perf:
                perf["task"] = task_key
                perf["raw_events_count"] = len(raw_events or [])
                if perf.get("tokens_per_second") is not None:
                    log.info(
                        "GuizangAI 推理性能 task=%s model=%s speed=%.2f tokens/s output_tokens=%s total=%.2fs",
                        task_key,
                        perf.get("model") or settings.guizangai_model,
                        perf["tokens_per_second"],
                        perf.get("eval_count", 0),
                        perf.get("total_duration_seconds", 0),
                    )
            parsed = extract_json(raw)
            if parsed is None:
                repaired = _repair_overview_from_raw(task_key, raw, summary)
                if repaired is not None:
                    parsed = repaired
                else:
                    if perf:
                        perf["last_error"] = "无法解析模型输出"
                    return {"_error": "无法解析模型输出", "_raw": raw[:500], "_perf": perf, **mock_result(task_key, summary)}
            parsed = _normalize_preset_result(task_key, parsed, summary, raw_events)
            if parsed is None:
                if perf:
                    perf["last_error"] = "无法解析模型输出"
                return {"_error": "无法解析模型输出", "_raw": raw[:500], "_perf": perf, **mock_result(task_key, summary)}
            parsed["_source"] = "guizangai"
            if perf:
                parsed["_perf"] = perf
            return parsed
        except Exception as e:
            return {
                "_error": str(e),
                "_perf": {"task": task_key, "raw_events_count": len(raw_events or []), "last_error": str(e)},
                **mock_result(task_key, summary),
            }

    async def advise(self, kind: str, context: dict[str, Any], lang: str = "zh", debug: bool = False) -> dict[str, Any]:
        rule_advice = mock_advice(kind, context, lang)
        prompt = _build_sft_advice_prompt(kind, context) or build_advice_prompt(kind, context, lang, "full")
        cache_key = _advice_cache_key(kind, context, lang)
        cached = None if debug else _read_guizangai_cache(cache_key, settings.guizangai_advice_cache_ttl_seconds)
        if cached:
            return {**cached, "_cached": True}

        def with_debug(result: dict[str, Any], raw: str | None, perf: dict[str, Any] | None, err: str | None = None) -> dict[str, Any]:
            if not debug:
                return result
            result["_debug"] = {
                "kind": kind,
                "lang": lang,
                "enabled": self.enabled,
                "api_style": (settings.guizangai_api_style or "openai") if self.enabled else "mock",
                "model": settings.guizangai_model if self.enabled else None,
                "context": context,
                "prompt": prompt,
                "raw": raw,
                "duration_ms": round(float((perf or {}).get("total_duration_seconds") or 0) * 1000),
                "input_tokens": (perf or {}).get("prompt_eval_count"),
                "output_tokens": (perf or {}).get("eval_count"),
                "error": err,
            }
            return result

        if not self.enabled:
            result = with_debug(rule_advice, None, None, "未配置 GuizangAI 端点（规则建议）")
            if not debug:
                _write_guizangai_cache(cache_key, f"advice_{kind}", result)
            return result
        try:
            raw, perf = await self._call(prompt, max_tokens=520)
            parsed = extract_json(raw)
            if parsed is None:
                result = with_debug({"_error": "无法解析模型输出", "_perf": perf, **rule_advice}, raw, perf, "无法解析模型输出")
                if not debug:
                    _write_guizangai_cache(cache_key, f"advice_{kind}", result)
                return result
            steps = clean_advice_steps(parsed.get("steps"))
            runbook = _clean_runbook(parsed.get("runbook"))
            if steps_conflict_with_target_os(steps, context):
                result = with_debug({
                    **rule_advice,
                    "_error": "模型建议包含与目标系统不匹配的命令，已回退到规则建议",
                    "_perf": perf,
                }, raw, perf, "模型建议包含与目标系统不匹配的命令")
                if not debug:
                    _write_guizangai_cache(cache_key, f"advice_{kind}", result)
                return result
            if steps_are_too_generic(steps):
                steps = rule_advice.get("steps")
            if not _runbook_is_usable(runbook, context):
                runbook = rule_advice.get("runbook") or _runbook_from_steps(rule_advice.get("steps") or [], context, lang)
            result = with_debug({
                **rule_advice,
                "summary": parsed.get("summary") or rule_advice.get("summary"),
                "steps": steps or rule_advice.get("steps"),
                "runbook": runbook,
                "impact": parsed.get("impact") or rule_advice.get("impact"),
                "priority": _norm_priority(parsed.get("priority") or rule_advice.get("priority")),
                "_source": "guizangai",
                "_perf": perf,
            }, raw, perf)
            if not debug:
                _write_guizangai_cache(cache_key, f"advice_{kind}", result)
            return result
        except Exception as e:
            result = with_debug({"_error": str(e), **rule_advice}, None, None, str(e))
            if not debug:
                _write_guizangai_cache(cache_key, f"advice_{kind}", result)
            return result

    async def advise_stream(self, kind: str, context: dict[str, Any], lang: str = "zh", debug: bool = False) -> AsyncIterator[dict[str, Any]]:
        """流式生成建议：先逐段吐出文本，结束后再吐出最终结构化结果。"""
        rule_advice = mock_advice(kind, context, lang)
        prompt = _build_sft_advice_prompt(kind, context) or build_advice_prompt(kind, context, lang, "full")
        if not self.enabled:
            preview = _advice_preview_text(rule_advice, lang)
            for chunk in _chunk_text(preview):
                yield {"type": "delta", "text": chunk}
            yield {"type": "final", "result": rule_advice}
            return

        raw_parts: list[str] = []
        emitted: set[str] = set()
        start = time.perf_counter()
        try:
            async for chunk in self._stream_call(prompt, max_tokens=700):
                raw_parts.append(chunk)
                raw_now = "".join(raw_parts)
                for text in _display_segments_from_partial_json(raw_now):
                    if text not in emitted:
                        emitted.add(text)
                        yield {"type": "delta", "text": text}
            raw = "".join(raw_parts)
            perf = {"provider": settings.guizangai_api_style or "openai", "model": settings.guizangai_model, "total_duration_seconds": round(time.perf_counter() - start, 3)}
            result = _finalize_advice_result(kind, context, lang, rule_advice, raw, perf, debug, prompt)
            if not emitted:
                yield {"type": "delta", "text": _advice_preview_text(result, lang)}
            yield {"type": "final", "result": result}
        except Exception as e:
            err_result = {"_error": str(e), **rule_advice}
            if debug:
                err_result["_debug"] = {"kind": kind, "lang": lang, "enabled": self.enabled, "context": context, "prompt": prompt, "raw": "".join(raw_parts), "error": str(e)}
            yield {"type": "final", "result": err_result}

    async def polish_alert_description(self, context: dict[str, Any], lang: str = "zh") -> dict[str, Any]:
        fallback = _fallback_alert_description(context, lang)
        cache_key = _alert_description_cache_key(context, lang)
        cached = _read_guizangai_cache(cache_key)
        if cached:
            cached = dict(cached)
            cached["description"] = _translate_alert_description(cached.get("description") or fallback, context, lang)
            return {**cached, "_cached": True}
        if not self.enabled:
            result = {"description": fallback, "_source": "rule"}
            _write_guizangai_cache(cache_key, "alert_description", result)
            return result
        prompt = _build_alert_description_prompt(context, lang)
        try:
            raw, perf = await self._call(prompt, max_tokens=180)
            parsed = extract_json(raw)
            description = clean_text((parsed or {}).get("description") or "")
            if not _valid_polished_description(description):
                result = {"description": fallback, "_source": "rule", "_error": "模型描述不可用，已回退规则描述", "_perf": perf}
                _write_guizangai_cache(cache_key, "alert_description", result)
                return result
            description = _translate_alert_description(description, context, lang)
            if _description_too_similar(description, context):
                description = _expanded_alert_description(context, lang)
            result = {"description": description, "_source": "guizangai", "_perf": perf}
            _write_guizangai_cache(cache_key, "alert_description", result)
            return result
        except Exception as e:
            result = {"description": fallback, "_source": "rule", "_error": str(e)}
            _write_guizangai_cache(cache_key, "alert_description", result)
            return result

    def _build_prompt(self, task: dict, summary: dict, raw_events: list[dict] | None = None) -> str:
        parts = [
            "【输出原则】",
            "1. 像安全主管给老板汇报：结论先行，必须有具体依据。",
            "2. 必须引用输入里的真实字段：设备名、规则名、告警数量、合规分、未通过项、路径或来源 IP。",
            "3. 禁止空话：不要写“加强安全意识”“定期检查”“持续关注”“建议排查”等无对象无动作的建议。",
            "4. 不确定时说明“当前摘要未提供该细项”，不要编造不存在的检查项。",
            "",
            "【任务要求】",
            task["instruction"],
            "",
            "【数据摘要】",
            json.dumps(summary, ensure_ascii=False),
        ]
        if raw_events:
            parts += [
                "",
                f"【原始日志证据（已裁剪/去重/按风险排序，共 {len(raw_events)} 条）】",
                json.dumps(raw_events, ensure_ascii=False),
            ]
        if task.get("few_shot"):
            parts += [
                "",
                "【输出示例（学习风格，不要照抄不存在的数据）】",
                json.dumps(task["few_shot"], ensure_ascii=False),
            ]
        parts += [
            "",
            "【只返回如下结构的 JSON】",
            json.dumps(task["schema"], ensure_ascii=False),
            "",
            "必须返回单行紧凑 JSON：不要换行、不要缩进、不要 Markdown、不要解释文字。",
        ]
        return "\n".join(parts)

    async def _call(self, message: str, max_tokens: int | None = None) -> tuple[str, dict[str, Any]]:
        style = (settings.guizangai_api_style or "openai").lower()
        if style == "ollama":
            return await self._call_ollama(message, max_tokens)
        if style in ("custom_sse", "custom", "sse"):
            return await self._call_custom_sse(message, max_tokens)
        return await self._call_openai(message, max_tokens)

    async def _stream_call(self, message: str, max_tokens: int | None = None) -> AsyncIterator[str]:
        style = (settings.guizangai_api_style or "openai").lower()
        if style == "ollama":
            async for chunk in self._stream_ollama(message, max_tokens):
                yield chunk
            return
        if style in ("custom_sse", "custom", "sse"):
            async for chunk in self._stream_custom_sse(message, max_tokens):
                yield chunk
            return
        async for chunk in self._stream_openai(message, max_tokens):
            yield chunk

    async def _call_openai(self, message: str, max_tokens: int | None = None) -> tuple[str, dict[str, Any]]:
        url = self.base_url + (settings.guizangai_chat_path or "/v1/chat/completions")
        headers = {"Authorization": f"Bearer {settings.guizangai_api_key}"} if settings.guizangai_api_key else {}
        payload = {
            "model": settings.guizangai_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PERSONA},
                {"role": "user", "content": message},
            ],
            "temperature": settings.guizangai_temperature,
            "max_tokens": max_tokens or settings.guizangai_max_new_tokens,
            "stream": False,
        }
        start = time.perf_counter()
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=settings.guizangai_timeout_seconds) as c:
            r = await c.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
        elapsed = time.perf_counter() - start
        usage = data.get("usage") or {}
        completion_tokens = usage.get("completion_tokens")
        perf = {
            "provider": "openai",
            "model": settings.guizangai_model,
            "eval_count": completion_tokens,
            "prompt_eval_count": usage.get("prompt_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "total_duration_seconds": round(elapsed, 3),
            "tokens_per_second": round(completion_tokens / elapsed, 2) if completion_tokens and elapsed > 0 else None,
        }
        return data["choices"][0]["message"]["content"], perf

    async def _stream_openai(self, message: str, max_tokens: int | None = None) -> AsyncIterator[str]:
        url = self.base_url + (settings.guizangai_chat_path or "/v1/chat/completions")
        headers = {"Authorization": f"Bearer {settings.guizangai_api_key}"} if settings.guizangai_api_key else {}
        payload = {
            "model": settings.guizangai_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PERSONA},
                {"role": "user", "content": message},
            ],
            "temperature": settings.guizangai_temperature,
            "max_tokens": max_tokens or settings.guizangai_max_new_tokens,
            "stream": True,
        }
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=settings.guizangai_timeout_seconds) as c:
            async with c.stream("POST", url, json=payload, headers=headers) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == "[DONE]":
                        break
                    try:
                        obj = json.loads(data)
                        chunk = ((obj.get("choices") or [{}])[0].get("delta") or {}).get("content")
                        if chunk:
                            yield chunk
                    except Exception:
                        continue

    async def _call_ollama(self, message: str, max_tokens: int | None = None) -> tuple[str, dict[str, Any]]:
        url = self.base_url + (settings.guizangai_chat_path or "/api/chat")
        payload = {
            "model": settings.guizangai_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PERSONA},
                {"role": "user", "content": message},
            ],
            "format": "json",
            "stream": False,
            "keep_alive": settings.guizangai_keep_alive,
            "options": {
                "temperature": settings.guizangai_temperature,
                "num_predict": max_tokens or settings.guizangai_max_new_tokens,
                "num_ctx": settings.guizangai_num_ctx,
                "num_gpu": settings.guizangai_num_gpu,
            },
        }
        async with httpx.AsyncClient(timeout=settings.guizangai_timeout_seconds) as c:
            r = await c.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
        return data.get("message", {}).get("content", ""), ollama_perf(data, settings.guizangai_model)

    async def _stream_ollama(self, message: str, max_tokens: int | None = None) -> AsyncIterator[str]:
        url = self.base_url + (settings.guizangai_chat_path or "/api/chat")
        payload = {
            "model": settings.guizangai_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PERSONA},
                {"role": "user", "content": message},
            ],
            "format": "json",
            "stream": True,
            "keep_alive": settings.guizangai_keep_alive,
            "options": {
                "temperature": settings.guizangai_temperature,
                "num_predict": max_tokens or settings.guizangai_max_new_tokens,
                "num_ctx": settings.guizangai_num_ctx,
                "num_gpu": settings.guizangai_num_gpu,
            },
        }
        async with httpx.AsyncClient(timeout=settings.guizangai_timeout_seconds) as c:
            async with c.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        chunk = (obj.get("message") or {}).get("content")
                        if chunk:
                            yield chunk
                        if obj.get("done"):
                            break
                    except Exception:
                        continue

    async def _call_custom_sse(self, message: str, max_tokens: int | None = None) -> tuple[str, dict[str, Any]]:
        url = self.base_url + (settings.guizangai_chat_path or "/chat")
        payload = {
            "message": message,
            "persona": SYSTEM_PERSONA,
            "max_new_tokens": max_tokens or settings.guizangai_max_new_tokens,
            "temperature": settings.guizangai_temperature,
            "top_p": 0.9,
        }
        text_parts: list[str] = []
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=settings.guizangai_timeout_seconds) as c:
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
        return "".join(text_parts), {"provider": "custom_sse", "model": settings.guizangai_model}

    async def _stream_custom_sse(self, message: str, max_tokens: int | None = None) -> AsyncIterator[str]:
        url = self.base_url + (settings.guizangai_chat_path or "/chat")
        payload = {
            "message": message,
            "persona": SYSTEM_PERSONA,
            "max_new_tokens": max_tokens or settings.guizangai_max_new_tokens,
            "temperature": settings.guizangai_temperature,
            "top_p": 0.9,
        }
        async with httpx.AsyncClient(verify=settings.verify_tls, timeout=settings.guizangai_timeout_seconds) as c:
            async with c.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    try:
                        obj = json.loads(data)
                        if obj.get("text"):
                            yield obj["text"]
                    except json.JSONDecodeError:
                        continue


def _seconds_from_ns(value: Any) -> float | None:
    try:
        ns = int(value or 0)
    except (TypeError, ValueError):
        return None
    return ns / 1_000_000_000 if ns > 0 else None


def ollama_perf(data: dict[str, Any], model: str) -> dict[str, Any]:
    eval_count = int(data.get("eval_count") or 0)
    prompt_eval_count = int(data.get("prompt_eval_count") or 0)
    eval_seconds = _seconds_from_ns(data.get("eval_duration"))
    total_seconds = _seconds_from_ns(data.get("total_duration"))
    load_seconds = _seconds_from_ns(data.get("load_duration"))
    prompt_eval_seconds = _seconds_from_ns(data.get("prompt_eval_duration"))
    speed_seconds = eval_seconds if eval_seconds and eval_seconds >= 0.01 else total_seconds
    return {
        "provider": "ollama",
        "model": data.get("model") or model,
        "num_ctx": settings.guizangai_num_ctx,
        "num_gpu": settings.guizangai_num_gpu,
        "keep_alive": settings.guizangai_keep_alive,
        "eval_count": eval_count,
        "prompt_eval_count": prompt_eval_count,
        "total_tokens": eval_count + prompt_eval_count,
        "eval_duration_seconds": round(eval_seconds, 3) if eval_seconds is not None else None,
        "prompt_eval_duration_seconds": round(prompt_eval_seconds, 3) if prompt_eval_seconds is not None else None,
        "load_duration_seconds": round(load_seconds, 3) if load_seconds is not None else None,
        "total_duration_seconds": round(total_seconds, 3) if total_seconds is not None else None,
        "tokens_per_second": round(eval_count / speed_seconds, 2) if eval_count and speed_seconds else None,
    }


guizang_ai = GuizangAIClient()


def _build_sft_prompt(task_key: str, summary: dict[str, Any], raw_events: list[dict] | None = None) -> str | None:
    if task_key != "overview":
        return None
    task = PRESET_TASKS[task_key]
    payload = {
        "task": "overview",
        "instruction": (
            "根据 Wazuh 安全摘要生成安全主管式中文态势结论。"
            "必须只输出一个 JSON 对象，第一个字符必须是 {，最后一个字符必须是 }。"
            "不要输出自然语言段落、Markdown、解释或前缀。"
            "summary 必须引用真实数量/设备/规则/合规分；top_actions 必须正好3条，且每条有处理对象和动作。"
            "禁止空话：不要写加强安全意识、定期检查、持续关注。"
        ),
        "style": "安全主管给老板汇报，结论先行，少空话，多依据。",
        "output_schema": task["schema"],
        "few_shot_output": task.get("few_shot", {}).get("output"),
        "input": {"summary": summary},
    }
    if raw_events:
        payload["input"]["raw_events"] = raw_events[:20]
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _normalize_preset_result(task_key: str, parsed: Any, summary: dict[str, Any], raw_events: list[dict] | None = None) -> dict[str, Any] | None:
    if not isinstance(parsed, dict):
        return None
    result = dict(parsed)
    if task_key == "overview":
        result.setdefault("risk_level", _risk_level_from_summary(summary))
        result.setdefault("risk_score", _risk_score_from_summary(summary))
        result["headline"] = clean_text(result.get("headline") or _overview_headline(summary))
        result["summary"] = clean_text(result.get("summary") or _overview_summary(summary))
        result["top_actions"] = _ensure_actions(_specific_actions(result.get("top_actions"), summary), _overview_actions(summary, raw_events), 3)
    elif task_key == "compliance":
        worst, score = _worst_compliance(summary)
        result["worst_endpoint"] = worst or result.get("worst_endpoint") or "—"
        result["worst_score"] = score if worst else (result.get("worst_score") or 0)
        result["recommendations"] = _compliance_actions(summary)
    elif task_key == "alert_triage":
        clusters = result.get("clusters")
        if isinstance(clusters, list):
            for cluster in clusters:
                if isinstance(cluster, dict) and not cluster.get("evidence"):
                    cluster["evidence"] = _cluster_evidence(raw_events)
    return result


def _repair_overview_from_raw(task_key: str, raw: str, summary: dict[str, Any]) -> dict[str, Any] | None:
    if task_key != "overview" or not clean_text(raw):
        return None
    text = clean_text(raw).replace("\n", " ")
    if not any(word in text for word in ("安全", "风险", "告警", "合规", "端口", "设备")):
        return None
    level = "严重" if "严重" in text else ("警告" if "警告" in text else ("关注" if "关注" in text else _risk_level_from_summary(summary)))
    headline = re.split(r"[。.!！?？]", text, maxsplit=1)[0].strip(" ：:，,")
    return {
        "risk_level": level,
        "risk_score": _risk_score_from_summary(summary),
        "headline": headline[:28] or _overview_headline(summary),
        "summary": text[:90] or _overview_summary(summary),
        "top_actions": _overview_actions(summary, None),
        "_repaired": True,
    }


def _ensure_actions(value: Any, fallback: list[str], count: int) -> list[str]:
    actions: list[str] = []
    if isinstance(value, list):
        actions = [clean_text(item) for item in value if clean_text(item)]
    for item in fallback:
        if len(actions) >= count:
            break
        if item not in actions:
            actions.append(item)
    return actions[:count]


def _specific_actions(value: Any, summary: dict[str, Any]) -> list[str]:
    if not isinstance(value, list):
        return []
    evidence_tokens = _summary_evidence_tokens(summary)
    out: list[str] = []
    for item in value:
        text = clean_text(item)
        if not text or any(token in text for token in ("加强安全意识", "定期检查", "持续关注", "建议排查")):
            continue
        has_evidence = any(token and token in text for token in evidence_tokens)
        has_number = bool(re.search(r"\d", text))
        if has_evidence or has_number:
            out.append(text)
    return out


def _summary_evidence_tokens(summary: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    tokens.extend(str(name) for name in (summary.get("compliance") or {}).keys())
    alerts = summary.get("alerts") or {}
    tokens.extend(str(name) for name in (alerts.get("by_agent") or {}).keys())
    tokens.extend(_short_rule(rule) for rule in (alerts.get("top_rules") or {}).keys())
    return [token for token in tokens if token]


def _risk_score_from_summary(summary: dict[str, Any]) -> int:
    alerts = summary.get("alerts") or {}
    sev = alerts.get("by_severity") or {}
    high = int(sev.get("high") or 0) + int(sev.get("critical") or 0)
    security_total = int(alerts.get("security_total") or alerts.get("total") or 0)
    worst, worst_score = _worst_compliance(summary)
    disconnected = int((summary.get("endpoints") or {}).get("disconnected") or 0)
    score = 18
    if security_total:
        score = max(score, min(70, 35 + security_total // 5))
    if high:
        score = max(score, min(90, 55 + high * 2))
    if worst and worst_score < 50:
        score = max(score, 78)
    if disconnected:
        score = max(score, min(75, 45 + disconnected * 8))
    return int(min(score, 95))


def _risk_level_from_summary(summary: dict[str, Any]) -> str:
    score = _risk_score_from_summary(summary)
    if score >= 85:
        return "严重"
    if score >= 60:
        return "警告"
    if score >= 35:
        return "关注"
    return "安全"


def _overview_headline(summary: dict[str, Any]) -> str:
    alerts = summary.get("alerts") or {}
    top_rule = next(iter((alerts.get("top_rules") or {}).keys()), "")
    if top_rule:
        return f"{_short_rule(top_rule)}需要优先确认"
    return "终端安全态势需复核"


def _overview_summary(summary: dict[str, Any]) -> str:
    eps = summary.get("endpoints") or {}
    alerts = summary.get("alerts") or {}
    worst, score = _worst_compliance(summary)
    top_rule = next(iter((alerts.get("top_rules") or {}).keys()), "暂无 Top 规则")
    return (
        f"{eps.get('active', 0)}/{eps.get('total', 0)}台在线，"
        f"{alerts.get('security_total', alerts.get('total', 0))}条安全告警集中在“{_short_rule(top_rule)}”；"
        f"{worst or '暂无设备'}合规{score if worst else 0}分。"
    )


def _overview_actions(summary: dict[str, Any], raw_events: list[dict] | None) -> list[str]:
    alerts = summary.get("alerts") or {}
    eps = summary.get("endpoints") or {}
    worst, score = _worst_compliance(summary)
    top_rule = next(iter((alerts.get("top_rules") or {}).keys()), "")
    top_agent = next(iter((alerts.get("by_agent") or {}).keys()), "")
    actions: list[str] = []
    if worst:
        comp = (summary.get("compliance") or {}).get(worst) or {}
        actions.append(f"处理 {worst} 的{comp.get('fail', 0)}项未通过基线（合规{score}分）")
    if top_rule:
        target = top_agent or "高频告警设备"
        actions.append(f"核查 {target} 的“{_short_rule(top_rule)}”触发原因")
    if int(eps.get("disconnected") or 0) > 0:
        actions.append(f"恢复{eps.get('disconnected')}台离线 Agent，消除监控盲区")
    if raw_events:
        first = raw_events[0]
        if first.get("agent") and first.get("rule"):
            actions.append(f"复核 {first.get('agent')} 的“{_short_rule(first.get('rule'))}”证据")
    actions.append("确认端口变化对应进程和业务授权")
    return actions


def _compliance_actions(summary: dict[str, Any]) -> list[str]:
    rows = sorted(
        ((name, data or {}) for name, data in (summary.get("compliance") or {}).items()),
        key=lambda item: int((item[1] or {}).get("score") or 100),
    )
    actions: list[str] = []
    for name, data in rows[:3]:
        score = int(data.get("score") or 0)
        fail = int(data.get("fail") or 0)
        policy = clean_text(data.get("policy") or "CIS 基线")
        actions.append(f"{name}：先处理{fail}项未通过项，依据 {policy}（{score}分）")
    while len(actions) < 3:
        actions.append("补齐缺失的 SCA 基线结果，确保每台终端有合规分")
    return actions


def _worst_compliance(summary: dict[str, Any]) -> tuple[str | None, int]:
    worst, score = None, 101
    for name, data in (summary.get("compliance") or {}).items():
        current = int((data or {}).get("score") or 100)
        if current < score:
            worst, score = str(name), current
    return worst, score


def _cluster_evidence(raw_events: list[dict] | None) -> str:
    if not raw_events:
        return "依据：告警摘要中的规则分组和 Top 规则"
    event = raw_events[0]
    bits = []
    if event.get("rule"):
        bits.append(f"规则：{_short_rule(event.get('rule'))}")
    if event.get("agent"):
        bits.append(f"设备：{event.get('agent')}")
    if event.get("occurrences"):
        bits.append(f"触发{event.get('occurrences')}次")
    return "；".join(bits) or "依据：原始告警证据"


def _short_rule(value: Any) -> str:
    text = clean_text(value)
    return text[:42] + ("…" if len(text) > 42 else "")


def _build_sft_advice_prompt(kind: str, context: dict[str, Any]) -> str | None:
    task_by_kind = {
        "alert": ("alert_advice", "根据单条 Wazuh 告警生成中文处置建议和 runbook，只返回 JSON。"),
        "vuln": ("vuln_advice", "根据单条漏洞生成中文修复建议和验证步骤，只返回 JSON。"),
    }
    if kind not in task_by_kind:
        return None
    task, instruction = task_by_kind[kind]
    return json.dumps({
        "task": task,
        "instruction": instruction,
        "input": {
            "kind": kind,
            "context": context,
        },
    }, ensure_ascii=False, sort_keys=True)


_ALERT_DESC_TRANSLATIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Multiple authentication failures", re.I), "多次认证失败（疑似爆破）"),
    (re.compile(r"Multiple Windows Logon Failures", re.I), "多次 Windows 登录失败"),
    (re.compile(r"Windows Logon Failure", re.I), "Windows 登录失败"),
    (re.compile(r"Windows Logon Success", re.I), "Windows 登录成功"),
    (re.compile(r"Host-based anomaly detection event", re.I), "主机异常检测事件"),
    (re.compile(r"Wazuh agent disconnected", re.I), "Wazuh Agent 连接断开"),
    (re.compile(r"Wazuh server started", re.I), "Wazuh 服务端已启动"),
    (re.compile(r"System time changed", re.I), "系统时间被修改"),
    (re.compile(r"New Windows software installed|software installed|application installed", re.I), "软件安装事件"),
    (re.compile(r"Package installed|New .*package.*installed", re.I), "软件包安装事件"),
    (re.compile(r"Package removed", re.I), "软件包卸载事件"),
)


def _translate_alert_description(value: Any, context: dict[str, Any], lang: str) -> str:
    text = clean_text(value or "")
    if not text or lang == "en":
        return text

    if re.search(r"Listened ports status|监听端口状态发生变化|监听端口变化", text, re.I):
        port = (
            _first_text(context.get("port"), context.get("dst_port"), context.get("src_port"))
            or _port_from_text(text)
            or _port_from_text(clean_text(context.get("raw_log") or ""))
        )
        protocol = clean_text(context.get("protocol") or "")
        if port and protocol and "/" not in port:
            port = f"{port}/{protocol}"
        zh = f"监听端口变化：{port} 被打开或关闭，请核查对应进程。" if port else "监听端口变化：有端口被打开或关闭，请核查对应进程。"
        translated = re.sub(
            r"Listened ports status \(netstat\) changed \(new port opened or closed\)\.?",
            zh,
            text,
            flags=re.I,
        )
        if port:
            translated = re.sub(r"[（(]端口[:：]\s*[^)）]+[)）]", "", translated).strip()
        return translated

    for pattern, translated in _ALERT_DESC_TRANSLATIONS:
        if pattern.search(text):
            return pattern.sub(translated, text).strip()
    return text


def _first_text(*values: Any) -> str:
    for value in values:
        text = clean_text(value or "")
        if text:
            return text
    return ""


def _port_from_text(text: str) -> str:
    patterns = (
        r"[（(]端口[:：]\s*([^)）]+)[)）]",
        r"\b(?:port|dstport|dst_port|dport)[:=]\s*([0-9]+(?:/[a-z0-9]+)?)",
        r"\b([0-9]{1,5}/(?:tcp|udp)[46]?)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return clean_text(match.group(1))
    return ""


def _fallback_alert_description(context: dict[str, Any], lang: str) -> str:
    desc = _translate_alert_description(context.get("display_description") or context.get("description") or "", context, lang)
    agent = clean_text(context.get("agent") or "")
    level = context.get("level")
    if not desc:
        return "该告警缺少描述，请查看原始日志确认事件详情。" if lang != "en" else "This alert has no description; review the raw log for details."
    if lang == "en":
        return f"{agent + ' triggered ' if agent else ''}{desc}."
    level_text = f"等级 {level}" if level not in (None, "") else "未定级"
    return f"{agent or '该终端'} 触发{level_text}告警：{desc}"


def _expanded_alert_description(context: dict[str, Any], lang: str) -> str:
    agent = clean_text(context.get("agent") or "该终端")
    level = context.get("level")
    desc = _translate_alert_description(context.get("display_description") or context.get("description") or "该告警", context, lang)
    port = context.get("port") or context.get("dst_port") or context.get("src_port")
    protocol = context.get("protocol")
    process = clean_text(context.get("process") or "")
    listen_ip = clean_text(context.get("listen_ip") or "")
    tracking = context.get("trojan_tracking") if isinstance(context.get("trojan_tracking"), dict) else {}
    facts: list[str] = []
    if port:
        facts.append(f"端口 {port}{('/' + str(protocol)) if protocol else ''}")
    if listen_ip:
        facts.append(f"监听地址 {listen_ip}")
    if process:
        facts.append(f"关联进程 {process}")
    if tracking:
        status = "已清除" if str(tracking.get("status") or "").lower() == "cleared" else "追踪中"
        tid = tracking.get("tracking_id")
        events = tracking.get("events_count")
        facts.append(f"追踪状态 {status}{f'，追踪编号 {tid}' if tid else ''}{f'，关联事件 {events} 条' if events else ''}")
    fact_text = "；".join(facts)
    level_text = f"等级 {level}" if level not in (None, "") else "未定级"
    desc = desc.rstrip("。.!！")
    if lang == "en":
        return f"{agent} triggered a level {level or 'unknown'} alert: {desc}. Additional context: {fact_text or 'no extra port/process details were available'}."
    return f"{agent} 触发{level_text}告警：{desc}。补充详情：{fact_text or '当前未提供端口、进程或追踪编号等额外字段'}。"


def _build_alert_description_prompt(context: dict[str, Any], lang: str) -> str:
    schema = {"description": "一段 1-2 句的告警描述"}
    prompt_context = dict(context)
    prompt_context["description_zh"] = _translate_alert_description(
        context.get("display_description") or context.get("description") or "",
        context,
        lang,
    )
    if lang == "en":
        instruction = (
            "Rewrite this security alert into a concise, user-facing English description. "
            "Keep concrete facts: device, severity, rule, port, process, tracking status, and cleanup status if present. "
            "Do not repeat the original wording verbatim. Add useful detail from the structured fields when available. "
            "Do not add remediation steps, commands, invented IPs, or uncertain facts. Return only JSON."
        )
    else:
        instruction = (
            "把这条安全告警润色成简洁、专业、适合仪表盘展示的中文描述。"
            "必须保留已有事实：设备、等级、规则、端口、进程、追踪状态、清除状态等；不要编造 IP/端口/用户/进程。"
            "不要复述原文，要尽量利用结构化字段补充有增量的细节。"
            "不要写处理步骤、命令或泛泛建议，只描述发生了什么和当前状态。只返回 JSON。"
        )
    return "\n".join([
        instruction,
        f"告警上下文：{json.dumps(prompt_context, ensure_ascii=False)}",
        f"返回结构：{json.dumps(schema, ensure_ascii=False)}",
    ])


def _valid_polished_description(value: str) -> bool:
    if len(value) < 8 or len(value) > 260:
        return False
    text = value.lower()
    banned = ["<pid>", "<ip>", "<port>", "example.com", "your_server", "simulate-wazuh-attack.sh", "test-wazuh-alert.sh"]
    return not any(item in text for item in banned)


def _description_too_similar(description: str, context: dict[str, Any]) -> bool:
    original = clean_text(context.get("display_description") or context.get("description") or "")
    if not original:
        return False
    a = _normalize_for_similarity(description)
    b = _normalize_for_similarity(original)
    if not a or not b:
        return False
    if a == b or a in b or b in a:
        return True
    overlap = len(set(a) & set(b)) / max(1, len(set(b)))
    return overlap > 0.88 and abs(len(a) - len(b)) < 20


def _normalize_for_similarity(value: str) -> str:
    text = re.sub(r"\s+", "", value.lower())
    text = re.sub(r"[，。；：:;,.!！?？（）()【】\\[\\]`'\"-]", "", text)
    return text


def _alert_description_cache_key(context: dict[str, Any], lang: str) -> str:
    relevant = {
        key: context.get(key)
        for key in (
            "time", "agent", "rule_id", "level", "description", "display_description",
            "port", "protocol", "process", "listen_ip", "raw_log", "trojan_event", "trojan_tracking",
        )
    }
    payload = json.dumps({"lang": lang, "context": relevant}, ensure_ascii=False, sort_keys=True, default=str)
    return "alert_description:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _advice_cache_key(kind: str, context: dict[str, Any], lang: str) -> str:
    payload = json.dumps(
        {
            "kind": kind,
            "lang": lang,
            "model": settings.guizangai_model,
            "context": context,
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return "advice:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _clean_runbook(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        commands = item.get("commands") if isinstance(item.get("commands"), list) else []
        cleaned = {
            "phase": _norm_phase(item.get("phase")),
            "goal": clean_text(item.get("goal") or item.get("title") or item.get("step") or ""),
            "where": clean_text(item.get("where") or item.get("target") or ""),
            "commands": [clean_text(cmd) for cmd in commands if clean_text(cmd)],
            "expected_result": clean_text(item.get("expected_result") or item.get("success") or ""),
            "if_abnormal": clean_text(item.get("if_abnormal") or item.get("next") or ""),
            "risk": _norm_risk(item.get("risk")),
            "requires_confirmation": bool(item.get("requires_confirmation")),
        }
        if cleaned["goal"] or cleaned["commands"]:
            if cleaned["risk"] in {"modify", "danger"}:
                cleaned["requires_confirmation"] = True
            out.append(cleaned)
    return out[:8]


def _finalize_advice_result(
    kind: str,
    context: dict[str, Any],
    lang: str,
    rule_advice: dict[str, Any],
    raw: str,
    perf: dict[str, Any],
    debug: bool,
    prompt: str,
) -> dict[str, Any]:
    parsed = extract_json(raw)
    if parsed is None:
        result = {"_error": "无法解析模型输出", "_perf": perf, **rule_advice}
    else:
        steps = clean_advice_steps(parsed.get("steps"))
        runbook = _clean_runbook(parsed.get("runbook"))
        if steps_conflict_with_target_os(steps, context):
            result = {**rule_advice, "_error": "模型建议包含与目标系统不匹配的命令，已回退到规则建议", "_perf": perf}
        else:
            if steps_are_too_generic(steps):
                steps = rule_advice.get("steps")
            if not _runbook_is_usable(runbook, context):
                runbook = rule_advice.get("runbook") or _runbook_from_steps(rule_advice.get("steps") or [], context, lang)
            result = {
                **rule_advice,
                "summary": parsed.get("summary") or rule_advice.get("summary"),
                "steps": steps or rule_advice.get("steps"),
                "runbook": runbook,
                "impact": parsed.get("impact") or rule_advice.get("impact"),
                "priority": _norm_priority(parsed.get("priority") or rule_advice.get("priority")),
                "_source": "guizangai",
                "_perf": perf,
            }
    if debug:
        result["_debug"] = {
            "kind": kind,
            "lang": lang,
            "enabled": True,
            "api_style": settings.guizangai_api_style or "openai",
            "model": settings.guizangai_model,
            "context": context,
            "prompt": prompt,
            "raw": raw,
            "duration_ms": round(float((perf or {}).get("total_duration_seconds") or 0) * 1000),
            "error": result.get("_error"),
        }
    return result


def _runbook_is_usable(runbook: list[dict[str, Any]], context: dict[str, Any]) -> bool:
    if len(runbook) < 2:
        return False
    has_verify = False
    for item in runbook:
        if not item.get("goal") or not item.get("where"):
            return False
        commands = item.get("commands") or []
        if commands and steps_conflict_with_target_os(commands, context):
            return False
        text = "\n".join(commands)
        if _has_bad_command_value(text):
            return False
        if item.get("phase") == "verify" or item.get("expected_result"):
            has_verify = True
        if item.get("risk") in {"modify", "danger"} and not item.get("requires_confirmation"):
            return False
    return has_verify


def _runbook_from_steps(steps: list[str], context: dict[str, Any], lang: str) -> list[dict[str, Any]]:
    agent = context.get("agent") or ("target endpoint" if lang == "en" else "目标终端")
    phases = ["check", "check", "contain", "remediate", "verify", "rollback"]
    out: list[dict[str, Any]] = []
    for i, step in enumerate(steps[:6]):
        commands = _extract_commands(step)
        risk = _command_risk("\n".join(commands))
        phase = phases[min(i, len(phases) - 1)]
        out.append({
            "phase": phase,
            "goal": step,
            "where": str(agent),
            "commands": commands,
            "expected_result": "Command output or alert status matches the expected safe state." if lang == "en" else "命令输出或告警状态符合预期安全状态。",
            "if_abnormal": "Keep the incident open and collect more evidence before cleanup." if lang == "en" else "保持问题未修复，先补充取证后再清理。",
            "risk": risk,
            "requires_confirmation": risk in {"modify", "danger"},
        })
    return out


def _norm_phase(value: Any) -> str:
    text = str(value or "").lower()
    if text in {"check", "contain", "remediate", "verify", "rollback"}:
        return text
    if any(x in text for x in ("verify", "复核", "验证")):
        return "verify"
    if any(x in text for x in ("rollback", "restore", "恢复", "回滚")):
        return "rollback"
    if any(x in text for x in ("contain", "block", "isolate", "阻断", "隔离")):
        return "contain"
    if any(x in text for x in ("remediate", "fix", "cleanup", "修复", "清理")):
        return "remediate"
    return "check"


def _norm_risk(value: Any) -> str:
    text = str(value or "").lower()
    if text in {"read", "modify", "danger"}:
        return text
    if any(x in text for x in ("danger", "危险", "delete", "kill", "remove")):
        return "danger"
    if any(x in text for x in ("modify", "change", "stop", "block", "修改", "停止", "阻断")):
        return "modify"
    return "read"


def _norm_priority(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"immediate", "soon", "scheduled"}:
        return text
    if text in {"critical", "high", "urgent", "严重", "高", "高危", "立即", "立刻"}:
        return "immediate"
    if text in {"medium", "moderate", "中", "中危", "尽快"}:
        return "soon"
    try:
        score = float(text)
    except ValueError:
        return "scheduled"
    if score >= 8:
        return "immediate"
    if score >= 5:
        return "soon"
    return "scheduled"


def _extract_commands(text: str) -> list[str]:
    commands = [m.strip() for m in re.findall(r"`([^`\n]+)`", text or "") if m.strip()]
    if commands:
        return commands[:4]
    return []


def _command_risk(text: str) -> str:
    low = (text or "").lower()
    if re.search(r"\b(rm\s+-rf|mkfs|dd\s+|shutdown|reboot|taskkill|remove-item|pfctl\s+-f)\b", low):
        return "danger"
    if re.search(r"\b(rm|mv|chmod|chown|kill|pkill|systemctl\s+(stop|restart|disable)|launchctl\s+(bootout|remove|unload)|iptables|nft|ufw|firewall-cmd|new-netfirewallrule|net\s+stop)\b", low):
        return "modify"
    return "read"


def _has_bad_command_value(text: str) -> bool:
    low = (text or "").lower()
    if re.search(r"<\s*(pid|port|ip|host|hostname|server|username|user|path|file)\s*>", text or "", re.I):
        return True
    return any(x in low for x in ("your_server", "your-server", "example.com", "1.2.3.4", "simulate-wazuh-attack.sh", "test-wazuh-alert.sh"))


def _advice_preview_text(result: dict[str, Any], lang: str) -> str:
    title = "正在生成可执行 Runbook" if lang != "en" else "Generating executable runbook"
    parts = [title, "", str(result.get("summary") or "")]
    for idx, step in enumerate(result.get("steps") or [], 1):
        parts.append(f"{idx}. {step}")
    return "\n".join(parts)


def _display_segments_from_partial_json(raw: str) -> list[str]:
    """从仍在生成中的 JSON 文本里提取已闭合的用户可读字段，避免把原始 JSON 展示给用户。"""
    segments: list[str] = []
    for key in ("summary", "impact"):
        value = _json_string_value(raw, key)
        if value:
            segments.append(value + "\n")
    for idx, item in enumerate(_json_array_strings(raw, "steps"), 1):
        if item:
            segments.append(f"{idx}. {item}\n")
    goals = _json_all_string_values(raw, "goal")
    for idx, goal in enumerate(goals, 1):
        if goal:
            segments.append(f"{idx}. {goal}\n")
    expected = _json_all_string_values(raw, "expected_result")
    for item in expected:
        if item:
            segments.append(("预期结果：" if _looks_chinese(raw) else "Expected result: ") + item + "\n")
    return [_normalize_display_punctuation(clean_text(item)) + "\n" for item in segments if clean_text(item)]


def _json_string_value(raw: str, key: str) -> str:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"', raw, re.S)
    return _unescape_json_str(match.group(1)) if match else ""


def _json_all_string_values(raw: str, key: str) -> list[str]:
    return [_unescape_json_str(m.group(1)) for m in re.finditer(rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"', raw, re.S)]


def _json_array_strings(raw: str, key: str) -> list[str]:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*\[(.*?)\]', raw, re.S)
    if not match:
        return []
    body = match.group(1)
    return [_unescape_json_str(m.group(1)) for m in re.finditer(r'"((?:\\.|[^"\\])*)"', body, re.S)]


def _unescape_json_str(value: str) -> str:
    try:
        return json.loads(f'"{value}"')
    except Exception:
        return value.replace('\\"', '"').replace("\\n", "\n")


def _normalize_display_punctuation(value: str) -> str:
    text = re.sub(r"([。！？!?])\1+", r"\1", value or "")
    text = re.sub(r"\.{2,}", ".", text)
    text = re.sub(r"。+\.", "。", text)
    text = re.sub(r"\.+。", "。", text)
    text = re.sub(r"([。.!！?？])\s+([。.!！?？])", r"\1", text)
    return text.strip()


def _looks_chinese(text: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", text))


def _chunk_text(text: str, size: int = 36) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)] or [text]


def _read_guizangai_cache(cache_key: str, max_age_seconds: int | None = None) -> dict[str, Any] | None:
    try:
        with SessionLocal() as s:
            row = s.query(GuizangAICache).filter(GuizangAICache.cache_key == cache_key).first()
            if not row:
                return None
            if max_age_seconds and max_age_seconds > 0:
                created_at = row.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=dt.timezone.utc)
                age = (dt.datetime.now(dt.timezone.utc) - created_at.astimezone(dt.timezone.utc)).total_seconds()
                if age > max_age_seconds:
                    return None
            return dict(row.result or {})
    except Exception:
        return None


def _write_guizangai_cache(cache_key: str, purpose: str, result: dict[str, Any]) -> None:
    safe_result = {k: v for k, v in result.items() if k != "_perf"}
    try:
        with SessionLocal() as s:
            row = s.query(GuizangAICache).filter(GuizangAICache.cache_key == cache_key).first()
            if row:
                row.result = safe_result
                row.purpose = purpose
                row.created_at = dt.datetime.now(dt.timezone.utc)
            else:
                s.add(GuizangAICache(cache_key=cache_key, purpose=purpose, result=safe_result))
            s.commit()
    except Exception:
        return
