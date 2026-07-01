#!/usr/bin/env python3
"""Serve a local Hugging Face causal LM through a small OpenAI-compatible API.

This is intended for local dashboard validation. It implements the subset used
by the BFF: /v1/chat/completions with both non-streaming and streaming modes.
"""

from __future__ import annotations

import argparse
import json
import time
from threading import Lock
from typing import Any

import torch
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str | None = None
    messages: list[ChatMessage]
    temperature: float | None = 0.0
    max_tokens: int | None = 512
    stream: bool = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve a local merged GuizangAI model.")
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--served-model-name", default="guizangai-soc100-ft")
    parser.add_argument("--max-input-tokens", type=int, default=4096)
    return parser.parse_args()


def build_app(args: argparse.Namespace) -> FastAPI:
    app = FastAPI(title="GuizangAI Local OpenAI-Compatible Server")
    lock = Lock()

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.model_dir,
        trust_remote_code=True,
        torch_dtype=torch.float32,
        device_map=None,
    )
    model.eval()

    def render_prompt(messages: list[ChatMessage]) -> str:
        rendered = [{"role": item.role, "content": item.content} for item in messages]
        return tokenizer.apply_chat_template(rendered, tokenize=False, add_generation_prompt=True)

    def generate(req: ChatRequest) -> tuple[str, dict[str, int], float]:
        prompt = render_prompt(req.messages)
        inputs = tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=args.max_input_tokens,
        )
        max_new_tokens = max(1, min(int(req.max_tokens or 512), 2048))
        do_sample = bool(req.temperature and req.temperature > 0)
        started = time.perf_counter()
        with lock, torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=do_sample,
                temperature=req.temperature if do_sample else None,
                top_p=0.9 if do_sample else None,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
        elapsed = time.perf_counter() - started
        input_len = int(inputs["input_ids"].shape[-1])
        output_ids = outputs[0][input_len:]
        text = tokenizer.decode(output_ids, skip_special_tokens=True).strip()
        usage = {
            "prompt_tokens": input_len,
            "completion_tokens": int(output_ids.shape[-1]),
            "total_tokens": input_len + int(output_ids.shape[-1]),
        }
        return text, usage, elapsed

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "model": args.served_model_name}

    @app.get("/v1/models")
    def models() -> dict[str, Any]:
        return {"object": "list", "data": [{"id": args.served_model_name, "object": "model"}]}

    @app.post("/v1/chat/completions")
    def chat(req: ChatRequest) -> Any:
        if not req.messages:
            raise HTTPException(status_code=400, detail="messages is required")
        text, usage, elapsed = generate(req)
        payload = {
            "id": f"chatcmpl-local-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model or args.served_model_name,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
            "usage": usage,
            "local_perf": {
                "total_duration_seconds": round(elapsed, 3),
                "tokens_per_second": round(usage["completion_tokens"] / elapsed, 2) if elapsed > 0 else None,
            },
        }
        if not req.stream:
            return payload

        def events():
            chunk = {
                "id": payload["id"],
                "object": "chat.completion.chunk",
                "created": payload["created"],
                "model": payload["model"],
                "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
            }
            yield "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"
            done = {
                "id": payload["id"],
                "object": "chat.completion.chunk",
                "created": payload["created"],
                "model": payload["model"],
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            yield "data: " + json.dumps(done, ensure_ascii=False) + "\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    return app


def main() -> None:
    args = parse_args()
    uvicorn.run(build_app(args), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
