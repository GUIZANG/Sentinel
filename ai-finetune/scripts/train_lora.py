#!/usr/bin/env python3
"""Train Qwen2.5 with LoRA/QLoRA on GuizangAI reviewed JSONL records.

Install dependencies in a separate training environment:
  pip install "torch" "transformers>=4.44" "datasets" "accelerate" "peft" "trl"
  # QLoRA only:
  pip install "bitsandbytes"

Example LoRA:
  python ai-finetune/scripts/train_lora.py \
    --train-file ai-finetune/data/processed/train.jsonl \
    --output-dir ai-finetune/out/qwen2.5-guizangai-lora

Example QLoRA:
  python ai-finetune/scripts/train_lora.py \
    --train-file ai-finetune/data/processed/train.jsonl \
    --output-dir ai-finetune/out/qwen2.5-guizangai-qlora \
    --use-4bit
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
from pathlib import Path
from typing import Any


SYSTEM_PROMPT = (
    "你是一名企业终端安全分析与应急响应助手。"
    "你只处理防守场景：Wazuh 告警分析、漏洞处置、合规加固、告警描述润色。"
    "必须严格按照用户要求输出 JSON，不要输出 Markdown、解释文字或额外前后缀。"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune Qwen2.5 with LoRA/QLoRA for GuizangAI tasks.")
    parser.add_argument("--train-file", default="ai-finetune/data/processed/train.jsonl")
    parser.add_argument("--val-file", default="", help="Optional validation JSONL file.")
    parser.add_argument("--output-dir", default="ai-finetune/out/qwen2.5-guizangai-lora")
    parser.add_argument("--model-name", default="Qwen/Qwen2.5-3B-Instruct")
    parser.add_argument("--max-seq-length", type=int, default=2048)
    parser.add_argument("--epochs", type=float, default=3.0)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--use-4bit", action="store_true", help="Enable QLoRA 4-bit loading via bitsandbytes.")
    parser.add_argument("--gradient-checkpointing", action="store_true", default=True)
    parser.add_argument("--save-steps", type=int, default=50)
    parser.add_argument("--logging-steps", type=int, default=5)
    parser.add_argument("--early-stopping-patience", type=int, default=0, help="Stop after this many evals without improvement.")
    parser.add_argument("--early-stopping-threshold", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true", help="Only load and format data; do not train.")
    return parser.parse_args()


def load_reviewed_records(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            text = line.strip()
            if not text:
                continue
            record = json.loads(text)
            if record.get("review_status") != "reviewed":
                continue
            if not record.get("expected_output"):
                raise ValueError(f"{path}:{line_no} reviewed record has empty expected_output")
            records.append(record)
    return records


def user_prompt(record: dict[str, Any]) -> str:
    payload = {
        "task": record["task"],
        "instruction": record["instruction"],
        "input": record["input"],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def assistant_response(record: dict[str, Any]) -> str:
    return json.dumps(record["expected_output"], ensure_ascii=False, sort_keys=True)


def format_record(tokenizer: Any, record: dict[str, Any]) -> dict[str, str]:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt(record)},
        {"role": "assistant", "content": assistant_response(record)},
    ]
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    return {"text": text}


def build_dataset(tokenizer: Any, records: list[dict[str, Any]]):
    from datasets import Dataset

    return Dataset.from_list([format_record(tokenizer, record) for record in records])


def main() -> int:
    args = parse_args()
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    # Heavy imports are inside main so --help remains fast and dependency errors are clearer.
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, EarlyStoppingCallback, TrainingArguments
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTTrainer

    try:
        from trl import SFTConfig
    except ImportError:
        SFTConfig = None

    train_records = load_reviewed_records(args.train_file)
    if not train_records:
        raise SystemExit(f"No reviewed records found in {args.train_file}")
    if len(train_records) < 50:
        print(f"[WARN] only {len(train_records)} reviewed records. This is enough to test the pipeline, not enough for useful fine-tuning.")

    val_records = load_reviewed_records(args.val_file) if args.val_file else []

    tokenizer = AutoTokenizer.from_pretrained(args.model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    train_dataset = build_dataset(tokenizer, train_records)
    eval_dataset = build_dataset(tokenizer, val_records) if val_records else None

    if args.dry_run:
        print("[OK] dry run loaded records:", len(train_dataset))
        print(train_dataset[0]["text"][:1200])
        return 0

    quantization_config = None
    if args.use_4bit:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    mps_available = bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_available())
    target_device = "cuda" if torch.cuda.is_available() else ("mps" if mps_available else "cpu")
    model_dtype = torch.bfloat16 if target_device == "cuda" else (torch.float16 if target_device == "mps" else torch.float32)
    model_kwargs = {
        "trust_remote_code": True,
        "torch_dtype": model_dtype,
        "quantization_config": quantization_config,
    }
    if args.use_4bit:
        model_kwargs["device_map"] = "auto"

    model = AutoModelForCausalLM.from_pretrained(args.model_name, **model_kwargs)
    if not args.use_4bit:
        model.to(target_device)
    if args.use_4bit:
        model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
    )

    training_kwargs = {
        "output_dir": args.output_dir,
        "num_train_epochs": args.epochs,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.batch_size,
        "gradient_accumulation_steps": args.grad_accum,
        "learning_rate": args.learning_rate,
        "logging_steps": args.logging_steps,
        "save_steps": args.save_steps,
        "save_total_limit": 3,
        "bf16": torch.cuda.is_available(),
        "fp16": False,
        "report_to": "none",
        "seed": args.seed,
        "gradient_checkpointing": args.gradient_checkpointing,
        "eval_steps": args.save_steps if eval_dataset is not None else None,
    }

    training_cls = SFTConfig or TrainingArguments
    training_params = inspect.signature(training_cls.__init__).parameters
    strategy_name = "eval_strategy" if "eval_strategy" in training_params else "evaluation_strategy"
    training_kwargs[strategy_name] = "steps" if eval_dataset is not None else "no"
    if eval_dataset is not None:
        for name, value in {
            "save_strategy": "steps",
            "load_best_model_at_end": args.early_stopping_patience > 0,
            "metric_for_best_model": "eval_loss",
            "greater_is_better": False,
        }.items():
            if name in training_params:
                training_kwargs[name] = value
    if SFTConfig is not None:
        if "dataset_text_field" in training_params:
            training_kwargs["dataset_text_field"] = "text"
        if "max_length" in training_params:
            training_kwargs["max_length"] = args.max_seq_length
        elif "max_seq_length" in training_params:
            training_kwargs["max_seq_length"] = args.max_seq_length
        if "packing" in training_params:
            training_kwargs["packing"] = False

    training_args = training_cls(**training_kwargs)

    trainer_kwargs = {
        "model": model,
        "args": training_args,
        "train_dataset": train_dataset,
        "eval_dataset": eval_dataset,
        "peft_config": lora_config,
    }
    trainer_params = inspect.signature(SFTTrainer.__init__).parameters
    if "tokenizer" in trainer_params:
        trainer_kwargs["tokenizer"] = tokenizer
    elif "processing_class" in trainer_params:
        trainer_kwargs["processing_class"] = tokenizer
    if "dataset_text_field" in trainer_params:
        trainer_kwargs["dataset_text_field"] = "text"
    if "max_seq_length" in trainer_params:
        trainer_kwargs["max_seq_length"] = args.max_seq_length
    if "packing" in trainer_params:
        trainer_kwargs["packing"] = False
    if eval_dataset is not None and args.early_stopping_patience > 0 and "callbacks" in trainer_params:
        trainer_kwargs["callbacks"] = [
            EarlyStoppingCallback(
                early_stopping_patience=args.early_stopping_patience,
                early_stopping_threshold=args.early_stopping_threshold,
            )
        ]

    trainer = SFTTrainer(**trainer_kwargs)
    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"[OK] LoRA adapter saved to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
