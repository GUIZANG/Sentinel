"""哨眼 Sentinel BFF 入口：FastAPI 应用 + 定时分析调度。"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import latest_analysis, run_analysis
from .ai.client import guizang_ai
from .ai.prompts import PRESET_TASKS
from .auth import seed_default_user
from .config import settings
from .db import init_db
from .issues import reconcile_issues
from .routers import auth, dashboard

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("main")

scheduler = AsyncIOScheduler(timezone=settings.timezone)


async def _run_initial_analysis() -> None:
    for attempt in range(1, 7):
        try:
            latest = latest_analysis()
            if all(latest.get(task, {}).get("source") == "guizangai" for task in PRESET_TASKS):
                log.info("已有完整 GuizangAI 分析结果，跳过启动时首轮分析。")
                break
            await run_analysis()
            log.info("首轮分析完成（第 %s 次尝试）", attempt)
            break
        except Exception as e:
            log.warning("首轮分析第 %s/6 次失败：%s", attempt, e)
            await asyncio.sleep(15)
    else:
        log.warning("首轮分析多次失败，转由调度器周期重试。")
    try:
        await reconcile_issues()
    except Exception as e:
        log.warning("首轮问题对账失败：%s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_default_user()
    # 首轮分析可能需要等待本地模型推理，放到后台避免阻塞 /health 和前端访问。
    asyncio.create_task(_run_initial_analysis())
    scheduler.add_job(
        run_analysis,
        "interval",
        minutes=settings.analysis_interval_minutes,
        id="periodic_analysis",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.add_job(
        reconcile_issues,
        "interval",
        minutes=settings.issue_reconcile_minutes,
        id="periodic_issue_reconcile",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
    log.info("调度器已启动：每 %s 分钟分析一次 | GuizangAI=%s",
             settings.analysis_interval_minutes, "已接入" if guizang_ai.enabled else "Mock模式")
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="哨眼 Sentinel BFF", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(auth.router)


@app.get("/health")
async def health():
    return {"status": "ok", "guizangAI": "connected" if guizang_ai.enabled else "mock"}
