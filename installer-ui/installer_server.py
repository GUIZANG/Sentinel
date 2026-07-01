#!/usr/bin/env python3
"""Local visual installer server.

Runs an install command, serves the progress UI, and streams logs/events over SSE.
Only binds to 127.0.0.1.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"


class State:
    def __init__(self) -> None:
        self.logs: list[str] = []
        self.current_event: dict[str, object] = {"step": "prepare", "status": "running", "progress": 0, "message": "准备启动安装"}
        self.subscribers: list[queue.Queue[tuple[str, str]]] = []
        self.lock = threading.Lock()

    def publish(self, kind: str, data: str) -> None:
        with self.lock:
            if kind == "log":
                self.logs.append(data)
                self.logs = self.logs[-800:]
            elif kind == "install":
                try:
                    self.current_event = json.loads(data)
                except Exception:
                    pass
            subscribers = list(self.subscribers)
        for q in subscribers:
            q.put((kind, data))

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return {"logs": list(self.logs), "current_event": self.current_event}


STATE = State()


def install_event(step: str, status: str, progress: int, message: str) -> None:
    STATE.publish("install", json.dumps({"step": step, "status": status, "progress": progress, "message": message}, ensure_ascii=False))


def run_command(command: list[str], cwd: str | None) -> None:
    install_event("prepare", "running", 1, "启动安装进程")
    try:
        proc = subprocess.Popen(
            command,
            cwd=cwd or None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env={**os.environ, "GUIZANG_NO_OPEN_BROWSER": os.environ.get("GUIZANG_NO_OPEN_BROWSER", "1")},
        )
    except Exception as exc:
        install_event("failed", "error", 100, f"启动失败：{exc}")
        return

    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        if line.startswith("INSTALL_EVENT="):
            payload = line.split("=", 1)[1]
            STATE.publish("install", payload)
        else:
            STATE.publish("log", line)
    code = proc.wait()
    if code == 0:
        install_event("done", "done", 100, "安装完成")
    else:
        install_event("failed", "error", 100, f"安装失败，退出码 {code}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            data = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/status":
            data = json.dumps(STATE.snapshot(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/events":
            q: queue.Queue[tuple[str, str]] = queue.Queue()
            with STATE.lock:
                STATE.subscribers.append(q)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                snap = STATE.snapshot()
                self.wfile.write(f"event: install\ndata: {json.dumps(snap['current_event'], ensure_ascii=False)}\n\n".encode("utf-8"))
                self.wfile.flush()
                while True:
                    kind, data = q.get()
                    self.wfile.write(f"event: {kind}\ndata: {data}\n\n".encode("utf-8", errors="replace"))
                    self.wfile.flush()
            except Exception:
                pass
            finally:
                with STATE.lock:
                    if q in STATE.subscribers:
                        STATE.subscribers.remove(q)
            return
        self.send_response(404)
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--cwd", default="")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing command")

    threading.Thread(target=run_command, args=(command, args.cwd), daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"INSTALLER_UI=http://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
