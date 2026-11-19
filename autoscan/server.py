"""autoscan Web 平台：python -m autoscan.server → http://127.0.0.1:8400

一键式自动化测评：输入目标 URL → 自动探测/选型/测评/建议 → 出报告。
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from autoscan.pipeline import AutoScan

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

app = FastAPI(title="AgentProbe AutoScan")
scanner = AutoScan()


@app.get("/api/jobs")
def list_jobs():
    return {"jobs": [j.to_dict() for j in
                     sorted(scanner.jobs.values(), key=lambda x: -x.created)]}


@app.get("/api/job/{jid}")
def get_job(jid: str):
    job = scanner.get(jid)
    if not job:
        return JSONResponse(status_code=404, content={"error": "not found"})
    return job.to_dict()


@app.post("/api/scan")
async def scan(req: Request):
    body = await req.json()
    target = str(body.get("target", "")).strip()
    demo = bool(body.get("demo", False))
    if not demo and not target.startswith(("http://", "https://")):
        return JSONResponse(status_code=400,
                            content={"error": "请输入 http:// 或 https:// 开头的目标"})
    if demo:
        target = "内置演示靶子"
    rounds = min(max(int(body.get("rounds", 2)), 1), 6)
    jid = scanner.submit(target, demo=demo, rounds=rounds)
    return {"id": jid, "state": "queued"}


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        return f.read()


if os.path.isdir(STATIC):
    app.mount("/static", StaticFiles(directory=STATIC), name="static")


if __name__ == "__main__":
    import uvicorn
    print("AgentProbe AutoScan: http://127.0.0.1:8400")
    uvicorn.run(app, host="127.0.0.1", port=8400, log_level="warning")
