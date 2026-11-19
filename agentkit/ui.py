"""agentkit Web UI：FastAPI 后端 + 单页前端。

启动：python -m agentkit.ui
打开：http://127.0.0.1:8300

左边聊天，右边实时显示 agent 每一步决策 + 工具调用（可观测可视化）。
真 LLM 需要 .env 里的 key；没配 key 时自动用假 LLM，保证离线可演示。
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request

load_dotenv()  # 加载 .env 里的 LLM key（不进 git）
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from agentkit import ToolRegistry
from agentkit.core import ToolSpec
from agentkit.langchain_runner import LangChainRunner
from agentkit.runner import ReActRunner

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

app = FastAPI(title="agentkit demo")


def build_tools() -> ToolRegistry:
    tools = ToolRegistry()

    def search(query: str) -> str:
        kb = {
            "差旅": "跨省差旅住宿 450 元/晚，一线城市 600 元/晚",
            "住宿": "跨省差旅住宿 450 元/晚，一线城市 600 元/晚",
            "报销": "每月 15 日、30 日集中审批，单笔 5000 元以上需签字",
            "审批": "出差需提前 3 个工作日在系统提交",
            "邮件": "仅允许发送到 @yanjiuyuan.org 域名",
        }
        for k, v in kb.items():
            if k in query:
                return v
        return "资料库未找到相关内容"

    def email(to: str, subject: str = "", body: str = "") -> str:
        return f"邮件已发送至 {to}"

    def read_file(path: str) -> str:
        return f"（模拟）读取文件：{path}"

    tools.register(ToolSpec("search_docs", "检索内部资料（差旅/报销/审批/邮件）",
                            {"query": "str"}, search))
    tools.register(ToolSpec("read_file", "读取资料库文件",
                            {"path": "str"}, read_file,
                            guard=lambda a: "拒绝：路径越界" if ".." in a.get("path", "") else None))
    tools.register(ToolSpec("send_email", "发送邮件",
                            {"to": "str", "subject": "str", "body": "str"}, email,
                            guard=lambda a: None if a.get("to", "").endswith(
                                "@yanjiuyuan.org") else "拒绝：收件人域名不允许"))
    return tools


TOOLS = build_tools()
_RUNNERS: dict[str, object] = {}


def get_runner(session_id: str):
    if session_id in _RUNNERS:
        return _RUNNERS[session_id]
    api_key = os.getenv("LLM_API_KEY", "")
    if api_key:
        from langchain_openai import ChatOpenAI
        model = ChatOpenAI(
            base_url=os.getenv("LLM_BASE_URL", "https://token.sensenova.cn/v1"),
            api_key=api_key,
            model=os.getenv("LLM_MODEL", "sensenova-6.8-flash-lite"),
            temperature=0, max_tokens=512,
        )
        runner = LangChainRunner(
            TOOLS, model,
            system_prompt="你是内部资料助手。查资料用 search_docs，读文件用 read_file，发邮件用 send_email。")
        mode = "langchain (真 LLM · 原生 function calling)"
    else:
        # 离线假 LLM：看关键词决定工具，保证无 key 也能演示 trace
        def fake_llm(messages):
            import json as _json
            last = messages[-1].get("content", "")
            if last.startswith("工具") or "工具 " in last[:6]:
                return _json.dumps({"final": "根据检索到的资料，跨省住宿 450 元/晚，一线城市 600 元/晚。"},
                                   ensure_ascii=False)
            if any(k in last for k in ("邮件", "发送")):
                return _json.dumps({"tool": "send_email",
                                    "args": {"to": "hr@yanjiuyuan.org", "subject": "通知", "body": last}},
                                   ensure_ascii=False)
            return _json.dumps({"tool": "search_docs", "args": {"query": last}},
                               ensure_ascii=False)
        runner = ReActRunner(TOOLS, fake_llm, max_steps=4)
        mode = "react (离线假 LLM)"
    runner._mode = mode
    _RUNNERS[session_id] = runner
    return runner


@app.get("/api/tools")
def tools():
    return {"tools": [s.to_openai_schema() for s in TOOLS._tools.values()],
            "mode": ("langchain (真 LLM)" if os.getenv("LLM_API_KEY") else "react (离线)")}


@app.post("/api/chat")
async def chat(req: Request):
    body = await req.json()
    msg = body.get("message", "")
    sid = body.get("session_id", "default")
    try:
        runner = get_runner(sid)
        trace = runner.run(msg, session_id=sid)
        return JSONResponse(content={
            "answer": trace.answer,
            "mode": getattr(runner, "_mode", ""),
            "steps": trace.steps,
            "tool_calls": trace.tool_calls,
            "total_ms": round(trace.total_ms, 1),
            "error": trace.error,
        })
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=200, content={
            "answer": f"出错了：{type(e).__name__}: {e}",
            "steps": [], "tool_calls": [], "error": str(e)})


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as f:
        return f.read()


if os.path.isdir(STATIC):
    app.mount("/static", StaticFiles(directory=STATIC), name="static")


if __name__ == "__main__":
    import uvicorn
    print("agentkit UI: http://127.0.0.1:8300")
    uvicorn.run(app, host="127.0.0.1", port=8300, log_level="warning")
