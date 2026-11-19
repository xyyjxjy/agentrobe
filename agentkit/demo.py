"""真 LLM demo：用商汤 sensenova-6.8-flash-lite + agentkit 跑完整 agent 会话。

展示原生 function calling：LLM 自己决定调哪个工具、传什么参数。
用法：python -m agentkit.demo
"""

from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from agentkit import ToolRegistry, Trace
from agentkit.core import ToolSpec
from agentkit.langchain_runner import LangChainRunner

load_dotenv()


def main():
    # 1. 注册工具（带权限钩子）
    tools = ToolRegistry()

    def search(query: str) -> str:
        # 简单演示：真项目这里接向量检索
        kb = {
            "差旅": "跨省差旅住宿 450 元/晚，一线城市 600 元/晚",
            "报销": "每月 15 日、30 日集中审批，单笔 5000 元以上需签字",
        }
        for k, v in kb.items():
            if k in query:
                return v
        return "资料库未找到相关内容"

    def email(to: str, subject: str = "", body: str = "") -> str:
        return f"邮件已发送至 {to}"

    def path_guard(args):
        return "拒绝：路径越界" if ".." in args.get("path", "") else None

    tools.register(ToolSpec("search_docs", "检索内部资料", {"query": "str"}, search))
    tools.register(ToolSpec("send_email", "发送邮件",
                            {"to": "str", "subject": "str", "body": "str"}, email,
                            guard=lambda a: None if a.get("to", "").endswith(
                                "@yanjiuyuan.org") else "拒绝：收件人域名不允许"))

    print("工具 schemas（导出给 LLM 的 function calling 定义）:")
    print(json.dumps(tools.schemas(), ensure_ascii=False, indent=1)[:400], "...\n")

    # 2. 真 LLM（商汤，OpenAI 兼容）
    model = ChatOpenAI(
        base_url=os.getenv("LLM_BASE_URL", "https://token.sensenova.cn/v1"),
        api_key=os.getenv("LLM_API_KEY"),
        model=os.getenv("LLM_MODEL", "sensenova-6.8-flash-lite"),
        temperature=0,
        max_tokens=512,
    )

    # 3. Runner + 跑一个会触发工具的问题
    runner = LangChainRunner(tools, model,
                             system_prompt="你是内部资料助手。查资料用 search_docs，发邮件用 send_email。")
    trace = runner.run("跨省出差住宿标准是多少？")

    print("\n=== 真 LLM Agent 会话 trace ===")
    print(f"输入: {trace.input}")
    print(f"回答: {trace.answer}")
    print(f"工具调用: {json.dumps(trace.tool_calls, ensure_ascii=False)}")
    print(f"步数: {len(trace.steps)} | 耗时: {trace.total_ms:.0f}ms | 错误: {trace.error}")


if __name__ == "__main__":
    main()
