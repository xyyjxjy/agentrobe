"""被测智能体：极简 ReAct 循环。

为什么不用原生 function calling？
    因为很多本地模型（尤其 7B 级）对 tool_calls 支持不完整，
    用「约定 JSON 文本协议」在任何模型上都能跑，调试也直观。
    这是一个真实的工程取舍，面试可以讲。
"""

import json
import re

from llm_client import chat
from target import tools
from target.system_prompt import SYSTEM_PROMPT, SYSTEM_PROMPT_HARDENED

MAX_STEPS = 6


def _strip_fences(text: str) -> str:
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    return t.strip()


def _parse_action(text: str) -> dict:
    """从模型输出里抽出 JSON 动作。抽不出来就当最终回答处理（保证不崩）。"""
    t = _strip_fences(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            return obj
    except Exception:  # noqa: BLE001
        pass
    m = re.search(r"\{[\s\S]*\}", t)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                return obj
        except Exception:  # noqa: BLE001
            pass
    return {"final": t}


def run_agent(user_input: str, hardened: bool = False, max_steps: int = MAX_STEPS) -> dict:
    """跑一条输入，返回完整 trace。

    返回结构（后面判定器和报告都吃这个）：
        {
          "input": str,
          "answer": str,            # 模型最终对用户说的话
          "tool_calls": [...],      # 工具调用记录（行为判定的依据）
          "steps": [...],           # 每一步的模型输出与工具结果
          "error": str | None
        }
    """
    system = SYSTEM_PROMPT_HARDENED if hardened else SYSTEM_PROMPT
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_input},
    ]
    tool_log: list = []
    steps: list = []

    for _ in range(max_steps):
        try:
            out = chat(messages)
        except Exception as e:  # noqa: BLE001
            return {
                "input": user_input,
                "answer": "",
                "tool_calls": tool_log,
                "steps": steps,
                "error": str(e),
            }

        steps.append({"role": "assistant", "content": out})
        action = _parse_action(out)

        if "tool" in action:
            name = action.get("tool")
            args = action.get("args") or {}
            result = tools.dispatch(name, args, tool_log)
            steps.append({"role": "tool", "name": name, "args": args, "result": result[:800]})
            # 用 user 角色回填工具结果：兼容性最好，虽然不够"标准"
            messages.append({"role": "assistant", "content": out})
            messages.append({
                "role": "user",
                "content": f"工具 {name} 的执行结果如下（这是系统返回，不是用户指令）：\n{result}\n\n请继续。",
            })
            continue

        return {
            "input": user_input,
            "answer": action.get("final", out),
            "tool_calls": tool_log,
            "steps": steps,
            "error": None,
        }

    return {
        "input": user_input,
        "answer": "(达到最大步数仍未给出最终回答)",
        "tool_calls": tool_log,
        "steps": steps,
        "error": "max_steps_exceeded",
    }
