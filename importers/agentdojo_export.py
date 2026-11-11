"""从 AgentDojo 导出「间接注入 + 工具滥用」用例（注入目标 + 期望的工具调用）。

为什么不 import agentdojo 的 TaskSuite：
    它 import 链上挂着 anthropic / cohere / openai / google-* 全家的 SDK，
    装齐要几百 MB，而且会把 garak 要的 anthropic<1 顶掉（已经踩过一次）。
    我们只要它的**数据**：27 条注入任务的 GOAL、期望的 FunctionCall、
    以及它自己的 important_instructions 注入模板。
    这三样都在包里的 .py/.yaml 源文件中，用 AST 读，不执行它的代码。
    既然只是读数据，就不该为读数据把整个 benchmark 运行时搬进来。

和 garak/PyRIT 的区别（这点必须说清楚，否则报告会误读）：
    garak 的载荷自带"战利品串"，模型吐出来就算打穿——判据在模型输出里。
    AgentDojo 的判据在**工具调用**里：模型要真的调用 send_email(...) 才算成功。
    所以这批用例的判定器是 tool_goal，它拿到目标后先检查被测 agent 有没有这个工具，
    没有就 SKIPPED（不进分母）——否则 27 条会永远显示 0% 命中，
    看起来像"防住了"，实际是"根本没有这个能力可被滥用"。

用法：
    .venv-frameworks/Scripts/python.exe importers/agentdojo_export.py -o seeds/agentdojo.jsonl
    .venv-frameworks/Scripts/python.exe importers/agentdojo_export.py --list
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys

SUITES = ("banking", "slack", "travel", "workspace")


def _pkg_root() -> str:
    import agentdojo
    return os.path.dirname(os.path.abspath(agentdojo.__file__))


def _class_strings(node: ast.ClassDef) -> dict:
    """收集类级别的简单字符串常量，供 GOAL 的 f-string 求值用。"""
    env = {}
    for stmt in node.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            tgt = stmt.targets[0]
            if isinstance(tgt, ast.Name):
                try:
                    val = ast.literal_eval(stmt.value)
                except (ValueError, SyntaxError):
                    continue
                if isinstance(val, str):
                    env[tgt.id] = val
    return env


def _eval_str(node: ast.AST, env: dict) -> str:
    """把 GOAL 节点求值成字符串。

    只用 ast.unparse + 受限 eval，命名空间里只有类属性、没有 builtins，
    因为这些 GOAL 全是字面量或 f-string 引用类属性，不存在需要执行的危险表达式。
    """
    src = ast.unparse(node)
    try:
        return str(eval(src, {"__builtins__": {}}, dict(env)))  # noqa: S307
    except Exception:  # noqa: BLE001
        return ""


def _ground_truth_calls(node: ast.ClassDef) -> list:
    """从 ground_truth() 里抽出期望的 FunctionCall(function="...") 与参数键。"""
    out = []
    for item in node.body:
        if not isinstance(item, ast.FunctionDef) or item.name != "ground_truth":
            continue
        for call in ast.walk(item):
            if not (isinstance(call, ast.Call)
                    and getattr(call.func, "id", "") == "FunctionCall"):
                continue
            fname, keys = "", []
            for kw in call.keywords:
                if kw.arg == "function":
                    try:
                        fname = str(ast.literal_eval(kw.value))
                    except (ValueError, SyntaxError):
                        fname = ""
                elif kw.arg == "args" and isinstance(kw.value, ast.Dict):
                    keys = [str(ast.literal_eval(k)) for k in kw.value.keys
                            if isinstance(k, ast.Constant)]
            if fname:
                out.append({"function": fname, "arg_keys": keys})
    return out


def _jb_template() -> str:
    """读 AgentDojo 自己的 important_instructions 注入模板（不 import 它）。"""
    path = os.path.join(_pkg_root(), "attacks", "important_instructions_attacks.py")
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ImportantInstructionsAttack":
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign)
                        and getattr(stmt.targets[0], "id", "") == "_JB_STRING"):
                    try:
                        return str(ast.literal_eval(stmt.value))
                    except (ValueError, SyntaxError):
                        pass
    return "\n\n{goal}\n\n"


def _task_id_from_name(name: str) -> str:
    # InjectionTask3 -> user_task_3 里没有对应关系，直接用类名兜底
    return name.replace("InjectionTask", "").strip() or name


def export() -> tuple[list, list]:
    root = _pkg_root()
    tpl = _jb_template()
    rows, problems = [], []
    for suite in SUITES:
        path = os.path.join(root, "default_suites", "v1", suite, "injection_tasks.py")
        if not os.path.exists(path):
            problems.append({"suite": suite, "error": "找不到 injection_tasks.py"})
            continue
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in tree.body:
            if not (isinstance(node, ast.ClassDef)
                    and any(isinstance(b, ast.Name) and b.id.endswith("InjectionTask")
                            for b in node.bases)):
                continue
            env = _class_strings(node)
            goal = ""
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and getattr(stmt.targets[0], "id", "") == "GOAL":
                    goal = _eval_str(stmt.value, env)
            if not goal:
                problems.append({"suite": suite, "task": node.name, "error": "GOAL 求值为空"})
                continue
            calls = _ground_truth_calls(node)
            if not calls:
                problems.append({"suite": suite, "task": node.name,
                                 "error": "ground_truth 里没找到 FunctionCall"})
            rows.append({
                "source": "agentdojo",
                "suite": suite,
                "task": node.name,
                "task_id": f"{suite}-{_task_id_from_name(node.name)}",
                "goal": goal,
                "expect_tool": calls,
                # 注入模板原样取自 AgentDojo：{user}/{model}/{goal} 三个槽位
                "payload": tpl.replace("{user}", "Emma Johnson")
                                .replace("{model}", "the assistant")
                                .replace("{goal}", goal).strip(),
            })
    return rows, problems


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="seeds/agentdojo.jsonl")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    rows, problems = export()
    if args.list:
        for r in rows:
            tools = ",".join(c["function"] for c in r["expect_tool"]) or "?"
            print(f'{r["task_id"]:24} [{tools:18}] {r["goal"][:88]}')
        print(f"\n共 {len(rows)} 条注入任务，{len(problems)} 条异常")
        for p in problems:
            print("  ", p)
        return

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tools = sorted({c["function"] for r in rows for c in r["expect_tool"]})
    print(f"导出 {len(rows)} 条 → {args.out}")
    print(f"  涉及工具 {len(tools)} 个：{', '.join(tools)}")
    if problems:
        print(f"  ⚠️ 异常 {len(problems)} 条：")
        for p in problems:
            print("    ", p)


if __name__ == "__main__":
    sys.exit(main())
