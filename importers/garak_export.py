"""从 garak 导出攻击载荷 → 统一 JSONL。

必须在装了 garak 的环境里跑（项目根目录下的 .venv-frameworks），
主项目本身不 import garak —— 这是刻意的：
    garak 要求 Python >=3.11，依赖一大堆，硬塞进主环境会把 openai 版本顶掉。
    我们只借它的数据，不借它的运行时。

用法：
    .venv-frameworks/Scripts/python.exe importers/garak_export.py -o seeds/garak.jsonl
    .venv-frameworks/Scripts/python.exe importers/garak_export.py --list      # 只列 probe

输出每条：
    {"source": "garak", "probe": "promptinject.HijackKillHumans",
     "name": "...", "goal": "...", "tags": [...], "owasp": "LLM01",
     "payload": "..."}
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _enumerate_probes():
    """garak 的 enumerate_plugins 返回 (插件名, 是否启用)，不是类。

    真正实例化要用 _plugins.load_plugin(name)，它返回的是实例而非类。
    """
    from garak import _plugins

    try:
        items = list(_plugins.enumerate_plugins("probes"))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for item in items:
        if isinstance(item, tuple):
            name = str(item[0])
            enabled = bool(item[1]) if len(item) > 1 else True
        else:
            name, enabled = str(item), True
        out.append((name, enabled))
    return out


def _prompt_texts(probe) -> list:
    """probe.prompts 里可能是 str，也可能是 garak.attempt.Prompt 对象。"""
    raw = getattr(probe, "prompts", None) or []
    out = []
    for item in raw:
        if isinstance(item, str):
            out.append(item)
            continue
        text = getattr(item, "text", None)
        if text:
            out.append(str(text))
        else:
            out.append(str(item))
    return out


def _owasp_from_tags(tags) -> str:
    for t in tags or []:
        t = str(t).lower()
        if t.startswith("owasp:"):
            return t.split(":", 1)[1].upper()      # owasp:llm01 -> LLM01
    return ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="seeds/garak.jsonl")
    ap.add_argument("--per-probe", type=int, default=20,
                    help="每个 probe 最多导出多少条（garak 单 probe 可能上千条）")
    ap.add_argument("--only", default="", help="只导出名字含该子串的 probe，如 promptinject")
    ap.add_argument("--list", action="store_true", help="只列出 probe 名称，不导出")
    ap.add_argument("--max-probes", type=int, default=0)
    args = ap.parse_args()

    try:
        import garak  # noqa: F401
    except ImportError:
        print("当前环境没有 garak。请用 .venv-frameworks/Scripts/python.exe 运行本脚本。")
        sys.exit(1)

    # garak 的 probe 实例化依赖全局配置，CLI 启动时会自动加载，我们得手动来一次
    try:
        from garak import _config
        _config.load_base_config()
    except Exception as e:  # noqa: BLE001
        print(f"（配置初始化告警，继续尝试：{type(e).__name__}: {e}）", file=sys.stderr)

    entries = _enumerate_probes()
    if args.only:
        entries = [e for e in entries if args.only.lower() in e[0].lower()]
    if args.max_probes:
        entries = entries[: args.max_probes]

    if args.list:
        for name, enabled in entries:
            flag = "" if enabled else "  (inactive)"
            print(name + flag)
        print(f"\n共 {len(entries)} 个 probe")
        return

    from garak import _plugins

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    written = skipped = 0
    with open(args.out, "w", encoding="utf-8") as f:
        for name, _enabled in entries:
            try:
                probe = _plugins.load_plugin(name)   # 返回实例
            except Exception as e:  # noqa: BLE001  个别 probe 实例化就要读大文件
                print(f"  skip {name}: {type(e).__name__}: {e}", file=sys.stderr)
                skipped += 1
                continue

            prompts = _prompt_texts(probe)
            if not prompts:
                skipped += 1
                continue

            # triggers 是 garak 自己的判定依据：prompts[i] 发出去，
            # 期望得到的输出就对应 triggers[i]。两者通常等长。
            # 把它一起导出来，下游就不用再靠正则去猜"模型该吐什么"了。
            triggers = list(getattr(probe, "triggers", None) or [])

            tags = [str(t) for t in (getattr(probe, "tags", None) or [])]
            goal = str(getattr(probe, "goal", "") or "")
            desc = str(getattr(probe, "description", "") or "")
            short = name.split(".", 2)[-1]
            cat = name.split(".")[1] if name.count(".") >= 2 else "probes"

            for i, payload in enumerate(prompts[: args.per_probe]):
                if not payload.strip():
                    continue
                trigger = ""
                if i < len(triggers):
                    trigger = str(triggers[i])
                rec = {
                    "source": "garak",
                    "probe": name,
                    "name": f"{short}#{i}",
                    "goal": goal,
                    "description": desc[:300],
                    "tags": tags,
                    "owasp": _owasp_from_tags(tags),
                    "category_hint": cat,
                    "detector_hint": str(getattr(probe, "primary_detector", "") or ""),
                    "trigger": trigger,
                    "payload": payload,
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                written += 1

    print(f"导出 {written} 条 → {args.out}（跳过 {skipped} 个 probe）")


if __name__ == "__main__":
    main()
