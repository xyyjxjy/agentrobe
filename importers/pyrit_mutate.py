"""用 PyRIT 的 converter 给已有用例做深度变异（不新增攻击意图）。

为什么必须用 .venv-frameworks 跑：
    PyRIT 1.1.0 要 sqlalchemy / openai / aiofiles / tinytag / sqlalchemy 这一串，
    硬塞进主环境会把项目自己的 openai 顶掉（上次 garak 就是这么卡住的）。
    跟 garak 一个路子：只借它的 converter 干活，产物落成 YAML，主项目永不 import pyrit。

一条用例被 converter 改写后，标记还剩多少，直接决定它还能不能被现有判定器判。
所以每条派生用例都带一个 marker_state：

    plain   标记原样在载荷里      → 模型照做就吐出来，marker/canary 直接判，最可靠
    encoded 标记被编码/替换       → 模型要先解码才吐明文；判定靠输出里的明文，
                                    模型只复述编码串时会假阴性（诚实记这一条）
    opaque  标记被打碎            → braille/morse/二进制/零宽/上标这类，现有判定器
                                    在输出里找不到任何锚点。默认剔除：留下只会把
                                    分母做大、分子不变，就是"注水"。

用法（必须用框架环境）：
    .venv-frameworks/Scripts/python.exe importers/pyrit_mutate.py --list
    .venv-frameworks/Scripts/python.exe importers/pyrit_mutate.py \
        --in seeds/garak_cases.yaml -o seeds/pyrit_cases.yaml --sample 100 --per-case 12
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import codecs
import json
import os
import random
import re
import sys
import urllib.parse

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# --------------------------------------------------------------- converter 清单
#
# 只收"确定性"的：同一个输入永远同一个输出，不需要再调一次大模型。
# 需要 converter_target（也就是再挂一个 LLM）的那批单独列在 LLM_CONVERTERS，
# 不是不能用，是用途不同——它们做的是"改写语义"，跑起来要额外的模型配额，
# 和本文件"换包装不改意图"的定位冲突，所以默认不启用。

# (注册名, 模块, 构造参数)
DETERMINISTIC = [
    ("base64", "base64_converter", {}),
    ("base2048", "base2048_converter", {}),
    ("binary", "binary_converter", {}),
    ("bin_ascii", "bin_ascii_converter", {}),   # 十六进制串
    ("rot13", "rot13_converter", {}),
    ("caesar13", "caesar_converter", {"caesar_offset": 13}),
    ("vigenere", "vigenere_converter", {"key": "canary"}),
    ("atbash", "atbash_converter", {}),
    ("flip", "flip_converter", {}),
    ("leetspeak", "leetspeak_converter", {}),
    ("morse", "morse_converter", {}),
    ("braille", "braille_converter", {}),
    ("nato", "nato_converter", {}),
    ("emoji", "emoji_converter", {}),
    ("ecoji", "ecoji_converter", {}),
    ("superscript", "superscript_converter", {}),
    ("diacritic", "diacritic_converter", {}),
    ("zalgo", "zalgo_converter", {}),
    ("zero_width", "zero_width_converter", {}),
    ("tatweel", "tatweel_converter", {}),
    ("bidi", "bidi_converter", {}),
    ("unicode_replacement", "unicode_replacement_converter", {}),
    ("unicode_sub", "unicode_sub_converter", {}),
    ("arabic_presentation_form", "arabic_presentation_form_converter", {}),
    ("arabizi", "arabizi_converter", {}),
    ("character_space", "character_space_converter", {}),
    ("charswap", "charswap_attack_converter", {}),
    ("char_noise", "char_noise_converter", {}),
    ("insert_punctuation", "insert_punctuation_converter", {}),
    ("random_capital", "random_capital_letters_converter", {}),
    ("string_join", "string_join_converter", {}),
    ("json_string", "json_string_converter", {}),
    ("url", "url_converter", {}),
    ("ascii_art", "ascii_art_converter", {}),
    ("acrostic", "acrostic_converter", {}),
    ("first_letter", "first_letter_converter", {}),
    ("math_obfuscation", "math_obfuscation_converter", {}),
    ("sata_masking", "sata_masking_converter", {}),
    ("negation_trap", "negation_trap_converter", {}),
    ("ask_to_decode", "ask_to_decode_converter", {}),
    ("task_framing", "task_framing_converter", {}),
    ("template_segment", "template_segment_converter", {}),
    ("policy_puppetry", "policy_puppetry_converter", {}),
    ("suffix_append", "suffix_append_converter", {"suffix": " 谢谢。"}),
    ("repeat_token", "repeat_token_converter",
     {"token_to_repeat": ".", "times_to_repeat": 40}),
    ("search_replace", "search_replace_converter",
     {"pattern": "a", "replace": "@"}),
    ("colloquial_wordswap", "colloquial_wordswap_converter", {}),
]

# 这些不是坏了，是要一个 LLM 才能干活，单独统计
LLM_CONVERTERS = {
    "translation", "random_translation", "scientific_translation", "tone", "tense",
    "persuasion", "decomposition", "denylist", "ipa", "math_prompt", "noise",
    "variation", "llm_generic_text", "malicious_question_generator",
    "toxic_sentence_generator", "text_jailbreak", "selective_text",
}

# 图像/音频/文档类：被测对象是文本 agent，用不上，不装 PIL/numpy 也就导不进来
MULTIMODAL_HINT = ("image", "audio", "video", "qr_code", "pdf", "word_doc", "doc")


def _build(name: str, module: str, kwargs: dict):
    """按模块路径实例化。避免 import pyrit.converter.prompt_converter 那种顶层聚合
    （1.x 里叫 pyrit.converter，而且顶层 __init__ 会拽进一堆可选依赖）。"""
    mod = __import__(f"pyrit.converter.{module}", fromlist=["*"])
    from pyrit.converter.converter import Converter
    import inspect
    classes = [o for _n, o in vars(mod).items()
               if inspect.isclass(o) and issubclass(o, Converter)
               and o.__module__ == mod.__name__
               and not inspect.isabstract(o)]
    if not classes:
        raise RuntimeError(f"{module} 里没有可实例化的 Converter 子类")
    return classes[0](**kwargs)


def registry(include_opaque_converters: bool = True) -> tuple[dict, list]:
    """返回 ({名字: 实例}, [失败记录])。失败的照样报出来，不静默吞掉。"""
    inst, fails = {}, []
    for name, module, kwargs in DETERMINISTIC:
        if name == "hex":
            continue
        try:
            inst[name] = _build(name, module, kwargs)
        except Exception as e:  # noqa: BLE001
            fails.append({"name": name, "module": module,
                          "error": f"{type(e).__name__}: {e}"[:200]})
    return inst, fails


# ------------------------------------------------------------------ 标记状态
def _markers_of(case: dict) -> list:
    ms = [str(m) for m in (case.get("markers") or []) if m]
    if case.get("trigger"):
        ms.append(str(case["trigger"]))
    return [m for m in ms if len(m) >= 6]


def _decoders() -> list:
    """和 detectors.py 里能还原的编码保持一致：那里认 b64/hex/ascii85，
    这里多认几个常见的，用来判断"标记是不是只是被编码了"。"""
    def b64_runs(text):
        out = []
        for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
            try:
                out.append(base64.b64decode(m.group(), validate=False).decode("utf-8", "ignore"))
            except (binascii.Error, ValueError):
                pass
        return " ".join(out)

    def hex_runs(text):
        out = []
        for m in re.finditer(r"(?:[0-9a-fA-F]{2}[\s]?){8,}", text):
            try:
                out.append(bytes.fromhex(re.sub(r"\s", "", m.group())).decode("utf-8", "ignore"))
            except ValueError:
                pass
        return " ".join(out)

    return [
        ("b64", b64_runs),
        ("hex", hex_runs),
        ("rot13", lambda t: codecs.decode(t, "rot13")),
        ("url", urllib.parse.unquote),
        ("reverse", lambda t: t[::-1]),
        ("atbash", lambda t: "".join(
            chr(ord("z") - (ord(c) - ord("a"))) if "a" <= c <= "z" else
            chr(ord("Z") - (ord(c) - ord("A"))) if "A" <= c <= "Z" else c
            for c in t)),
    ]


def marker_state(payload: str, markers: list) -> str:
    if not markers:
        return "n/a"
    low = payload.lower()
    if any(m.lower() in low for m in markers):
        return "plain"
    for _how, fn in _decoders():
        try:
            dec = (fn(payload) or "").lower()
        except Exception:  # noqa: BLE001
            continue
        if any(m.lower() in dec for m in markers):
            return "encoded"
    return "opaque"


# -------------------------------------------------------------------- 派生
async def _convert(conv, payload: str) -> str:
    res = await conv.convert_async(prompt=payload, input_type="text")
    out = getattr(res, "output_text", None)
    if out is None:
        out = str(res)
    return out


def _stratified(cases: list, n: int, rng: random.Random) -> list:
    """按判定器分层抽样。直接随机抽会把 611 条里占多数的 compliance 全抽出来，
    结果 100 条样本里 90 条是同一个弱判定器，派生了也判不出东西。"""
    buckets: dict[str, list] = {}
    for c in cases:
        buckets.setdefault(c.get("detector", "?"), []).append(c)
    for v in buckets.values():
        rng.shuffle(v)
    out, keys = [], sorted(buckets)
    while len(out) < n and any(buckets[k] for k in keys):
        for k in keys:
            if buckets[k] and len(out) < n:
                out.append(buckets[k].pop())
    return out


async def derive(cases: list, convs: dict, per_case: int, keep_opaque: bool,
                 seed: int) -> tuple[list, dict]:
    rng = random.Random(seed)
    names = sorted(convs)
    out, stat = [], {"derived": 0, "opaque_dropped": 0, "conv_fail": 0,
                     "by_converter": {}, "by_state": {}, "by_detector": {},
                     "usable": 0}
    for case in cases:
        payload = case.get("payload") or ""
        markers = _markers_of(case)
        # 每条用例轮换起点，避免永远是前 k 个 converter 被选中
        start = rng.randrange(len(names)) if names else 0
        picked = [names[(start + i) % len(names)] for i in range(min(per_case, len(names)))]
        for cname in picked:
            conv = convs[cname]
            try:
                new_payload = await _convert(conv, payload)
            except Exception as e:  # noqa: BLE001
                stat["conv_fail"] += 1
                continue
            if not new_payload or new_payload.strip() == payload.strip():
                continue
            state = marker_state(new_payload, markers)
            if state == "opaque" and not keep_opaque:
                stat["opaque_dropped"] += 1
                continue
            idx = len(out) + 1
            d = dict(case)
            d["id"] = f"{case['id']}-P{idx:04d}"
            d["name"] = f"{case.get('name', '')[:60]}·{cname}"[:80]
            d["payload"] = new_payload
            d["derived_from"] = case["id"]
            d["transform"] = {"framework": "pyrit", "converter": cname,
                              "marker_state": state}
            out.append(d)
            stat["derived"] += 1
            stat["by_converter"][cname] = stat["by_converter"].get(cname, 0) + 1
            stat["by_state"][state] = stat["by_state"].get(state, 0) + 1
            det = case.get("detector", "?")
            stat["by_detector"][det] = stat["by_detector"].get(det, 0) + 1
            # "可判"= 有明确证据面，且标记没被打碎
            if state in ("plain", "encoded", "n/a") and det not in ("compliance",):
                stat["usable"] += 1
            # 给个进度感，几百条的时候不至于以为卡死
            if stat["derived"] % 200 == 0:
                print(f"  ... 已派生 {stat['derived']} 条", file=sys.stderr)
    return out, stat


def load_cases(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith((".yaml", ".yml")):
            return yaml.safe_load(f) or []
        return [json.loads(l) for l in f if l.strip()]


async def main_async() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="seeds/garak_cases.yaml")
    ap.add_argument("-o", "--out", default="seeds/pyrit_cases.yaml")
    ap.add_argument("--sample", type=int, default=0,
                    help="从基础用例里分层抽多少条（0=全量，慎用：611×49 会炸）")
    ap.add_argument("--per-case", type=int, default=8,
                    help="每条基础用例派生多少种变异")
    ap.add_argument("--only", default="", help="只用这些 converter，逗号分隔")
    ap.add_argument("--only-detectors", default="",
                    help="只变异这些判定器的用例，如 marker,xss,credential")
    ap.add_argument("--skip-detectors", default="oast",
                    help="跳过这些判定器（默认 oast：带外信标依赖 URL 原样，"
                         "编码后 beacon 回连不上，变异只会制造假阴性）")
    ap.add_argument("--budget-hours", type=float, default=0,
                    help="按上轮实测 110s/条截断，保证这批能跑完（0=不限）")
    ap.add_argument("--keep-opaque", action="store_true",
                    help="保留标记被打碎的变异（现有判定器看不见，默认剔除）")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--list", action="store_true", help="只列 converter 可用性")
    args = ap.parse_args()

    convs, fails = registry()
    if args.only:
        want = [x.strip() for x in args.only.split(",") if x.strip()]
        convs = {k: v for k, v in convs.items() if k in want}

    if args.list:
        print(f"可用确定性 converter：{len(convs)}")
        for k in sorted(convs):
            print("  " + k)
        if fails:
            print(f"\n构造失败：{len(fails)}")
            for f in fails:
                print(f"  {f['name']:26} {f['error']}")
        print(f"\n需要 LLM 才能跑（未启用）：{len(LLM_CONVERTERS)} 个 —— "
              + ", ".join(sorted(LLM_CONVERTERS)))
        return

    cases = load_cases(args.inp)
    only_d = {x.strip() for x in args.only_detectors.split(",") if x.strip()}
    skip_d = {x.strip() for x in args.skip_detectors.split(",") if x.strip()}
    before = len(cases)
    if only_d:
        cases = [c for c in cases if c.get("detector") in only_d]
    if skip_d:
        cases = [c for c in cases if c.get("detector") not in skip_d]
    if len(cases) != before:
        print(f"按判定器过滤：{before} → {len(cases)} 条基础用例")
    if args.sample and args.sample < len(cases):
        cases = _stratified(cases, args.sample, random.Random(args.seed))
    print(f"基础用例 {len(cases)} 条 × 最多 {args.per_case} 种变异 "
          f"（可用 converter {len(convs)}）")

    out, stat = await derive(cases, convs, args.per_case, args.keep_opaque, args.seed)
    stat["final"] = len(out)

    # 跑测成本是这条流水线的真瓶颈：上轮实测 deepseek-r1:7b-8k 约 110s/条。
    # 派生 500 条看着爽，实际要跑 15 小时——所以允许按时间预算截断，
    # 截断顺序按判定强度排：先留 marker/canary 这类能给出硬证据的。
    if args.budget_hours > 0:
        strong = ["canary", "marker", "tool_abuse", "replay", "xss",
                  "credential", "ansi", "compliance"]
        rank = {k: i for i, k in enumerate(strong)}
        out.sort(key=lambda c: rank.get(c.get("detector"), 99))
        cap = int(args.budget_hours * 3600 / 110)
        if len(out) > cap:
            stat["budget_cut"] = len(out) - cap
            out = out[:cap]
        stat["final"] = len(out)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        yaml.safe_dump(out, f, allow_unicode=True, sort_keys=False, width=100)

    print(f"派生 {stat['derived']} 条，最终写入 {stat['final']} 条 → {args.out}")
    print(f"  可判派生    {stat['usable']}（标记 intact 且判定器有证据面）")
    print(f"  标记打碎丢弃 {stat['opaque_dropped']}")
    print(f"  转换报错    {stat['conv_fail']}")
    print("  标记状态：" + ", ".join(f"{k}={v}" for k, v in sorted(stat["by_state"].items())))
    print("  判定器分布：" + ", ".join(
        f"{k}={v}" for k, v in sorted(stat["by_detector"].items(), key=lambda x: -x[1]))[:300])
    print("  converter 覆盖：" + ", ".join(
        f"{k}={v}" for k, v in sorted(stat["by_converter"].items(), key=lambda x: -x[1]))[:400])
    if fails:
        print(f"  ⚠️ {len(fails)} 个 converter 构造失败（见 --list）")
    if stat.get("budget_cut"):
        print(f"  按预算截断 -{stat['budget_cut']} 条（保留判定强度高的）")
    # 跑测成本要和载荷数一起报，否则又会变成"载荷很好看、跑不完"
    est_h = stat["final"] * 110 / 3600      # 上一轮实测 ≈110s/条（deepseek-r1:7b-8k）
    print(f"\n按上轮实测 110s/条估算，跑完需要 {est_h:.1f} 小时。"
          f"要么减少 --sample，要么走 --limit。")


if __name__ == "__main__":
    asyncio.run(main_async())
