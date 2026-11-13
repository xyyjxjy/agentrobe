"""统一的 LLM 调用入口。

设计要点（面试可以讲）：
    用 OpenAI 兼容协议做抽象，所以本地 Ollama、DeepSeek、通义、OpenAI
    都能通过改环境变量切换，不用改一行代码。
    跑 45 条用例 × 加固前后两轮 = 90+ 次调用，本地模型在成本上优势明显。
"""

import os
import threading
import time

import httpx
from dotenv import load_dotenv
from openai import OpenAI

# 任何入口都要能拿到 .env（商汤 key / 模型 / 超时），不能依赖外部先 load。
# 踩坑：单独跑一个 import llm_client 的脚本时 .env 没加载，LLM_BASE_URL 落到
# 默认 localhost:11434（本地 Ollama 未运行）→ 报 APIConnectionError，
# 看起来像"商汤挂了"，实际是环境变量没读。load_dotenv 幂等，不覆盖已有值。
load_dotenv()

_client = None
_call_count = 0
last_finish_reason = ""   # 最近一次调用的 finish_reason，供 agent 落盘排查
_total_tokens = 0

# finish_reason 必须是"本线程最后一次调用"的，不能是全局最后一次。
# --workers>1 时同一个进程里多条 agent 会话并行，全局变量会被别的请求覆盖，
# 落盘的 finish 就跟这条载荷对不上了——「预算截断」和「模型自己说完」分不清，
# 而这正是 245 条空回答那个事故的根因。
_finish_tls = threading.local()


def _set_finish(reason: str) -> None:
    global last_finish_reason
    last_finish_reason = reason
    _finish_tls.last = reason

# 全局节流：同一进程内所有调用共用一个时间戳。
# 商汤网关的 token plan 是「低 RPM + 低 TPM」，784 条用例连跑时
# 前 149 条里有 71 条 429（48% 失败率），等于一半的钱和时间都烧在重试上。
# LLM_MIN_INTERVAL 设成秒数即可把请求摊开，默认 0（本地 Ollama 不需要）。
_throttle_lock = threading.Lock()
_last_call_ts = 0.0

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1")


def _base_url() -> str:
    return os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")


def get_client() -> OpenAI:
    """构建客户端。

    本地地址强制不走系统代理，云端地址保留代理。

    【踩坑记录】最初怀疑是系统代理（127.0.0.1:60886）劫持了 localhost，
    实测后确认：代理是正常转发的，真实原因只是 Ollama 服务没启动
    （直连报 WinError 10061，经代理则被转述成 "upstream connect failed"，误导性很强）。
    保留 trust_env=False 是因为确实存在会拦截 localhost 的代理配置，
    属于防御性写法，不是这个 bug 的成因。

    排查提示：判断本地服务是否在跑，必须看直连状态码；
    curl 经代理时即使上游全挂也可能返回 502 且退出码为 0，会骗人。
    """
    global _client
    if _client is None:
        base = _base_url()
        is_local = any(h in base for h in _LOCAL_HOSTS)
        # 单次 HTTP 读超时必须可配：它决定"卡住的请求多久能被判死"。
        # 固定 180s 时，一条卡死的载荷要烧 3 分钟才轮到下一条，而 flash-lite
        # 正常只要 2-20s——90% 的时间花在等一个不会来的响应。
        #
        # 【重要】不要传自定义 http_client=httpx.Client(...)。
        # openai 3.48 + httpx 0.28 下，SDK 对传入的 httpx.Client 处理不兼容，
        # 请求会抛 APIConnectionError（裸 httpx 直连却 200，手动 OpenAI() 不传
        # http_client 也 200——唯一变量就是 http_client 参数）。
        # 改用 SDK 原生 timeout / max_retries，语义相同且稳定。
        _client = OpenAI(
            api_key=os.getenv("LLM_API_KEY", "ollama"),
            base_url=base,
            timeout=float(os.getenv("LLM_HTTP_TIMEOUT", "180") or 180),
            max_retries=0,  # 重试由 chat() 自己控制（_retry_delay 有 Retry-After）
        )
    return _client


def reset_client() -> None:
    """切换模型/地址后需要重建客户端。"""
    global _client
    _client = None


def model_name() -> str:
    return os.getenv("LLM_MODEL", "qwen2.5:7b")


def _throttle() -> None:
    """按 LLM_MIN_INTERVAL 把请求摊开。

    这个函数存在的原因很具体：784 条用例连跑时，前 149 条里有 71 条 429，
    其中 54 条是 `rpm exhausted`。网关的 token plan 只有个位数 RPM，
    而我们的节奏是「一次请求结束立刻发下一条」，于是必然撞墙。

    设 LLM_MIN_INTERVAL=20 就是 3 RPM，宁可慢，不要一半失败。
    """
    gap = float(os.getenv("LLM_MIN_INTERVAL", "0") or 0)
    if gap <= 0:
        return
    global _last_call_ts
    with _throttle_lock:
        wait = _last_call_ts + gap - time.time()
        if wait > 0:
            time.sleep(wait)
        _last_call_ts = time.time()


def _retry_delay(e: Exception, attempt: int) -> float:
    """429 要按服务端的节奏等，不能拍脑袋 1.5 秒。

    优先用 Retry-After；没有就指数退避。限流场景下 retry-after 常见是几十秒，
    之前固定睡 1.5s/3s，等于连续三次撞同一堵墙——重试预算全浪费了。
    """
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            ra = resp.headers.get("retry-after")
            if ra:
                return max(1.0, float(ra))
        except (AttributeError, TypeError, ValueError):
            pass
    return min(90.0, 5.0 * (2 ** attempt))


def chat(messages: list[dict], temperature: float = 0.0, max_retries: int = 5,
         max_tokens: int | None = None) -> str:
    """单轮对话，返回纯文本。异常会重试，避免个别超时打断整批测试。

    【性能关键】max_tokens 一定要设。
    deepseek-r1 这类推理模型会先生成一大段思考再回答，
    不设上限时单次调用可能吐 2000+ token，在 7B 本地模型上就是几十秒。
    我们只关心它最终的动作/回答，思考过程纯属浪费。

    【限流关键】重试次数默认 5 次而不是 2 次：429 不是"调用失败"，
    是"等一会儿就能成功"，重试 2 次（累计等 4.5 秒）根本熬不过 RPM 窗口。
    """
    global _call_count, _total_tokens, last_finish_reason
    mt = max_tokens or int(os.getenv("LLM_MAX_TOKENS", "8192"))
    ceiling = int(os.getenv("LLM_MAX_TOKENS_CEILING", "32768"))
    last_err = None
    bumped = False
    for attempt in range(max_retries + 1):
        _throttle()
        try:
            resp = get_client().chat.completions.create(
                model=model_name(),
                messages=messages,
                temperature=temperature,
                max_tokens=mt,
            )
            _call_count += 1
            if getattr(resp, "usage", None):
                _total_tokens += resp.usage.total_tokens or 0
            choice = resp.choices[0]
            _set_finish(choice.finish_reason)
            content = choice.message.content or ""

            # 空内容 + finish_reason=length = 推理 token 把预算吃光了，
            # 一个字的回答都没轮到。这**不是**「模型拒答」，是我们的预算太小。
            # 实测 G-0324：max_tokens=2048 时 reasoning 正好用满 2048、content 为空；
            # 调到 8192 就吐出完整 XSS 载荷（18.9s vs 卡死）。
            # 之前把这种空回答当成「无判定依据」剔出分母，等于用自己的配置上限
            # 给被测模型送了一次免死金牌——245 条（32%）全是这么来的。
            if not content.strip() and choice.finish_reason == "length" \
                    and mt < ceiling and not bumped:
                bumped = True
                mt = min(ceiling, mt * 4)
                print(f"   ↻ 推理吃满预算（finish=length），预算提到 {mt} 重发", flush=True)
                continue
            return content
        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt < max_retries:
                delay = _retry_delay(e, attempt)
                print(f"   ⏳ 调用失败（{type(e).__name__}），{delay:.0f}s 后重试 "
                      f"{attempt + 1}/{max_retries}", flush=True)
                time.sleep(delay)
    raise RuntimeError(f"LLM 调用失败（已重试 {max_retries} 次）：{last_err}")


def finish_reason() -> str:
    """本线程最近一次调用的 finish_reason。

    必须是函数而不是模块级常量——`from llm_client import last_finish_reason`
    在 import 时就把当时的空串绑死了，之后调用多少次都读到 ""。
    也必须是线程局部的：并发跑批时全局值会被别的会话覆盖（见 _finish_tls）。
    """
    return getattr(_finish_tls, "last", "") or last_finish_reason


def stats() -> dict:
    return {"calls": _call_count, "tokens": _total_tokens}
