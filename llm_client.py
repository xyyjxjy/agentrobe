"""统一的 LLM 调用入口。

设计要点（面试可以讲）：
    用 OpenAI 兼容协议做抽象，所以本地 Ollama、DeepSeek、通义、OpenAI
    都能通过改环境变量切换，不用改一行代码。
    跑 45 条用例 × 加固前后两轮 = 90+ 次调用，本地模型在成本上优势明显。
"""

import os
import time

import httpx
from openai import OpenAI

_client = None
_call_count = 0
_total_tokens = 0

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
        http_client = httpx.Client(trust_env=not is_local, timeout=180.0)
        _client = OpenAI(
            api_key=os.getenv("LLM_API_KEY", "ollama"),
            base_url=base,
            http_client=http_client,
        )
    return _client


def reset_client() -> None:
    """切换模型/地址后需要重建客户端。"""
    global _client
    _client = None


def model_name() -> str:
    return os.getenv("LLM_MODEL", "qwen2.5:7b")


def chat(messages: list[dict], temperature: float = 0.0, max_retries: int = 2,
         max_tokens: int | None = None) -> str:
    """单轮对话，返回纯文本。异常会重试，避免个别超时打断整批测试。

    【性能关键】max_tokens 一定要设。
    deepseek-r1 这类推理模型会先生成一大段思考再回答，
    不设上限时单次调用可能吐 2000+ token，在 7B 本地模型上就是几十秒。
    我们只关心它最终的动作/回答，思考过程纯属浪费。
    """
    global _call_count, _total_tokens
    mt = max_tokens or int(os.getenv("LLM_MAX_TOKENS", "512"))
    last_err = None
    for attempt in range(max_retries + 1):
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
            return resp.choices[0].message.content or ""
        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt < max_retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"LLM 调用失败（已重试 {max_retries} 次）：{last_err}")


def stats() -> dict:
    return {"calls": _call_count, "tokens": _total_tokens}
