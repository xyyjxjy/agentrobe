"""AutoScan 流水线：把 evolve.py 引擎包装成一键式自动化平台。

状态机：
    probe（探测目标能力）
      → select（自动选判定器/用例子集）
      → campaign（调 evolve.py 跑测评+变异+收敛）
      → advise（生成加固建议）
      → done

进度可查：JobStatus 对象在内存里维护，Web 层轮询即可。
用子进程跑 evolve.py CLI，通过 partial.json 实时读进度——不污染引擎全局状态。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

from autoscan.advice import generate_advice, render_advice_md

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(ROOT, "runs", "autoscan")

# server 用 .venv-owui 起（那里有 fastapi），但 evolve.py 的依赖（httpx/openai/yaml）
# 装在系统 python 里。所以子进程固定用系统 python，不能用 sys.executable。
def _detect_python() -> str:
    import shutil
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "python.exe"),
        shutil.which("python") or "python",
        sys.executable,
    ]
    for cand in candidates:
        if not cand or not os.path.exists(cand):
            continue
        try:
            r = subprocess.run([cand, "-c",
                                "import evolve, transport, yaml, openai"],
                               cwd=ROOT, capture_output=True, timeout=10)
            if r.returncode == 0:
                return cand
        except Exception:  # noqa: BLE001
            continue
    return sys.executable

PYTHON = _detect_python()


@dataclass
class JobStatus:
    id: str
    target: str
    state: str = "queued"        # queued/probe/select/campaign/advise/done/error
    stage_detail: str = ""
    progress: dict = field(default_factory=dict)
    result: dict | None = None
    advice_md: str = ""
    report_md: str = ""
    error: str = ""
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "target": self.target, "state": self.state,
            "stage_detail": self.stage_detail, "progress": self.progress,
            "result": self.result, "advice_md": self.advice_md,
            "report_md": self.report_md, "error": self.error,
            "elapsed": round(time.time() - self.created, 1),
        }


class AutoScan:
    def __init__(self, max_concurrent: int = 2):
        self.jobs: dict[str, JobStatus] = {}
        self._lock = threading.Lock()
        self.max_concurrent = max_concurrent
        self._running = 0

    def submit(self, target: str, demo: bool = False, rounds: int = 2,
               strength: str = "strong", workers: int = 4) -> str:
        jid = uuid.uuid4().hex[:10]
        job = JobStatus(id=jid, target=target)
        with self._lock:
            self.jobs[jid] = job
        t = threading.Thread(target=self._run, args=(job, demo, rounds,
                                                     strength, workers), daemon=True)
        t.start()
        return jid

    def get(self, jid: str) -> JobStatus | None:
        return self.jobs.get(jid)

    def _set(self, job: JobStatus, state: str, detail: str = "") -> None:
        job.state = state
        job.stage_detail = detail
        job.updated = time.time()

    def _run(self, job: JobStatus, demo: bool, rounds: int,
             strength: str, workers: int) -> None:
        out = os.path.join(RUNS, f"{job.id}.json")
        partial = out + ".partial.json"
        os.makedirs(RUNS, exist_ok=True)
        # 清理可能存在的旧产物（新 job id 一般不会有，但重跑/重试时有用）
        for stale in (out, partial):
            if os.path.exists(stale):
                try:
                    os.remove(stale)
                except OSError:
                    pass
        try:
            # ① 探测：demo 模式用内置靶子；真实 URL 用 capabilities 端点探测
            self._set(job, "probe", "正在探测目标能力...")
            cap = self._probe(job, demo)
            job.progress["capabilities"] = cap

            # ② 选型：根据能力自动决定判定器强度
            self._set(job, "select", "根据探测结果选择判定器...")
            usable = cap.get("supported", [])
            chosen = self._select_strength(strength, usable, demo)
            job.progress["selected_strength"] = chosen
            job.progress["usable_detectors"] = usable

            # ③ 测评：子进程跑 evolve.py，轮询 partial 读进度
            self._set(job, "campaign", "开始自动化测评与变异...")
            result = self._campaign(job, demo, out, partial, rounds, chosen, workers)
            job.result = result

            # ④ 建议
            self._set(job, "advise", "分析攻破类型，生成加固建议...")
            adv = generate_advice(result)
            job.advice_md = render_advice_md(adv, job.target)
            job.report_md = self._render_report(result)

            self._set(job, "done", "完成")
            job.updated = time.time()
        except Exception as e:  # noqa: BLE001
            self._set(job, "error", f"{type(e).__name__}: {e}")
            job.error = str(e)

    def _probe(self, job: JobStatus, demo: bool) -> dict:
        if demo:
            return {
                "transport": "builtin-demo-target",
                "kind": "http",
                "supported": ["marker", "credential", "xss", "ansi",
                              "tool_abuse", "tool_goal", "replay"],
                "note": "内置演示靶子：返回 answer + tool_calls，可判工具滥用",
            }
        # 真实目标：http GET /capabilities，没有就降级为只有 answer 级判定
        import urllib.request
        base = self._base_url(job.target)
        url = base + "/capabilities"
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read().decode())
                return {"transport": job.target, "kind": "http",
                        "supported": data.get("supported", ["marker", "xss", "credential"]),
                        "source": "target /capabilities"}
        except Exception:  # noqa: BLE001
            return {"transport": job.target, "kind": "http",
                    "supported": ["marker", "xss", "credential", "ansi", "replay"],
                    "source": "默认 answer 级（目标未提供能力声明）"}

    @staticmethod
    def _base_url(target: str) -> str:
        """把用户填的 URL 规范化成 /chat 端点所在的 base。

        用户常填 http://host 或 http://host/chat 或 http://host/v1/chat，
        HTTPTarget 要求完整 URL，所以要认出端点、补上 /chat。
        """
        t = target.rstrip("/")
        if t.endswith("/chat"):
            return t[:-5]
        return t

    @staticmethod
    def _select_strength(requested: str, usable: list, demo: bool) -> str:
        # 只保留"目标能提供证据"且是 strong 的判定器；weak 不进主表
        return requested or "strong"

    def _campaign(self, job: JobStatus, demo: bool, out: str, partial: str,
                  rounds: int, strength: str, workers: int) -> dict:
        transport = "http"
        if demo:
            # 内置靶子：起 demo_target 服务，端点 /chat
            from autoscan.demo_target import ensure_server
            url = ensure_server() + "/chat"
        else:
            # 真实目标：规范化后补 /chat（HTTPTarget 投递到这个端点）
            url = self._base_url(job.target) + "/chat"
        cmd = [PYTHON, os.path.join(ROOT, "evolve.py"), "run",
               "--transport", transport, "--url", url,
               "--cases", "runs/mut_s100_cases.yaml",
               "--rounds", str(rounds), "--variants", "1",
               "--strength", strength, "--workers", str(workers),
               "--case-timeout", "60", "--checkpoint-every", "2",
               "--out", out]
        # stdout 重定向到日志文件，绝不用 PIPE 却不消费——
        # 管道缓冲满会阻塞子进程，这是之前任务跑到一半就"消失"的根因。
        log_path = out + ".log"
        with open(log_path, "w", encoding="utf-8") as logf:
            proc = subprocess.Popen(cmd, cwd=ROOT, stdout=logf,
                                    stderr=subprocess.STDOUT)
            # 读日志提取进度，绝不打开 partial.json——
            # 打开 partial 会与子进程的 os.replace 竞争，Windows 上导致 WinError 5。
            import re
            while proc.poll() is None:
                try:
                    with open(log_path, encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()[-40:]
                    n_broken = 0
                    cur_round = 0
                    for ln in lines:
                        if "攻破" in ln or "鉁?攻破" in ln:
                            n_broken += 1
                        m = re.search(r"轮次\s*(\d+)", ln)
                        if m:
                            cur_round = max(cur_round, int(m.group(1)))
                    if n_broken or cur_round:
                        job.progress["broken_so_far"] = n_broken
                        job.progress["round"] = cur_round
                        self._set(job, "campaign",
                                  f"轮次 {cur_round} · 累计攻破 {n_broken} 条")
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(1)
            rc = proc.wait()
        if not os.path.exists(out):
            tail = ""
            if os.path.exists(log_path):
                with open(log_path, encoding="utf-8", errors="replace") as f:
                    tail = "\n".join(f.read().splitlines()[-8:])
            raise RuntimeError(
                f"测评引擎未产出结果文件（returncode={rc}）。日志尾部：{tail}")
        with open(out, encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _render_report(result: dict) -> str:
        s = result.get("summary", {})
        lines = ["# AgentProbe 自动化测评报告", "",
                 f"- 模型：`{result.get('meta', {}).get('model', '?')}`",
                 f"- 可判：{s.get('judgeable', 0)} 条",
                 f"- 攻破：{s.get('final_broken', 0)} 条",
                 f"- ASR：{s.get('final_asr', '?')}%",
                 f"- 轮次：{s.get('rounds', '?')}（{s.get('stop_reason', '?')}）",
                 "", "## 分层", "", "| 强度 | 攻破/总数 | ASR |",
                 "|---|---:|---:|"]
        for tier, d in (s.get("by_strength") or {}).items():
            lines.append(f"| {tier} | {d.get('broken', 0)}/{d.get('total', 0)} | "
                         f"{d.get('asr', '?')}% |")
        return "\n".join(lines)
