"""autoscan — AgentProbe 的一键式自动化测评平台。

给一个目标 URL，自动完成：
    探测能力 → 选择判定器 → 测评+变异+收敛 → 出报告 → 生成加固建议

与 evolve.py 的关系：evolve.py 是引擎（CLI），autoscan 是编排层（平台）。
平台用子进程调引擎，通过 partial.json 读进度——不污染引擎的全局状态。

用法：
    python -m autoscan.server           # Web 平台 http://127.0.0.1:8400
    python -m autoscan.pipeline --url http://... --demo   # 命令行一键跑
"""

from autoscan.pipeline import AutoScan, JobStatus

__all__ = ["AutoScan", "JobStatus"]
