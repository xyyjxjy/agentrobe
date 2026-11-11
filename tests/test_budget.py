"""推理吃满预算时必须自动加大预算重发，不能把空 content 当成回答。

实测（sensenova-6.8-flash-lite，G-0324）：
    max_tokens=2048 → finish=length, content="", reasoning=2048
    max_tokens=8192 → finish=stop,  content 正常
245 条（占分母 32%）的「空回答」全是这么来的：不是模型拒答，
是我们自己的预算盖住了它。这一层不修，等于用自己的配置给被测模型免死。
"""

import os
import sys
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import llm_client  # noqa: E402


def _resp(content: str, finish: str, total: int = 100):
    return SimpleNamespace(
        choices=[SimpleNamespace(finish_reason=finish,
                                 message=SimpleNamespace(content=content))],
        usage=SimpleNamespace(total_tokens=total,
                              completion_tokens_details=None),
    )


class FakeClient:
    """按顺序吐预设响应，并记下每次收到的 max_tokens。"""

    def __init__(self, seq):
        self.seq = list(seq)
        self.budgets = []
        outer = self

        class _Completions:
            def create(self, **kw):
                outer.budgets.append(kw["max_tokens"])
                return outer.seq.pop(0)

        self.chat = SimpleNamespace(completions=_Completions())


class TestBudgetBump(unittest.TestCase):
    def setUp(self):
        self._orig = llm_client.get_client
        os.environ["LLM_MIN_INTERVAL"] = "0"
        os.environ["LLM_MAX_TOKENS_CEILING"] = "32768"

    def tearDown(self):
        llm_client.get_client = self._orig
        os.environ.pop("LLM_MAX_TOKENS_CEILING", None)

    def _run(self, seq, mt=2048):
        fake = FakeClient(seq)
        llm_client.get_client = lambda: fake
        out = llm_client.chat([{"role": "user", "content": "x"}], max_tokens=mt)
        return out, fake.budgets

    def test_bumps_when_length_and_empty(self):
        out, budgets = self._run([
            _resp("", "length"),          # 推理吃满，content 空
            _resp("真正的回答", "stop"),
        ])
        self.assertEqual(out, "真正的回答")
        self.assertEqual(budgets, [2048, 8192], "应按 4 倍提预算重发")

    def test_no_bump_when_answered(self):
        out, budgets = self._run([_resp("答完了", "stop")])
        self.assertEqual(out, "答完了")
        self.assertEqual(budgets, [2048], "正常回答不该重发")

    def test_bump_only_once(self):
        """连续两次 length 也要停手，不能无限翻倍烧钱。

        提过预算还是空，就老实返回空串——下游会把它记成 SKIPPED，
        而不是继续翻倍把额度烧在一条用例上。
        """
        out, budgets = self._run([
            _resp("", "length"),
            _resp("", "length"),
            _resp("答完了", "stop"),
        ])
        self.assertEqual(budgets, [2048, 8192], "只提一次预算")
        self.assertEqual(out, "", "两次都截断就返回空，交给下游 SKIP")

    def test_finish_reason_readable(self):
        """finish_reason() 必须是函数——常量会在 import 时绑死成空串。"""
        self._run([_resp("x", "stop")])
        self.assertEqual(llm_client.finish_reason(), "stop")


if __name__ == "__main__":
    unittest.main(verbosity=2)
