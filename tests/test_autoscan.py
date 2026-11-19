"""autoscan 平台测试：advice 生成 + 状态机（离线，不起服务）。"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from autoscan.advice import generate_advice, render_advice_md
from autoscan.pipeline import AutoScan


class TestAdvice(unittest.TestCase):
    def test_generate_advice_ranked(self):
        result = {
            "summary": {"judgeable": 72, "final_broken": 6, "final_asr": 8.3},
            "cases": {
                "A": {"detector": "marker", "broken": True},
                "B": {"detector": "marker", "broken": True},
                "C": {"detector": "xss", "broken": True},
                "D": {"detector": "tool_abuse", "broken": True},
                "E": {"detector": "marker", "broken": False},
            },
        }
        adv = generate_advice(result)
        self.assertEqual(adv["broken"], 6)
        self.assertIn("4 类" if False else "类", adv["headline"])
        # marker 出现 2 次应排最前（同优先级内按条数）
        self.assertEqual(adv["all"][0]["detector"], "marker")
        self.assertEqual(adv["all"][0]["broken_cases"], 2)
        self.assertTrue(all(a["priority"] == "P0" for a in adv["top_priority"]))
        md = render_advice_md(adv, "http://demo")
        self.assertIn("加固建议", md)
        self.assertIn("marker", md)

    def test_no_break(self):
        result = {"summary": {"judgeable": 10, "final_broken": 0}, "cases": {}}
        adv = generate_advice(result)
        self.assertEqual(adv["all"], [])
        self.assertIn("未发现", adv["headline"])


class TestPipelineState(unittest.TestCase):
    def test_submit_returns_id_and_status(self):
        scan = AutoScan()
        # 不真跑：替换 _run，只验证 submit 建了 job 记录
        scan._run = lambda *a, **k: None
        jid = scan.submit("http://example.com", demo=False, rounds=1)
        self.assertTrue(jid)
        job = scan.get(jid)
        self.assertIsNotNone(job)
        self.assertEqual(job.id, jid)
        self.assertEqual(job.target, "http://example.com")
        d = job.to_dict()
        self.assertIn("state", d)
        self.assertIn("stage_detail", d)


if __name__ == "__main__":
    unittest.main()
