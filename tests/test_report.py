"""report.py 的渲染规则测试。

这里锁三条行为，都是踩过的坑：
    1. is_mock 的运行必须落到独立区块，不许混进结论表。
    2. 旧格式（summary 没有 skipped_runtime）必须被标成不可引用。
    3. 样本量不足时必须写出"只能当参考"，而不是安静地给个百分比。
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import report  # noqa: E402


def _case(broken=False):
    return {"ID": {"id": "X-01", "name": "测试用例", "category": "direct_injection",
                   "detector": "canary", "payload": "p", "broken": broken,
                   "attempt_only": False, "variants": [],
                   "seed": {"success": broken, "reason": "命中标记"}}}


def _summary(**kw):
    base = {"is_mock": False, "judgeable": 40, "final_asr": 5.0, "seed_asr": 5.0,
            "final_broken": 2, "variants": 10, "rounds": 2, "skipped": 0,
            "skipped_preflight": 0, "skipped_runtime": 0,
            "stop_reason": "收敛", "by_strength": {}, "family": {},
            "attempt_only": 0}
    base.update(kw)
    return base


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, name, summary, model="m1", cases=None):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "rounds": [], "cases": cases or _case(),
                       "meta": {"model": model, "ts": "2026-01-01 00:00:00"}}, f)
        return p

    def test_mock_goes_to_separate_section(self):
        real = self._write("real_a.json", _summary())
        mock = self._write("mock_b.json", _summary(is_mock=True))
        text = report.build([real, mock])
        self.assertIn("干跑记录（不构成任何安全结论）", text)
        # 干跑那次不能出现在"全部运行一览"的结论表里带百分比
        overview = text.split("## 数据卫生检查")[0]
        self.assertIn("**干跑**", overview)

    def test_legacy_record_flagged(self):
        legacy = _summary(skipped=119)
        del legacy["skipped_runtime"]
        p = self._write("real_old.json", legacy)
        text = report.build([p])
        self.assertIn("旧格式记录", text)
        self.assertIn("不能作为证据引用", text)

    def test_small_sample_warned(self):
        p = self._write("real_small.json", _summary(judgeable=12, final_broken=1,
                                                    final_asr=8.3))
        text = report.build([p])
        self.assertIn("只能当参考，不能当结论", text)

    def test_strength_split_rendered(self):
        bs = {"strong": {"total": 11, "broken": 0, "asr": 0.0, "detectors": ["canary"]},
              "weak": {"total": 5, "broken": 1, "asr": 20.0, "detectors": ["compliance"]}}
        p = self._write("real_bs.json", _summary(by_strength=bs))
        text = report.build([p])
        self.assertIn("| strong | 0/11 |", text)
        self.assertIn("只能当线索", text)


    def test_gain_section_attributes_operator(self):
        """变异收益必须写出「是哪个算子第一次打穿的」。"""
        cases = {
            "A-01": {"id": "A-01", "name": "种子就打穿", "detector": "marker",
                     "broken": True, "attempt_only": False, "variants": [],
                     "seed": {"success": True, "reason": "命中标记"}},
            "A-02": {"id": "A-02", "name": "靠变异打穿", "detector": "marker",
                     "broken": True, "attempt_only": False,
                     "seed": {"success": False, "reason": "未命中"},
                     "variants": [{"op": "split", "success": True, "reason": "命中"},
                                  {"op": "b64", "success": True, "reason": "命中"}]},
        }
        p = self._write("real_gain.json", _summary(final_broken=2), cases=cases)
        text = report.build([p])
        self.assertIn("变异收益（1 条靠变异打穿）", text)
        self.assertIn("`split`×1", text)
        self.assertNotIn("`b64`×1", text, "同一用例只记第一次打穿的算子")


if __name__ == "__main__":
    unittest.main()
