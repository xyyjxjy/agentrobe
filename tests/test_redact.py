"""落盘打码的回归测试。

来历：2026-11-11，路径穿越用例 T-01 真的读到了 .env，被测模型把
`LLM_API_KEY=sk-...` 原样复述进回答，这份回答被存进 runs/*.json，
随后被我提交进了 git。等于"自己测出来的漏洞"把部署凭据写进了仓库。

修复分两层，这里测第二层：
    1. 落盘前统一打码（evolve._redact）——本文件
    2. 仓库守卫（CI 的 guards job）扫 git 历史里有没有 sk- 形态的串
"""

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from evolve import _redact  # noqa: E402


# 占位串故意写成「带连字符、不像真 key」的样子：
#   - 能被 _redact 的 sk-[A-Za-z0-9_\-]{12,} 命中，测试照常有效
#   - 不会触发仓库密钥扫描（那条正则只认 sk- 后一串纯字母数字）
# 真实密钥绝不能出现在本仓库，包括测试夹具——历史上已经踩过一次。
FAKE_KEY = "sk-placeholder-not-a-real-key-0000"


class TestRedact(unittest.TestCase):
    def test_masks_openai_style_key(self):
        out = _redact(f"LLM_API_KEY={FAKE_KEY}")
        self.assertNotIn("placeholder", out)
        self.assertIn("REDACTED", out)

    def test_masks_assignment_forms(self):
        for text in ("api_key: abcdefghijklmnop123456",
                     "API_KEY=abcdefghijklmnop123456",
                     "secret = abcdefghijklmnop123456"):
            out = _redact(text)
            self.assertNotIn("abcdefghijklmnop123456", out, text)

    def test_keeps_ordinary_text(self):
        for text in ("正常回答，没有任何凭据",
                     "文件里没有数据库配置",
                     "sk-"):
            self.assertEqual(_redact(text), text)

    def test_output_still_valid_json(self):
        """打码发生在 JSON 序列化之前，不能把引号搞坏。"""
        payload = {"answer": f'他说 "LLM_API_KEY={FAKE_KEY}" 在这里'}
        text = json.dumps({"answer": _redact(payload["answer"])}, ensure_ascii=False)
        self.assertEqual(json.loads(text)["answer"].count("REDACTED"), 1)


if __name__ == "__main__":
    unittest.main()
