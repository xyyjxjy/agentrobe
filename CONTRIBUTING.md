# 贡献

## 先跑起来

```bash
pip install -r requirements.txt
python -m unittest discover -s tests     # 75 条，全离线，约 5 秒
```

测试是 `unittest` 风格，不需要装 pytest。全部离线，不调模型、不联网——如果你发现某条测试要联网，那是 bug。

## 加一个判定器

判定器是这个项目唯一的技术核心。门槛故意设高：**新判定器必须能被证伪**，加进去之前先想清楚"什么样的回答会被它误判"。

三步：

**1. 写函数**（`detectors.py`）

```python
def detect_xxx(trace: dict) -> dict:
    """一句话说清判据。"""
    answer = trace.get("answer") or ""
    hits = [...]
    return {
        "success": bool(hits),
        "attempt": False,          # True = 只有越界尝试，没真生效
        "reason": "...",
        "evidence": hits[:8],
    }
```

**2. 注册两处**

- `DETECTORS`：名字 → 函数
- `DETECTOR_META`：`{"strength": ..., "cap": ..., "hint": ...}`

`cap` 决定这个判定器需要什么接入能力（`answer` / `tools` / `oast`）。拿不到就标 SKIPPED，**不要退化成"判失败"**。

**3. 加测试**（`tests/test_detectors.py`）

至少一个正例、一个反例。反例更重要——只测"能命中"等于没测。

### 强度怎么选

| 强度 | 标准 | 后果 |
|---|---|---|
| `strong` | 零误报，判据在被测系统之外 | 能直接进 ASR |
| `medium` | 有已知假阳性，但方向明确 | 单独统计，不混算 |
| `weak` | 需要人工复核 | 不进 ASR，只当线索 |

选 `strong` 意味着你愿意为它的每一次误报负责。拿不准就往下选一档。

判据优先级：**能看行为就不看文本，能看固定串就不看语义**。「让模型判断算不算攻破」是最后手段，而且必须按 `calibrate.py` 的路子标过 gold 集才能用。

## 加用例

```yaml
- id: D-13                  # 前缀表类别：D 直接注入 / I 间接 / S 提示泄露 / T 工具越权
  category: direct_injection
  owasp: LLM01              # OWASP LLM Top 10 (2025)
  name: 一句话说明
  detector: marker          # 必须是 DETECTOR_META 里已注册的名字
  note: 这条在测什么
  payload: |
    载荷原文
```

`detector` 写错名字不会报错，这条用例会静默失效——CI 有一条 guard 专门查这个。

## 提交前

```bash
python -m unittest discover -s tests
git grep -nE 'sk-[A-Za-z0-9]{16,}' -- . ':!*.md' ':!NOTICE'    # 必须为空
```

另外两条 CI 会挡：

- HarmBench 的派生数据不能入库（许可不允许再分发，只保留下载器）
- 用例里引用的判定器必须存在

## 两条踩过的坑

**别把真实密钥写进测试夹具。** 写过一次，还是拿正在用的那把。要样例就写 `sk-placeholder-not-a-real-key-0000`——带连字符的形式既能被判定器正则命中，又不会触发仓库密钥扫描。

**别为了让数字好看缩小分母。** 判定不了的用例标 SKIPPED 是对的，把它从"可判"里悄悄挪走、或者干脆不算进总数，就是另一回事了。这个项目里所有百分比的分母都是"可判条数"，改了要说明。
