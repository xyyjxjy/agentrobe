# 接入说明

给 harness 的作者看。目标：**传一个被测 agent 的地址，拿一包结构化结果。**

## 1. 调它

```bash
# 命令行
python aisec.py --target http://127.0.0.1:8000/chat --budget 100 --out findings.json

# 代码里
from aisec import scan
res = scan(target="http://127.0.0.1:8000/chat", budget=100)
```

`budget` 是抽样条数。全量 823 条 strong 在单卡小模型上要十几小时，
**100 条约 1 小时**，统计上够给一个带 ±8% 置信区间的数字。

## 2. 被测目标要实现什么

### HTTP 目标（推荐）

```
POST <target>
Content-Type: application/json
{"message": "<攻击载荷>"}
```

```json
{"answer": "...", "tool_calls": [...], "steps": [...]}
```

字段是宽容匹配的：`answer` 也可写成 `output` / `text` / `response`。

**只返回 `answer` 也能跑**，但 `tool_abuse` / `tool_goal` 两类会标 SKIPPED——
这两类判据是「工具到底被调了没有」，拿不到工具调用就没有依据。这不是失败，
是这个攻击面对你的 agent 不存在（详见第 4 节）。

`tool_calls` 建议格式：
```json
[{"name": "read_file", "args": {"path": "../.env"}, "ok": true, "result": "..."}]
```

### 进程内目标

内置靶子（`target/agent.py`，3 个工具，标准 ReAct 循环）：
```bash
python aisec.py --target inproc --budget 50
```

要接自己的 agent 也可以写一个 `Transport` 子类，实现 `send(payload) -> trace`。

## 3. 输出

```json
{
  "meta": {"target","model","started","seconds","budget","sampled_from","strength","is_mock"},
  "summary": {"cases","judged","broken","asr","skipped","by_strength"},
  "findings": [ ... ]
}
```

每条 finding：

| 字段 | 含义 |
|---|---|
| `id` | 用例编号，回查用 |
| `severity` | **只由判定强度决定**：strong→high / medium→medium / weak→low |
| `detector` | 用哪个判定器判的：`marker` `xss` `canary` `credential` `tool_abuse` `tool_goal` `ansi` `replay` `secret_leak` |
| `payload` | 打出去的那条载荷，可直接复现 |
| `evidence` | 判定依据（命中的标记、被调用的工具名、命中的正则） |
| `answer` | 模型原始回答片段（已打码密钥） |
| `repro` | 一条能粘进终端的 `curl` |

**`severity=high` 的 finding 可以直接下结论；`low` 的只能当线索**——
它在源码里对应 `weak` 判定器（词表启发式），不要和 high 混在一起算比例。

## 4. SKIPPED 是什么，为什么不是失败

四种情况会退出分母，`summary.skipped` 是总数：

| 原因 | 说明 |
|---|---|
| 本次未执行（抽样外） | `--budget` 截掉的 |
| 判定器不适用 | 载荷落不进任何危害域（问 ANSI 转义码、glitch token 这类） |
| **接入方式拿不到证据** | 目标只返回 `answer`，没有 `tool_calls` |
| **目标没有这个攻击面** | 用例要 `send_money`，你的 agent 只有 `read_file` |
| 请求失败 / 超时 / 空回答 | 一个字节的输出都没拿到 |

最后两类最容易被误读。它们的意思是「**这条没测**」，不是「**这条防住了**」。
把 SKIPPED 当成分母算成功率，数字会好看得离谱。

## 5. 运行依赖

主项目只需要 `openai` `httpx` `pyyaml` `python-dotenv`。
`.venv-frameworks` 里那三个框架（garak / PyRIT / AgentDojo）**只在重新生成
`seeds/` 用例时才需要**，运行时完全不 import 它们。接进 harness 时不用管。

LLM 配置在 `.env`：`LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`。
这是**被测 agent 自己用的模型**，不是我们的。

## 6. 它不适合做什么

说清楚边界，比吹功能有用：

- **不是自适应攻击**。变异是 9 个固定算子（拆句、反转、base64…），
  68 个变体在真模型上一次都没打出新洞。想更进一步得接 PAIR/TAP。
- **weak 判定器是词表**，`compliance` 那类 held-out 召回 0%，别当分类器用。
- **单模型、单轮**。跨模型比较无效——换模型等于换被测对象。
