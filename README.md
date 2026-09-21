# 冷链告警抑制策略沙盒 (Cold-Chain Alert Suppression Sandbox)

一个可 **Docker 一键启动** 的本地 Web 应用，用于在真实转发前试验冷链告警的抑制/放行策略：

- 导入告警 JSON（设备、批次、级别、时间）
- 编写按 **设备 / 批次 / 级别 / 时间段** 匹配的抑制规则，支持 **显式优先级** 与 **冷却窗口**
- 系统按顺序评估连续告警，输出每条告警的 **放行 (pass) / 抑制 (suppress)** 决定，以及**命中规则与逐条条件的解释**
- 支持 **逐条注入**、**撤销最近注入**、规则变更后的 **策略回放与前后结果对比**
- 内置 **「事件关联」工作台**：按 `device_id + alert_type` 把相邻告警聚合成事件，确认/筛选，乱序与规则修改后**确定性重算**，不改变 live/replay 决定
- 内置 **模拟接收端**（mock inbox），可观察放行告警的转发效果；也可配置外部 webhook
- 数据存于本地 SQLite，**默认无需任何第三方账号、密钥或外网服务**

技术栈：FastAPI + SQLite + 原生 HTML/CSS/JavaScript（无前端构建步骤）。

---

## 一键启动（推荐）

```bash
docker compose up --build
```

启动后浏览器打开：

- 应用主页：<http://localhost:8000>
- 健康检查：<http://localhost:8000/api/health>
- OpenAPI 文档：<http://localhost:8000/docs>

数据持久化在 Docker volume `sandbox-data`（容器内 `/data/sandbox.db`）。停止后重新 `up`，规则、告警、评估历史、关联事件/确认状态与投递日志都会保留。

停止：

```bash
docker compose down          # 保留数据
docker compose down -v       # 连同数据卷一起删除（恢复出厂）
```

> 端口冲突时改 `docker-compose.yml` 里的 `8000:8000`，例如 `18000:8000`。

## 不用 Docker 的本地启动

需要 Python 3.11+：

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

数据库默认放在项目根目录 `./data/sandbox.db`，可用环境变量 `SANDBOX_DATA=/your/dir` 改位置。

---

## 30 秒快速体验

应用首次启动自带 **3 条示例规则** 与 **8 条示例冷链告警队列**：

1. 打开 **「告警注入」** 页，点击 **「⏩ 全部顺序注入」**。
2. 观察「实时注入链决定」表格：
   - `#1 / #3` 夜间 22:00–06:00 的 TR-01 warning 温度告警 → **抑制**
   - `#2` 同为 TR-01 但级别 critical → **放行**（priority=10 的规则优先于 priority=100）
   - `#4 → #5 → #6` TR-02 连续开门告警：首条放行，300 秒冷却窗内的重复告警抑制，超过窗口后再次放行
   - `#7` 无规则匹配 → 默认放行；`#8` 在白天（时段窗口外）→ 默认放行
3. 点 **「↩ 撤销最近注入」**：最后一条告警退回队列头部，其决定与投递记录一并删除，冷却状态同步回滚。
4. 到 **「抑制规则」** 页停用「夜间冷藏车温度抖动抑制」，再到 **「策略对比」** 页点
   **「🔁 用当前规则生成回放」**，即可看到停用前后每条告警的差异（#1、#3 由抑制变放行）。
5. 打开 **「事件关联」** 页：默认 900 秒（15 分钟）聚合间隔下，`#1/#2/#3`（TR-01 temp_high）
   聚成一个最高级别 critical 的事件，`#4/#5/#6`（TR-02 door_open）聚成一个事件，`#7`、`#8` 各自独立。
   点击事件标题展开成员时间线（含每条的 live 放行/抑制），可**确认 / 取消确认**，并按设备、级别、时间筛选；
   改小聚合间隔点「保存间隔并重算」可看到事件被确定性地拆开/合并（live/replay 决定保持不变）。
6. 在 **「模拟接收端」** 页勾选「启用自动转发」后再注入告警，放行项会出现在投递日志里；抑制项不会转发。

---

## 告警 JSON 格式

导入接口接受一个数组，或 `{"alerts": [...], "append": true}` 对象：

```json
[
  {
    "device_id": "TR-01",
    "batch_id": "B2026-09A",
    "level": "warning",
    "alert_type": "temp_high",
    "message": "厢内温度 -15.2℃，高于阈值 -18℃",
    "ts": "2026-09-21T00:05:00"
  }
]
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `device_id` | 否 | 设备编号，规则按精确值匹配 |
| `batch_id` | 否 | 运输/仓储批次号 |
| `level` | 否 | `info` / `warning` / `critical`，缺省为 `info` |
| `alert_type` | 否 | 告警类型，参与冷却指纹计算 |
| `message` | 否 | 文本说明 |
| `ts` | 否 | ISO 8601 时间（支持 `Z` 结尾的 UTC）；**省略则使用注入时刻** |

其他自定义字段会原样保存在 `raw_json` 中，不影响评估。

导入入口：页面上的「导入（替换队列）/ 追加到队列」，或：

```bash
curl -X POST http://localhost:8000/api/alerts/import \
  -H 'Content-Type: application/json' \
  -d '{"alerts":[ {"device_id":"TR-01","level":"critical","alert_type":"power_off"} ]}'
```

也可以跳过队列直接注入单条：

```bash
curl -X POST http://localhost:8000/api/alerts/inject \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"WH-03","batch_id":"B-1","level":"critical","alert_type":"power_off"}'
```

---

## 规则语义

每条规则包含：

| 字段 | 说明 |
| --- | --- |
| `name` / `description` | 名称与意图说明 |
| `action` | **`suppress`**：命中即抑制；**`pass`**：放行（可配冷却） |
| `priority` | **显式优先级，数字越小越优先**；相同优先级按规则 id 排序（稳定） |
| `cooldown_seconds` | 仅对 `pass` 生效。规则放行后，在冷却窗内对**同一指纹**的后续告警执行抑制 |
| `match_device` / `match_batch` / `match_level` | 精确匹配，留空或 `*` 表示通配 |
| `time_start` / `time_end` | 每日循环窗口 `HH:MM`；`end <= start` 视为**跨午夜**（如 22:00–06:00）；留空表示全天 |
| `date_start` / `date_end` | 可选绝对日期边界 `YYYY-MM-DD`，含端点 |
| `enabled` | 停用的规则不参与评估，但仍保留在历史快照中可见 |

评估算法：

1. 取所有**启用**规则，按 `(priority, id)` 升序；
2. 逐条检查设备、批次、级别、时间四个条件，取**第一个完全匹配**的规则；
3. `suppress` 规则 → 决定 **抑制**；
4. `pass` 规则 → 默认放行；若同一指纹在 `cooldown_seconds` 内已有放行记录，则抑制重复告警（原因中给出已等待秒数与剩余秒数），超过窗口则放行并**刷新冷却基准**；
5. 无任何规则匹配 → **默认放行**（fail-open）。

**冷却指纹** = `device_id | batch_id | level | alert_type`，即同一设备、同批次、同级别、同类型的连续告警才共享一个冷却窗口。时间戳早于已记录放行时刻的乱序告警会直接放行且不移动冷却基准。

每个决定都带 `candidates`：所有规则对该告警的逐项条件判定（设备/批次/级别/时间段是否命中），可在界面上展开查看完整评估过程。

---

## 实时注入链 vs 策略回放

- **实时注入链 (live run)**：页面「注入」操作的评估记录。冷却状态随注入**逐条累积**；规则改动只影响之后注入的告警。撤销会删除告警及其在所有评估中的痕迹与投递日志，冷却状态随剩余决定自动重建。
- **策略回放 (replay run)**：点击「用当前规则生成回放」时，对**全部已注入告警**用一份规则快照、**从零开始的冷却状态**重新评估。回放**不会向接收端转发**，只用于对比。
- **前后对比**：任选两个 run（默认新回放 vs live 链），按告警逐条并列两次决定与解释，高亮发生变化的条目，并展示版本 A 当时的规则快照。

---

## 事件关联工作台（事件聚合）

在告警注入链之外新增的**只读派生视图**，把同一来源的连续告警归并为运维「事件」，便于确认与筛选：

- **分组**：已注入告警按 `device_id | alert_type` 分组；
- **聚合**：每组按告警时间排序，相邻告警时间差 **≤ 聚合间隔**（`correlation_interval_seconds`，默认 900 秒，0 表示仅同一时刻才合并）即并入同一事件，gap 超过间隔则另开新事件；
- **事件信息**：首末时间、告警数、最高级别（info < warning < critical）、成员注入序号、成员时间线（每条告警附 live 链上的放行/抑制决定，只读）；
- **确认状态**：每个事件可确认 / 取消确认；
- **筛选**：按设备、最低级别（事件最高级别 ≥ 指定级别）、时间范围（与事件首末区间有重叠即命中）、确认状态过滤。

### 确定性与不改变原决定

1. 聚合是**纯函数全量重算**：组内排序键固定为 `(ts, seq, id)`，与注入顺序无关。乱序（ts 早于已有告警）注入后，同一批告警永远得到同一种划分；页面上的「立即重算」与任何时候的注入/撤销结果一致。
2. 每个事件有由**成员 alert_id 集合**派生的稳定标识 `event_key`（SHA256 前 16 位）。间隔调整导致合并/拆分时，成员集合没变的事件复用同一 key，**确认状态保留**；成员集合变化的事件视为新事件（未确认），不携带旧状态。撤销注入后若成员集合恢复，确认状态也会随之恢复。
3. 事件关联**只读取** alerts 表，从不写入/修改 decisions、runs，也不触发任何转发：live 链的冷却累积与 replay 的回放结果完全不受影响。
4. 注入（单条/队首/全部）与撤销时会自动重算；也可调用 `POST /api/correlation/recompute` 手动重算。

---

## 模拟接收端与转发

- 默认接收端是应用**内置的 mock inbox**：放行告警自动转发后落库展示，无需任何外部服务。
- 「模拟接收端」页可切换为 **外部 webhook**（任意 HTTP POST JSON 地址）；目标不可达时记录 `failed` 而不影响沙盒使用。
- 内置接收端本身也暴露为 HTTP 端点，可用于连通性自测：

```bash
curl -X POST http://localhost:8000/mock-webhook \
  -H 'Content-Type: application/json' \
  -d '{"hello":"cold-chain"}'
```

- 只有 **实时注入且决定为 pass** 的告警才会转发；被抑制的告警与策略回放均不转发。

---

## 事件关联 API 示例

```bash
# 查看/修改聚合间隔（修改即全量重算）
curl -s http://localhost:8000/api/correlation/config
curl -s -X PUT http://localhost:8000/api/correlation/config \
  -H 'Content-Type: application/json' \
  -d '{"correlation_interval_seconds": 300}'

# 手动重算（乱序补入后）
curl -s -X POST http://localhost:8000/api/correlation/recompute

# 筛选：TR-02 设备、warning 及以上、某时间窗内、未确认的事件
curl -s "http://localhost:8000/api/correlation/events?device=TR-02&level=warning&start=2026-09-21T00:00:00&end=2026-09-21T02:00:00&acknowledged=false"

# 确认事件（key 用上一步响应中的 event_key）
curl -s -X POST http://localhost:8000/api/correlation/events/011ebcc41f7e0726/acknowledge \
  -H 'Content-Type: application/json' -d '{"acknowledged": true}'
```

---

## HTTP API 摘要

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| GET/POST | `/api/rules` | 规则列表 / 新建 |
| PUT/DELETE | `/api/rules/{id}` | 修改 / 删除 |
| POST | `/api/rules/{id}/toggle` | 启停切换 |
| GET | `/api/staged` | 待注入队列 |
| POST | `/api/alerts/import` | 导入告警到队列（替换或追加） |
| POST | `/api/alerts/inject-next` | 注入队首 1 条并评估 |
| POST | `/api/alerts/inject-all` | 顺序注入队列全部 |
| POST | `/api/alerts/inject` | 直接注入单条 |
| GET | `/api/alerts` | 已注入告警 + live 决定 |
| POST | `/api/alerts/undo` | 撤销最近注入 |
| POST | `/api/replays` | 用当前规则生成回放 |
| GET | `/api/runs` | 全部评估版本（含规则快照与统计） |
| GET | `/api/runs/{id}/decisions` | 某次评估的逐条决定与解释 |
| GET | `/api/compare?run_a=&run_b=` | 两个版本的逐条差异 |
| GET/PUT | `/api/correlation/config` | 聚合间隔配置（GET 查询 / PUT 修改并重算） |
| POST | `/api/correlation/recompute` | 按当前间隔确定性全量重算事件 |
| GET | `/api/correlation/events` | 事件列表（device/level/start/end/acknowledged 筛选，含时间线） |
| POST | `/api/correlation/events/{key}/acknowledge` | 确认 / 取消确认事件 |
| GET/PUT | `/api/settings` | 转发开关与接收端配置 |
| POST | `/mock-webhook` | 内置模拟接收端 |
| GET | `/api/receiver/logs` | 投递日志 |
| POST | `/api/receiver/clear` | 清空投递日志 |
| POST | `/api/reset` | 恢复出厂示例数据 |

完整的请求/响应结构见 <http://localhost:8000/docs>（Swagger UI）。

---

## 项目结构

```
.
├── app/
│   ├── main.py          # FastAPI 路由：注入/撤销/回放/对比/事件关联/接收端
│   ├── engine.py        # 纯函数决策引擎：匹配、优先级、冷却窗口
│   ├── correlation.py   # 纯函数事件关联引擎：分组、间隔聚合、稳定 event_key
│   ├── db.py            # SQLite 建表、连接、内置示例数据
│   └── static/          # 原生前端（index.html / styles.css / app.js）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

决策引擎 (`engine.py`) 与事件关联引擎 (`correlation.py`) 都不依赖 FastAPI 与数据库，可单独导入做单元测试或嵌入真实处理流水线。

## 常见问题

- **时间对不上？** 规则的 `time_start/time_end` 按每条告警自身的 `ts`（无时区时按本地时间）判定。导入带时区的 ISO 时间时会转换为服务器本地时间。
- **事件想按更短/更长的时间窗聚合？** 在「事件关联」页修改聚合间隔（秒）后保存即触发确定性重算；间隔只影响事件划分，不影响任何放行/抑制决定。
- **乱序注入的告警怎么算事件？** 一律按告警自身 `ts` 在组内归位后重新划分（`(ts, seq, id)` 稳定排序），重复重算结果不变；成员集合未变的事件保留确认状态。
- **想默认全部抑制？** 建一条优先级最低（如 9999）、全部通配的 `suppress` 规则，并让需要放行的规则 priority 更小。
- **想清空重来？** 调用 `POST /api/reset`（或 `docker compose down -v` 后重新启动）。
