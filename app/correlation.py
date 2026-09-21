"""事件关联引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

把**已注入**的告警按 `device_id | alert_type` 分组，按告警时间排序后，
以**相邻告警时间间隔**（gap <= interval_seconds）为界聚合成事件：

    同一组内，若相邻两条告警的时间差 <= interval_seconds，则并入同一事件；
    一旦某条与前一条的 gap > interval，则另开一个新事件。

确定性保证
----------
1. 分组键固定为 `device_id | alert_type`，组内排序键为 `(ts, seq, id)`：
   乱序注入（告警 ts 早于已注入告警）只会改变按时间归位后的结果，
   同一组输入永远得到同一组划分，与注入顺序无关。
2. 每个事件的稳定标识 event_key 由**成员 alert_id 集合**计算
   （排序后 SHA256 前 16 位）。乱序补入或规则/间隔调整后全量重算时，
   成员集合未变的事件复用同一 key，确认状态得以保留；成员集合变化
   （事件被合并/拆开）的事件视为新事件，不携带旧确认。
3. 本模块只读取告警数据，绝不写入或修改 decisions/runs，
   因此 live / replay 的放行、抑制决定完全不受影响。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

# 级别严重度排序：数字越大越严重
LEVEL_RANK = {"info": 1, "warning": 2, "critical": 3}
RANK_LEVEL = {v: k for k, v in LEVEL_RANK.items()}

MIN_INTERVAL_SECONDS = 0
MAX_INTERVAL_SECONDS = 7 * 24 * 3600  # 一周，防止误传毫秒等离谱值
DEFAULT_INTERVAL_SECONDS = 900        # 15 分钟：内置示例夜间 TR-01 三条正好聚成一个事件


def normalize_interval_seconds(value: Any) -> int:
    """校验聚合时间间隔（秒），非法时抛出 ValueError。"""
    if value is None or value == "":
        raise ValueError("correlation_interval_seconds 不能为空")
    try:
        interval = int(value)
    except (TypeError, ValueError):
        raise ValueError("correlation_interval_seconds 必须是非负整数（秒）")
    if interval < MIN_INTERVAL_SECONDS:
        raise ValueError("correlation_interval_seconds 不能为负数")
    if interval > MAX_INTERVAL_SECONDS:
        raise ValueError(
            f"correlation_interval_seconds 不能超过 {MAX_INTERVAL_SECONDS}（7 天）"
        )
    return interval


def higher_level(a: str, b: str) -> str:
    """返回两个级别中更严重的一个。"""
    return a if LEVEL_RANK.get(a, 1) >= LEVEL_RANK.get(b, 1) else b


def correlation_group_key(alert: dict) -> str:
    """关联分组键：设备 + 告警类型（缺失按空串处理，保持与注入链一致）。"""
    return f"{alert.get('device_id', '') or ''}|{alert.get('alert_type', '') or ''}"


@dataclass
class CorrelatedEvent:
    """一次确定性聚合计算产出的事件（未落库前的值对象）。"""

    group_key: str
    device_id: str
    alert_type: str
    members: list[dict] = field(default_factory=list)  # 按 (ts, seq, id) 升序

    @property
    def start_ts(self) -> datetime:
        return self.members[0]["ts"]

    @property
    def end_ts(self) -> datetime:
        return self.members[-1]["ts"]

    @property
    def alert_count(self) -> int:
        return len(self.members)

    @property
    def max_level(self) -> str:
        top = 1
        for m in self.members:
            top = max(top, LEVEL_RANK.get(m.get("level", "info"), 1))
        return RANK_LEVEL[top]

    @property
    def member_seqs(self) -> list[int]:
        return [m["seq"] for m in self.members]

    @property
    def member_ids(self) -> list[int]:
        return [m["id"] for m in self.members]

    @property
    def event_key(self) -> str:
        return compute_event_key(self.member_ids)


def compute_event_key(member_ids: Iterable[int]) -> str:
    """由成员 alert_id 集合计算稳定事件标识（与顺序无关，只取决于集合）。"""
    joined = ",".join(str(i) for i in sorted(int(i) for i in member_ids))
    return hashlib.sha256(f"event:{joined}".encode("utf-8")).hexdigest()[:16]


def correlate(alerts: list[dict], interval_seconds: int) -> list[CorrelatedEvent]:
    """把已注入告警聚合为事件。

    参数
    ----
    alerts: 规范化后的告警字典，必须含 id/seq/ts(datetime)/device_id/
            alert_type/level；ts 缺失或无法解析的告警会被跳过。
    interval_seconds: 相邻告警聚合的最大时间间隔（秒）。

    返回事件按 (start_ts, group_key, event_key) 全局升序排列，
    保证同样的输入集合在任何进程/任何时刻得到同样的输出顺序。
    """
    interval_seconds = normalize_interval_seconds(interval_seconds)
    groups: dict[str, list[dict]] = {}
    for alert in alerts:
        ts = alert.get("ts")
        if not isinstance(ts, datetime):
            continue
        groups.setdefault(correlation_group_key(alert), []).append(alert)

    events: list[CorrelatedEvent] = []
    for key in sorted(groups):  # 组间顺序也确定
        items = sorted(groups[key], key=lambda a: (a["ts"], a["seq"], a["id"]))
        current: Optional[CorrelatedEvent] = None
        prev_ts: Optional[datetime] = None
        for alert in items:
            ts = alert["ts"]
            if current is None or (ts - prev_ts).total_seconds() > interval_seconds:
                current = CorrelatedEvent(
                    group_key=key,
                    device_id=alert.get("device_id", "") or "",
                    alert_type=alert.get("alert_type", "") or "",
                )
                events.append(current)
            current.members.append(alert)
            prev_ts = ts

    events.sort(key=lambda e: (e.start_ts, e.group_key, e.event_key))
    return events
