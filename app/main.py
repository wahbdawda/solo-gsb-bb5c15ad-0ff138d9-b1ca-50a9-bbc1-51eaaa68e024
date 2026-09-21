"""FastAPI 主应用：规则 CRUD、告警注入/撤销、策略回放对比、内置模拟接收端。

默认数据文件位于 ./data/sandbox.db，可用环境变量 SANDBOX_DATA 覆盖。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .correlation import (
    DEFAULT_INTERVAL_SECONDS,
    LEVEL_RANK,
    MAX_INTERVAL_SECONDS,
    correlate,
    normalize_interval_seconds,
)
from .engine import (
    LEVELS,
    EvalState,
    RuleView,
    alert_fingerprint,
    evaluate,
    normalize_alert,
    normalize_rule,
    ordered_rules,
)

app = FastAPI(title="冷链告警抑制策略沙盒", version="1.1.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _rule_views(conn) -> list[RuleView]:
    rows = conn.execute("SELECT * FROM rules").fetchall()
    return ordered_rules([dict(r) for r in rows])


def _alert_dict(row) -> dict:
    return {
        "id": row["id"],
        "seq": row["seq"],
        "device_id": row["device_id"],
        "batch_id": row["batch_id"],
        "level": row["level"],
        "alert_type": row["alert_type"],
        "message": row["message"],
        "ts": row["ts"],
        "raw_json": json.loads(row["raw_json"]),
    }


def _decision_dict(row) -> dict:
    return {
        "id": row["id"],
        "run_id": row["run_id"],
        "alert_id": row["alert_id"],
        "position": row["position"],
        "decision": row["decision"],
        "rule_id": row["rule_id"],
        "rule_name": row["rule_name"],
        "reason": row["reason"],
        "fingerprint": row["fingerprint"],
        "fired_at_epoch": row["fired_at_epoch"],
        "candidates": json.loads(row["detail_json"]),
    }


def _live_run_id(conn) -> int:
    row = conn.execute("SELECT id FROM runs WHERE kind='live'").fetchone()
    return row["id"]


def _load_live_state(conn, run_id: int) -> EvalState:
    """从已有放行决定中重建冷却状态（同一规则+指纹取最近一次放行时间）。"""
    state = EvalState()
    rows = conn.execute(
        "SELECT rule_id, fingerprint, fired_at_epoch FROM decisions "
        "WHERE run_id=? AND fired_at_epoch IS NOT NULL",
        (run_id,),
    ).fetchall()
    for r in rows:
        state.seed(r["rule_id"], r["fingerprint"], r["fired_at_epoch"])
    return state


def _persist_decision(conn, run_id: int, alert_id: int, result: dict) -> int:
    position = conn.execute(
        "SELECT COALESCE(MAX(position), 0) + 1 FROM decisions WHERE run_id=?",
        (run_id,),
    ).fetchone()[0]
    cur = conn.execute(
        """INSERT INTO decisions(run_id, alert_id, position, decision, rule_id, rule_name,
           reason, fingerprint, fired_at_epoch, detail_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id, alert_id, position, result["decision"], result["rule_id"],
            result["rule_name"], result["reason"], result["fingerprint"],
            result["fired_at_epoch"],
            json.dumps(result["candidates"], ensure_ascii=False),
        ),
    )
    return cur.lastrowid


def _get_settings(conn) -> dict:
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


def _deliver(conn, alert: dict, result: dict, settings: dict) -> dict:
    """把放行告警转发到接收端。replay 回放不会调用本函数。"""
    ts = alert["ts"]
    payload = {
        "alert": {
            **{k: alert[k] for k in
               ("seq", "device_id", "batch_id", "level", "alert_type", "message")},
            "ts": ts.isoformat(timespec="seconds") if isinstance(ts, datetime) else ts,
        },
        "decision": {
            "decision": result["decision"],
            "rule_id": result["rule_id"],
            "rule_name": result["rule_name"],
            "reason": result["reason"],
        },
        "forwarded_at": datetime.now().isoformat(timespec="seconds"),
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    if settings.get("receiver_mode", "mock") == "mock":
        target = "内置模拟接收端 mock-inbox"
        cur = conn.execute(
            """INSERT INTO receiver_logs(alert_id, status, target, payload_json, detail)
               VALUES (?, 'received', ?, ?, '放行告警已投递到内置模拟接收端')""",
            (alert["id"], target, json.dumps(payload, ensure_ascii=False)),
        )
        return {"delivered": True, "target": target, "log_id": cur.lastrowid}

    url = settings.get("external_url", "")
    if not url:
        raise HTTPException(400, "已选择外部 webhook 但未配置 external_url")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            detail = f"HTTP {resp.status}"
            status = "delivered"
            ok = 200 <= resp.status < 300
    except (urllib.error.URLError, OSError) as exc:
        detail = f"请求失败: {exc}"
        status = "failed"
        ok = False
    cur = conn.execute(
        """INSERT INTO receiver_logs(alert_id, status, target, payload_json, detail)
           VALUES (?, ?, ?, ?, ?)""",
        (alert["id"], status, url, json.dumps(payload, ensure_ascii=False), detail),
    )
    return {"delivered": ok, "target": url, "log_id": cur.lastrowid, "detail": detail}


def _inject_one(conn, payload: dict) -> dict:
    """规范化 -> 评估 -> 持久化 ->（可选）转发，返回完整结果。"""
    try:
        seq = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM alerts").fetchone()[0]
        alert = normalize_alert(payload, seq=seq, fallback_ts=datetime.now())
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    rules = _rule_views(conn)
    run_id = _live_run_id(conn)
    state = _load_live_state(conn, run_id)
    result = evaluate(alert, rules, state)

    cur = conn.execute(
        """INSERT INTO alerts(seq, device_id, batch_id, level, alert_type, message, ts, raw_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["seq"], alert["device_id"], alert["batch_id"], alert["level"],
            alert["alert_type"], alert["message"],
            alert["ts"].isoformat(timespec="seconds"),
            json.dumps(alert["raw_json"], ensure_ascii=False),
        ),
    )
    alert["id"] = cur.lastrowid
    decision_id = _persist_decision(conn, run_id, alert["id"], result)

    delivery = None
    settings = _get_settings(conn)
    if result["decision"] == "pass" and settings.get("forward_enabled") == "true":
        delivery = _deliver(conn, alert, result, settings)

    return {
        "alert": alert,
        "decision": {**result, "id": decision_id, "run_id": run_id},
        "delivery": delivery,
    }


# ---------------------------------------------------------------------------
# 事件关联（与 live/replay 决定完全解耦：只读取 alerts，不触碰 decisions/runs）
# ---------------------------------------------------------------------------

def _get_interval_seconds(conn) -> int:
    row = conn.execute(
        "SELECT value FROM settings WHERE key='correlation_interval_seconds'"
    ).fetchone()
    try:
        return normalize_interval_seconds(row["value"] if row else DEFAULT_INTERVAL_SECONDS)
    except ValueError:
        return DEFAULT_INTERVAL_SECONDS


def _load_alerts_with_ts(conn) -> list[dict]:
    """读取全部已注入告警并把 ts 还原为 datetime（供纯函数关联引擎使用）。"""
    rows = conn.execute("SELECT * FROM alerts ORDER BY seq").fetchall()
    alerts = []
    for row in rows:
        alert = _alert_dict(row)
        alert["ts"] = datetime.fromisoformat(alert["ts"])
        alerts.append(alert)
    return alerts


def recompute_events(conn) -> dict:
    """按当前间隔对全部已注入告警做确定性全量重算并刷新事件快照。

    调用方负责事务边界（通常已在 BEGIN 内或随当前写入一并提交）。
    成员集合未变的事件复用同一 event_key，确认状态天然保留；
    消失事件的旧确认记录保留在 event_acknowledgements 中（不影响结果），
    以便撤销注入等操作后事件以相同成员集合重新出现时恢复确认。
    """
    interval = _get_interval_seconds(conn)
    alerts = _load_alerts_with_ts(conn)
    events = correlate(alerts, interval)

    conn.execute("DELETE FROM correlation_events")
    for ev in events:
        conn.execute(
            """INSERT INTO correlation_events
               (event_key, device_id, alert_type, start_ts, end_ts, max_level,
                alert_count, member_ids, member_seqs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev.event_key, ev.device_id, ev.alert_type,
                ev.start_ts.isoformat(timespec="seconds"),
                ev.end_ts.isoformat(timespec="seconds"),
                ev.max_level, ev.alert_count,
                json.dumps(ev.member_ids), json.dumps(ev.member_seqs),
            ),
        )
    return {"interval_seconds": interval, "event_count": len(events),
            "alert_count": len(alerts)}


def _parse_filter_ts(value: Optional[str], field_name: str) -> Optional[datetime]:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        raise HTTPException(400, f"{field_name} 需为 ISO 8601 时间，如 2026-09-21T00:00:00")


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _startup() -> None:
    db.init_db()
    # 升级场景（旧库新建了事件表但未填充）：有已注入告警而无事件快照时补算一次
    conn = db.get_conn()
    try:
        ev_n = conn.execute("SELECT COUNT(*) FROM correlation_events").fetchone()[0]
        al_n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if ev_n == 0 and al_n > 0:
            conn.execute("BEGIN")
            try:
                recompute_events(conn)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    finally:
        conn.close()


@app.exception_handler(HTTPException)
def _http_exc_handler(request: Request, exc: HTTPException):  # noqa: ARG001
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


# ---------------------------------------------------------------------------
# 元信息 / 健康检查
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "cold-chain-alert-suppression-sandbox",
            "time": datetime.now().isoformat(timespec="seconds")}


@app.get("/api/meta")
def meta():
    return {"levels": LEVELS}


# ---------------------------------------------------------------------------
# 规则 CRUD
# ---------------------------------------------------------------------------

@app.get("/api/rules")
def list_rules():
    conn = db.get_conn()
    try:
        rows = conn.execute("SELECT * FROM rules ORDER BY priority, id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.post("/api/rules")
def create_rule(payload: dict = Body(...)):
    try:
        data = normalize_rule(payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    conn = db.get_conn()
    try:
        cols = ", ".join(data)
        cur = conn.execute(
            f"INSERT INTO rules({cols}) VALUES ({', '.join(':' + k for k in data)})", data
        )
        conn.commit()
        row = conn.execute("SELECT * FROM rules WHERE id=?", (cur.lastrowid,)).fetchone()
        return dict(row)
    finally:
        conn.close()


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: int, payload: dict = Body(...)):
    try:
        data = normalize_rule(payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    conn = db.get_conn()
    try:
        if not conn.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone():
            raise HTTPException(404, "规则不存在")
        sets = ", ".join(f"{k}=:{k}" for k in data)
        data["id"] = rule_id
        conn.execute(f"UPDATE rules SET {sets} WHERE id=:id", data)
        conn.commit()
        return dict(conn.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone())
    finally:
        conn.close()


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int):
    conn = db.get_conn()
    try:
        cur = conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "规则不存在")
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT enabled FROM rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(404, "规则不存在")
        new_val = 0 if row["enabled"] else 1
        conn.execute("UPDATE rules SET enabled=? WHERE id=?", (new_val, rule_id))
        conn.commit()
        return {"id": rule_id, "enabled": new_val}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 待注入队列（staged）与导入
# ---------------------------------------------------------------------------

@app.get("/api/staged")
def list_staged():
    conn = db.get_conn()
    try:
        rows = conn.execute("SELECT * FROM staged ORDER BY ord, id").fetchall()
        return [{"id": r["id"], "ord": r["ord"], "payload": json.loads(r["payload"])}
                for r in rows]
    finally:
        conn.close()


@app.post("/api/alerts/import")
async def import_alerts(request: Request):
    """导入告警 JSON 到待注入队列。接受 [..] 数组或 {"alerts": [..], "append": true}。"""
    raw = await request.json()
    append = False
    if isinstance(raw, dict):
        items = raw.get("alerts")
        append = bool(raw.get("append", False))
    else:
        items = raw
    if not isinstance(items, list) or not items:
        raise HTTPException(400, "需要非空的告警数组（或 {\"alerts\": [...]} 对象）")

    conn = db.get_conn()
    inserted = 0
    try:
        if not append:
            conn.execute("DELETE FROM staged")
        next_ord = conn.execute("SELECT COALESCE(MAX(ord), -1) + 1 FROM staged").fetchone()[0]
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                raise HTTPException(400, f"第 {idx + 1} 条不是 JSON 对象")
            # 提前校验可解析性（不入库无效数据）
            try:
                normalize_alert(item, seq=0, fallback_ts=datetime.now())
            except ValueError as exc:
                raise HTTPException(400, f"第 {idx + 1} 条告警无效: {exc}")
            conn.execute(
                "INSERT INTO staged(ord, payload) VALUES (?, ?)",
                (next_ord + idx, json.dumps(item, ensure_ascii=False)),
            )
            inserted += 1
        conn.commit()
        return {"imported": inserted, "appended": append}
    finally:
        conn.close()


@app.delete("/api/staged/{staged_id}")
def delete_staged(staged_id: int):
    conn = db.get_conn()
    try:
        cur = conn.execute("DELETE FROM staged WHERE id=?", (staged_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "队列项不存在")
        return {"ok": True}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 注入 / 撤销 / 已注入列表
# ---------------------------------------------------------------------------

@app.post("/api/alerts/inject-next")
def inject_next():
    """从待注入队列头部取一条，按当前策略评估（逐条注入）。"""
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT * FROM staged ORDER BY ord, id LIMIT 1").fetchone()
        if not row:
            raise HTTPException(404, "待注入队列为空")
        payload = json.loads(row["payload"])
        conn.execute("DELETE FROM staged WHERE id=?", (row["id"],))
        out = _inject_one(conn, payload)
        out["correlation"] = recompute_events(conn)
        conn.commit()
        out["staged_remaining"] = conn.execute("SELECT COUNT(*) FROM staged").fetchone()[0]
        return out
    finally:
        conn.close()


@app.post("/api/alerts/inject-all")
def inject_all():
    """依次注入队列中的全部告警，返回每条决定（用于快速观察整条序列）。"""
    conn = db.get_conn()
    try:
        rows = conn.execute("SELECT * FROM staged ORDER BY ord, id").fetchall()
        if not rows:
            raise HTTPException(404, "待注入队列为空")
        results = []
        for row in rows:
            results.append(_inject_one(conn, json.loads(row["payload"])))
        conn.execute("DELETE FROM staged")
        correlation = recompute_events(conn)
        conn.commit()
        return {"injected": len(results), "results": results, "correlation": correlation}
    finally:
        conn.close()


@app.post("/api/alerts/inject")
async def inject_single(request: Request):
    """直接注入一条告警 JSON（不经过队列）。"""
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(400, "请求体必须是单个告警 JSON 对象")
    conn = db.get_conn()
    try:
        out = _inject_one(conn, payload)
        out["correlation"] = recompute_events(conn)
        conn.commit()
        return out
    finally:
        conn.close()


@app.get("/api/alerts")
def list_alerts():
    """已注入告警 + live 链上的决定（按注入顺序）。"""
    conn = db.get_conn()
    try:
        run_id = _live_run_id(conn)
        alerts = conn.execute("SELECT * FROM alerts ORDER BY seq").fetchall()
        out = []
        for a in alerts:
            d = conn.execute(
                "SELECT * FROM decisions WHERE run_id=? AND alert_id=?",
                (run_id, a["id"]),
            ).fetchone()
            out.append({"alert": _alert_dict(a),
                        "decision": _decision_dict(d) if d else None})
        return out
    finally:
        conn.close()


@app.post("/api/alerts/undo")
def undo_last():
    """撤销最近一次注入：删除该告警及其全部决定/投递记录，并退回队列头部。"""
    conn = db.get_conn()
    try:
        last = conn.execute("SELECT * FROM alerts ORDER BY seq DESC LIMIT 1").fetchone()
        if not last:
            raise HTTPException(404, "没有可撤销的注入")
        alert = _alert_dict(last)
        conn.execute("BEGIN")
        try:
            head_ord = conn.execute("SELECT COALESCE(MIN(ord), 0) FROM staged").fetchone()[0]
            conn.execute(
                "INSERT INTO staged(ord, payload) VALUES (?, ?)",
                (head_ord - 1, last["raw_json"]),
            )
            # 级联删除各 run 中该告警的 decisions 与投递日志
            conn.execute("DELETE FROM receiver_logs WHERE alert_id=?", (last["id"],))
            conn.execute("DELETE FROM alerts WHERE id=?", (last["id"],))
            correlation = recompute_events(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return {"ok": True, "undone": alert,
                "remaining": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "correlation": correlation}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 策略回放与前后对比
# ---------------------------------------------------------------------------

@app.post("/api/replays")
def create_replay(payload: dict = Body(default={})):
    """用当前启用的规则快照，按顺序重放全部已注入告警（全新冷却状态）。"""
    note = str((payload or {}).get("note", "")).strip() or "策略变更后手动回放"
    conn = db.get_conn()
    try:
        rules = _rule_views(conn)
        snapshot = [
            {k: getattr(r, k) for k in (
                "id", "name", "description", "action", "priority", "cooldown_seconds",
                "match_device", "match_batch", "match_level", "time_start", "time_end",
                "date_start", "date_end", "enabled")}
            for r in rules
        ]
        cur = conn.execute(
            "INSERT INTO runs(kind, note, rule_snapshot) VALUES ('replay', ?, ?)",
            (note[:200], json.dumps(snapshot, ensure_ascii=False)),
        )
        run_id = cur.lastrowid

        state = EvalState()
        alerts = conn.execute("SELECT * FROM alerts ORDER BY seq").fetchall()
        for position, row in enumerate(alerts, start=1):
            alert = _alert_dict(row)
            alert["ts"] = datetime.fromisoformat(alert["ts"])
            result = evaluate(alert, rules, state)
            _persist_decision(conn, run_id, row["id"], result)
        conn.commit()
        return {"id": run_id, "note": note, "replayed_alerts": len(alerts),
                "rules_in_snapshot": len(snapshot)}
    finally:
        conn.close()


@app.get("/api/runs")
def list_runs():
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT r.*,
                      (SELECT COUNT(*) FROM decisions d WHERE d.run_id=r.id) AS decision_count,
                      (SELECT COUNT(*) FILTER (WHERE decision='pass') FROM decisions d
                       WHERE d.run_id=r.id) AS pass_count,
                      (SELECT COUNT(*) FILTER (WHERE decision='suppress') FROM decisions d
                       WHERE d.run_id=r.id) AS suppress_count
               FROM runs r ORDER BY r.id"""
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r["id"], "kind": r["kind"], "note": r["note"],
                "created_at": r["created_at"], "decision_count": r["decision_count"],
                "pass_count": r["pass_count"], "suppress_count": r["suppress_count"],
                "rule_snapshot": json.loads(r["rule_snapshot"]),
            })
        return out
    finally:
        conn.close()


@app.get("/api/runs/{run_id}/decisions")
def run_decisions(run_id: int):
    conn = db.get_conn()
    try:
        run = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            raise HTTPException(404, "评估记录不存在")
        rows = conn.execute(
            """SELECT d.*, a.seq, a.device_id, a.batch_id, a.level, a.alert_type,
                      a.message, a.ts AS alert_ts
               FROM decisions d JOIN alerts a ON a.id=d.alert_id
               WHERE d.run_id=? ORDER BY d.position""",
            (run_id,),
        ).fetchall()
        decisions = []
        for r in rows:
            d = _decision_dict(r)
            d.update({
                "seq": r["seq"], "device_id": r["device_id"], "batch_id": r["batch_id"],
                "level": r["level"], "alert_type": r["alert_type"],
                "message": r["message"], "alert_ts": r["alert_ts"],
            })
            decisions.append(d)
        return {
            "run": {"id": run["id"], "kind": run["kind"], "note": run["note"],
                    "created_at": run["created_at"],
                    "rule_snapshot": json.loads(run["rule_snapshot"])},
            "decisions": decisions,
        }
    finally:
        conn.close()


@app.get("/api/compare")
def compare_runs(run_a: int, run_b: Optional[int] = None):
    """对比两次评估（默认 run_b=live 链）中每条告警的决定差异。"""
    conn = db.get_conn()
    try:
        live_id = _live_run_id(conn)
        run_b = run_b or live_id
        if not conn.execute("SELECT 1 FROM runs WHERE id=?", (run_a,)).fetchone():
            raise HTTPException(404, f"run {run_a} 不存在")
        if not conn.execute("SELECT 1 FROM runs WHERE id=?", (run_b,)).fetchone():
            raise HTTPException(404, f"run {run_b} 不存在")

        def load(rid: int) -> dict[int, dict]:
            rows = conn.execute(
                """SELECT d.*, a.seq FROM decisions d JOIN alerts a ON a.id=d.alert_id
                   WHERE d.run_id=?""", (rid,),
            ).fetchall()
            return {r["alert_id"]: _decision_dict(r) | {"seq": r["seq"]} for r in rows}

        da, db_ = load(run_a), load(run_b)
        alerts = conn.execute("SELECT * FROM alerts ORDER BY seq").fetchall()
        rows_out, changed = [], 0
        for a in alerts:
            x, y = da.get(a["id"]), db_.get(a["id"])
            is_changed = bool(x and y and x["decision"] != y["decision"])
            changed += is_changed
            rows_out.append({
                "alert": _alert_dict(a),
                "a": x, "b": y, "changed": is_changed,
            })

        def run_meta(rid: int) -> dict:
            r = conn.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
            return {"id": r["id"], "kind": r["kind"], "note": r["note"],
                    "created_at": r["created_at"]}

        return {"run_a": run_meta(run_a), "run_b": run_meta(run_b),
                "rows": rows_out, "changed_count": changed,
                "total": len(rows_out)}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 事件关联工作台
# ---------------------------------------------------------------------------

@app.get("/api/correlation/config")
def get_correlation_config():
    """当前关联配置（聚合间隔）。"""
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM correlation_events"
        ).fetchone()
        return {"correlation_interval_seconds": _get_interval_seconds(conn),
                "event_count": row["n"],
                "min_interval_seconds": 0,
                "max_interval_seconds": MAX_INTERVAL_SECONDS}
    finally:
        conn.close()


@app.put("/api/correlation/config")
async def update_correlation_config(request: Request):
    """修改聚合间隔并立即以新间隔全量重算（幂等、确定性；不影响 live/replay）。"""
    body = await request.json()
    if not isinstance(body, dict) or "correlation_interval_seconds" not in body:
        raise HTTPException(400, "请求体需包含 correlation_interval_seconds")
    try:
        interval = normalize_interval_seconds(body["correlation_interval_seconds"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    conn = db.get_conn()
    try:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES ('correlation_interval_seconds', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(interval),),
        )
        conn.execute("BEGIN")
        try:
            summary = recompute_events(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return {"correlation_interval_seconds": interval, **summary}
    finally:
        conn.close()


@app.post("/api/correlation/recompute")
def recompute_correlation():
    """对全部已注入告警按当前间隔做一次确定性全量重算（乱序补入后可手动调用）。"""
    conn = db.get_conn()
    try:
        conn.execute("BEGIN")
        try:
            summary = recompute_events(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return {"ok": True, **summary}
    finally:
        conn.close()


@app.get("/api/correlation/events")
def list_correlation_events(
    device: Optional[str] = None,
    level: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    acknowledged: Optional[bool] = None,
):
    """事件列表，支持按设备 / 最低级别 / 时间范围 / 确认状态筛选。

    - level：保留**最高级别 >= 指定级别**的事件（warning 含 warning/critical）
    - start/end：事件时间范围与 [start, end] 有重叠即保留（按首末时间）
    - 每个事件携带成员时间线（含 live 链上的放行/抑制决定，只读展示）
    """
    min_rank = None
    if level:
        level = level.strip().lower()
        if level not in LEVEL_RANK:
            raise HTTPException(400, f"level 只能是 {', '.join(LEVEL_RANK)} 之一")
        min_rank = LEVEL_RANK[level]
    start_dt = _parse_filter_ts(start, "start")
    end_dt = _parse_filter_ts(end, "end")
    if start_dt and end_dt and start_dt > end_dt:
        raise HTTPException(400, "start 不能晚于 end")

    conn = db.get_conn()
    try:
        run_id = _live_run_id(conn)
        rows = conn.execute(
            """SELECT ce.*, ack.acknowledged, ack.acknowledged_at, ack.note AS ack_note
               FROM correlation_events ce
               LEFT JOIN event_acknowledgements ack ON ack.event_key=ce.event_key
               ORDER BY ce.start_ts DESC, ce.device_id, ce.alert_type, ce.id"""
        ).fetchall()

        # 预取 live 决定，避免逐成员查询
        dec_rows = conn.execute(
            "SELECT alert_id, decision, rule_id, rule_name, reason FROM decisions WHERE run_id=?",
            (run_id,),
        ).fetchall()
        decisions = {r["alert_id"]: dict(r) for r in dec_rows}
        alert_rows = {r["id"]: r for r in conn.execute("SELECT * FROM alerts").fetchall()}

        events = []
        for r in rows:
            if device is not None and device.strip() and r["device_id"] != device.strip():
                continue
            if min_rank is not None and LEVEL_RANK.get(r["max_level"], 1) < min_rank:
                continue
            ev_start = datetime.fromisoformat(r["start_ts"])
            ev_end = datetime.fromisoformat(r["end_ts"])
            if start_dt and ev_end < start_dt:
                continue
            if end_dt and ev_start > end_dt:
                continue
            is_acked = bool(r["acknowledged"])
            if acknowledged is not None and is_acked != acknowledged:
                continue

            member_ids = json.loads(r["member_ids"])
            member_seqs = json.loads(r["member_seqs"])
            timeline = []
            for aid, seq in zip(member_ids, member_seqs):
                a = alert_rows.get(aid)
                dec = decisions.get(aid)
                timeline.append({
                    "alert_id": aid,
                    "seq": seq,
                    "ts": a["ts"] if a else None,
                    "device_id": a["device_id"] if a else r["device_id"],
                    "batch_id": a["batch_id"] if a else "",
                    "level": a["level"] if a else None,
                    "alert_type": a["alert_type"] if a else r["alert_type"],
                    "message": a["message"] if a else "",
                    "live_decision": dec["decision"] if dec else None,
                    "live_rule_id": dec["rule_id"] if dec else None,
                    "live_rule_name": dec["rule_name"] if dec else None,
                })
            events.append({
                "id": r["id"],
                "event_key": r["event_key"],
                "device_id": r["device_id"],
                "alert_type": r["alert_type"],
                "start_ts": r["start_ts"],
                "end_ts": r["end_ts"],
                "max_level": r["max_level"],
                "alert_count": r["alert_count"],
                "member_ids": member_ids,
                "member_seqs": member_seqs,
                "acknowledged": is_acked,
                "acknowledged_at": r["acknowledged_at"],
                "ack_note": r["ack_note"] or "",
                "computed_at": r["computed_at"],
                "timeline": timeline,
            })
        return {"interval_seconds": _get_interval_seconds(conn),
                "total": len(events), "events": events}
    finally:
        conn.close()


@app.post("/api/correlation/events/{event_key}/acknowledge")
async def acknowledge_event(event_key: str, request: Request):
    """确认 / 取消确认一个事件。body: {"acknowledged": true, "note": "..."}。

    状态按 event_key（成员集合）持久化；重算后成员集合不变的事件保留状态。
    """
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "请求体必须是对象")
    acked = bool(body.get("acknowledged", True))
    note = str(body.get("note", "") or "")[:200]
    conn = db.get_conn()
    try:
        if not conn.execute(
            "SELECT 1 FROM correlation_events WHERE event_key=?", (event_key,)
        ).fetchone():
            raise HTTPException(404, "事件不存在或已因重算消失")
        if acked:
            conn.execute(
                """INSERT INTO event_acknowledgements(event_key, acknowledged, acknowledged_at, note)
                   VALUES (?, 1, datetime('now'), ?)
                   ON CONFLICT(event_key) DO UPDATE SET
                     acknowledged=1, acknowledged_at=datetime('now'), note=excluded.note""",
                (event_key, note),
            )
        else:
            conn.execute(
                """INSERT INTO event_acknowledgements(event_key, acknowledged, acknowledged_at, note)
                   VALUES (?, 0, NULL, '')
                   ON CONFLICT(event_key) DO UPDATE SET
                     acknowledged=0, acknowledged_at=NULL, note=''""",
                (event_key,),
            )
        conn.commit()
        return {"event_key": event_key, "acknowledged": acked}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 模拟接收端 + 转发设置
# ---------------------------------------------------------------------------

@app.post("/mock-webhook")
async def mock_webhook(request: Request):
    """内置模拟接收端：任何 POST 都会落库展示，返回 200。可用 curl 验证连通性。"""
    try:
        body = await request.json()
    except Exception:
        body = {"raw": (await request.body()).decode("utf-8", "replace")}
    conn = db.get_conn()
    try:
        alert_id = None
        if isinstance(body, dict):
            seq = (body.get("alert") or {}).get("seq")
            if seq is not None:
                row = conn.execute("SELECT id FROM alerts WHERE seq=?", (seq,)).fetchone()
                alert_id = row["id"] if row else None
        cur = conn.execute(
            """INSERT INTO receiver_logs(alert_id, status, target, payload_json, detail)
               VALUES (?, 'received', ?, ?, '外部调用内置模拟接收端 /mock-webhook')""",
            (alert_id, f"{request.url.path}", json.dumps(body, ensure_ascii=False)),
        )
        conn.commit()
        return {"ok": True, "received": True, "log_id": cur.lastrowid}
    finally:
        conn.close()


@app.get("/api/receiver/logs")
def receiver_logs(limit: int = 100):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT l.*, a.seq AS alert_seq FROM receiver_logs l
               LEFT JOIN alerts a ON a.id=l.alert_id
               ORDER BY l.id DESC LIMIT ?""",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return [{
            "id": r["id"], "created_at": r["created_at"], "alert_seq": r["alert_seq"],
            "status": r["status"], "target": r["target"],
            "payload": json.loads(r["payload_json"]), "detail": r["detail"],
        } for r in rows]
    finally:
        conn.close()


@app.post("/api/receiver/clear")
def clear_receiver_logs():
    conn = db.get_conn()
    try:
        cur = conn.execute("DELETE FROM receiver_logs")
        conn.commit()
        return {"ok": True, "cleared": cur.rowcount}
    finally:
        conn.close()


@app.get("/api/settings")
def get_settings():
    conn = db.get_conn()
    try:
        return _get_settings(conn)
    finally:
        conn.close()


@app.put("/api/settings")
async def update_settings(request: Request):
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "请求体必须是对象")
    allowed = set(db.DEFAULT_SETTINGS)
    conn = db.get_conn()
    try:
        for key, value in body.items():
            if key not in allowed:
                raise HTTPException(400, f"未知设置项: {key}")
            if key == "external_url" and value:
                if not str(value).startswith(("http://", "https://")):
                    raise HTTPException(400, "external_url 必须以 http:// 或 https:// 开头")
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, "true" if value is True else
                      "false" if value is False else str(value)),
            )
        conn.commit()
        return _get_settings(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 重置沙盒
# ---------------------------------------------------------------------------

@app.post("/api/reset")
def reset_sandbox():
    """清空全部业务数据并恢复内置示例规则与告警队列。"""
    conn = db.get_conn()
    try:
        db.reset_all(conn)
        return {"ok": True}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 静态前端（放在最后，避免覆盖 API 路由）
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
