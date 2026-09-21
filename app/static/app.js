/* 冷链告警抑制策略沙盒 —— 原生前端逻辑 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `请求失败 HTTP ${res.status}`);
  return data;
};

let state = {
  staged: [],
  alerts: [],
  rules: [],
  runs: [],
  settings: {},
  compare: { a: null, b: null, result: null },
  events: { total: 0, events: [], interval_seconds: 900 },
  evConfig: { correlation_interval_seconds: 900 },
  evFilters: { device: "", level: "", start: "", end: "", ack: "" },
};

// ---------------------------------------------------------------------------
// 通用 UI
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 3200);
}
const fail = (e) => toast(e.message || String(e), true);

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function levelBadge(level) {
  const l = (level || "info").toLowerCase();
  return `<span class="level level-${l}">${esc(l)}</span>`;
}

function levelCell(level) {
  return level ? levelBadge(level) : '<span class="badge">全部 *</span>';
}

// ---------------------------------------------------------------------------
// 数据加载
// ---------------------------------------------------------------------------

async function refreshAll() {
  await Promise.all([loadStaged(), loadAlerts(), loadRules(), loadRuns(), loadSettings()]);
  renderStaged();
  renderAlerts();
  renderRules();
  renderRunSelects();
  renderSettings();
  if (state.compare.a && state.compare.b) await loadCompare();
  await loadEvents();
}

async function loadStaged() {
  state.staged = await api("/api/staged");
}
async function loadAlerts() {
  state.alerts = await api("/api/alerts");
}
async function loadRules() {
  state.rules = await api("/api/rules");
}
async function loadRuns() {
  state.runs = await api("/api/runs");
}
async function loadSettings() {
  state.settings = await api("/api/settings");
}

// ---------------------------------------------------------------------------
// Tab 1: 告警注入
// ---------------------------------------------------------------------------

function renderStaged() {
  $("#staged-count").textContent = state.staged.length;
  const box = $("#staged-list");
  if (!state.staged.length) {
    box.innerHTML = '<p class="empty">队列为空，可在右侧导入 JSON 或填充内置示例</p>';
    return;
  }
  box.innerHTML = state.staged.map((item, i) => {
    const p = item.payload;
    return `<div class="staged-item">
      <span class="seq">${i + 1}</span>
      <div class="body">
        <div class="meta">${esc(p.ts || "(无 ts，用注入时刻)")} · ${esc(p.device_id || "-")} ·
          ${esc(p.batch_id || "-")} · ${levelBadge(p.level)} · ${esc(p.alert_type || "-")}</div>
        <div class="msg">${esc(p.message || "")}</div>
      </div>
      <button class="btn ghost small" data-del-staged="${item.id}">移除</button>
    </div>`;
  }).join("");
}

function renderCandidates(cands) {
  if (!cands || !cands.length) return "";
  const items = cands.map((c) => {
    const checks = (c.checks || []).map((t) => {
      const miss = t.includes("不匹配") || t.includes("不命中") || t.includes("早于") || t.includes("晚于");
      return `<li class="${miss ? "check-miss" : "check-hit"}">${esc(t)}</li>`;
    }).join("");
    return `<div class="candidate ${c.matched ? "winner" : ""}">
      <div class="cand-head">#${c.rule_id} ${esc(c.name)} · 优先级 ${c.priority} ·
        动作 ${c.action === "pass" ? "放行" : "抑制"} ${c.matched ? "— <b>匹配</b>" : "— 未匹配"}</div>
      <ul class="checks">${checks}</ul>
    </div>`;
  }).join("");
  return `<div class="candidates"><div style="color:var(--accent)">规则评估过程（按优先级）：</div>${items}</div>`;
}

function renderAlerts() {
  const rows = state.alerts;
  const tbody = $("#alerts-body");
  let passN = 0, suppressN = 0;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">尚未注入告警</td></tr>';
  } else {
    tbody.innerHTML = rows.map(({ alert, decision }) => {
      if (decision) {
        if (decision.decision === "pass") passN++; else suppressN++;
      }
      const d = decision
        ? `<span class="decision ${decision.decision}">${decision.decision === "pass" ? "放行 PASS" : "抑制 SUPPRESS"}</span>`
        : '<span class="badge">未评估</span>';
      const rule = decision
        ? `<div class="reason-cell">
             <div class="reason-text">${decision.rule_id ? `命中规则 #${decision.rule_id}「${esc(decision.rule_name)}」` : "无命中规则（默认策略）"}</div>
             <div style="color:var(--muted);margin-top:2px">${esc(decision.reason)}</div>
             <div style="color:var(--muted);margin-top:2px;font-size:11.5px">冷却指纹: <code>${esc(decision.fingerprint)}</code></div>
             ${renderCandidates(decision.candidates)}
           </div>`
        : '<span class="empty">-</span>';
      return `<tr>
        <td>${alert.seq}</td>
        <td>${esc(alert.ts)}</td>
        <td>${esc(alert.device_id || "-")}</td>
        <td>${esc(alert.batch_id || "-")}</td>
        <td>${levelBadge(alert.level)}</td>
        <td>${esc(alert.alert_type || "-")}</td>
        <td style="max-width:220px">${esc(alert.message || "")}</td>
        <td>${d}</td>
        <td>${rule}</td>
      </tr>`;
    }).join("");
  }
  $("#live-pass").textContent = `${passN} 放行`;
  $("#live-suppress").textContent = `${suppressN} 抑制`;
}

async function doInject(next) {
  try {
    if (next) await api("/api/alerts/inject-next", { method: "POST" });
    else await api("/api/alerts/inject-all", { method: "POST" });
    await refreshAll();
    await loadReceiverLogs();
    toast(next ? "已注入队首 1 条" : "队列已全部顺序注入");
  } catch (e) { fail(e); }
}

async function doUndo() {
  if (!state.alerts.length) return toast("没有可撤销的注入", true);
  const last = state.alerts[state.alerts.length - 1].alert;
  if (!confirm(`撤销最近注入 #${last.seq}（${last.device_id} / ${last.alert_type}）？\n该告警会退回队列头部，其在所有评估中的决定与投递日志一并删除。`)) return;
  try {
    await api("/api/alerts/undo", { method: "POST" });
    await refreshAll();
    await loadReceiverLogs();
    toast("已撤销最近注入");
  } catch (e) { fail(e); }
}

function readJsonTextarea(el) {
  const text = el.value.trim();
  if (!text) throw new Error("JSON 内容为空");
  try { return JSON.parse(text); }
  catch { throw new Error("JSON 解析失败，请检查格式"); }
}

async function doImport(append) {
  let data;
  try { data = readJsonTextarea($("#import-json")); } catch (e) { return fail(e); }
  const body = Array.isArray(data) ? { alerts: data, append } : { ...data, append: append || data.append };
  try {
    const r = await api("/api/alerts/import", { method: "POST", body: JSON.stringify(body) });
    await refreshAll();
    toast(`已${r.appended ? "追加" : "导入"} ${r.imported} 条告警到队列`);
  } catch (e) { fail(e); }
}

async function doDirectInject() {
  let data;
  try { data = readJsonTextarea($("#direct-json")); } catch (e) { return fail(e); }
  if (Array.isArray(data)) return fail("该入口仅接受单条 JSON 对象，批量导入请使用左侧");
  try {
    await api("/api/alerts/inject", { method: "POST", body: JSON.stringify(data) });
    await refreshAll();
    await loadReceiverLogs();
    toast("单条告警已注入并完成评估");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 2: 规则
// ---------------------------------------------------------------------------

function ruleMatches(r) {
  const dev = r.match_device || "*", batch = r.match_batch || "*", lvl = r.match_level || "*";
  const time = r.time_start ? `${r.time_start}-${r.time_end}` : "全天";
  const dates = (r.date_start || r.date_end)
    ? `${r.date_start || "…"} ~ ${r.date_end || "…"}` : "不限";
  return { dev, batch, lvl, time, dates };
}

function renderRules() {
  const tbody = $("#rules-body");
  if (!state.rules.length) {
    tbody.innerHTML = '<tr><td colspan="12" class="empty">暂无规则（无匹配时全部默认放行）</td></tr>';
    return;
  }
  const enabledOrdered = state.rules.filter((r) => r.enabled);
  const orderMap = new Map(enabledOrdered.map((r, i) => [r.id, i + 1]));
  tbody.innerHTML = state.rules.map((r) => {
    const m = ruleMatches(r);
    const order = r.enabled ? (orderMap.get(r.id) || "-") : "—";
    return `<tr${r.enabled ? "" : ' style="opacity:0.45"'}>
      <td>${order}</td>
      <td><b>${esc(r.name)}</b><br><span style="color:var(--muted);font-size:11.5px">${esc(r.description || "")}</span></td>
      <td>${r.action === "pass"
        ? '<span class="decision pass">pass</span>'
        : '<span class="decision suppress">suppress</span>'}</td>
      <td>${r.priority}</td>
      <td>${r.cooldown_seconds || "-"}</td>
      <td>${esc(m.dev)}</td>
      <td>${esc(m.batch)}</td>
      <td>${levelCell(m.lvl === "*" ? "" : m.lvl)}</td>
      <td>${esc(m.time)}</td>
      <td>${esc(m.dates)}</td>
      <td>${r.enabled ? '<span class="badge pass">启用</span>' : '<span class="badge suppress">停用</span>'}</td>
      <td style="white-space:nowrap">
        <button class="btn small" data-edit-rule="${r.id}">编辑</button>
        <button class="btn small" data-toggle-rule="${r.id}">${r.enabled ? "停用" : "启用"}</button>
        <button class="btn small danger" data-del-rule="${r.id}">删除</button>
      </td>
    </tr>`;
  }).join("");
}

function fillRuleForm(r) {
  $("#rule-id").value = r ? r.id : "";
  $("#form-title").textContent = r ? `编辑规则 #${r.id}` : "新建抑制规则";
  $("#f-name").value = r ? r.name : "";
  $("#f-desc").value = r ? r.description : "";
  $("#f-action").value = r ? r.action : "suppress";
  $("#f-priority").value = r ? r.priority : 100;
  $("#f-cooldown").value = r ? r.cooldown_seconds : 0;
  $("#f-device").value = r ? r.match_device : "";
  $("#f-batch").value = r ? r.match_batch : "";
  $("#f-level").value = r ? r.match_level : "";
  $("#f-time-start").value = r ? r.time_start : "";
  $("#f-time-end").value = r ? r.time_end : "";
  $("#f-date-start").value = r ? r.date_start : "";
  $("#f-date-end").value = r ? r.date_end : "";
  $("#f-enabled").checked = r ? !!r.enabled : true;
}

function collectRuleForm() {
  return {
    name: $("#f-name").value,
    description: $("#f-desc").value,
    action: $("#f-action").value,
    priority: Number($("#f-priority").value),
    cooldown_seconds: Number($("#f-cooldown").value),
    match_device: $("#f-device").value.trim(),
    match_batch: $("#f-batch").value.trim(),
    match_level: $("#f-level").value,
    time_start: $("#f-time-start").value.trim(),
    time_end: $("#f-time-end").value.trim(),
    date_start: $("#f-date-start").value,
    date_end: $("#f-date-end").value,
    enabled: $("#f-enabled").checked,
  };
}

async function saveRule() {
  const id = $("#rule-id").value;
  const body = collectRuleForm();
  try {
    await api(id ? `/api/rules/${id}` : "/api/rules", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(body),
    });
    fillRuleForm(null);
    await loadRules();
    renderRules();
    toast(id ? "规则已更新（提示：可到「策略对比」生成回放查看影响）" : "规则已创建");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 3: 策略对比
// ---------------------------------------------------------------------------

function runLabel(r) {
  return `#${r.id} ${r.kind === "live" ? "[实时链]" : "[回放]"} ${r.note || ""} (${r.created_at}) — ${r.pass_count}放/${r.suppress_count}抑`;
}

function renderRunSelects() {
  const a = $("#cmp-a"), b = $("#cmp-b");
  const opts = state.runs.map((r) => `<option value="${r.id}">${esc(runLabel(r))}</option>`).join("");
  a.innerHTML = opts;
  b.innerHTML = opts;
  const live = state.runs.find((r) => r.kind === "live");
  const latestReplay = [...state.runs].reverse().find((r) => r.kind === "replay");
  state.compare.a = state.compare.a || (latestReplay ? latestReplay.id : live ? live.id : null);
  state.compare.b = state.compare.b || (live ? live.id : null);
  if (state.compare.a && state.runs.some((r) => r.id === state.compare.a)) a.value = state.compare.a;
  if (state.compare.b && state.runs.some((r) => r.id === state.compare.b)) b.value = state.compare.b;
  renderSnapshot();
}

async function doReplay() {
  try {
    const r = await api("/api/replays", {
      method: "POST",
      body: JSON.stringify({ note: $("#replay-note").value || "策略变更后回放" }),
    });
    $("#replay-note").value = "";
    await loadRuns();
    renderRunSelects();
    state.compare.a = r.id;
    $("#cmp-a").value = r.id;
    await loadCompare();
    toast(`已生成回放 #${r.id}，重放 ${r.replayed_alerts} 条告警`);
  } catch (e) { fail(e); }
}

async function loadCompare() {
  const a = Number($("#cmp-a").value);
  const b = Number($("#cmp-b").value);
  state.compare.a = a; state.compare.b = b;
  try {
    const result = await api(`/api/compare?run_a=${a}&run_b=${b}`);
    state.compare.result = result;
    renderCompare();
    renderSnapshot();
  } catch (e) { fail(e); }
}

function decisionCell(d) {
  if (!d) return '<span class="badge">无记录</span>';
  return `<span class="decision ${d.decision}">${d.decision === "pass" ? "放行" : "抑制"}</span>
          <div style="color:var(--muted);margin-top:3px;font-size:11.5px">
            ${d.rule_id ? `#${d.rule_id} ${esc(d.rule_name)}` : "默认策略"}</div>`;
}

function renderCompare() {
  const res = state.compare.result;
  if (!res) return;
  $("#cmp-summary").innerHTML =
    `对比 <b>${esc(res.run_a.note || res.run_a.kind)} (#${res.run_a.id})</b> 与
     <b>${esc(res.run_b.note || res.run_b.kind)} (#${res.run_b.id})</b><br>
     共 ${res.total} 条告警，<b style="color:var(--amber)">${res.changed_count} 条决定发生变化</b>`;
  $("#compare-body").innerHTML = res.rows.map((row) => {
    const a = row.alert;
    return `<tr class="${row.changed ? "row-changed" : ""}">
      <td>${a.seq}</td>
      <td>${esc(a.device_id || "-")}<br><span style="color:var(--muted)">${esc(a.batch_id || "-")}</span></td>
      <td>${levelBadge(a.level)}<br><span style="color:var(--muted)">${esc(a.alert_type || "-")}</span></td>
      <td style="white-space:nowrap">${esc(a.ts)}</td>
      <td>${decisionCell(row.a)}</td>
      <td class="reason-cell" style="max-width:280px;color:var(--muted);font-size:12px">${esc(row.a ? row.a.reason : "-")}</td>
      <td>${decisionCell(row.b)}</td>
      <td class="reason-cell" style="max-width:280px;color:var(--muted);font-size:12px">${esc(row.b ? row.b.reason : "-")}</td>
      <td>${row.changed
        ? '<span class="diff-mark">⇄ 已变化</span>'
        : '<span class="no-diff">一致</span>'}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="9" class="empty">暂无已注入告警</td></tr>';
}

function renderSnapshot() {
  const a = state.runs.find((r) => r.id === Number($("#cmp-a")?.value));
  if (!a) return;
  $("#cmp-snapshot").innerHTML = (a.rule_snapshot || []).map((r) => {
    const m = ruleMatches(r);
    return `<div class="snap-rule">
      <div class="top">
        <b>#${r.id} ${esc(r.name)}</b>
        ${r.action === "pass" ? '<span class="decision pass">pass</span>' : '<span class="decision suppress">suppress</span>'}
        <span class="badge">优先级 ${r.priority}</span>
        ${r.cooldown_seconds ? `<span class="badge">冷却 ${r.cooldown_seconds}s</span>` : ""}
      </div>
      <div class="conds">设备 ${esc(m.dev)} · 批次 ${esc(m.batch)} · 级别 ${esc(m.lvl)} · 时段 ${esc(m.time)} · 日期 ${esc(m.dates)}</div>
    </div>`;
  }).join("") || '<p class="empty">无规则</p>';
}

// ---------------------------------------------------------------------------
// Tab 4: 模拟接收端
// ---------------------------------------------------------------------------

function renderSettings() {
  $("#set-forward").checked = state.settings.forward_enabled === "true";
  $("#set-mode").value = state.settings.receiver_mode || "mock";
  $("#set-url").value = state.settings.external_url || "";
}

async function saveSettings() {
  const body = {
    forward_enabled: $("#set-forward").checked,
    receiver_mode: $("#set-mode").value,
    external_url: $("#set-url").value.trim(),
  };
  try {
    state.settings = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    renderSettings();
    toast("设置已保存");
  } catch (e) { fail(e); }
}

async function loadReceiverLogs() {
  const logs = await api("/api/receiver/logs?limit=100");
  const box = $("#receiver-logs");
  if (!logs.length) {
    box.innerHTML = '<p class="empty">暂无投递记录。开启自动转发后注入放行告警，或手动发送测试包。</p>';
    return;
  }
  box.innerHTML = logs.map((l) => `
    <div class="log-item">
      <div class="top">
        <span><span class="status-${esc(l.status)}">● ${esc(l.status)}</span>
          ${l.alert_seq ? ` · 告警 #${l.alert_seq}` : ""} · ${esc(l.target)}</span>
        <span style="color:var(--muted)">${esc(l.created_at)}</span>
      </div>
      <div style="color:var(--muted);font-size:12px;margin-top:3px">${esc(l.detail)}</div>
      <pre>${esc(JSON.stringify(l.payload, null, 2))}</pre>
    </div>`).join("");
}

async function testMock() {
  try {
    await api("/mock-webhook", {
      method: "POST",
      body: JSON.stringify({ test: true, source: "sandbox-ui", at: new Date().toISOString() }),
    });
    await loadReceiverLogs();
    toast("测试包已送达内置接收端");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 1b: 事件关联
// ---------------------------------------------------------------------------

function fmtTs(ts) {
  // 后端存的是 naive ISO（YYYY-MM-DDTHH:MM:SS），直接按本地时间展示
  return esc((ts || "").replace("T", " "));
}

function liveDecisionBadge(dec) {
  if (!dec) return '<span class="badge">未评估</span>';
  return dec === "pass"
    ? '<span class="decision pass">live 放行</span>'
    : '<span class="decision suppress">live 抑制</span>';
}

function evQueryString() {
  const f = state.evFilters;
  const p = new URLSearchParams();
  if (f.device) p.set("device", f.device);
  if (f.level) p.set("level", f.level);
  if (f.start) p.set("start", f.start);
  if (f.end) p.set("end", f.end);
  if (f.ack === "acked") p.set("acknowledged", "true");
  if (f.ack === "unacked") p.set("acknowledged", "false");
  const qs = p.toString();
  return qs ? `?${qs}` : "";
}

async function loadEvents() {
  const [cfg, data] = await Promise.all([
    api("/api/correlation/config"),
    api(`/api/correlation/events${evQueryString()}`),
  ]);
  state.evConfig = cfg;
  state.events = data;
  renderEvents();
}

function renderEvents() {
  $("#ev-interval-input").value = state.evConfig.correlation_interval_seconds;
  $("#ev-interval").textContent = `间隔 ${state.evConfig.correlation_interval_seconds}s`;

  // 设备下拉：从已注入告警收集（确定且无需额外接口）
  const devices = [...new Set(state.alerts.map((x) => x.alert.device_id).filter(Boolean))].sort();
  const devSel = $("#ev-filter-device");
  const cur = state.evFilters.device;
  devSel.innerHTML = '<option value="">全部设备</option>' +
    devices.map((d) => `<option value="${esc(d)}"${d === cur ? " selected" : ""}>${esc(d)}</option>`).join("");

  const list = state.events.events || [];
  const unacked = list.filter((e) => !e.acknowledged).length;
  $("#ev-total").textContent = `${state.events.total} 事件`;
  $("#ev-unacked").textContent = `${unacked} 未确认`;

  const box = $("#events-list");
  if (!list.length) {
    box.innerHTML = '<div class="card"><p class="empty">没有匹配的事件。先在「告警注入」页注入告警，或调整筛选条件 / 聚合间隔。</p></div>';
    return;
  }
  box.innerHTML = list.map((e) => {
    const seqs = e.member_seqs.join(", ");
    const dur = (new Date(e.end_ts) - new Date(e.start_ts)) / 1000;
    const durTxt = dur >= 60 ? `${Math.round(dur / 60)} 分钟` : `${dur} 秒`;
    const tl = e.timeline.map((m) => `
      <li>
        <span class="tl-time">${fmtTs(m.ts)}</span>
        <span class="tl-seq">#${m.seq}</span>
        ${levelBadge(m.level)}
        <span class="tl-msg">${esc(m.message || m.alert_type || "")}</span>
        ${liveDecisionBadge(m.live_decision)}
      </li>`).join("");
    return `<div class="event-card ${e.acknowledged ? "acked" : "unacked"}" data-event-card="${esc(e.event_key)}">
      <div class="event-head" data-toggle-event="${esc(e.event_key)}">
        <span class="ev-title">${esc(e.device_id || "(无设备)")} · ${esc(e.alert_type || "(无类型)")}</span>
        ${levelBadge(e.max_level)}
        <span class="badge">${e.alert_count} 条告警</span>
        <span class="ev-sub">${fmtTs(e.start_ts)} → ${fmtTs(e.end_ts)}（持续约 ${durTxt}）</span>
        <span class="ev-sub">成员序号: ${esc(seqs)}</span>
        <span class="spacer"></span>
        ${e.acknowledged
          ? `<span class="badge pass">✓ 已确认${e.acknowledged_at ? " " + esc(e.acknowledged_at) : ""}</span>`
          : '<span class="badge suppress">● 未确认</span>'}
        <span class="ev-actions">
          <button class="btn small ${e.acknowledged ? "ghost" : "primary"}"
            data-ack-event="${esc(e.event_key)}" data-ack-val="${e.acknowledged ? 0 : 1}">
            ${e.acknowledged ? "取消确认" : "确认"}</button>
        </span>
      </div>
      <div class="event-body collapsed" data-event-body="${esc(e.event_key)}">
        <div class="ack-note">事件标识 <code>${esc(e.event_key)}</code>（成员集合不变即跨重算保留确认状态；最近重算 ${esc(e.computed_at)}）</div>
        <ul class="timeline">${tl}</ul>
      </div>
    </div>`;
  }).join("");
}

async function saveInterval() {
  const val = Number($("#ev-interval-input").value);
  try {
    const r = await api("/api/correlation/config", {
      method: "PUT", body: JSON.stringify({ correlation_interval_seconds: val }),
    });
    await loadEvents();
    toast(`已按 ${r.interval_seconds}s 间隔重算，得到 ${r.event_count} 个事件（live/replay 决定不变）`);
  } catch (e) { fail(e); }
}

async function recomputeEvents() {
  try {
    const r = await api("/api/correlation/recompute", { method: "POST" });
    await loadEvents();
    toast(`重算完成：${r.event_count} 个事件 / ${r.alert_count} 条告警`);
  } catch (e) { fail(e); }
}

async function setEventAck(eventKey, acked) {
  try {
    await api(`/api/correlation/events/${encodeURIComponent(eventKey)}/acknowledge`, {
      method: "POST", body: JSON.stringify({ acknowledged: !!acked }),
    });
    await loadEvents();
  } catch (e) { fail(e); }
}

function syncFilterInputs() {
  const f = state.evFilters;
  $("#ev-filter-device").value = f.device;
  $("#ev-filter-level").value = f.level;
  $("#ev-filter-start").value = f.start;
  $("#ev-filter-end").value = f.end;
  $("#ev-filter-ack").value = f.ack;
}

function readEventFilters() {
  state.evFilters = {
    device: $("#ev-filter-device").value,
    level: $("#ev-filter-level").value,
    start: $("#ev-filter-start").value,
    end: $("#ev-filter-end").value,
    ack: $("#ev-filter-ack").value,
  };
}

// ---------------------------------------------------------------------------
// 示例数据 & 重置
// ---------------------------------------------------------------------------

const SAMPLE = [
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -15.2℃，高于阈值 -18℃", ts: "2026-09-21T00:05:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "critical", alert_type: "temp_high",
    message: "厢内温度 -9.0℃，存在断链风险", ts: "2026-09-21T00:15:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -16.4℃，夜间抖动", ts: "2026-09-21T00:30:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门开启超过 2 分钟", ts: "2026-09-21T00:45:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门仍未关闭", ts: "2026-09-21T00:47:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门仍未关闭（冷却窗内）", ts: "2026-09-21T00:52:00" },
  { device_id: "WH-03", batch_id: "B2026-09C", level: "info", alert_type: "sensor_offline",
    message: "冷库传感器心跳超时", ts: "2026-09-21T01:00:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -16.0℃，白天仍偏高（时段窗口外）", ts: "2026-09-21T09:00:00" },
];

// ---------------------------------------------------------------------------
// 事件绑定
// ---------------------------------------------------------------------------

document.addEventListener("click", async (e) => {
  const t = e.target;
  const ds = t.dataset;
  if (ds.delStaged) {
    try { await api(`/api/staged/${ds.delStaged}`, { method: "DELETE" }); await loadStaged(); renderStaged(); }
    catch (err) { fail(err); }
  }
  if (ds.editRule) {
    const r = state.rules.find((x) => x.id === Number(ds.editRule));
    if (r) { fillRuleForm(r); window.scrollTo({ top: 0, behavior: "smooth" }); }
  }
  if (ds.toggleRule) {
    try { await api(`/api/rules/${ds.toggleRule}/toggle`, { method: "POST" }); await loadRules(); renderRules(); }
    catch (err) { fail(err); }
  }
  if (ds.delRule) {
    if (!confirm("确认删除该规则？")) return;
    try {
      await api(`/api/rules/${ds.delRule}`, { method: "DELETE" });
      if (Number($("#rule-id").value) === Number(ds.delRule)) fillRuleForm(null);
      await loadRules(); renderRules();
    } catch (err) { fail(err); }
  }
  if (ds.ackEvent) {
    e.stopPropagation();  // 避免冒泡到 .event-head 触发折叠
    await setEventAck(ds.ackEvent, ds.ackVal === "1");
  }
  if (ds.toggleEvent) {
    const body = document.querySelector(`[data-event-body="${CSS.escape(ds.toggleEvent)}"]`);
    if (body) body.classList.toggle("collapsed");
  }
});

function bind() {
  document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "receiver") loadReceiverLogs();
    if (btn.dataset.tab === "events") { syncFilterInputs(); loadEvents().catch(fail); }
  }));

  $("#btn-inject-next").addEventListener("click", () => doInject(true));
  $("#btn-inject-all").addEventListener("click", () => doInject(false));
  $("#btn-undo").addEventListener("click", doUndo);
  $("#btn-import").addEventListener("click", () => doImport(false));
  $("#btn-import-append").addEventListener("click", () => doImport(true));
  $("#btn-direct-inject").addEventListener("click", doDirectInject);
  $("#btn-sample").addEventListener("click", () => {
    $("#import-json").value = JSON.stringify(SAMPLE, null, 2);
    toast("已填充 8 条内置示例，点击「导入（替换队列）」");
  });
  $("#btn-save-rule").addEventListener("click", saveRule);
  $("#btn-cancel-edit").addEventListener("click", () => fillRuleForm(null));
  $("#btn-replay").addEventListener("click", doReplay);
  $("#cmp-a").addEventListener("change", loadCompare);
  $("#cmp-b").addEventListener("change", loadCompare);
  $("#btn-save-settings").addEventListener("click", saveSettings);
  $("#btn-test-mock").addEventListener("click", testMock);
  $("#btn-clear-logs").addEventListener("click", async () => {
    try { await api("/api/receiver/clear", { method: "POST" }); await loadReceiverLogs(); toast("日志已清空"); }
    catch (err) { fail(err); }
  });

  // 事件关联
  $("#btn-ev-save-interval").addEventListener("click", saveInterval);
  $("#btn-ev-recompute").addEventListener("click", recomputeEvents);
  ["#ev-filter-device", "#ev-filter-level", "#ev-filter-start", "#ev-filter-end", "#ev-filter-ack"]
    .forEach((sel) => $(sel).addEventListener("change", () => {
      readEventFilters();
      loadEvents().catch(fail);
    }));
  $("#btn-ev-clear-filters").addEventListener("click", () => {
    state.evFilters = { device: "", level: "", start: "", end: "", ack: "" };
    syncFilterInputs();
    loadEvents().catch(fail);
  });
}

bind();
refreshAll().catch(fail);
