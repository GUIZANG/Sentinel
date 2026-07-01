import { useEffect, useMemo, useState } from "react";
import { Table, Tag, Button, Spin, Dropdown, Modal, Input, message, Tabs, Select, Empty, Switch, Alert, Drawer, Descriptions, Timeline } from "antd";
import {
  DashboardOutlined,
  DesktopOutlined,
  SafetyCertificateOutlined,
  ReloadOutlined,
  RobotOutlined,
  UserOutlined,
  LogoutOutlined,
  KeyOutlined,
  BugOutlined,
  AlertOutlined,
  FilePdfOutlined,
  WindowsFilled,
  AppleFilled,
  ArrowLeftOutlined,
  SafetyOutlined,
  AppstoreOutlined,
  MoreOutlined,
} from "@ant-design/icons";
import {
  fetchOverview,
  fetchAgents,
  fetchTrend,
  fetchAiStatus,
  fetchSystemHealth,
  deleteAgent,
  fetchAgentAliases,
  setAgentAliases,
  agentAlias,
  renameAgent,
  fetchIssues,
  resolveIssue,
  reopenIssue,
  fetchAlertDetail,
  fetchVulnerabilities,
  fetchPorts,
  fetchSoftware,
  fetchAlertsList,
  fetchAlertDescription,
  fetchFim,
  fetchActiveResponse,
  fetchAgentDetail,
  fetchAgentSelfCheck,
  changeCredentials,
  clearAuth,
  getUser,
  setUnauthorizedHandler,
  verifySession,
  demoMode,
  tokenQuery,
  type OverviewResp,
  type AgentRow,
  type VulnResp,
  type PortRow,
  type SoftwareRow,
  type AlertRow,
  type FimRow,
  type ArRow,
  type AgentDetail,
  type FirewallState,
  type VulnRow,
  type AiStatusResp,
  type SystemHealthResp,
  type AgentSelfCheckResp,
  type SecurityIssue,
  type AlertDetailResp,
} from "./api";
import Login from "./Login";
import { brand } from "./brand";
import { exportReport } from "./report";
import { currentLang, useLang, t, LangSelect } from "./i18n";
import { tDesc, tDynamic, tGroup, tMitre, tSeverity, tFimEvent, tPortRisk } from "./ai/dynamicText";
import { AiAdviceButton } from "./ai/AiAdvice";
import { alertDescription } from "./ai/alertText";
import {
  RiskGauge,
  SeverityDonut,
  OsDistribution,
  TrendChart,
  TopRulesBar,
} from "./components/charts";

type Page = "overview" | "alerts" | "vulns" | "assets" | "compliance";

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null); // null=校验中
  const [username, setUsername] = useState(getUser());

  useEffect(() => {
    setUnauthorizedHandler(() => setAuthed(false));
    verifySession().then((ok) => setAuthed(ok));
  }, []);

  if (authed === null) {
    return <div style={{ display: "grid", placeItems: "center", height: "100vh" }}><Spin size="large" /></div>;
  }
  if (!authed) {
    return <Login onSuccess={() => { setUsername(getUser()); setAuthed(true); }} />;
  }
  return <Dashboard username={username} onLogout={() => { clearAuth(); setAuthed(false); }} onUserChange={setUsername} />;
}

function Dashboard({ username, onLogout, onUserChange }: { username: string; onLogout: () => void; onUserChange: (u: string) => void }) {
  const { lang } = useLang();
  const [page, setPage] = useState<Page>("overview");
  const [ov, setOv] = useState<OverviewResp | null>(null);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [live, setLive] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [now, setNow] = useState(new Date());
  const [pwdOpen, setPwdOpen] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);

  async function load(showSpinner = true) {
    if (showSpinner) setLoading(true);
    try {
      const [o, a, aliases] = await Promise.all([fetchOverview(), fetchAgents(), fetchAgentAliases()]);
      setAgentAliases(aliases);
      setOv(o.data);
      setAgents(a.data.items);
      setLive(o.live && a.live);
      setLoadError("");
    } catch (e: any) {
      setLive(false);
      setLoadError(e?.message || t("后端接口不可用，请检查服务状态。"));
    } finally {
      if (showSpinner) setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(() => setNow(new Date()), 1000);
    const refresh = setInterval(() => load(false), 5_000);
    return () => {
      clearInterval(t);
      clearInterval(refresh);
    };
  }, [lang]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="logo">{brand.logo}</div>
          <div>
            <div className="name">{brand.name}</div>
            <div className="sub">{t(brand.subtitleKey)}</div>
          </div>
        </div>
        <div className="spacer" />
        <span className="chip">
          <span className={`dot ${ov?.ai?.overview?.source === "guizangai" ? "ok" : "warn"}`} />
          {t("AI 分析：")}{ov?.ai?.overview?.source === "guizangai" ? t("AI 已接入", { name: brand.aiName }) : t("Mock 模式")}
        </span>
        <span className="chip">
          <span className={`dot ${live ? "ok" : "warn"}`} />
          {t("数据源：")}{live ? t("实时") : (demoMode ? t("演示数据") : t("接口异常"))}
        </span>
        <span className="chip">{now.toLocaleString(lang === "en" ? "en-US" : "zh-CN")}</span>
        <LangSelect />
        <Button
          icon={<FilePdfOutlined />}
          onClick={() => ov && exportReport(ov, agents)}
          disabled={!ov}
        >
          {t("导出报告")}
        </Button>
        <Button icon={<ReloadOutlined />} onClick={() => load(true)} type="primary" ghost>
          {t("刷新")}
        </Button>
        <Dropdown
          menu={{
            items: [
              { key: "pwd", icon: <KeyOutlined />, label: t("修改账号密码"), onClick: () => setPwdOpen(true) },
              { type: "divider" },
              { key: "logout", icon: <LogoutOutlined />, label: t("退出登录"), danger: true, onClick: onLogout },
            ],
          }}
        >
          <span className="chip" style={{ cursor: "pointer" }}>
            <UserOutlined /> {username}
          </span>
        </Dropdown>
      </header>

      <ChangeCredentials open={pwdOpen} currentUser={username} onClose={() => setPwdOpen(false)} onChanged={onUserChange} />

      <div className="layout">
        <nav className="nav">
          <NavItem icon={<DashboardOutlined />} label={t("总览大屏")} active={!detailId && page === "overview"} onClick={() => { setDetailId(null); setPage("overview"); }} />
          <NavItem icon={<AlertOutlined />} label={t("安全告警")} active={!detailId && page === "alerts"} onClick={() => { setDetailId(null); setPage("alerts"); }} />
          <NavItem icon={<BugOutlined />} label={t("漏洞与补丁")} active={!detailId && page === "vulns"} onClick={() => { setDetailId(null); setPage("vulns"); }} />
          <NavItem icon={<DesktopOutlined />} label={t("资产清点")} active={!detailId && page === "assets"} onClick={() => { setDetailId(null); setPage("assets"); }} />
          <NavItem icon={<SafetyCertificateOutlined />} label={t("合规加固")} active={!detailId && page === "compliance"} onClick={() => { setDetailId(null); setPage("compliance"); }} />
        </nav>

        <main className="content">
          {loadError ? (
            <Alert
              type="error"
              showIcon
              style={{ marginBottom: 16 }}
              message={t("后端接口不可用")}
              description={loadError}
            />
          ) : null}
          {detailId ? (
            <DeviceDetail id={detailId} onBack={() => setDetailId(null)} />
          ) : loading || !ov ? (
            <div style={{ display: "grid", placeItems: "center", height: "60vh" }}>
              <Spin size="large" />
            </div>
          ) : page === "overview" ? (
            <Overview ov={ov} agents={agents} now={now} onOpen={setDetailId} />
          ) : page === "alerts" ? (
            <AlertsPage agents={agents} />
          ) : page === "vulns" ? (
            <VulnsPage />
          ) : page === "assets" ? (
            <AssetsPage agents={agents} onOpen={setDetailId} />
          ) : (
            <Compliance ov={ov} />
          )}
        </main>
      </div>
    </div>
  );
}

function ChangeCredentials({ open, currentUser, onClose, onChanged }: { open: boolean; currentUser: string; onClose: () => void; onChanged: (u: string) => void }) {
  const [oldPwd, setOldPwd] = useState("");
  const [newUser, setNewUser] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [newPwd2, setNewPwd2] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (open) { setOldPwd(""); setNewUser(currentUser); setNewPwd(""); setNewPwd2(""); }
  }, [open, currentUser]);

  async function submit() {
    if (!oldPwd) return message.warning(t("请输入原密码"));
    if (!newUser.trim()) return message.warning(t("请输入新账号"));
    if (newPwd.length < 6) return message.warning(t("新密码至少 6 位"));
    if (newPwd !== newPwd2) return message.warning(t("两次输入的新密码不一致"));
    setLoading(true);
    try {
      // 用原账号(当前账号)+原密码校验后修改
      await changeCredentials(currentUser, oldPwd, newUser.trim(), newPwd);
      message.success(t("修改成功"));
      onChanged(newUser.trim());
      onClose();
    } catch (e: any) {
      message.error(e.message || t("修改失败"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title={t("修改账号密码")} open={open} onCancel={onClose} onOk={submit} confirmLoading={loading} okText={t("保存")} cancelText={t("取消")} destroyOnClose>
      <p className="muted" style={{ marginTop: 0 }}>{t("用原密码验证后即可修改账号与密码。当前账号：")}<b>{currentUser}</b></p>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <Input.Password placeholder={t("原密码")} value={oldPwd} onChange={(e) => setOldPwd(e.target.value)} />
        <Input placeholder={t("新账号")} value={newUser} onChange={(e) => setNewUser(e.target.value)} />
        <Input.Password placeholder={t("新密码（至少 6 位）")} value={newPwd} onChange={(e) => setNewPwd(e.target.value)} />
        <Input.Password placeholder={t("确认新密码")} value={newPwd2} onChange={(e) => setNewPwd2(e.target.value)} />
      </div>
    </Modal>
  );
}

function NavItem({ icon, label, active, onClick }: any) {
  return (
    <div className={`item ${active ? "active" : ""}`} onClick={onClick}>
      {icon} {label}
    </div>
  );
}

// ----------------------------------------------------------------- 终端席位墙（首页最上方）
function SeatsWall({ agents, onOpen }: { agents: AgentRow[]; onOpen: (id: string) => void }) {
  const online = agents.filter((a) => a.status === "active").length;
  const duplicateCount = agents.filter((a) => a.duplicate_note).length;
  const recentAgents = agents
    .filter((a) => a.registered_at && Date.now() - new Date(a.registered_at).getTime() < 24 * 3600_000)
    .sort((a, b) => new Date(b.registered_at || 0).getTime() - new Date(a.registered_at || 0).getTime())
    .slice(0, 3);
  const [q, setQ] = useState("");
  const [offlineFirst, setOfflineFirst] = useState(true);
  const osIcon = (platform: string) => {
    if (platform === "windows") return <WindowsFilled />;
    if (platform === "darwin") return <AppleFilled />;
    return <DesktopOutlined />;
  };
  async function editSeatAlias(row: AgentRow) {
    const current = agentAlias(row.name) || "";
    const value = await new Promise<string | null>((resolve) => {
      let next = current;
      Modal.confirm({
        title: t("设置终端显示名称"),
        content: (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div className="muted">{t("仅修改仪表盘显示名，不改变 Wazuh 注册名。")}</div>
            <Input defaultValue={current} placeholder={row.name} onChange={(e) => { next = e.target.value; }} />
          </div>
        ),
        okText: t("保存"),
        cancelText: t("取消"),
        onOk: () => resolve(next.trim()),
        onCancel: () => resolve(null),
      });
    });
    if (value === null) return;
    try {
      await renameAgent(row.name, value);
      setAgentAliases(await fetchAgentAliases());
      message.success(t("已保存"));
    } catch {
      message.error(t("保存失败"));
    }
  }
  async function clearSeatAlias(row: AgentRow) {
    try {
      await renameAgent(row.name, "");
      setAgentAliases(await fetchAgentAliases());
      message.success(t("已恢复注册名"));
    } catch {
      message.error(t("保存失败"));
    }
  }
  const shown = useMemo(() => {
    const kw = q.trim().toLowerCase();
    const list = agents.filter(
      (a) => !kw || (a.name || "").toLowerCase().includes(kw) || (a.id || "").includes(kw)
    );
    return [...list].sort((x, y) => {
      if (offlineFirst) {
        const ox = x.status === "active" ? 1 : 0;
        const oy = y.status === "active" ? 1 : 0;
        if (ox !== oy) return ox - oy; // 离线(0)排前
      }
      return (x.id || "").localeCompare(y.id || "", undefined, { numeric: true });
    });
  }, [agents, q, offlineFirst]);
  return (
    <div className="card seats-card">
      <div className="h-row" style={{ flexWrap: "wrap", gap: 10 }}>
        <h3>{t("终端席位总览")}</h3>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginLeft: "auto", flexWrap: "wrap" }}>
          <span className="muted">{online}/{agents.length} {t("台在线")}</span>
          <Select
            value={offlineFirst ? "offline" : "id"}
            size="small"
            style={{ width: 132 }}
            onChange={(v) => setOfflineFirst(v === "offline")}
            options={[
              { value: "offline", label: t("离线优先") },
              { value: "id", label: t("按 ID 排序") },
            ]}
          />
          <Input.Search placeholder={t("搜索设备名/ID")} allowClear size="small" style={{ width: 180 }} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      {duplicateCount > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ margin: "10px 0" }}
          message={t("发现 {n} 条疑似旧终端记录，建议确认后在 Wazuh 中清理。", { n: duplicateCount })}
        />
      ) : null}
      {recentAgents.length > 0 ? (
        <Alert
          type="info"
          showIcon
          style={{ margin: "10px 0" }}
          message={t("最近新增终端：{names}", { names: recentAgents.map((a) => `${a.name}（${a.status === "active" ? t("在线") : t("离线")}）`).join(currentLang === "en" ? ", " : "、") })}
        />
      ) : null}
      <div className="seats">
        {shown.length === 0 && <Empty style={{ gridColumn: "1 / -1" }} description={t("没有匹配的设备")} />}
        {shown.map((a) => {
          const on = a.status === "active";
          return (
            <button key={a.id} className={`seat ${on ? "online" : "offline"}`} onClick={() => onOpen(a.id)} title={`${displayAgent(a.name)} (${a.name})`}>
              <Dropdown
                trigger={["click"]}
                menu={{
                  items: [
                    { key: "rename", label: t("改名"), onClick: () => editSeatAlias(a) },
                    ...(agentAlias(a.name) ? [{ key: "clear", label: t("恢复注册名"), onClick: () => clearSeatAlias(a) }] : []),
                  ],
                }}
              >
                <span className="seat-more" onClick={(e) => e.stopPropagation()} title={t("更多操作")}>
                  <MoreOutlined />
                </span>
              </Dropdown>
              <div className="screen">{osIcon(a.platform)}</div>
              <div className="stand" />
              <div className="seat-status">
                {on ? t("在线") : t("离线")}
                <span className={`live-dot ${on ? "on" : "off"}`} />
              </div>
              <div className="seat-id">ID:{a.id}</div>
              <div className="seat-name">{displayAgent(a.name)}</div>
              {a.duplicate_note ? <Tag color="gold" style={{ marginTop: 6 }}>{t("疑似旧记录")}</Tag> : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------- 总览大屏
function Overview({ ov, agents, now, onOpen }: { ov: OverviewResp; agents: AgentRow[]; now: Date; onOpen: (id: string) => void }) {
  const s = ov.summary;
  const ai = ov.ai?.overview?.result || {};
  const triage = ov.ai?.alert_triage?.result || {};
  const [trendRange, setTrendRange] = useState<"24h" | "7d" | "30d">("7d");
  const [trendData, setTrendData] = useState(ov.trend || []);
  const [aiStatus, setAiStatus] = useState<AiStatusResp | null>(null);
  const [systemHealth, setSystemHealth] = useState<SystemHealthResp | null>(null);
  const [kpiModal, setKpiModal] = useState<null | "high" | "security">(null);
  const perf = useMemo(() => {
    if (!aiStatus) return ov.ai_perf;
    const fallbackSpeed = aiStatus.tokens_per_second ?? aiStatus.avg_tokens_per_second ?? ov.ai_perf?.avg_tokens_per_second;
    const latest = aiStatus.latest || ov.ai_perf?.latest || null;
    const latestWithFallback = latest
      ? {
        ...latest,
        tokens_per_second: latest.tokens_per_second ?? fallbackSpeed,
      }
      : null;
    return {
      ...(ov.ai_perf || { per_task: {}, total_eval_count: 0 }),
      latest: latestWithFallback,
      avg_tokens_per_second: aiStatus.avg_tokens_per_second ?? ov.ai_perf?.avg_tokens_per_second,
      total_eval_count: aiStatus.total_eval_count ?? ov.ai_perf?.total_eval_count ?? 0,
      running: aiStatus.running ?? ov.ai_perf?.running,
      current_task: aiStatus.current_task ?? ov.ai_perf?.current_task,
      running_seconds: aiStatus.running_seconds ?? ov.ai_perf?.running_seconds,
    };
  }, [aiStatus, ov.ai_perf]);
  const high = (s.alerts.by_severity.high || 0) + (s.alerts.by_severity.critical || 0);
  const avgCompliance = useMemo(() => {
    const arr = Object.values(s.compliance).map((c) => c.score || 0).filter(Boolean);
    return arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
  }, [s]);

  useEffect(() => {
    const config = trendRange === "24h"
      ? { days: 1, interval: "hour" as const }
      : trendRange === "30d"
        ? { days: 30, interval: "day" as const }
        : { days: 7, interval: "day" as const };
    fetchTrend(config.days, config.interval)
      .then((r) => setTrendData(r.data.items))
      .catch(() => setTrendData(ov.trend || []));
  }, [trendRange, ov.trend]);

  useEffect(() => {
    fetchSystemHealth().then((r) => setSystemHealth(r.data)).catch(() => setSystemHealth(null));
  }, []);

  useEffect(() => {
    let alive = true;
    const load = () => {
      fetchAiStatus()
        .then((r) => {
          if (alive) setAiStatus(r.data);
        })
        .catch(() => {
          if (alive) setAiStatus(null);
        });
    };
    load();
    const timer = window.setInterval(load, 2000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <>
      <SeatsWall agents={agents} onOpen={onOpen} />
      <div className="grid kpis" style={{ marginTop: 16 }}>
        <Kpi cls="accent" label={t("在线设备")} value={`${s.endpoints.active}`} unit={`/ ${s.endpoints.total} ${t("台")}`} delta={`${s.endpoints.disconnected} ${t("离线")}`} />
        <Kpi cls="danger" label={t("高危/严重告警")} value={`${high}`} unit={t("条")} delta={t("24h 内")} onDetail={() => setKpiModal("high")} />
        <Kpi label={t("安全告警(24h)")} value={`${s.alerts.security_total ?? s.alerts.total}`} unit={t("条")} delta={t("已剔除合规/基线噪声")} onDetail={() => setKpiModal("security")} />
        <Kpi cls={avgCompliance >= 60 ? "ok" : "warn"} label={t("平均合规分")} value={`${avgCompliance}`} unit="/ 100" delta={t("CIS 基线")} />
        <Kpi cls="warn" label={t("整体风险指数")} value={`${ai.risk_score ?? "—"}`} unit="/ 100" delta={ai.risk_level || ""} />
      </div>
      <AlertsKpiModal open={kpiModal === "high"} onClose={() => setKpiModal(null)} title={t("高危/严重告警")} minLevel={12} excludeFimLow={false} agents={agents} />
      <AlertsKpiModal open={kpiModal === "security"} onClose={() => setKpiModal(null)} title={t("安全告警(24h)")} minLevel={7} excludeFimLow={true} agents={agents} />

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        {/* AI 整体态势 —— 产品核心卖点 */}
        <div className="card">
          <div className="ai-head">
            <RobotOutlined style={{ color: "hsl(var(--foreground))" }} />
            <h3>{t("AI 安全态势研判")}</h3>
            <span className="ai-badge">{ov.ai?.overview?.source === "guizangai" ? brand.aiName : "Mock"}</span>
            {ai.risk_level && <span className={`risk-pill lvl-${ai.risk_level}`} style={{ marginLeft: "auto" }}>{ai.risk_level}</span>}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 8, alignItems: "center" }}>
            <RiskGauge score={ai.risk_score ?? 0} />
            <div>
              <div className="ai-headline">{ai.headline || "—"}</div>
              <div className="ai-summary">{ai.summary || t("暂无分析结果。")}</div>
            </div>
          </div>
          {Array.isArray(ai.top_actions) && (
            <ul className="action-list">
              {ai.top_actions.map((a: string, i: number) => (
                <li key={i}>
                  <span className="idx">{i + 1}</span>
                  <span>{cleanAiText(a)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* 风险趋势 */}
        <div className="card">
          <div className="h-row">
            <h3>{t("风险趋势")}</h3>
            <Select
              size="small"
              value={trendRange}
              onChange={setTrendRange}
              style={{ width: 120 }}
              options={[
                { value: "24h", label: t("近 24 小时") },
                { value: "7d", label: t("近 7 天") },
                { value: "30d", label: t("近 30 天") },
              ]}
            />
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: -4, marginBottom: 8 }}>
            {t("高危告警按 Wazuh 当前索引实时统计，口径与安全告警页一致。")}
          </div>
          <TrendChart trend={trendData} />
        </div>
      </div>

      <div className="grid cols-3" style={{ marginTop: 16 }}>
        <div className="card">
          <h3>{t("告警严重度分布")}</h3>
          <SeverityDonut s={s} />
        </div>
        <div className="card">
          <h3>{t("AI 告警归并（降噪后）")}</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {(triage.clusters || []).map((c: any, i: number) => (
              <div key={i} className="list-row">
                <div>
                  <div className="title">{tDynamic(cleanAiText(c.category))}</div>
                  <div className="desc">{tDynamic(cleanAiText(c.meaning))}</div>
                  {c.evidence && <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{t("依据：")}{tDynamic(cleanAiText(c.evidence))}</div>}
                </div>
                <div style={{ textAlign: "right", display: "flex", alignItems: "center", gap: 10 }}>
                  <div className="num">{c.count}</div>
                  <Tag color={c.severity === "高" || c.severity === "High" ? "red" : c.severity === "中" || c.severity === "Medium" ? "orange" : "blue"} style={{ marginInlineEnd: 0 }}>{triageSeverityText(c.severity)}</Tag>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <h3>{t("设备系统分布")}</h3>
          <OsDistribution s={s} />
        </div>
      </div>

      <div className="grid cols-3" style={{ marginTop: 16 }}>
        <div className="card">
          <h3>{t("最常触发的安全规则 Top 6")}</h3>
          <TopRulesBar s={s} />
        </div>
        <div className="card">
          <h3>{t("合规标签覆盖")}</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,1fr)", gap: 12 }}>
            {Object.entries(s.compliance_tags).map(([k, v]) => (
              <div key={k} className="tile">
                <div className="k">{tDynamic(k).replace("_", " ")}</div>
                <div className="v">{v}</div>
                <div className="sub">{t("相关事件")}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="h-row">
            <h3>{t("AI 推理性能", { name: brand.aiName })}</h3>
            <Tag color={perf?.running ? "processing" : perf?.latest?.provider === "ollama" ? "green" : "default"}>
              {perf?.running ? t("分析中") : perf?.latest?.provider || t("暂无")}
            </Tag>
          </div>
          <div className="tile" style={{ marginTop: 10 }}>
            <div className="k">{t("推理速度")}</div>
            <div className="v">
              {perf?.latest?.tokens_per_second ?? "—"} <small>tokens/s</small>
            </div>
            <div className="sub">{t("最后刷新：")}{now.toLocaleTimeString(currentLang === "en" ? "en-US" : "zh-CN")}</div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,1fr)", gap: 12, marginTop: 12 }}>
            <div className="tile">
              <div className="k">{t("输入 Tokens")}</div>
              <div className="v">{perf?.latest?.prompt_eval_count ?? "—"}</div>
              <div className="sub">{t("提示词")}</div>
            </div>
            <div className="tile">
              <div className="k">{t("输出 Tokens")}</div>
              <div className="v">{perf?.latest?.eval_count ?? "—"}</div>
              <div className="sub">{t("最近任务")}</div>
            </div>
            <div className="tile">
              <div className="k">{t("发送日志")}</div>
              <div className="v">{perf?.latest?.raw_events_count ?? "—"}</div>
              <div className="sub">{t("条原始日志")}</div>
            </div>
            <div className="tile">
              <div className="k">{t("任务")}</div>
              <div className="v" style={{ fontSize: 16 }}>{perf?.current_task || perf?.latest?.task || "—"}</div>
              <div className="sub">{perf?.running ? `${t("已运行")} ${perf.running_seconds ?? 0} ${t("秒")}` : brand.aiName}</div>
            </div>
          </div>
          {perf?.latest?.last_error && <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>{t("最近错误：")}{perf.latest.last_error}</div>}
          <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>
            {t("AI 状态：", { name: brand.aiName })}{aiStatus?.mode || (ov.ai?.overview?.source === "guizangai" ? brand.aiName : "Mock")}
            {aiStatus?.connected ? ` · ${t("模型已连接")}` : ` · ${t("当前 Mock")}`}
            {aiStatus?.latest_seconds ? ` · ${t("最近耗时")} ${aiStatus.latest_seconds}s` : ""}
            {aiStatus?.tokens_per_second ? ` · ${aiStatus.tokens_per_second} tokens/s` : ""}
            {aiStatus?.last_error ? ` · ${t("最近错误：")}${aiStatus.last_error}` : ""}
          </div>
        </div>
        <SystemHealthCard health={systemHealth} />
      </div>
    </>
  );
}

function cleanAiText(value: any): string {
  let text = String(value ?? "").trim().replace(/^[、，,;；。\s]+/, "");
  const singleQuotedList = text.match(/^\[\s*'([^']+)'\s*\]$/);
  const doubleQuotedList = text.match(/^\[\s*"([^"]+)"\s*\]$/);
  if (singleQuotedList) text = singleQuotedList[1];
  if (doubleQuotedList) text = doubleQuotedList[1];
  return text.trim().replace(/^['"]|['"]$/g, "").replace(/^[、，,;；。\s]+/, "");
}

function displayAgent(name?: string | null): string {
  return agentAlias(name) || name || "—";
}

function apiText(item: any, field: "label" | "message" = "message"): string {
  const key = item?.[`${field}_key`];
  const fallback = item?.[field] || "";
  const params = item?.params || {};
  const map: Record<string, string> = {
    web: "Web",
    db: "DB",
    wazuh_api: "Wazuh API",
    indexer: "Indexer",
    guizangai: brand.aiName,
    agent_registered: "Wazuh 注册状态",
    agent_running: "Agent 在线状态",
    manager_address: "Manager 地址",
    last_heartbeat: "最近心跳",
    port_connectivity: "{port} 连通性",
    web_ok: "前端入口已响应",
    db_ok: "数据库可查询",
    wazuh_api_ok: "{name} API 可登录",
    indexer_status: "Indexer 状态：{status}",
    guizangai_connected: "已连接",
    guizangai_mock: "Mock 模式",
    check_failed: "检查失败：{error}",
    tcp_ok: "{host}:{port} 可连通",
    tcp_failed: "{host}:{port} 不通：{error}",
    registered_ok: "已注册：{name}",
    registered_missing: "未在 Wazuh API 查到该 Agent",
    agent_status: "当前状态：{status}",
    manager_address_value: "{host}",
    manager_missing: "未配置 Manager 地址",
    heartbeat_value: "{time}",
    heartbeat_missing: "未读取到心跳时间",
  };
  return key && map[key] ? t(map[key], params) : t(fallback, params);
}

function triggerText(item: any): string {
  const params = { ...(item?.params || {}) };
  if (currentLang === "en") {
    for (const key of Object.keys(params)) {
      if (typeof params[key] === "string") params[key] = params[key].replace(/、/g, ", ");
    }
  }
  const map: Record<string, string> = {
    trigger_rule: "命中 Wazuh 规则 {rule_id}：{description}",
    trigger_level_critical: "规则等级 ≥15，按严重告警处理。",
    trigger_level_high: "规则等级 ≥12，按高危告警处理。",
    trigger_level_medium: "规则等级 ≥7，按中危及以上安全告警展示。",
    trigger_groups: "规则分类包含：{groups}",
    trigger_mitre: "关联 MITRE 技术：{mitre}",
    trigger_files: "原始日志包含受影响文件/进程路径：{files}",
    trigger_win_field: "Windows 事件字段 {field}={value}",
    trigger_src_ip: "来源 IP：{ip}",
  };
  return item?.key && map[item.key] ? t(map[item.key], params) : t(item?.text || "");
}

function triageSeverityText(value: any): string {
  const text = String(value ?? "").trim();
  if (text === "高" || /^high$/i.test(text)) return t("高危");
  if (text === "中" || /^medium$/i.test(text)) return t("中危");
  if (text === "低" || /^low$/i.test(text)) return t("低危");
  if (/^critical$/i.test(text)) return t("严重");
  return tDynamic(text);
}

function isActivePinnedTracking(r: AlertRow): boolean {
  return r.issue_status !== "resolved" && !!r.trojan_tracking?.pinned && r.trojan_tracking?.status !== "cleared";
}

function canMarkAlertResolved(r: AlertRow): boolean {
  return r.issue_status !== "resolved" && ((r.level || 0) >= 12 || isActivePinnedTracking(r));
}

function Kpi({ label, value, unit, delta, cls = "", onDetail }: any) {
  return (
    <div className={`card kpi ${cls}`}>
      <div className="label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>{label}</span>
        {onDetail ? <a className="kpi-detail-link" onClick={onDetail}>{t("详情")}</a> : null}
      </div>
      <div className="value">
        {value} <small>{unit}</small>
      </div>
      <div className="delta muted">{delta}</div>
    </div>
  );
}

function SystemHealthCard({ health }: { health: SystemHealthResp | null }) {
  const checks = health?.checks || [];
  return (
    <div className="card">
      <div className="h-row">
        <h3>{t("系统状态")}</h3>
        <Tag color={health?.ok ? "green" : "orange"}>{health?.ok ? t("正常") : t("需关注")}</Tag>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 10 }}>
        {checks.length ? checks.map((item) => (
          <div key={item.key} className="fw-row">
            <span>{apiText(item, "label")}</span>
            <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
              <span className="muted" style={{ fontSize: 12, maxWidth: 170, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.detail || apiText(item)}</span>
              <Tag color={item.ok ? "green" : "red"}>{item.ok ? t("正常") : t("异常")}</Tag>
            </span>
          </div>
        )) : <Empty description={t("暂无系统状态")} />}
      </div>
    </div>
  );
}

function AlertsKpiModal({ open, onClose, title, minLevel, excludeFimLow, agents }: { open: boolean; onClose: () => void; title: string; minLevel: number; excludeFimLow: boolean; agents: AgentRow[] }) {
  const [rows, setRows] = useState<AlertRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [detailRow, setDetailRow] = useState<AlertRow | null>(null);
  const [detailData, setDetailData] = useState<Record<string, AlertDetailResp>>({});
  const [descriptions, setDescriptions] = useState<Record<string, string>>({});
  const [loadingKeys, setLoadingKeys] = useState<Record<string, boolean>>({});
  const agentOs = useMemo(() => agentOsMap(agents), [agents]);
  const rowKey = (r: AlertRow) => `${currentLang}-${r.time}-${r.agent}-${r.rule_id || r.description}`;

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    fetchAlertsList({ min_level: minLevel, exclude_fim_low: excludeFimLow, limit: 500 })
      .then((r) => setRows(normalizeTrojanTrackingRows(r.data.items)))
      .finally(() => setLoading(false));
  }, [open, minLevel, excludeFimLow]);

  async function openDetail(row: AlertRow) {
    setDetailRow(row);
    const key = rowKey(row);
    if (descriptions[key] || loadingKeys[key]) return;
    setLoadingKeys((prev) => ({ ...prev, [key]: true }));
    try {
      const detail = await fetchAlertDetail({ agent: row.agent, description: row.description, time: row.time, fingerprint: row.fingerprint });
      setDetailData((prev) => ({ ...prev, [key]: detail.data }));
      setDescriptions((prev) => ({ ...prev, [key]: detail.data.ai?.description || "" }));
    } finally {
      setLoadingKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function markResolved(row: AlertRow) {
    Modal.confirm({
      title: t("确认已处置该告警？"),
      content: t("该告警会进入已修复问题，可在已修复列表重新打开。"),
      okText: t("确认"),
      cancelText: t("取消"),
      onOk: async () => {
        await resolveIssue({
          fingerprint: row.fingerprint,
          agent: row.agent,
          rule_id: row.rule_id,
          file: row.file,
          target: row.issue_target,
          description: row.description,
          level: row.level,
        });
        message.success(t("已标记为已处置"));
        const refreshed = await fetchAlertsList({ min_level: minLevel, exclude_fim_low: excludeFimLow, limit: 500 });
        setRows(normalizeTrojanTrackingRows(refreshed.data.items));
      },
    });
  }

  const columns = [
    { title: t("时间"), dataIndex: "time", key: "time", width: 170, render: (val: string) => (val ? new Date(val).toLocaleString() : "—") },
    { title: t("设备"), dataIndex: "agent", key: "agent", width: 130, render: (v: string) => displayAgent(v) },
    { title: t("等级"), dataIndex: "level", key: "level", width: 110, render: (l: number) => levelTag(l || 0) },
    { title: t("告警描述"), dataIndex: "description", key: "description", render: (_: string, r: AlertRow) => <span>{alertDescription(r)}</span> },
    {
      title: t("操作"),
      key: "ops",
      width: 280,
      render: (_: any, r: AlertRow) => (
        <span style={{ display: "inline-flex", gap: "6px 12px", alignItems: "center", flexWrap: "wrap" }}>
          <Button size="small" type="link" style={{ padding: 0 }} loading={!!loadingKeys[rowKey(r)]} onClick={() => openDetail(r)}>{t("详情")}</Button>
          <AiAdviceButton kind="alert" ctx={alertAdviceContext(r, resolveAlertAgent(r, agents, agentOs))} />
          {canMarkAlertResolved(r) ? (
            <Button size="small" type="link" danger style={{ padding: 0 }} onClick={() => markResolved(r)}>
              {t("标记已处置")}
            </Button>
          ) : null}
        </span>
      ),
    },
  ];

  return (
    <Modal title={title} open={open} onCancel={onClose} footer={null} width="80vw" destroyOnClose>
      <Table rowKey={rowKey} loading={loading} dataSource={rows} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} scroll={{ x: "max-content", y: 520 }} sticky />
      <AlertDetailDrawer row={detailRow} description={detailRow ? descriptions[rowKey(detailRow)] : ""} detail={detailRow ? detailData[rowKey(detailRow)] : undefined} loading={detailRow ? !!loadingKeys[rowKey(detailRow)] : false} onClose={() => setDetailRow(null)} />
    </Modal>
  );
}

// ----------------------------------------------------------------- 设备资产
function Assets({ agents, onOpen }: { agents: AgentRow[]; onOpen?: (id: string) => void }) {
  const [rows, setRows] = useState(agents);
  const [cleaningId, setCleaningId] = useState<string | null>(null);
  useEffect(() => setRows(agents), [agents]);
  async function cleanupOldAgent(row: AgentRow) {
    Modal.confirm({
      title: t("确认清理旧记录"),
      content: t("将从 Wazuh 删除该旧 Agent 记录：{name}（ID: {id}）。在线终端请不要清理。", { name: row.name, id: row.id }),
      okText: t("确认清理"),
      cancelText: t("取消"),
      okButtonProps: { danger: true },
      onOk: async () => {
        setCleaningId(row.id);
        try {
          await deleteAgent(row.id);
          message.success(t("旧 Agent 记录已清理"));
          const next = await fetchAgents();
          setRows(next.data.items);
        } catch {
          message.error(t("清理失败，请检查 Wazuh API 状态"));
        } finally {
          setCleaningId(null);
        }
      },
    });
  }
  async function editAlias(row: AgentRow) {
    const current = agentAlias(row.name) || "";
    const value = await new Promise<string | null>((resolve) => {
      let next = current;
      Modal.confirm({
        title: t("设置终端显示名称"),
        content: (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div className="muted">{t("仅修改仪表盘显示名，不改变 Wazuh 注册名。")}</div>
            <Input defaultValue={current} placeholder={row.name} onChange={(e) => { next = e.target.value; }} />
          </div>
        ),
        okText: t("保存"),
        cancelText: t("取消"),
        onOk: () => resolve(next.trim()),
        onCancel: () => resolve(null),
      });
    });
    if (value === null) return;
    try {
      await renameAgent(row.name, value);
      setAgentAliases(await fetchAgentAliases());
      message.success(t("已保存"));
    } catch {
      message.error(t("保存失败"));
    }
  }
  const columns = [
    {
      title: t("设备名"),
      dataIndex: "name",
      key: "name",
      render: (n: string, r: AgentRow) => (
        <div>
          <div>
            {onOpen ? <a onClick={() => onOpen(r.id)}>{displayAgent(n)}</a> : displayAgent(n)}
            {agentAlias(n) ? <span className="muted" style={{ marginLeft: 6 }}>({n})</span> : null}
            <Button size="small" type="link" onClick={() => editAlias(r)}>{t("改名")}</Button>
          </div>
          {r.duplicate_note ? (
            <div className="muted" style={{ marginTop: 4 }}>
              <Tag color="gold">{t("疑似旧记录")}</Tag>{r.duplicate_note}
              <Button
                size="small"
                danger
                loading={cleaningId === r.id}
                style={{ marginLeft: 8 }}
                onClick={() => cleanupOldAgent(r)}
              >
                {t("确认清理旧记录")}
              </Button>
            </div>
          ) : null}
        </div>
      ),
    },
    { title: t("IP 地址"), dataIndex: "ip", key: "ip" },
    {
      title: t("系统"),
      dataIndex: "os",
      key: "os",
      filters: [
        { text: "macOS", value: "darwin" },
        { text: "Windows", value: "windows" },
        { text: "Linux", value: "linux" },
      ],
      onFilter: (v: any, r: AgentRow) => r.platform === v,
    },
    {
      title: t("状态"),
      dataIndex: "status",
      key: "status",
      render: (s: string) =>
        s === "active" ? <Tag color="green">{t("在线")}</Tag> : <Tag color="red">{t("离线")}</Tag>,
      filters: [
        { text: t("在线"), value: "active" },
        { text: t("离线"), value: "disconnected" },
      ],
      onFilter: (v: any, r: AgentRow) => r.status === v,
    },
    { title: t("Agent 版本"), dataIndex: "version", key: "version" },
    {
      title: t("最后心跳"),
      dataIndex: "last_keep_alive",
      key: "last_keep_alive",
      render: (val: string) => (val ? new Date(val).toLocaleString() : "—"),
    },
  ];
  const online = rows.filter((a) => a.status === "active").length;
  return (
    <>
      <div className="grid kpis" style={{ gridTemplateColumns: "repeat(3,1fr)" }}>
        <Kpi cls="accent" label={t("设备总数")} value={rows.length} unit={t("台")} delta={t("纳管终端")} />
        <Kpi cls="ok" label={t("在线")} value={online} unit={t("台")} delta={t("在线")} />
        <Kpi cls="danger" label={t("离线")} value={rows.length - online} unit={t("台")} delta={t("需关注")} />
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <div className="h-row">
          <h3>{t("设备资产清单")}</h3>
          <a href={`/api/export/agents.csv${tokenQuery()}`}>
            <Button size="small">{t("导出 CSV")}</Button>
          </a>
        </div>
        <Table rowKey="id" dataSource={rows} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} />
      </div>
    </>
  );
}

// ----------------------------------------------------------------- 合规加固
function Compliance({ ov }: { ov: OverviewResp }) {
  const comp = ov.summary.compliance;
  const ai = ov.ai?.compliance?.result || {};
  const rows = Object.entries(comp).map(([name, c]) => ({ name, ...c }));
  const columns = [
    { title: t("设备"), dataIndex: "name", key: "name" },
    { title: t("基线策略"), dataIndex: "policy", key: "policy" },
    {
      title: t("评分"),
      dataIndex: "score",
      key: "score",
      render: (v: number) => (
        <Tag color={v >= 70 ? "green" : v >= 50 ? "orange" : "red"}>{v}{t("分")}</Tag>
      ),
      sorter: (a: any, b: any) => (a.score || 0) - (b.score || 0),
    },
    { title: t("通过项"), dataIndex: "pass", key: "pass" },
    { title: t("未通过"), dataIndex: "fail", key: "fail" },
  ];
  return (
    <>
      <div className="grid cols-2">
        <div className="card">
          <div className="ai-head">
            <RobotOutlined style={{ color: "hsl(var(--foreground))" }} />
            <h3>{t("AI 加固建议")}</h3>
            <span className="ai-badge">{ov.ai?.compliance?.source === "guizangai" ? brand.aiName : "Mock"}</span>
          </div>
          <div className="ai-summary" style={{ marginBottom: 12 }}>
            {t("合规最差设备：")}<b className="text-destructive">{ai.worst_endpoint || "—"}</b>（{ai.worst_score ?? "—"}{t("分），建议优先处理。")}
          </div>
          <ul className="action-list">
            {(ai.recommendations || []).map((r: string, i: number) => (
              <li key={i}>
                <span className="idx">{i + 1}</span>
                <span>{cleanAiText(r)}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="card">
          <h3>{t("合规标签覆盖（事件数）")}</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,1fr)", gap: 12 }}>
            {Object.entries(ov.summary.compliance_tags).map(([k, v]) => (
              <div key={k} className="tile">
                <div className="k">{tDynamic(k).replace("_", " ")}</div>
                <div className="v">{v}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <h3>{t("各设备 CIS 基线评分")}</h3>
        <Table rowKey="name" dataSource={rows} columns={columns as any} size="middle" pagination={false} />
      </div>
    </>
  );
}

// ----------------------------------------------------------------- 通用：严重度/等级标签
function levelTag(level: number) {
  if (level >= 15) return <Tag color="red">{t("严重")} ({level})</Tag>;
  if (level >= 12) return <Tag color="volcano">{t("高危")} ({level})</Tag>;
  if (level >= 7) return <Tag color="orange">{t("中危")} ({level})</Tag>;
  return <Tag color="blue">{t("低危")} ({level})</Tag>;
}
function sevTag(sev: string) {
  const m: Record<string, string> = { Critical: "red", High: "volcano", Medium: "orange", Low: "blue" };
  return <Tag color={m[sev] || "default"}>{sev ? tSeverity(sev) : t("未定级")}</Tag>;
}

// ----------------------------------------------------------------- 安全告警（明细 / FIM / 自动响应）
function AlertsPage({ agents }: { agents: AgentRow[] }) {
  const [tab, setTab] = useState("alerts");
  return (
    <div className="card">
      <Tabs
        activeKey={tab}
        onChange={setTab}
        items={[
          { key: "alerts", label: t("告警明细"), children: <AlertsDrill agents={agents} /> },
          { key: "resolved", label: t("已修复问题"), children: <ResolvedIssuesTable /> },
          { key: "fim", label: t("文件变更 (FIM)"), children: <FimTable /> },
          { key: "ar", label: t("自动响应"), children: <ArTable /> },
        ]}
      />
    </div>
  );
}

function AlertsDrill({ agents }: { agents: AgentRow[] }) {
  const [minLevel, setMinLevel] = useState(7);
  const [agent, setAgent] = useState<string | undefined>(undefined);
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<AlertRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [latestAlertTime, setLatestAlertTime] = useState<string>("");
  const [polishedDescriptions, setPolishedDescriptions] = useState<Record<string, string>>({});
  const [polishingKeys, setPolishingKeys] = useState<Record<string, boolean>>({});
  const [detailRow, setDetailRow] = useState<AlertRow | null>(null);
  const [detailData, setDetailData] = useState<Record<string, AlertDetailResp>>({});
  const agentOs = useMemo(() => agentOsMap(agents), [agents]);

  const rowKey = (r: AlertRow) => `${currentLang}-${r.time}-${r.agent}-${r.rule_id || r.description}`;

  async function openAlertDetail(row: AlertRow) {
    setDetailRow(row);
    const key = rowKey(row);
    if (polishedDescriptions[key] || polishingKeys[key]) return;
    setPolishingKeys((prev) => ({ ...prev, [key]: true }));
    try {
      const detail = await fetchAlertDetail({ agent: row.agent, description: row.description, time: row.time, fingerprint: row.fingerprint });
      setDetailData((prev) => ({ ...prev, [key]: detail.data }));
      setPolishedDescriptions((prev) => ({ ...prev, [key]: detail.data.ai?.description || "" }));
    } catch {
      try {
        const result = await fetchAlertDescription(alertAdviceContext(row, resolveAlertAgent(row, agents, agentOs)));
        setPolishedDescriptions((prev) => ({ ...prev, [key]: result.description }));
      } catch {
        message.error(t("详情生成失败，请稍后重试。"));
      }
    } finally {
      setPolishingKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function load() {
    setLoading(true);
    const r = await fetchAlertsList({ min_level: minLevel, agent, q: q || undefined, limit: 300 });
    const normalized = normalizeTrojanTrackingRows(r.data.items);
    setRows(normalized);
    setLatestAlertTime(normalized[0]?.time || "");
    setLoading(false);
  }
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [minLevel, agent]);
  useEffect(() => {
    if (!rows.some((row) => row.trojan_tracking?.pinned)) {
      return;
    }
    const timer = setInterval(() => load(), 10_000);
    return () => clearInterval(timer);
    /* eslint-disable-next-line */
  }, [minLevel, agent, q, rows]);
  useEffect(() => {
    const timer = setInterval(async () => {
      const r = await fetchAlertsList({ min_level: minLevel, agent, q: q || undefined, limit: 1 });
      const latest = r.data.items[0]?.time || "";
      if (latest && latest !== latestAlertTime) {
        await load();
      }
    }, 10_000);
    return () => clearInterval(timer);
    /* eslint-disable-next-line */
  }, [minLevel, agent, q, latestAlertTime]);

  const sortedRows = useMemo(() => {
    return [...rows].sort((a, b) => {
      const ah = canMarkAlertResolved(a) || isActivePinnedTracking(a) ? 1 : 0;
      const bh = canMarkAlertResolved(b) || isActivePinnedTracking(b) ? 1 : 0;
      if (ah !== bh) return bh - ah;
      return (new Date(b.time).getTime() || 0) - (new Date(a.time).getTime() || 0);
    });
  }, [rows]);

  async function markResolved(row: AlertRow) {
    Modal.confirm({
      title: t("确认已处置该告警？"),
      content: t("该告警会进入已修复问题，可在已修复列表重新打开。"),
      okText: t("确认"),
      cancelText: t("取消"),
      onOk: async () => {
        await resolveIssue({
          fingerprint: row.fingerprint,
          agent: row.agent,
          rule_id: row.rule_id,
          file: row.file,
          target: row.issue_target,
          description: row.description,
          level: row.level,
        });
        message.success(t("已标记为已处置"));
        await load();
      },
    });
  }

  const columns = [
    { title: t("时间"), dataIndex: "time", key: "time", width: 170, render: (val: string) => (val ? new Date(val).toLocaleString() : "—") },
    { title: t("设备"), dataIndex: "agent", key: "agent", width: 120, render: (v: string) => displayAgent(v) },
    { title: t("等级"), dataIndex: "level", key: "level", width: 110, render: (l: number) => levelTag(l || 0), sorter: (a: AlertRow, b: AlertRow) => (a.level || 0) - (b.level || 0) },
    {
      title: t("告警描述"),
      dataIndex: "description",
      key: "description",
      width: "38%",
      render: (_: string, r: AlertRow) => (
        <div>
          {isActivePinnedTracking(r) ? (
            <Tag color="red" style={{ marginBottom: 4 }}>
              {t("置顶追踪中")}
            </Tag>
          ) : null}
          <span>{alertDescription(r)}</span>
          {(r.occurrence_count || 0) > 1 ? <Tag color="blue" style={{ marginLeft: 8 }}>{t("同类 {n} 次", { n: r.occurrence_count || 1 })}</Tag> : null}
          {r.issue_status === "open" ? <Tag color="red" style={{ marginLeft: 8 }}>{t("未修复")}</Tag> : null}
          {r.issue_status === "resolved" ? <Tag color="green" style={{ marginLeft: 8 }}>{t("已修复")}</Tag> : null}
        </div>
      ),
    },
    { title: t("分类"), dataIndex: "groups", key: "groups", width: 160, render: (g: string[]) => (g || []).slice(0, 2).map((x) => <Tag key={x}>{tGroup(x)}</Tag>) },
    { title: "MITRE", dataIndex: "mitre", key: "mitre", width: 110, render: (m: string[]) => (m || []).slice(0, 2).map((x) => <Tag color="purple" key={x}>{tMitre(x)}</Tag>) },
    {
      title: t("操作"),
      key: "ops",
      width: 220,
      render: (_: any, r: AlertRow) => (
        <span style={{ display: "inline-flex", gap: "6px 12px", alignItems: "center", flexWrap: "wrap" }}>
          <Button
            size="small"
            type="link"
            style={{ padding: 0 }}
            loading={!!polishingKeys[rowKey(r)]}
            onClick={() => openAlertDetail(r)}
          >
            {t("详情")}
          </Button>
          <AiAdviceButton kind="alert" ctx={alertAdviceContext(r, resolveAlertAgent(r, agents, agentOs))} />
          {canMarkAlertResolved(r) ? (
            <Button size="small" type="link" danger style={{ padding: 0 }} onClick={() => markResolved(r)}>
              {t("标记已处置")}
            </Button>
          ) : null}
        </span>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <span className="muted">{t("最低等级")}</span>
        <Select
          value={minLevel}
          style={{ width: 150 }}
          onChange={setMinLevel}
          options={[
            { value: 0, label: t("全部") },
            { value: 7, label: t("中危及以上 (≥7)") },
            { value: 12, label: t("高危及以上 (≥12)") },
            { value: 15, label: t("仅严重 (≥15)") },
          ]}
        />
        <Select
          value={agent}
          style={{ width: 170 }}
          allowClear
          placeholder={t("按设备筛选")}
          onChange={(v) => setAgent(v)}
          options={agents.map((a) => ({ value: a.name, label: displayAgent(a.name) }))}
        />
        <Input.Search
          placeholder={t("搜索告警描述关键词")}
          style={{ width: 240 }}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onSearch={load}
          allowClear
        />
      </div>
      <Table
        rowKey={rowKey}
        loading={loading}
        dataSource={sortedRows}
        columns={columns as any}
        size="middle"
        pagination={{ pageSize: 12 }}
        scroll={{ y: 560 }}
        sticky
        rowClassName={(r) => {
          if (isActivePinnedTracking(r)) return "trojan-tracking-row";
          if ((r.level || 0) >= 12 && r.issue_status === "resolved") return "row-high-resolved";
          if (canMarkAlertResolved(r)) return "row-high-open";
          return "";
        }}
      />
      <AlertDetailDrawer
        row={detailRow}
        description={detailRow ? polishedDescriptions[rowKey(detailRow)] : ""}
        detail={detailRow ? detailData[rowKey(detailRow)] : undefined}
        loading={detailRow ? !!polishingKeys[rowKey(detailRow)] : false}
        onClose={() => setDetailRow(null)}
      />
    </>
  );
}

function AlertDetailDrawer({
  row,
  description,
  detail,
  loading,
  onClose,
}: {
  row: AlertRow | null;
  description: string;
  detail?: AlertDetailResp;
  loading: boolean;
  onClose: () => void;
}) {
  if (!row) return null;
  const tracking = row.trojan_tracking;
  const facts = [
    { label: t("设备"), value: row.agent },
    { label: t("等级"), value: row.level ? `${row.level}` : "—" },
    { label: t("规则 ID"), value: row.rule_id || "—" },
    { label: t("端口"), value: row.port || row.dst_port || row.src_port || "—" },
    { label: t("协议"), value: row.protocol || "—" },
    { label: t("监听地址"), value: row.listen_ip || "—" },
    { label: t("进程"), value: row.process || "—" },
    { label: t("追踪编号"), value: tracking?.tracking_id || "—" },
    { label: t("追踪状态"), value: tracking?.status || "—" },
  ];
  const affectedFiles = detail?.factual?.affected_files || [];
  const trigger = detail?.factual?.trigger_explain;
  const sep = currentLang === "en" ? ": " : "：";
  const detailText = [
    `${t("原始描述")}${sep}${alertDescription(row)}`,
    `${t("AI 详情", { name: brand.aiName })}${sep}${description || t("暂无详情，请稍后重试。")}`,
    ...facts.map((item) => `${item.label}${sep}${item.value ?? "—"}`),
    `${t("原始日志片段")}${sep}${row.raw_log || t("无原始日志片段")}`,
  ].join("\n");
  const copyText = async (text: string, okText: string) => {
    const value = text || "";
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        fallbackCopyText(value);
      }
      message.success(okText);
    } catch {
      try {
        fallbackCopyText(value);
        message.success(okText);
      } catch {
        message.error(t("复制失败，请手动选中复制"));
      }
    }
  };
  return (
    <Drawer
      title={t("告警详情")}
      open={!!row}
      onClose={onClose}
      width={720}
      extra={
        <div style={{ display: "flex", gap: 8 }}>
          <Button size="small" onClick={() => copyText(row.raw_log || "", t("已复制原始日志"))}>{t("复制原始日志")}</Button>
          <Button size="small" type="primary" onClick={() => copyText(detailText, t("已复制详情"))}>{t("复制详情")}</Button>
        </div>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div>
          <div className="section-title" style={{ margin: "0 0 6px" }}>{t("原始描述")}</div>
          <div className="ai-summary">{alertDescription(row)}</div>
        </div>
        <div>
          <div className="section-title" style={{ margin: "0 0 6px" }}>{t("AI 详情", { name: brand.aiName })}</div>
          {loading ? <Spin size="small" /> : <div className="ai-summary">{description || t("暂无详情，请稍后重试。")}</div>}
        </div>
        <Descriptions size="small" bordered column={2} items={facts.map((item) => ({ key: item.label, label: item.label, children: String(item.value ?? "—") }))} />
        {trigger ? (
          <div>
            <div className="section-title" style={{ margin: "0 0 6px" }}>{t("为什么触发")}</div>
            <Alert
              type={trigger.highlighted ? "warning" : "info"}
              showIcon
              message={(trigger.reason_items || []).slice(0, 3).map(triggerText).join(currentLang === "en" ? "; " : "；") || t("已根据原始日志解析触发原因")}
              description={
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                  {(trigger.reason_items || []).map((reason: any, i: number) => <li key={i}>{triggerText(reason)}</li>)}
                  <li>{t(trigger.highlight_reason_key === "trigger_highlighted" ? "高危等级或命中重点安全规则，因此在列表中优先展示/标红。" : "未达到高危标红条件。")}</li>
                </ul>
              }
            />
          </div>
        ) : null}
        {affectedFiles.length ? (
          <div>
            <div className="section-title" style={{ margin: "0 0 6px" }}>{t("受影响文件")}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {affectedFiles.map((file: string) => <Tag key={file}>{file}</Tag>)}
            </div>
          </div>
        ) : null}
        {detail?.issue ? <IssueTimelineView issue={detail.issue} /> : null}
        <div>
          <div className="section-title" style={{ margin: "0 0 6px" }}>{t("原始日志片段")}</div>
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 260, overflow: "auto", background: "#0f172a", color: "#e5e7eb", padding: 12, borderRadius: 8 }}>
            {row.raw_log || t("无原始日志片段")}
          </pre>
        </div>
      </div>
    </Drawer>
  );
}

function fallbackCopyText(text: string) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(textarea);
  if (!ok) throw new Error("copy failed");
}

function IssueTimelineView({ issue }: { issue: SecurityIssue }) {
  const resolved = issue.status === "resolved";
  const color = (type: string) => type === "cleared" ? "green" : type === "reopened" ? "red" : type === "active_response" ? "blue" : type.startsWith("review_") ? "green" : "gray";
  const label = (type: string) => {
    if (type === "detected") return t("发现");
    if (type === "cleared") return t("已清除");
    if (type === "reopened") return t("再次出现");
    if (type === "active_response") return t("自动响应");
    if (type.startsWith("review_")) return t("自动复核");
    return type;
  };
  const timeline = issue.timeline || [];
  return (
    <div>
      <div className="section-title" style={{ margin: "0 0 8px" }}>
        {t("处置时间轴（发现 → 清除）")}
        <span style={{ marginLeft: 8 }}>
          {resolved ? <Tag color="green">{t("已修复")}</Tag> : <Tag color="red">{t("未修复 · 追踪中")}</Tag>}
        </span>
      </div>
      <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
        {t("首次发现")}: {issue.first_seen ? new Date(issue.first_seen).toLocaleString() : "—"}
        {"　"}{t("最近出现")}: {issue.last_seen ? new Date(issue.last_seen).toLocaleString() : "—"}
        {resolved ? <>{"　"}{t("清除时间")}: {issue.resolved_at ? new Date(issue.resolved_at).toLocaleString() : "—"}</> : null}
        {"　"}{t("出现次数")}: {issue.occurrences ?? "—"}
      </div>
      {timeline.length ? (
        <Timeline
          items={timeline.map((item) => ({
            color: color(item.type),
            children: (
              <div>
                <div style={{ fontSize: 12 }}>
                  <b>{label(item.type)}</b>
                  <span className="muted" style={{ marginLeft: 8 }}>{item.ts ? new Date(item.ts).toLocaleString() : ""}</span>
                </div>
                <div style={{ fontSize: 13 }}>{item.detail}</div>
              </div>
            ),
          }))}
        />
      ) : <Empty description={t("暂无时间线")} />}
    </div>
  );
}

function ResolvedIssuesTable() {
  const [rows, setRows] = useState<SecurityIssue[]>([]);
  const [loading, setLoading] = useState(true);
  const [openIssue, setOpenIssue] = useState<SecurityIssue | null>(null);

  async function load() {
    setLoading(true);
    const r = await fetchIssues("resolved");
    setRows(r.data.items);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  const columns = [
    { title: t("清除时间"), dataIndex: "resolved_at", key: "resolved_at", width: 175, render: (v: string) => (v ? new Date(v).toLocaleString() : "—") },
    { title: t("设备"), dataIndex: "agent", key: "agent", width: 130, render: (v: string) => displayAgent(v) },
    { title: t("严重度"), dataIndex: "severity", key: "severity", width: 100, render: (s: string, r: SecurityIssue) => sevTag(s || String(r.level || "")) },
    { title: t("问题描述"), dataIndex: "description", key: "description", render: (d: string) => tDesc(d) },
    { title: t("清除方式"), dataIndex: "resolution", key: "resolution", width: 130, render: (v: string) => <Tag color={v === "manual" ? "blue" : "green"}>{v || t("自动")}</Tag> },
    { title: t("复核状态"), key: "review", width: 130, render: (_: any, r: SecurityIssue) => reviewStatusTag(r) },
    {
      title: t("操作"),
      key: "ops",
      width: 170,
      render: (_: any, r: SecurityIssue) => (
        <span style={{ display: "inline-flex", gap: 10 }}>
          <Button size="small" type="link" onClick={() => setOpenIssue(r)}>{t("时间线")}</Button>
          <Button
            size="small"
            type="link"
            onClick={async () => {
              await reopenIssue(r.fingerprint);
              message.success(t("已重新打开追踪"));
              load();
            }}
          >
            {t("重新打开")}
          </Button>
        </span>
      ),
    },
  ];

  return (
    <>
      <Table rowKey="fingerprint" loading={loading} dataSource={rows} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} scroll={{ x: "max-content", y: 520 }} sticky />
      <Drawer title={t("问题时间线")} open={!!openIssue} onClose={() => setOpenIssue(null)} width={620}>
        {openIssue ? <IssueTimelineView issue={openIssue} /> : <Empty description={t("暂无时间线")} />}
      </Drawer>
    </>
  );
}

function reviewStatusTag(issue: SecurityIssue) {
  const types = new Set((issue.timeline || []).map((item) => item.type));
  if (types.has("review_30m")) return <Tag color="green">{t("确认稳定")}</Tag>;
  if (types.has("review_15m")) return <Tag color="cyan">{t("15 分钟通过")}</Tag>;
  if (types.has("review_5m")) return <Tag color="blue">{t("5 分钟通过")}</Tag>;
  return <Tag color="gold">{t("待复核")}</Tag>;
}

function agentOsMap(agents: AgentRow[]): Map<string, AgentRow> {
  return new Map((agents || []).filter((agent) => agent.name).map((agent) => [agent.name, agent]));
}

function resolveAlertAgent(row: AlertRow, agents: AgentRow[], byName: Map<string, AgentRow>): AgentRow | undefined {
  const direct = byName.get(row.agent);
  if (direct) return direct;
  const raw = `${row.raw_log || ""}\n${row.description || ""}`;
  return (agents || []).find((agent) => agent.name && raw.includes(agent.name));
}

function osAdviceFields(agent?: AgentRow | null): Record<string, any> {
  return {
    target_os: agent?.os || "",
    target_platform: agent?.platform || "",
  };
}

function alertAdviceContext(r: AlertRow, agent?: AgentRow): Record<string, any> {
  return {
    ...osAdviceFields(agent),
    rule_id: r.rule_id,
    fingerprint: r.fingerprint,
    issue_target: r.issue_target,
    issue_status: r.issue_status,
    resolved_at: r.resolved_at,
    description: r.description,
    display_description: alertDescription(r),
    level: r.level,
    groups: r.groups,
    mitre: r.mitre,
    agent: r.agent,
    time: r.time,
    src_ip: r.src_ip,
    dst_ip: r.dst_ip,
    src_port: r.src_port,
    dst_port: r.dst_port,
    port: r.port,
    protocol: r.protocol,
    listen_ip: r.listen_ip,
    process: r.process,
    listened_ports: r.listened_ports,
    changed_ports: r.changed_ports,
    port_change: r.port_change,
    raw_log: r.raw_log,
    trojan_event: r.trojan_event,
    trojan_tracking: r.trojan_tracking,
  };
}

function vulnAdviceContext(r: VulnRow, agent?: AgentRow | null, fallback?: Record<string, any>): Record<string, any> {
  return {
    ...osAdviceFields(agent),
    ...fallback,
    cve: r.cve,
    severity: r.severity,
    score: r.score,
    package: r.package,
    version: r.version,
    condition: r.condition,
    description: r.description,
    agent: r.agent || fallback?.agent,
  };
}

function normalizeTrojanTrackingRows(rows: AlertRow[]): AlertRow[] {
  const activeIds = new Set(
    rows
      .map((row) => row.trojan_tracking)
      .filter((tracking) => tracking?.tracking_id && tracking.pinned && tracking.status !== "cleared")
      .map((tracking) => String(tracking!.tracking_id))
  );
  const clearedIds = new Set(
    rows
      .map((row) => row.trojan_tracking)
      .filter((tracking) => tracking?.tracking_id && tracking.status === "cleared" && !activeIds.has(String(tracking.tracking_id)))
      .map((tracking) => String(tracking!.tracking_id))
  );
  if (!clearedIds.size) return rows;
  return rows.map((row) => {
    const tracking = row.trojan_tracking;
    if (!tracking || !clearedIds.has(String(tracking.tracking_id))) return row;
    return {
      ...row,
      trojan_tracking: {
        ...tracking,
        status: "cleared",
        pinned: false,
        stages: Array.from(new Set([...(tracking.stages || []), "cleared"])),
      },
    };
  });
}

function FimTable() {
  const [rows, setRows] = useState<FimRow[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetchFim().then((r) => { setRows(r.data.items); setLoading(false); }); }, []);
  const eventTag = (e: string) => {
    const c: Record<string, string> = { added: "green", modified: "orange", deleted: "red" };
    return <Tag color={c[e] || "default"}>{tFimEvent(e)}</Tag>;
  };
  const columns = [
    { title: t("时间"), dataIndex: "time", key: "time", width: 170, render: (val: string) => (val ? new Date(val).toLocaleString() : "—") },
    { title: t("设备"), dataIndex: "agent", key: "agent", width: 120 },
    { title: t("变更"), dataIndex: "event", key: "event", width: 90, render: eventTag },
    { title: t("文件路径"), dataIndex: "path", key: "path", ellipsis: true },
    { title: t("说明"), dataIndex: "description", key: "description", width: 220, render: (d: string) => tDesc(d) },
  ];
  return <Table rowKey={(r) => `${r.time}-${r.path}`} loading={loading} dataSource={rows} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} scroll={{ x: "max-content", y: 520 }} sticky locale={{ emptyText: <Empty description={t("近 24 小时无文件变更记录")} /> }} />;
}

function ArTable() {
  const [rows, setRows] = useState<ArRow[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetchActiveResponse().then((r) => { setRows(r.data.items); setLoading(false); }); }, []);
  const columns = [
    { title: t("时间"), dataIndex: "time", key: "time", width: 170, render: (val: string) => (val ? new Date(val).toLocaleString() : "—") },
    { title: t("设备"), dataIndex: "agent", key: "agent", width: 120 },
    { title: t("处置动作"), dataIndex: "command", key: "command", width: 180, render: (c: string) => <Tag color="geekblue">{c || "—"}</Tag> },
    { title: t("说明"), dataIndex: "description", key: "description", render: (d: string) => tDesc(d) },
  ];
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>{t("自动响应：满足条件时系统自动执行的处置（如封禁来源 IP、禁用账户）。未配置或近 24h 无触发时此处为空。")}</p>
      <Table rowKey={(r) => `${r.time}-${r.command}`} loading={loading} dataSource={rows} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} scroll={{ x: "max-content", y: 520 }} sticky locale={{ emptyText: <Empty description={t("近 24 小时无自动响应记录")} /> }} />
    </>
  );
}

// ----------------------------------------------------------------- 漏洞与补丁
function VulnsPage() {
  const [data, setData] = useState<VulnResp | null>(null);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetchVulnerabilities().then((r) => { setData(r.data); setLoading(false); }); }, []);
  useEffect(() => { fetchAgents().then((r) => setAgents(r.data.items)); }, []);

  if (loading || !data) {
    return <div style={{ display: "grid", placeItems: "center", height: "50vh" }}><Spin size="large" /></div>;
  }
  const ov = data.overview;
  const sev = ov.by_severity || {};
  const affected = Object.keys(ov.by_agent || {}).length;
  const osByAgent = agentOsMap(agents);

  const columns = [
    { title: t("设备"), dataIndex: "agent", key: "agent", width: 120 },
    { title: t("CVE 编号"), dataIndex: "cve", key: "cve", width: 260, render: (c: string, r: VulnRow) => <CveText cve={c} description={r.condition || r.description} /> },
    { title: t("严重度"), dataIndex: "severity", key: "severity", width: 110, render: (s: string) => sevTag(s) },
    { title: "CVSS", dataIndex: "score", key: "score", width: 90, render: (v: number | null) => (v ?? "—"), sorter: (a: any, b: any) => (a.score || 0) - (b.score || 0) },
    { title: t("受影响软件"), dataIndex: "package", key: "package" },
    { title: t("版本"), dataIndex: "version", key: "version", width: 120 },
    { title: "", key: "ai", width: 120, render: (_: any, r: VulnRow) => <AiAdviceButton kind="vuln" ctx={vulnAdviceContext(r, osByAgent.get(r.agent))} /> },
  ];

  return (
    <>
      <div className="grid kpis" style={{ gridTemplateColumns: "repeat(5,1fr)" }}>
        <Kpi cls="accent" label={t("漏洞总数")} value={ov.total} unit={t("个")} delta={t("待评估/修复")} />
        <Kpi cls="danger" label={t("严重")} value={sev.Critical || 0} unit={t("个")} delta={t("应立即修复")} />
        <Kpi cls="warn" label={t("高危")} value={sev.High || 0} unit={t("个")} delta={t("尽快修复")} />
        <Kpi label={t("中/低危")} value={(sev.Medium || 0) + (sev.Low || 0)} unit={t("个")} delta={t("计划处理")} />
        <Kpi cls="accent" label={t("受影响设备")} value={affected} unit={t("台")} delta={t("存在漏洞")} />
      </div>

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <div className="card">
          <h3>{t("Top 高频漏洞 (CVE)")}</h3>
          <TopCveList details={ov.top_cve_details} fallback={ov.top_cves} />
        </div>
        <div className="card">
          <h3>{t("漏洞最多的设备")}</h3>
          <RankList data={ov.by_agent} unit={t("个")} />
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="h-row">
          <h3>{t("漏洞明细（按 CVSS 评分排序）")}</h3>
        </div>
        <Table
          rowKey={(r) => `${r.agent}-${r.cve}-${r.package}`}
          dataSource={data.items}
          columns={columns as any}
          size="middle"
          pagination={{ pageSize: 12 }}
          locale={{ emptyText: <Empty description={t("暂无漏洞数据（漏洞检测可能仍在首次扫描中，请稍后刷新）")} /> }}
        />
      </div>
    </>
  );
}

function RankList({ data, unit }: { data: Record<string, number>; unit: string }) {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = entries.length ? entries[0][1] : 1;
  if (!entries.length) return <Empty description={t("暂无数据")} />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 13, marginBottom: 4 }}>{k}</div>
            <div style={{ height: 6, background: "#f4f4f5", borderRadius: 4 }}>
              <div style={{ width: `${Math.max(6, (v / max) * 100)}%`, height: 6, background: "#18181b", borderRadius: 4 }} />
            </div>
          </div>
          <div className="num" style={{ minWidth: 56, textAlign: "right" }}>{v} {unit}</div>
        </div>
      ))}
    </div>
  );
}

function TopCveList({
  details,
  fallback,
}: {
  details?: NonNullable<VulnResp["overview"]["top_cve_details"]>;
  fallback: Record<string, number>;
}) {
  const items = (details || []).slice(0, 8);
  if (!items.length) return <RankList data={fallback} unit={t("次")} />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {items.map((v) => (
        <div key={v.cve} style={{ borderBottom: "1px solid #f4f4f5", paddingBottom: 10 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ fontWeight: 600 }}>{v.cve}</span>
            {v.severity ? sevTag(v.severity) : null}
            <span className="muted">{v.count} {t("次")}</span>
          </div>
          <div style={{ fontSize: 13, marginTop: 4 }}>
            {(v.package || t("受影响软件"))}{v.version ? ` ${v.version}` : ""}
            {v.score ? <span className="muted"> · CVSS {v.score}</span> : null}
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
            {vulnDescriptionText(v.condition || v.description) || t("查看 CVE 详情确认影响范围和修复版本")}
          </div>
        </div>
      ))}
    </div>
  );
}

function CveText({ cve, description }: { cve: string; description?: string }) {
  const text = vulnDescriptionText(description);
  return (
    <div>
      <div style={{ fontWeight: 600 }}>{cve}</div>
      {text ? <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>{text}</div> : null}
    </div>
  );
}

function vulnDescriptionText(text?: string) {
  if (!text) return "";
  if (currentLang !== "zh") return text;
  const fixedVersion = text.match(/^Package less than\s+(.+)$/i)?.[1]?.trim();
  if (fixedVersion && fixedVersion.toLowerCase() !== "fixed version") {
    return `当前软件版本低于安全修复版本 ${fixedVersion}，建议升级到 ${fixedVersion} 或更高版本。`;
  }
  if (/^Package less than fixed version$/i.test(text)) {
    return "当前软件版本低于安全修复版本，建议升级到官方修复版本或更高版本。";
  }
  return text;
}

// ----------------------------------------------------------------- 资产清点（设备 / 端口 / 软件）
function AssetsPage({ agents, onOpen }: { agents: AgentRow[]; onOpen: (id: string) => void }) {
  const [tab, setTab] = useState("devices");
  return (
    <div className="card">
      <Tabs
        activeKey={tab}
        onChange={setTab}
        items={[
          { key: "devices", label: t("设备清单"), children: <Assets agents={agents} onOpen={onOpen} /> },
          { key: "ports", label: t("开放端口"), children: <PortsTable /> },
          { key: "software", label: t("软件清单"), children: <SoftwareTable /> },
        ]}
      />
    </div>
  );
}

function PortsTable() {
  const [rows, setRows] = useState<PortRow[]>([]);
  const [scanned, setScanned] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetchPorts().then((r) => { setRows(r.data.items); setScanned(r.data.scanned_agents); setLoading(false); }); }, []);
  const columns = [
    { title: t("端口"), dataIndex: "port", key: "port", width: 100, sorter: (a: PortRow, b: PortRow) => a.port - b.port },
    { title: t("协议"), dataIndex: "protocol", key: "protocol", width: 100 },
    { title: t("进程"), dataIndex: "process", key: "process" },
    { title: t("开放设备数"), dataIndex: "agents", key: "agents", width: 120, sorter: (a: PortRow, b: PortRow) => a.agents - b.agents, defaultSortOrder: "descend" as const },
    { title: t("风险提示"), dataIndex: "risky", key: "risky", width: 200, render: (r: string | null) => (r ? <Tag color="red">{tPortRisk(r)}</Tag> : <Tag color="default">{t("常规")}</Tag>) },
  ];
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>{t("已扫描 {n} 台设备的监听端口。", { n: scanned })}<b>{t("红色为高风险/敏感端口")}</b>{t("（如 RDP、SMB、数据库），建议确认是否必要并限制来源。")}</p>
      <Table rowKey={(r) => `${r.port}-${r.protocol}`} loading={loading} dataSource={rows} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} locale={{ emptyText: <Empty description={t("暂无端口数据")} /> }} />
    </>
  );
}

function SoftwareTable() {
  const [rows, setRows] = useState<SoftwareRow[]>([]);
  const [scanned, setScanned] = useState(0);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  useEffect(() => { fetchSoftware().then((r) => { setRows(r.data.items); setScanned(r.data.scanned_agents); setLoading(false); }); }, []);
  const filtered = useMemo(() => rows.filter((r) => !q || (r.name || "").toLowerCase().includes(q.toLowerCase())), [rows, q]);
  const columns = [
    { title: t("软件名称"), dataIndex: "name", key: "name" },
    { title: t("厂商"), dataIndex: "vendor", key: "vendor", width: 200 },
    { title: t("版本(示例)"), dataIndex: "version", key: "version", width: 140 },
    { title: t("安装设备数"), dataIndex: "agents", key: "agents", width: 120, sorter: (a: SoftwareRow, b: SoftwareRow) => a.agents - b.agents, defaultSortOrder: "descend" as const },
  ];
  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
        <span className="muted">{t("已扫描 {n} 台设备的已装软件。可用于排查违规软件 / 影子 IT。", { n: scanned })}</span>
        <Input.Search placeholder={t("搜索软件名称")} style={{ width: 240 }} value={q} onChange={(e) => setQ(e.target.value)} allowClear />
      </div>
      <Table rowKey={(r) => r.name} loading={loading} dataSource={filtered} columns={columns as any} size="middle" pagination={{ pageSize: 12 }} locale={{ emptyText: <Empty description={t("暂无软件数据")} /> }} />
    </>
  );
}

// ----------------------------------------------------------------- 设备详情页（点击席位进入）
function fwLabel(v: string | null | undefined): { text: string; color: string } {
  if (v === "on") return { text: t("已开启"), color: "green" };
  if (v === "off") return { text: t("已关闭"), color: "red" };
  if (v === "na") return { text: t("不适用"), color: "default" };
  return { text: t("未知"), color: "default" };
}

function KV({ k, v }: { k: string; v: any }) {
  return (
    <div className="kv-row">
      <span className="kv-k">{k}</span>
      <span className="kv-v">{v ?? "—"}</span>
    </div>
  );
}

function FirewallCard({ fw }: { fw: FirewallState | null }) {
  if (!fw) {
    return (
      <div className="card">
        <div className="ai-head"><SafetyOutlined /><h3>{t("防火墙与安全状态")}</h3></div>
        <Empty description={t("尚未采集到防火墙状态（Agent 每小时上报一次，或该 Agent 未启用采集，请稍后查看）")} />
      </div>
    );
  }
  const main = fwLabel(fw.enabled);
  const isWin = fw.platform === "windows";
  return (
    <div className="card">
      <div className="ai-head"><SafetyOutlined /><h3>{t("防火墙与安全状态")}</h3></div>
      <div className="fw-main">
        <span>{isWin ? t("Windows 防火墙") : t("系统防火墙")}</span>
        <Switch checked={fw.enabled === "on"} disabled size="default" />
        <Tag color={main.color}>{main.text}</Tag>
      </div>
      <div className="fw-list">
        {isWin && <FwRow label={t("域网络")} v={fw.domain} />}
        {isWin && <FwRow label={t("专用网络")} v={fw.private} />}
        {isWin && <FwRow label={t("公用网络")} v={fw.public} />}
        <FwRow label={t("实时防护")} v={fw.realtime} />
      </div>
      {fw.time && <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>{t("采集时间：")}{new Date(fw.time).toLocaleString()}</div>}
    </div>
  );
}

function FwRow({ label, v }: { label: string; v: string | null }) {
  const l = fwLabel(v);
  return (
    <div className="fw-row">
      <span>{label}</span>
      <Tag color={l.color}>{l.text}</Tag>
    </div>
  );
}

function DeviceDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const [d, setD] = useState<AgentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [vulnOpen, setVulnOpen] = useState(false);
  const [selfCheck, setSelfCheck] = useState<AgentSelfCheckResp | null>(null);
  const [selfCheckLoading, setSelfCheckLoading] = useState(false);
  useEffect(() => { setLoading(true); fetchAgentDetail(id).then((r) => { setD(r.data); setLoading(false); }); }, [id]);

  async function runSelfCheck() {
    setSelfCheckLoading(true);
    try {
      const r = await fetchAgentSelfCheck(id);
      setSelfCheck(r.data);
    } finally {
      setSelfCheckLoading(false);
    }
  }

  if (loading || !d) {
    return <div style={{ display: "grid", placeItems: "center", height: "60vh" }}><Spin size="large" /></div>;
  }
  const info = d.info || {};
  const on = info.status === "active";
  const platform = info.os?.platform || d.os?.sysname || "";
  const osName = d.os?.os?.name || info.os?.name || "—";
  const ramGB = d.hardware?.ram?.total ? `${Math.round((d.hardware.ram.total as number) / 1024 / 1024)} GB` : "—";
  const cpu = d.hardware?.cpu?.name || "—";
  const cores = d.hardware?.cpu?.cores;
  const arch = d.os?.architecture || "—";
  const sev = d.vulnerabilities?.by_severity || {};
  const osIcon = platform === "windows" ? <WindowsFilled /> : platform === "darwin" ? <AppleFilled /> : <DesktopOutlined />;

  const software = (d.software || []).filter((s) => !q || (s.name || "").toLowerCase().includes(q.toLowerCase()));

  const portCols = [
    { title: t("端口"), dataIndex: "port", key: "port", width: 72 },
    { title: t("协议"), dataIndex: "protocol", key: "protocol", width: 70 },
    { title: t("进程"), dataIndex: "process", key: "process", ellipsis: true },
    { title: t("风险"), dataIndex: "risky", key: "risky", width: 100, render: (r: string | null) => (r ? <Tag color="red">{tPortRisk(r)}</Tag> : <Tag>{t("常规")}</Tag>) },
  ];
  const swCols = [
    { title: t("软件名称"), dataIndex: "name", key: "name", render: (n: string) => (<span><AppstoreOutlined style={{ color: "hsl(var(--muted-foreground))", marginRight: 8 }} />{n}</span>) },
    { title: t("版本"), dataIndex: "version", key: "version", width: 200 },
    { title: t("厂商"), dataIndex: "vendor", key: "vendor", width: 240 },
  ];
  const fimEventTag = (e: string) => {
    const c: Record<string, string> = { added: "green", modified: "orange", deleted: "red" };
    return <Tag color={c[e] || "default"}>{tFimEvent(e)}</Tag>;
  };
  const fimCols = [
    { title: t("时间"), dataIndex: "time", key: "time", width: 170, render: (val: string) => (val ? new Date(val).toLocaleString() : "—") },
    { title: t("变更"), dataIndex: "event", key: "event", width: 90, render: fimEventTag },
    { title: t("文件路径"), dataIndex: "path", key: "path", ellipsis: true },
    { title: t("说明"), dataIndex: "description", key: "description", width: 220, render: (d: string) => tDesc(d) },
  ];

  return (
    <>
      <div className="detail-head">
        <a className="back-link" onClick={onBack}><ArrowLeftOutlined /> {t("返回席位总览")}</a>
        <div className="detail-title">
          <span className="detail-monitor">{osIcon}</span>
          <div>
            <h2 style={{ margin: 0 }}>{info.name || id}</h2>
            <div className="muted">{osName} · {info.ip || "—"}</div>
          </div>
          <span className={`status-pill ${on ? "on" : "off"}`}>{on ? t("在线") : t("离线")}<span className={`live-dot ${on ? "on" : "off"}`} /></span>
        </div>
      </div>

      <div className="detail-grid">
        <div className="card">
          <div className="ai-head">
            <DesktopOutlined /><h3>{t("系统信息")}</h3>
            <Button size="small" style={{ marginLeft: "auto" }} loading={selfCheckLoading} onClick={runSelfCheck}>{t("本机自检")}</Button>
          </div>
          <KV k={t("操作系统")} v={osName} />
          <KV k={t("架构")} v={arch} />
          <KV k="CPU" v={cores ? `${cpu}（${cores} ${t("核")}）` : cpu} />
          <KV k={t("内存")} v={ramGB} />
          <KV k={t("主机名")} v={d.os?.hostname || info.name} />
          <KV k={t("Agent 版本")} v={info.version} />
          <KV k={t("最后心跳")} v={info.lastKeepAlive ? new Date(info.lastKeepAlive).toLocaleString() : "—"} />
          <KV k={t("纳管时间")} v={info.dateAdd ? new Date(info.dateAdd).toLocaleString() : "—"} />
          {selfCheck ? (
            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
              <div className="section-title" style={{ margin: 0 }}>{t("Agent 自检结果")}</div>
              {selfCheck.checks.map((item) => (
                <div key={item.key} className="fw-row">
                  <span>{apiText(item, "label")}</span>
                  <Tag color={item.ok ? "green" : "red"}>{apiText(item)}</Tag>
                </div>
              ))}
            </div>
          ) : null}
        </div>

        <FirewallCard fw={d.firewall} />

        <div className="card">
          <div className="ai-head"><AlertOutlined /><h3>{t("开放端口")}</h3></div>
          <Table rowKey={(r) => `${r.port}-${r.protocol}`} dataSource={d.ports} columns={portCols as any} size="small" pagination={false} scroll={{ y: 220 }} locale={{ emptyText: <Empty description={t("无监听端口")} /> }} />
        </div>

        <div className="card card-clickable" onClick={() => setVulnOpen(true)} title={t("查看明细 ›")}>
          <div className="ai-head"><BugOutlined /><h3>{t("漏洞概况")}</h3><span className="muted" style={{ marginLeft: "auto", fontSize: 12 }}>{t("查看明细 ›")}</span></div>
          <div className="vuln-mini">
            <div className="vm"><div className="vm-n text-destructive">{sev.Critical || 0}</div><div className="vm-l">{t("严重")}</div></div>
            <div className="vm"><div className="vm-n" style={{ color: "#f97316" }}>{sev.High || 0}</div><div className="vm-l">{t("高危")}</div></div>
            <div className="vm"><div className="vm-n" style={{ color: "#f59e0b" }}>{(sev.Medium || 0) + (sev.Low || 0)}</div><div className="vm-l">{t("中/低")}</div></div>
            <div className="vm"><div className="vm-n">{d.vulnerabilities?.total || 0}</div><div className="vm-l">{t("总计")}</div></div>
          </div>
        </div>
      </div>

      <Modal
        title={`${info.name || id} · ${t("漏洞概况")}`}
        open={vulnOpen}
        onCancel={() => setVulnOpen(false)}
        footer={null}
        width={900}
      >
        <Table
          rowKey={(r: VulnRow) => `${r.cve}-${r.package}`}
          dataSource={d.vulnerabilities?.items || []}
          size="small"
          pagination={{ pageSize: 10 }}
          columns={[
            { title: t("CVE 编号"), dataIndex: "cve", key: "cve", width: 240, render: (c: string, r: VulnRow) => <CveText cve={c} description={r.condition || r.description} /> },
            { title: t("严重度"), dataIndex: "severity", key: "severity", width: 96, render: (s: string) => sevTag(s) },
            { title: "CVSS", dataIndex: "score", key: "score", width: 72, render: (v: number | null) => (v ?? "—"), sorter: (a: VulnRow, b: VulnRow) => (a.score || 0) - (b.score || 0) },
            { title: t("软件"), dataIndex: "package", key: "package" },
            { title: t("版本"), dataIndex: "version", key: "version", width: 110 },
            { title: "", key: "ai", width: 116, render: (_: any, r: VulnRow) => <AiAdviceButton kind="vuln" ctx={vulnAdviceContext(r, null, { agent: info.name || id, target_os: osName, target_platform: platform })} /> },
          ] as any}
          locale={{ emptyText: <Empty description={t("该设备暂无漏洞数据")} /> }}
        />
      </Modal>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="h-row">
          <h3>{t("已安装软件（{n}）", { n: (d.software || []).length })}</h3>
          <Input.Search placeholder={t("搜索软件名称")} style={{ width: 240 }} value={q} onChange={(e) => setQ(e.target.value)} allowClear />
        </div>
        <Table rowKey={(r) => `${r.name}-${r.version}`} dataSource={software} columns={swCols as any} size="middle" pagination={{ pageSize: 10 }} locale={{ emptyText: <Empty description={t("暂无软件清单（可能仍在采集中）")} /> }} />
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>{t("文件变更日志 (FIM)")}</h3>
        <p className="muted" style={{ marginTop: 0 }}>{t("该设备受监控目录下文件的新增 / 修改 / 删除记录（近 30 天）。")}</p>
        <Table rowKey={(r) => `${r.time}-${r.path}`} dataSource={d.fim} columns={fimCols as any} size="middle" pagination={{ pageSize: 10 }} locale={{ emptyText: <Empty description={t("近 30 天无文件变更记录")} /> }} />
      </div>
    </>
  );
}
