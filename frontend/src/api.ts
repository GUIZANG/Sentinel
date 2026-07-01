// 仪表盘数据接口。开发/演示模式可回退 mock；生产模式接口失败时直接暴露错误，避免真假数据混淆。
import { brand } from "./brand";

export interface Summary {
  generated_at: string;
  window: string;
  endpoints: { total: number; active: number; disconnected: number; by_os: Record<string, number> };
  alerts: {
    total: number;
    security_total?: number;
    baseline_total?: number;
    by_severity: Record<string, number>;
    by_group: Record<string, number>;
    by_agent: Record<string, number>;
    top_rules: Record<string, number>;
  };
  fim: Record<string, number>;
  compliance: Record<string, { policy?: string; score?: number; pass?: number; fail?: number }>;
  compliance_tags: Record<string, number>;
}

export interface AiResult {
  result: any;
  source: "guizangai" | "mock";
  created_at: string;
}


export interface AiPerf {
  latest?: {
    provider?: string;
    model?: string;
    task?: string;
    eval_count?: number;
    prompt_eval_count?: number;
    total_tokens?: number;
    total_duration_seconds?: number;
    eval_duration_seconds?: number;
    tokens_per_second?: number;
    raw_events_count?: number;
    last_error?: string;
    created_at?: string;
    source?: string;
  } | null;
  per_task: Record<string, any>;
  avg_tokens_per_second?: number | null;
  total_eval_count: number;
  running?: boolean;
  current_task?: string | null;
  started_at?: string | null;
  running_seconds?: number;
}

export interface OverviewResp {
  summary: Summary;
  ai: Record<string, AiResult>;
  ai_perf?: AiPerf;
  trend: { time: string; risk_score: number; alerts_total: number; alerts_high: number; endpoints_active: number }[];
}

export interface AgentRow {
  id: string;
  name: string;
  ip: string;
  status: string;
  os: string;
  platform: string;
  version: string;
  last_keep_alive: string;
  registered_at?: string;
  duplicate_of?: string;
  duplicate_note?: string;
}

export interface SecurityIssue {
  id: number;
  fingerprint: string;
  kind: "alert" | "vuln" | string;
  agent: string;
  rule_id?: string | null;
  cve?: string | null;
  level: number;
  severity?: string | null;
  description: string;
  target?: string | null;
  groups?: string[];
  mitre?: string[];
  status: "open" | "resolved" | string;
  first_seen: string;
  last_seen: string;
  resolved_at?: string | null;
  resolution?: string | null;
  occurrences: number;
  timeline?: { ts: string; type: string; detail: string }[];
}

// ----------------------------------------------------------------- 登录鉴权
const STORAGE_PREFIX = import.meta.env.VITE_STORAGE_PREFIX || "sentinel";
const TOKEN_KEY = `${STORAGE_PREFIX}_token`;
const USER_KEY = `${STORAGE_PREFIX}_user`;
export const demoMode = import.meta.env.VITE_DEMO_MODE === "1" || import.meta.env.DEV;

export const getToken = () => localStorage.getItem(TOKEN_KEY) || "";
export const getUser = () => localStorage.getItem(USER_KEY) || "";
export function setAuth(token: string, username: string) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
}
export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}
export const tokenQuery = () => (getToken() ? `?token=${encodeURIComponent(getToken())}` : "");

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function authHeaders(): Record<string, string> {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export async function login(username: string, password: string): Promise<void> {
  const r = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.detail || "登录失败");
  }
  const d = await r.json();
  setAuth(d.token, d.username);
}

export async function changeCredentials(
  oldUsername: string,
  oldPassword: string,
  newUsername: string,
  newPassword: string
): Promise<void> {
  const r = await fetch("/api/auth/change", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({
      old_username: oldUsername,
      old_password: oldPassword,
      new_username: newUsername,
      new_password: newPassword,
    }),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.detail || "修改失败");
  }
  const d = await r.json();
  setAuth(d.token, d.username);
}

export async function verifySession(): Promise<boolean> {
  if (!getToken()) return false;
  try {
    const r = await fetch("/api/auth/me", { headers: { ...authHeaders() } });
    return r.ok;
  } catch {
    return false;
  }
}

async function get<T>(path: string, fallback: T): Promise<{ data: T; live: boolean }> {
  try {
    const r = await fetch(path, { headers: { Accept: "application/json", ...authHeaders() } });
    if (r.status === 401) {
      clearAuth();
      onUnauthorized?.();
      throw new Error("401");
    }
    if (!r.ok) throw new Error(String(r.status));
    return { data: (await r.json()) as T, live: true };
  } catch (e) {
    if (!demoMode) {
      throw e instanceof Error ? e : new Error("接口请求失败");
    }
    return { data: fallback, live: false };
  }
}

export const fetchOverview = () => get<OverviewResp>(`/api/overview?lang=${currentLang}`, MOCK_OVERVIEW);
export const fetchAgents = () => get<{ items: AgentRow[]; total: number }>("/api/agents", MOCK_AGENTS);
let _agentAliases: Record<string, string> = {};
export function setAgentAliases(value: Record<string, string>) { _agentAliases = value || {}; }
export function agentAlias(name?: string | null): string | undefined { return name ? _agentAliases[name] : undefined; }
export async function fetchAgentAliases(): Promise<Record<string, string>> {
  const r = await get<{ items: Record<string, string> }>("/api/agent-aliases", { items: {} });
  return r.data.items || {};
}
export async function renameAgent(name: string, alias: string): Promise<void> {
  const r = await fetch("/api/agents/rename", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ name, alias }),
  });
  if (r.status === 401) {
    clearAuth();
    onUnauthorized?.();
    throw new Error("401");
  }
  if (!r.ok) throw new Error(String(r.status));
}
export const fetchTrend = (days: number, interval: "hour" | "day" = "day") =>
  get<{ items: OverviewResp["trend"] }>(`/api/trend?days=${days}&interval=${interval}`, { items: [] });
export async function deleteAgent(agentId: string): Promise<void> {
  const r = await fetch(`/api/agents/${encodeURIComponent(agentId)}`, { method: "DELETE", headers: { ...authHeaders() } });
  if (r.status === 401) {
    clearAuth();
    onUnauthorized?.();
    throw new Error("401");
  }
  if (!r.ok) throw new Error(String(r.status));
}

export interface AiStatusResp {
  connected: boolean;
  mode: string;
  latest?: AiPerf["latest"];
  latest_task?: string;
  latest_seconds?: number;
  tokens_per_second?: number;
  avg_tokens_per_second?: number | null;
  total_eval_count?: number;
  last_error?: string;
  running?: boolean;
  current_task?: string | null;
  running_seconds?: number;
}
export const fetchAiStatus = () => get<AiStatusResp>("/api/ai/status", { connected: false, mode: "Mock" });

// ----------------------------------------------------------------- 漏洞与补丁
export interface VulnRow {
  agent: string;
  cve: string;
  severity: string;
  score: number | null;
  package: string;
  version: string;
  detected_at: string;
  condition?: string;
  description?: string;
  reference?: string;
}
export interface VulnResp {
  overview: {
    total: number;
    by_severity: Record<string, number>;
    top_cves: Record<string, number>;
    top_cve_details?: {
      cve: string;
      count: number;
      severity?: string;
      score?: number | null;
      package?: string;
      version?: string;
      condition?: string;
      description?: string;
      reference?: string;
    }[];
    by_agent: Record<string, number>;
    top_packages: Record<string, number>;
  };
  items: VulnRow[];
}
export const fetchVulnerabilities = () => get<VulnResp>("/api/vulnerabilities", MOCK_VULN);

// ----------------------------------------------------------------- 资产清点
export interface PortRow { port: number; protocol: string; process: string; agents: number; risky?: string | null }
export interface SoftwareRow { name: string; vendor: string; version: string; agents: number }
export const fetchPorts = () => get<{ items: PortRow[]; scanned_agents: number }>("/api/assets/ports", MOCK_PORTS);
export const fetchSoftware = () => get<{ items: SoftwareRow[]; scanned_agents: number }>("/api/assets/software", MOCK_SOFTWARE);

// ----------------------------------------------------------------- 安全告警 / FIM / 自动响应
export interface AlertRow {
  time: string;
  agent: string;
  rule_id?: number | string;
  level: number;
  description: string;
  groups: string[];
  mitre?: string[];
  src_ip?: string;
  dst_ip?: string;
  src_port?: number | string;
  dst_port?: number | string;
  port?: number | string;
  protocol?: string;
  listen_ip?: string;
  process?: string;
  listened_ports?: { port: number | string; protocol?: string; address?: string; process?: string; risky?: string | null }[];
  changed_ports?: { port: number | string; protocol?: string; address?: string; process?: string; risky?: string | null }[];
  port_change?: "opened" | "closed" | string;
  raw_log?: string;
  file?: string;
  fingerprint?: string;
  issue_status?: "open" | "resolved" | "none" | string;
  resolved_at?: string | null;
  issue_target?: string;
  occurrence_count?: number;
  first_seen?: string;
  last_seen?: string;
  sample_times?: string[];
  trojan_event?: { tracking_id: string; stage?: string; port?: number | string; rule_id?: number | string; time?: string };
  trojan_tracking?: {
    tracking_id: string;
    status: "active" | "cleared" | string;
    pinned?: boolean;
    severity?: string;
    first_seen?: string;
    last_seen?: string;
    stages?: string[];
    ports?: string[];
    events_count?: number;
  };
}
export interface FimRow { time: string; agent: string; path: string; event: string; description: string }
export interface ArRow { time: string; agent: string; command: string; description: string }
export function fetchAlertsList(params: { min_level?: number; group?: string; agent?: string; q?: string; limit?: number; exclude_fim_low?: boolean } = {}) {
  const qs = new URLSearchParams();
  if (params.min_level) qs.set("min_level", String(params.min_level));
  if (params.group) qs.set("group", params.group);
  if (params.agent) qs.set("agent", params.agent);
  if (params.q) qs.set("q", params.q);
  if (params.exclude_fim_low) qs.set("exclude_fim_low", "true");
  qs.set("limit", String(params.limit ?? 200));
  return get<{ items: AlertRow[]; total: number; raw_total?: number }>(`/api/alerts/list?${qs.toString()}`, MOCK_ALERTS_LIST);
}
export const fetchIssues = (status?: "open" | "resolved" | string) =>
  get<{ items: SecurityIssue[] }>(`/api/issues${status ? `?status=${encodeURIComponent(status)}` : ""}`, { items: [] });
export async function resolveIssue(payload: Record<string, any>): Promise<void> {
  const r = await fetch("/api/issues/resolve", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(payload),
  });
  if (r.status === 401) { clearAuth(); onUnauthorized?.(); throw new Error("401"); }
  if (!r.ok) throw new Error(String(r.status));
}
export async function reopenIssue(fingerprint: string): Promise<void> {
  const r = await fetch("/api/issues/reopen", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ fingerprint }),
  });
  if (r.status === 401) { clearAuth(); onUnauthorized?.(); throw new Error("401"); }
  if (!r.ok) throw new Error(String(r.status));
}
export interface AlertDetailResp {
  factual: Record<string, any>;
  ai: AlertDescriptionResp;
  raw: Record<string, any> | null;
  issue?: SecurityIssue | null;
}
export const fetchAlertDetail = (params: { agent: string; description: string; time?: string; fingerprint?: string }) => {
  const qs = new URLSearchParams();
  qs.set("agent", params.agent || "");
  qs.set("description", params.description || "");
  if (params.time) qs.set("ts", params.time);
  if (params.fingerprint) qs.set("fingerprint", params.fingerprint);
  qs.set("lang", currentLang);
  return get<AlertDetailResp>(`/api/alerts/detail?${qs.toString()}`, { factual: {}, ai: { description: "" }, raw: null });
};
export const fetchFim = () => get<{ items: FimRow[]; total: number }>("/api/fim/events", MOCK_FIM);
export const fetchActiveResponse = () => get<{ items: ArRow[]; total: number }>("/api/active-response", MOCK_AR);

export interface SystemHealthResp {
  ok: boolean;
  checks: { key: string; label: string; label_key?: string; ok: boolean; message: string; message_key?: string; params?: Record<string, string | number>; detail?: string }[];
}
export const fetchSystemHealth = () => get<SystemHealthResp>("/api/system/health", { ok: false, checks: [] });

export interface AgentSelfCheckResp {
  agent: Record<string, any>;
  manager: string;
  checks: { key: string; label: string; label_key?: string; ok: boolean; message: string; message_key?: string; params?: Record<string, string | number> }[];
}
export const fetchAgentSelfCheck = (id: string) => get<AgentSelfCheckResp>(`/api/agent/${encodeURIComponent(id)}/self-check`, { agent: {}, manager: "", checks: [] });

// ----------------------------------------------------------------- AI 处理建议（按需）
import { currentLang } from "./i18n";
export interface AdviceResp {
  summary: string;
  steps: string[];
  runbook?: AdviceRunbookStep[];
  impact?: string;
  priority?: "immediate" | "soon" | "scheduled" | string;
  _source?: string;
  _error?: string;
  _debug?: {
    kind?: string;
    lang?: string;
    enabled?: boolean;
    api_style?: string;
    model?: string | null;
    context?: Record<string, any>;
    prompt?: string;
    raw?: string | null;
    duration_ms?: number;
    input_tokens?: number | null;
    output_tokens?: number | null;
    error?: string | null;
    source_log?: any;
  };
}
export interface AdviceRunbookStep {
  phase?: "check" | "contain" | "remediate" | "verify" | "rollback" | string;
  goal: string;
  where?: string;
  commands?: string[];
  expected_result?: string;
  if_abnormal?: string;
  risk?: "read" | "modify" | "danger" | string;
  requires_confirmation?: boolean;
}
export async function fetchAdvice(kind: "vuln" | "alert", context: Record<string, any>): Promise<AdviceResp> {
  const r = await fetch("/api/ai/advice", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ kind, context, lang: currentLang, debug: true }),
  });
  if (r.status === 401) {
    clearAuth();
    onUnauthorized?.();
    throw new Error("401");
  }
  if (!r.ok) throw new Error(String(r.status));
  return (await r.json()) as AdviceResp;
}

export async function streamAdvice(
  kind: "vuln" | "alert",
  context: Record<string, any>,
  onDelta: (text: string) => void
): Promise<AdviceResp> {
  const r = await fetch("/api/ai/advice/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream", ...authHeaders() },
    body: JSON.stringify({ kind, context, lang: currentLang, debug: true }),
  });
  if (r.status === 401) {
    clearAuth();
    onUnauthorized?.();
    throw new Error("401");
  }
  if (!r.ok || !r.body) throw new Error(String(r.status));
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: AdviceResp | null = null;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split("\n\n");
    buffer = events.pop() || "";
    for (const raw of events) {
      const line = raw.split("\n").find((item) => item.startsWith("data:"));
      if (!line) continue;
      const payload = JSON.parse(line.slice(5).trim());
      if (payload.type === "delta" && payload.text) onDelta(payload.text);
      if (payload.type === "final") finalResult = payload.result as AdviceResp;
    }
  }
  if (!finalResult) throw new Error("missing final advice");
  return finalResult;
}

export interface AlertDescriptionResp {
  description: string;
  _source?: "guizangai" | "rule" | string;
  _error?: string;
}
export async function fetchAlertDescription(context: Record<string, any>): Promise<AlertDescriptionResp> {
  const r = await fetch("/api/ai/alert-description", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ context, lang: currentLang }),
  });
  if (r.status === 401) {
    clearAuth();
    onUnauthorized?.();
    throw new Error("401");
  }
  if (!r.ok) throw new Error(String(r.status));
  return (await r.json()) as AlertDescriptionResp;
}

// ----------------------------------------------------------------- 单台设备详情
export interface FirewallState {
  enabled: string | null;
  domain: string | null;
  private: string | null;
  public: string | null;
  realtime: string | null;
  platform: string | null;
  time: string | null;
}
export interface AgentDetail {
  info: { id?: string; name?: string; ip?: string; status?: string; version?: string; lastKeepAlive?: string; dateAdd?: string; group?: string[]; os?: { name?: string; platform?: string; version?: string } };
  hardware: { cpu?: { name?: string; cores?: number }; ram?: { total?: number }; board_serial?: string };
  os: { os?: { name?: string; version?: string }; architecture?: string; hostname?: string; sysname?: string };
  firewall: FirewallState | null;
  ports: PortRow[];
  vulnerabilities: { total?: number; by_severity?: Record<string, number>; items?: VulnRow[] };
  software: { name: string; version: string; vendor: string; arch?: string }[];
  fim: FimRow[];
}
export const fetchAgentDetail = (id: string) => get<AgentDetail>(`/api/agent/${encodeURIComponent(id)}`, mockAgentDetail(id));

// ----------------------------------------------------------------- Mock 数据（按 50 台规模设计）
const osList = ["macOS", "Windows", "Linux"];
const MOCK_AGENT_ITEMS: AgentRow[] = Array.from({ length: 50 }).map((_, i) => {
  const plat = i < 28 ? "darwin" : i < 46 ? "windows" : "linux";
  const osName = plat === "darwin" ? "macOS 15" : plat === "windows" ? "Windows 11" : "Ubuntu 22.04";
  const online = i % 9 !== 0; // 约 6 台离线
  return {
    id: String(i + 1).padStart(3, "0"),
    name: `${plat === "windows" ? "PC" : plat === "darwin" ? "MAC" : "SRV"}-${String(i + 1).padStart(2, "0")}`,
    ip: `192.168.31.${20 + i}`,
    status: online ? "active" : "disconnected",
    os: osName,
    platform: plat,
    version: "Wazuh v4.9.2",
    last_keep_alive: online ? new Date().toISOString() : new Date(Date.now() - 3600_000 * 5).toISOString(),
  };
});

const MOCK_AGENTS = { items: MOCK_AGENT_ITEMS, total: MOCK_AGENT_ITEMS.length };

const MOCK_OVERVIEW: OverviewResp = {
  summary: {
    generated_at: new Date().toISOString(),
    window: "now-24h",
    endpoints: { total: 50, active: 44, disconnected: 6, by_os: { darwin: 28, windows: 18, linux: 4 } },
    alerts: {
      total: 1284,
      by_severity: { low: 980, medium: 256, high: 41, critical: 7 },
      by_group: { sca: 412, syscheck: 318, authentication: 205, windows: 188, sudo: 96, rootcheck: 65 },
      by_agent: { "PC-07": 96, "MAC-03": 88, "PC-12": 71, "SRV-01": 64, "MAC-19": 52 },
      top_rules: {
        "用户登录失败(可能爆破)": 205,
        "关键系统文件被修改": 161,
        "CIS 基线检查未通过": 142,
        "检测到提权操作": 96,
        "新软件安装": 73,
      },
    },
    fim: { modified: 198, added: 86, deleted: 34 },
    compliance: {
      "PC-07": { policy: "CIS Windows 11", score: 38, pass: 76, fail: 124 },
      "MAC-03": { policy: "CIS macOS 15", score: 61, pass: 122, fail: 78 },
      "SRV-01": { policy: "CIS Ubuntu 22", score: 72, pass: 144, fail: 56 },
      "MAC-19": { policy: "CIS macOS 15", score: 67, pass: 134, fail: 66 },
    },
    compliance_tags: { pci_dss: 540, gdpr: 380, hipaa: 210, nist: 612, mitre: 288 },
  },
  ai: {
    overview: {
      source: "mock",
      created_at: new Date().toISOString(),
      result: {
        risk_level: "警告",
        risk_score: 68,
        headline: "44台在线 · 48条高危待处理",
        summary:
          "过去 24 小时共 1284 条安全事件，其中高危及以上 48 条，集中在登录爆破与关键文件改动。PC-07 合规仅 38 分，存在明显短板，建议优先加固。",
        top_actions: ["加固 PC-07（合规仅 38 分）", "排查多台主机登录失败激增", "复核关键文件变更是否授权"],
      },
    },
    alert_triage: {
      source: "mock",
      created_at: new Date().toISOString(),
      result: {
        clusters: [
          { category: "登录爆破", count: 205, meaning: "短时间大量登录失败，疑似密码爆破", severity: "高" },
          { category: "文件被改动", count: 318, meaning: "关键系统/配置文件发生变更", severity: "中" },
          { category: "基线未达标", count: 412, meaning: "系统安全配置不符合 CIS 基线", severity: "中" },
          { category: "提权操作", count: 96, meaning: "出现 sudo/管理员提权行为", severity: "中" },
        ],
      },
    },
    compliance: {
      source: "mock",
      created_at: new Date().toISOString(),
      result: {
        worst_endpoint: "PC-07",
        worst_score: 38,
        recommendations: ["开启 BitLocker 磁盘加密", "关闭过期的远程桌面端口", "安装待处理的系统安全补丁"],
      },
    },
  },
  ai_perf: {
    latest: {
      provider: "ollama",
      model: brand.aiName,
      task: "overview",
      eval_count: 128,
      prompt_eval_count: 888,
      total_tokens: 1016,
      total_duration_seconds: 20.09,
      eval_duration_seconds: 11.88,
      tokens_per_second: 10.77,
      raw_events_count: 0,
      last_error: "",
      source: "mock",
    },
    per_task: {},
    avg_tokens_per_second: 10.77,
    total_eval_count: 128,
    running: false,
    current_task: null,
    started_at: null,
    running_seconds: 0,
  },
  trend: Array.from({ length: 14 }).map((_, i) => {
    const t = new Date(Date.now() - (13 - i) * 86400_000);
    const base = 45 + Math.round(20 * Math.sin(i / 2)) + (i > 10 ? 12 : 0);
    return {
      time: t.toISOString(),
      risk_score: Math.max(15, Math.min(90, base)),
      alerts_total: 800 + Math.round(300 * Math.abs(Math.sin(i))),
      alerts_high: 20 + Math.round(30 * Math.abs(Math.sin(i / 1.5))),
      endpoints_active: 42 + (i % 4),
    };
  }),
};

const MOCK_VULN: VulnResp = {
  overview: {
    total: 173,
    by_severity: { Critical: 12, High: 47, Medium: 88, Low: 26 },
    top_cves: { "CVE-2024-3094": 14, "CVE-2023-44487": 11, "CVE-2024-21626": 9, "CVE-2023-4863": 8, "CVE-2024-6387": 7 },
    top_cve_details: [
      { cve: "CVE-2024-3094", count: 14, severity: "Critical", score: 9.8, package: "xz-utils", version: "5.6.0", condition: "Package less than 5.6.1", description: "xz-utils 后门风险，可能导致远程代码执行。" },
      { cve: "CVE-2023-44487", count: 11, severity: "Medium", score: 5.3, package: "nghttp2", version: "1.43.0", condition: "Package less than fixed version", description: "HTTP/2 Rapid Reset 可造成服务拒绝。" },
    ],
    by_agent: { "PC-07": 38, "SRV-01": 31, "MAC-03": 22, "PC-12": 19, "MAC-19": 14 },
    top_packages: { openssl: 21, "log4j-core": 14, "glibc": 12, curl: 11, "node.js": 9 },
  },
  items: [
    { agent: "PC-07", cve: "CVE-2024-3094", severity: "Critical", score: 9.8, package: "xz-utils", version: "5.6.0", detected_at: new Date().toISOString() },
    { agent: "SRV-01", cve: "CVE-2024-6387", severity: "High", score: 8.1, package: "openssh-server", version: "8.9p1", detected_at: new Date().toISOString() },
    { agent: "MAC-03", cve: "CVE-2023-4863", severity: "High", score: 8.8, package: "libwebp", version: "1.2.4", detected_at: new Date().toISOString() },
    { agent: "PC-12", cve: "CVE-2023-44487", severity: "Medium", score: 5.3, package: "nghttp2", version: "1.43.0", detected_at: new Date().toISOString() },
    { agent: "SRV-01", cve: "CVE-2024-21626", severity: "High", score: 8.6, package: "runc", version: "1.1.7", detected_at: new Date().toISOString() },
  ],
};

const MOCK_PORTS = {
  scanned_agents: 44,
  items: [
    { port: 3389, protocol: "tcp", process: "svchost", agents: 18, risky: "远程桌面 RDP" },
    { port: 445, protocol: "tcp", process: "System", agents: 22, risky: "SMB 文件共享" },
    { port: 22, protocol: "tcp", process: "sshd", agents: 9, risky: "SSH 远程登录" },
    { port: 3306, protocol: "tcp", process: "mysqld", agents: 3, risky: "MySQL" },
    { port: 443, protocol: "tcp", process: "nginx", agents: 6, risky: null },
    { port: 8080, protocol: "tcp", process: "java", agents: 4, risky: null },
  ] as PortRow[],
};

const MOCK_SOFTWARE = {
  scanned_agents: 44,
  items: [
    { name: "Google Chrome", vendor: "Google", version: "126.0", agents: 41 },
    { name: "Microsoft Office", vendor: "Microsoft", version: "16.0", agents: 33 },
    { name: "7-Zip", vendor: "Igor Pavlov", version: "23.01", agents: 21 },
    { name: "Node.js", vendor: "OpenJS", version: "18.19", agents: 9 },
    { name: "Python", vendor: "PSF", version: "3.11", agents: 12 },
  ] as SoftwareRow[],
};

const MOCK_ALERTS_LIST = {
  total: 5,
  items: [
    { time: new Date().toISOString(), agent: "PC-07", level: 12, description: "多次用户登录失败（可能爆破）（端口：3389/tcp）", groups: ["authentication_failed"], mitre: ["T1110"], dst_port: 3389, port: 3389, protocol: "tcp" },
    { time: new Date(Date.now() - 6e5).toISOString(), agent: "MAC-03", level: 10, description: "关键系统文件被修改", groups: ["syscheck"], mitre: ["T1565"] },
    { time: new Date(Date.now() - 12e5).toISOString(), agent: "SRV-01", level: 13, description: "检测到提权操作 sudo", groups: ["sudo"], mitre: ["T1548"] },
    { time: new Date(Date.now() - 18e5).toISOString(), agent: "PC-12", level: 7, description: "CIS 基线检查未通过", groups: ["sca"] },
    { time: new Date(Date.now() - 24e5).toISOString(), agent: "MAC-19", level: 5, description: "新软件安装", groups: ["package"] },
  ] as AlertRow[],
};

const MOCK_FIM = {
  total: 4,
  items: [
    { time: new Date().toISOString(), agent: "MAC-03", path: "/etc/hosts", event: "modified", description: "关键系统文件被修改" },
    { time: new Date(Date.now() - 7e5).toISOString(), agent: "PC-07", path: "C:\\Windows\\System32\\drivers\\etc\\hosts", event: "modified", description: "hosts 文件变更" },
    { time: new Date(Date.now() - 14e5).toISOString(), agent: "SRV-01", path: "/usr/bin/curl", event: "added", description: "新增可执行文件" },
    { time: new Date(Date.now() - 21e5).toISOString(), agent: "PC-12", path: "C:\\Program Files\\app\\config.ini", event: "deleted", description: "配置文件被删除" },
  ] as FimRow[],
};

const MOCK_AR = {
  total: 2,
  items: [
    { time: new Date().toISOString(), agent: "PC-07", command: "firewall-drop", description: "对爆破来源 IP 自动封禁 600 秒" },
    { time: new Date(Date.now() - 9e5).toISOString(), agent: "SRV-01", command: "disable-account", description: "自动禁用异常登录账户" },
  ] as ArRow[],
};

function mockAgentDetail(id: string): AgentDetail {
  const a = MOCK_AGENT_ITEMS.find((x) => x.id === id) || MOCK_AGENT_ITEMS[0];
  const win = a.platform === "windows";
  return {
    info: {
      id: a.id, name: a.name, ip: a.ip, status: a.status, version: a.version,
      lastKeepAlive: a.last_keep_alive, dateAdd: new Date(Date.now() - 30 * 86400_000).toISOString(),
      group: ["default"], os: { name: a.os, platform: a.platform, version: a.os },
    },
    hardware: { cpu: { name: "Intel(R) Core(TM) i7-1165G7", cores: 8 }, ram: { total: 16 * 1024 * 1024 }, board_serial: "—" },
    os: { os: { name: a.os, version: a.os }, architecture: "x86_64", hostname: a.name, sysname: a.platform },
    firewall: win
      ? { enabled: "on", domain: "on", private: "on", public: "off", realtime: "on", platform: "windows", time: new Date().toISOString() }
      : { enabled: "on", domain: "na", private: "na", public: "na", realtime: "unknown", platform: a.platform, time: new Date().toISOString() },
    ports: [
      { port: 3389, protocol: "tcp", process: "svchost", agents: 1, risky: "远程桌面 RDP" },
      { port: 445, protocol: "tcp", process: "System", agents: 1, risky: "SMB 文件共享" },
      { port: 443, protocol: "tcp", process: "nginx", agents: 1, risky: null },
    ],
    vulnerabilities: {
      total: 18,
      by_severity: { Critical: 2, High: 5, Medium: 8, Low: 3 },
      items: [
        { agent: a.name, cve: "CVE-2024-3094", severity: "Critical", score: 9.8, package: "xz-utils", version: "5.6.0", detected_at: new Date().toISOString() },
        { agent: a.name, cve: "CVE-2023-4863", severity: "High", score: 8.8, package: "libwebp", version: "1.2.4", detected_at: new Date().toISOString() },
        { agent: a.name, cve: "CVE-2024-6387", severity: "High", score: 8.1, package: "openssh", version: "8.9p1", detected_at: new Date().toISOString() },
        { agent: a.name, cve: "CVE-2023-44487", severity: "Medium", score: 5.3, package: "nghttp2", version: "1.43.0", detected_at: new Date().toISOString() },
      ],
    },
    software: [
      { name: "Google Chrome", version: "126.0.6478.127", vendor: "Google LLC" },
      { name: "Microsoft Office", version: "16.0.17328", vendor: "Microsoft" },
      { name: "7-Zip", version: "23.01", vendor: "Igor Pavlov" },
      { name: "Node.js", version: "18.19.0", vendor: "OpenJS Foundation" },
      { name: "Python", version: "3.11.5", vendor: "Python Software Foundation" },
      { name: "Notepad++", version: "8.6.2", vendor: "Notepad++ Team" },
    ],
    fim: [
      { time: new Date().toISOString(), agent: a.name, path: win ? "C\\temp\\a.exe" : "/tmp/a.sh", event: "added", description: "新文件已创建" },
      { time: new Date(Date.now() - 9e5).toISOString(), agent: a.name, path: win ? "C\\Windows\\System32\\drivers\\etc\\hosts" : "/etc/hosts", event: "modified", description: "文件内容已修改" },
      { time: new Date(Date.now() - 18e5).toISOString(), agent: a.name, path: win ? "C\\app\\config.ini" : "/opt/app/config.ini", event: "deleted", description: "文件已删除" },
    ],
  };
}
