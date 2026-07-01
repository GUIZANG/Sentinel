// 全局多语言（中文 / English）。
// 设计：中文为词典 key，t(中文) 在中文模式原样返回、在英文模式查 EN 映射；
// Wazuh 动态英文内容（告警描述 / MITRE / 分组 / 严重度 / 端口风险 / FIM）单独翻译。
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Select } from "antd";
import { GlobalOutlined } from "@ant-design/icons";

export type Lang = "zh" | "en";
const STORAGE_PREFIX = import.meta.env.VITE_STORAGE_PREFIX || "sentinel";
const LS_KEY = `${STORAGE_PREFIX}_lang`;

export const LANGS: { value: Lang; label: string }[] = [
  { value: "zh", label: "简体中文" },
  { value: "en", label: "English" },
];

// 模块级当前语言：供非组件函数（如 t / tDesc）同步读取。
export let currentLang: Lang = ((): Lang => {
  const v = (typeof localStorage !== "undefined" && localStorage.getItem(LS_KEY)) as Lang | null;
  return v === "en" ? "en" : "zh";
})();

const Ctx = createContext<{ lang: Lang; setLang: (l: Lang) => void }>({
  lang: currentLang,
  setLang: () => {},
});

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(currentLang);
  const setLang = (l: Lang) => {
    currentLang = l;
    try { localStorage.setItem(LS_KEY, l); } catch { /* ignore */ }
    setLangState(l);
  };
  useEffect(() => { currentLang = lang; }, [lang]);
  return <Ctx.Provider value={{ lang, setLang }}>{children}</Ctx.Provider>;
}

export function useLang() {
  return useContext(Ctx);
}

export function LangSelect({ size = "small", width = 120 }: { size?: "small" | "middle"; width?: number }) {
  const { lang, setLang } = useLang();
  return (
    <Select
      size={size}
      value={lang}
      onChange={(v) => setLang(v as Lang)}
      style={{ width }}
      popupMatchSelectWidth={false}
      suffixIcon={<GlobalOutlined />}
      options={LANGS}
    />
  );
}

// ---------------------------------------------------------------- 静态界面文案：中文 -> 英文
const EN: Record<string, string> = {
  // 顶栏 / 通用
  "企业终端安全态势 · 管理驾驶舱": "Endpoint Security Posture · Console",
  "AI 分析：": "AI Analysis: ",
  "AI 已接入": "{name} Connected",
  "Mock 模式": "Mock Mode",
  "数据源：": "Data: ",
  "实时": "Live",
  "演示数据": "Demo Data",
  "接口异常": "API Error",
  "后端接口不可用": "Backend API unavailable",
  "后端接口不可用，请检查服务状态。": "Backend API unavailable. Please check service status.",
  "导出报告": "Export Report",
  "刷新": "Refresh",
  "修改账号密码": "Change Credentials",
  "退出登录": "Sign Out",
  "保存": "Save",
  "取消": "Cancel",
  "确定": "OK",
  "已保存": "Saved",
  "保存失败": "Save failed",
  "已恢复注册名": "Registered name restored",

  // 导航
  "总览大屏": "Overview",
  "安全告警": "Alerts",
  "漏洞与补丁": "Vulnerabilities",
  "资产清点": "Assets",
  "合规加固": "Compliance",

  // 修改账号密码
  "请输入原密码": "Please enter your current password",
  "请输入新账号": "Please enter a new username",
  "新密码至少 6 位": "New password must be at least 6 characters",
  "两次输入的新密码不一致": "The two passwords do not match",
  "修改成功": "Updated successfully",
  "修改失败": "Update failed",
  "用原密码验证后即可修改账号与密码。当前账号：": "Verify with your current password to change account & password. Current account: ",
  "原密码": "Current password",
  "新账号": "New username",
  "新密码（至少 6 位）": "New password (min 6 chars)",
  "确认新密码": "Confirm new password",

  // 席位墙
  "终端席位总览": "Endpoint Seat Overview",
  "台在线": "online",
  "离线优先": "Offline first",
  "按 ID 排序": "Sort by ID",
  "搜索设备名/ID": "Search name / ID",
  "没有匹配的设备": "No matching devices",
  "在线": "Online",
  "离线": "Offline",
  "发现 {n} 条疑似旧终端记录，建议确认后在 Wazuh 中清理。": "Found {n} suspected stale endpoint records. Confirm and clean them in Wazuh.",
  "最近新增终端：{names}": "Recently added endpoints: {names}",
  "改名": "Rename",
  "恢复注册名": "Restore registered name",
  "更多操作": "More actions",
  "疑似旧记录": "Suspected stale record",
  "设置终端显示名称": "Set Endpoint Display Name",
  "仅修改仪表盘显示名，不改变 Wazuh 注册名。": "Only changes the dashboard display name. The Wazuh registered name is unchanged.",

  // 总览 KPI / 卡片
  "在线设备": "Online Devices",
  "台": "",
  "高危/严重告警": "High/Critical Alerts",
  "条": "",
  "24h 内": "last 24h",
  "详情": "Details",
  "告警总量(24h)": "Total Alerts (24h)",
  "安全告警(24h)": "Security Alerts (24h)",
  "已剔除合规/基线噪声": "compliance/baseline noise removed",
  "经 AI 归并展示": "AI-clustered",
  "平均合规分": "Avg. Compliance",
  "CIS 基线": "CIS baseline",
  "整体风险指数": "Overall Risk Index",
  "风险趋势": "Risk Trend",
  "近 24 小时": "Last 24 hours",
  "近 7 天": "Last 7 days",
  "近 30 天": "Last 30 days",
  "高危告警按 Wazuh 当前索引实时统计，口径与安全告警页一致。": "High-risk alerts are counted in real time from the current Wazuh index, using the same criteria as the Security Alerts page.",
  "系统状态": "System Status",
  "正常": "Healthy",
  "异常": "Error",
  "暂无系统状态": "No system status",
  "Web": "Web",
  "DB": "DB",
  "Wazuh API": "Wazuh API",
  "Indexer": "Indexer",
  "前端入口已响应": "Web entry is responding",
  "数据库可查询": "Database is queryable",
  "{name} API 可登录": "{name} API login works",
  "Indexer 状态：{status}": "Indexer status: {status}",
  "已连接": "Connected",
  "检查失败：{error}": "Check failed: {error}",
  "AI 安全态势研判": "AI Security Posture",
  "暂无分析结果。": "No analysis yet.",
  "风险趋势（近 14 天）": "Risk Trend (14 days)",
  "告警严重度分布": "Alert Severity Distribution",
  "AI 告警归并（降噪后）": "AI Alert Clustering (de-noised)",
  "危": " risk",
  "设备系统分布": "OS Distribution",
  "最常触发的安全规则 Top 6": "Top 6 Triggered Rules",
  "合规标签覆盖": "Compliance Tag Coverage",
  "相关事件": "related events",
  "AI 推理性能": "{name} Inference Performance",
  "分析中": "Running",
  "暂无": "N/A",
  "推理速度": "Inference Speed",
  "最后刷新：": "Last refresh: ",
  "输入 Tokens": "Input Tokens",
  "输出 Tokens": "Output Tokens",
  "最近任务": "Latest task",
  "发送日志": "Sent logs",
  "条原始日志": "raw log entries",
  "任务": "Task",
  "已运行": "running",
  "秒": "s",
  "最近错误：": "Last error: ",
  "触发次数": "Triggered",
  "AI 状态：": "{name} status: ",
  "模型已连接": "model connected",
  "当前 Mock": "Mock mode",
  "最近耗时": "latest latency",

  // 资产 / 设备表
  "设备名": "Device",
  "IP 地址": "IP Address",
  "系统": "OS",
  "状态": "Status",
  "Agent 版本": "Agent Version",
  "最后心跳": "Last Heartbeat",
  "设备总数": "Total Devices",
  "纳管终端": "managed",
  "需关注": "needs attention",
  "设备资产清单": "Device Inventory",
  "导出 CSV": "Export CSV",
  "确认清理旧记录": "Confirm Cleanup Stale Record",
  "将从 Wazuh 删除该旧 Agent 记录：{name}（ID: {id}）。在线终端请不要清理。": "This will delete the stale Wazuh Agent record: {name} (ID: {id}). Do not clean active endpoints.",
  "确认清理": "Confirm Cleanup",
  "旧 Agent 记录已清理": "Stale Agent record cleaned",
  "清理失败，请检查 Wazuh API 状态": "Cleanup failed, check Wazuh API status",

  // 合规
  "AI 加固建议": "AI Hardening Advice",
  "合规最差设备：": "Lowest compliance device: ",
  "分），建议优先处理。": " pts), recommend prioritizing.",
  "基线策略": "Baseline Policy",
  "评分": "Score",
  "分": " pts",
  "通过项": "Passed",
  "未通过": "Failed",
  "设备": "Device",
  "合规标签覆盖（事件数）": "Compliance Tag Coverage (events)",
  "各设备 CIS 基线评分": "CIS Baseline Score by Device",

  // 严重度
  "严重": "Critical",
  "高危": "High",
  "中危": "Medium",
  "低危": "Low",
  "中/低": "Med/Low",
  "未定级": "Unrated",
  "总计": "Total",

  // 告警页
  "告警明细": "Alert Details",
  "已修复问题": "Resolved Issues",
  "文件变更 (FIM)": "File Changes (FIM)",
  "自动响应": "Active Response",
  "时间": "Time",
  "等级": "Level",
  "告警描述": "Description",
  "分类": "Category",
  "操作": "Actions",
  "最低等级": "Min level",
  "置顶追踪中": "Pinned tracking",
  "木马已清除": "Trojan cleared",
  "全部": "All",
  "中危及以上 (≥7)": "Medium+ (≥7)",
  "高危及以上 (≥12)": "High+ (≥12)",
  "仅严重 (≥15)": "Critical only (≥15)",
  "按设备筛选": "Filter by device",
  "搜索告警描述关键词": "Search description keyword",
  "新增": "Added",
  "修改": "Modified",
  "删除": "Deleted",
  "变更": "Change",
  "文件路径": "File Path",
  "说明": "Note",
  "近 24 小时无文件变更记录": "No file changes in the last 24h",
  "处置动作": "Action",
  "自动响应：满足条件时系统自动执行的处置（如封禁来源 IP、禁用账户）。未配置或近 24h 无触发时此处为空。":
    "Active Response: automated actions taken when conditions match (e.g. block source IP, disable account). Empty if not configured or none triggered in the last 24h.",
  "近 24 小时无自动响应记录": "No active responses in the last 24h",
  "原始描述": "Original Description",
  "告警详情": "Alert Detail",
  "规则 ID": "Rule ID",
  "监听地址": "Listen Address",
  "追踪编号": "Tracking ID",
  "追踪状态": "Tracking Status",
  "受影响文件": "Affected Files",
  "已复制原始日志": "Raw log copied",
  "已复制详情": "Details copied",
  "复制失败，请手动选中复制": "Copy failed, please select and copy manually",
  "详情生成失败，请稍后重试。": "Failed to generate details, please try again later.",
  "确认已处置该告警？": "Confirm this alert is resolved?",
  "该告警会进入已修复问题，可在已修复列表重新打开。": "This alert will move to resolved issues and can be reopened from the resolved list.",
  "已标记为已处置": "Marked as resolved",
  "标记已处置": "Mark Resolved",
  "未修复": "Open",
  "AI 详情": "{name} Details",
  "暂无详情，请稍后重试。": "No details yet, please retry later.",
  "复制详情": "Copy Details",
  "复制原始日志": "Copy Raw Log",
  "原始日志片段": "Raw Log Snippet",
  "无原始日志片段": "No raw log snippet",
  "问题时间线": "Issue Timeline",
  "处置时间轴（发现 → 清除）": "Response Timeline (detected → cleared)",
  "已修复": "Resolved",
  "未修复 · 追踪中": "Open · tracking",
  "首次发现": "First seen",
  "最近出现": "Last seen",
  "清除时间": "Resolved at",
  "出现次数": "Occurrences",
  "发现": "Detected",
  "已清除": "Cleared",
  "再次出现": "Reopened",
  "重新打开": "Reopen",
  "暂无时间线": "No timeline",
  "时间线": "Timeline",
  "问题描述": "Issue Description",
  "清除方式": "Resolution",
  "复核状态": "Review Status",
  "自动复核": "Auto Review",
  "确认稳定": "Stable",
  "15 分钟通过": "15m passed",
  "5 分钟通过": "5m passed",
  "待复核": "Pending review",
  "自动": "Auto",
  "已重新打开追踪": "Tracking reopened",
  "调试信息（校验 AI 收发）": "Debug info (AI request/response)",
  "耗时": "Latency",
  "① 发送的 context": "1. Sent context",
  "④ 原始日志（监测引擎记录）": "4. Raw log (monitoring engine)",
  "未找到对应的原始日志": "No matching raw log found",
  "为什么触发": "Why It Triggered",
  "已根据原始日志解析触发原因": "Trigger reason parsed from raw log",
  "命中 Wazuh 规则 {rule_id}：{description}": "Matched Wazuh rule {rule_id}: {description}",
  "规则等级 ≥15，按严重告警处理。": "Rule level >=15, treated as critical.",
  "规则等级 ≥12，按高危告警处理。": "Rule level >=12, treated as high risk.",
  "规则等级 ≥7，按中危及以上安全告警展示。": "Rule level >=7, shown as medium-or-higher security alert.",
  "规则分类包含：{groups}": "Rule groups include: {groups}",
  "关联 MITRE 技术：{mitre}": "Related MITRE techniques: {mitre}",
  "原始日志包含受影响文件/进程路径：{files}": "Raw log contains affected file/process paths: {files}",
  "Windows 事件字段 {field}={value}": "Windows event field {field}={value}",
  "来源 IP：{ip}": "Source IP: {ip}",
  "高危等级或命中重点安全规则，因此在列表中优先展示/标红。": "High severity or key security rule matched, so it is prioritized/highlighted in the list.",
  "未达到高危标红条件。": "Did not meet high-risk highlighting conditions.",
  "同类 {n} 次": "{n} similar events",
  "本机自检": "Self Check",
  "Agent 自检结果": "Agent Self Check Result",
  "Wazuh 注册状态": "Wazuh Registration",
  "Agent 在线状态": "Agent Online Status",
  "Manager 地址": "Manager Address",
  "{port} 连通性": "{port} Connectivity",
  "{host}:{port} 可连通": "{host}:{port} reachable",
  "{host}:{port} 不通：{error}": "{host}:{port} unreachable: {error}",
  "已注册：{name}": "Registered: {name}",
  "未在 Wazuh API 查到该 Agent": "Agent not found in Wazuh API",
  "当前状态：{status}": "Current status: {status}",
  "{host}": "{host}",
  "未配置 Manager 地址": "Manager address is not configured",
  "{time}": "{time}",
  "未读取到心跳时间": "Last heartbeat not found",
  "只读核查": "Read-only check",
  "可能修改系统": "May modify system",
  "危险操作": "Dangerous operation",
  "缺少变量": "Missing variable",
  "示例值不可复制": "Example value cannot be copied",
  "缺少 PID": "Missing PID",
  "缺少端口": "Missing port",
  "确认复制危险命令": "Confirm Copy Dangerous Command",
  "该命令可能终止进程、删除文件或修改防火墙，请确认对象无误后再执行。": "This command may terminate processes, delete files, or modify firewall rules. Confirm the target before running it.",
  "确认复制包含危险操作的命令": "Confirm Copy Commands with Dangerous Operations",
  "命令列表包含可能修改系统的操作，请先确认每条命令的目标对象。": "The command list contains operations that may modify the system. Confirm every target first.",
  "确认复制": "Confirm Copy",

  // 漏洞页
  "CVE 编号": "CVE",
  "严重度": "Severity",
  "受影响软件": "Affected Package",
  "版本": "Version",
  "漏洞总数": "Total Vulnerabilities",
  "个": "",
  "待评估/修复": "to assess/fix",
  "应立即修复": "fix immediately",
  "尽快修复": "fix soon",
  "中/低危": "Medium/Low",
  "计划处理": "plan to fix",
  "受影响设备": "Affected Devices",
  "存在漏洞": "have vulnerabilities",
  "Top 高频漏洞 (CVE)": "Top CVEs",
  "次": "x",
  "漏洞最多的设备": "Most Vulnerable Devices",
  "漏洞明细（按 CVSS 评分排序）": "Vulnerability Details (sorted by CVSS)",
  "暂无漏洞数据（漏洞检测可能仍在首次扫描中，请稍后刷新）":
    "No vulnerability data yet (initial scan may still be running, refresh later)",
  "查看 CVE 详情确认影响范围和修复版本": "Open CVE details to confirm impact scope and fixed version",
  "暂无数据": "No data",

  // 资产清点页
  "设备清单": "Devices",
  "开放端口": "Open Ports",
  "软件清单": "Software",
  "端口": "Port",
  "协议": "Protocol",
  "进程": "Process",
  "开放设备数": "Devices",
  "风险提示": "Risk",
  "风险": "Risk",
  "常规": "Normal",
  "暂无端口数据": "No port data",
  "软件名称": "Software Name",
  "厂商": "Vendor",
  "版本(示例)": "Version (sample)",
  "安装设备数": "Installs",
  "搜索软件名称": "Search software name",
  "暂无软件数据": "No software data",
  "已扫描 {n} 台设备的监听端口。": "Scanned listening ports on {n} devices. ",
  "红色为高风险/敏感端口": "Red marks high-risk/sensitive ports",
  "（如 RDP、SMB、数据库），建议确认是否必要并限制来源。": " (e.g. RDP, SMB, databases); confirm necessity and restrict sources.",
  "已扫描 {n} 台设备的已装软件。可用于排查违规软件 / 影子 IT。": "Scanned installed software on {n} devices. Useful for spotting non-compliant software / shadow IT.",
  "已安装软件（{n}）": "Installed Software ({n})",
  "查看 {name} 详情": "View {name}",

  // 防火墙
  "已开启": "Enabled",
  "已关闭": "Disabled",
  "不适用": "N/A",
  "未知": "Unknown",
  "防火墙与安全状态": "Firewall & Security",
  "尚未采集到防火墙状态（Agent 每小时上报一次，或该 Agent 未启用采集，请稍后查看）":
    "Firewall status not collected yet (the agent reports hourly, or collection is not enabled — check back later)",
  "Windows 防火墙": "Windows Firewall",
  "系统防火墙": "System Firewall",
  "域网络": "Domain Network",
  "专用网络": "Private Network",
  "公用网络": "Public Network",
  "实时防护": "Real-time Protection",
  "采集时间：": "Collected: ",

  // 设备详情
  "返回席位总览": "Back to overview",
  "系统信息": "System Info",
  "操作系统": "Operating System",
  "架构": "Architecture",
  "核": "cores",
  "内存": "Memory",
  "主机名": "Hostname",
  "纳管时间": "Enrolled At",
  "无监听端口": "No listening ports",
  "漏洞概况": "Vulnerability Overview",
  "查看明细 ›": "View details ›",
  "该设备暂无漏洞数据": "No vulnerability data for this device",
  "软件": "Package",
  "文件变更日志 (FIM)": "File Change Log (FIM)",
  "该设备受监控目录下文件的新增 / 修改 / 删除记录（近 30 天）。":
    "Add / modify / delete records of files under monitored paths on this device (last 30 days).",
  "近 30 天无文件变更记录": "No file changes in the last 30 days",
  "暂无软件清单（可能仍在采集中）": "No software inventory yet (collection may be in progress)",

  // 登录页
  "登录控制台": "Sign in to Console",
  "请输入管理员账号与密码以访问仪表盘。": "Enter your admin account and password to access the dashboard.",
  "请输入管理员账号与密码以访问仪表盘。首次部署请查看 server/.env 中的 DEFAULT_ADMIN_USER / DEFAULT_ADMIN_PASSWORD。": "Enter your admin account and password to access the dashboard. For first deployment, check DEFAULT_ADMIN_USER / DEFAULT_ADMIN_PASSWORD in server/.env.",
  "账号": "Username",
  "密码": "Password",
  "切换密码可见": "Toggle password visibility",
  "登 录": "Sign In",
  "请输入账号和密码": "Please enter username and password",
  "登录失败": "Sign-in failed",

  // 图表
  "风险指数 / 100": "Risk / 100",
  "告警": "Alerts",
  "其他": "Other",
  "风险指数": "Risk Index",
  "高危告警": "High Alerts",

  // AI 处理建议
  "AI 处理建议": "AI Remediation",
  "AI 处理建议（由 {name} 生成）": "AI Remediation (by {name})",
  "AI 正在生成处理建议…": "{name} is generating remediation advice…",
  "正在连接模型，准备接收分段结果…": "Connecting to the model and waiting for streamed output…",
  "生成失败，请稍后重试。": "Generation failed, please try again later.",
  "风险概述": "Risk Summary",
  "建议处理步骤": "Recommended Steps",
  "可执行 Runbook": "Executable Runbook",
  "复制步骤": "Copy Steps",
  "复制全部命令": "Copy All Commands",
  "已复制步骤": "Steps copied",
  "已复制命令": "Commands copied",
  "可复制命令": "Copyable Commands",
  "复制命令": "Copy Command",
  "执行位置": "Where",
  "成功标准": "Expected Result",
  "异常处理": "If Abnormal",
  "需确认": "Requires Confirmation",
  "核查阶段": "Check Phase",
  "隔离阻断": "Containment",
  "处置修复": "Remediation",
  "验证复核": "Verification",
  "回滚恢复": "Rollback",
  "影响范围": "Impact",
  "处置优先级": "Priority",
  "立即处理": "Immediate",
  "尽快处理": "Soon",
  "可计划处理": "Scheduled",
  "AI + 规则步骤": "{name} + rule steps",
  "规则建议": "Rule advice",
};

export function t(zh: string, vars?: Record<string, string | number>): string {
  let s = currentLang === "zh" ? zh : (EN[zh] ?? zh);
  if (vars) {
    for (const k of Object.keys(vars)) {
      s = s.replace(new RegExp(`\\{${k}\\}`, "g"), String(vars[k]));
    }
  }
  return s;
}

// ---------------------------------------------------------------- Wazuh 动态内容：英文 -> 中文
// 严重度
const SEVERITY_ZH: Record<string, string> = { Critical: "严重", High: "高危", Medium: "中危", Low: "低危" };
const SEVERITY_EN: Record<string, string> = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low" };
export function tSeverity(s: string): string {
  if (!s) return s;
  return currentLang === "zh" ? (SEVERITY_ZH[s] ?? s) : (SEVERITY_EN[s] ?? s);
}

// FIM 变更类型
const FIM_ZH: Record<string, string> = { added: "新增", modified: "修改", deleted: "删除" };
const FIM_EN: Record<string, string> = { added: "Added", modified: "Modified", deleted: "Deleted" };
export function tFimEvent(e: string): string {
  if (!e) return e;
  return currentLang === "zh" ? (FIM_ZH[e] ?? e) : (FIM_EN[e] ?? e);
}

// rule.groups 分组
const GROUP_ZH: Record<string, string> = {
  windows: "Windows 系统事件", windows_security: "Windows 安全日志", group_changed: "用户组变更",
  adduser: "账户新增", account_changed: "账户变更", authentication_success: "认证成功",
  authentication_failed: "认证失败", authentication_failures: "多次认证失败", authentication: "身份认证",
  syscheck: "文件完整性(FIM)", syscheck_entry_modified: "文件被修改", syscheck_entry_added: "文件被新增",
  syscheck_entry_deleted: "文件被删除", ossec: "管理器事件", system: "系统服务/状态变更", sca: "安全基线(SCA)",
  rootcheck: "主机异常检查", sudo: "提权(sudo)", package: "软件包", pci_dss: "PCI DSS",
  gdpr: "GDPR", hipaa: "HIPAA", nist_800_53: "NIST 800-53", attack: "攻击行为",
  web: "Web", firewall: "防火墙", ids: "入侵检测", vulnerability_detector: "漏洞检测",
  active_response: "自动响应", invalid_login: "无效登录", win_evt_channel: "Windows事件",
  policy_changed: "策略变更", privilege_escalation: "提权",
};
export function tGroup(g: string): string {
  if (!g) return g;
  return currentLang === "zh" ? (GROUP_ZH[g] ?? g) : g;
}

// MITRE ATT&CK 技术名
const MITRE_ZH: Record<string, string> = {
  "Account Manipulation": "账户操纵",
  "Domain Policy Modification": "域策略篡改",
  "Account Access Removal": "账户访问移除",
  "Brute Force": "暴力破解",
  "Valid Accounts": "有效账户利用",
  "Data Manipulation": "数据篡改",
  "Stored Data Manipulation": "存储数据篡改",
  "Abuse Elevation Control Mechanism": "提权机制滥用",
  "Sudo and Sudo Caching": "Sudo 提权",
  "Command and Scripting Interpreter": "命令与脚本执行",
  "File and Directory Permissions Modification": "文件/目录权限修改",
  "Scheduled Task/Job": "计划任务",
  "OS Credential Dumping": "凭据导出",
  "Indicator Removal": "痕迹清除",
  "Create Account": "创建账户",
  "Create or Modify System Process": "创建/修改系统进程",
  "Modify Registry": "注册表篡改",
  "Disable or Modify Tools": "禁用/篡改安全工具",
  "Disable or Modify System Firewall": "禁用/篡改系统防火墙",
  "Remote Services": "远程服务",
  "Exploitation for Privilege Escalation": "漏洞提权利用",
  "Impair Defenses": "削弱防御",
};
export function tMitre(name: string): string {
  if (!name) return name;
  return currentLang === "zh" ? (MITRE_ZH[name] ?? name) : name;
}

// 端口风险：后端给的是中文字符串（如“远程桌面 RDP”），英文模式反查
const PORTRISK_EN: Record<string, string> = {
  "FTP 明文传输": "FTP (cleartext)", "SSH 远程登录": "SSH remote login", "Telnet 明文": "Telnet (cleartext)",
  "SMTP": "SMTP", "Windows RPC": "Windows RPC", "NetBIOS": "NetBIOS", "NetBIOS/SMB": "NetBIOS/SMB",
  "SMB 文件共享": "SMB file sharing", "SQL Server": "SQL Server", "Oracle": "Oracle", "MySQL": "MySQL",
  "远程桌面 RDP": "RDP remote desktop", "PostgreSQL": "PostgreSQL", "VNC 远程桌面": "VNC remote desktop",
  "Redis": "Redis", "Elasticsearch": "Elasticsearch", "MongoDB": "MongoDB",
};
export function tPortRisk(s: string | null | undefined): string {
  if (!s) return "";
  return currentLang === "zh" ? s : (PORTRISK_EN[s] ?? s);
}

export function tDynamic(s: string | null | undefined): string {
  if (!s) return s ?? "";
  if (currentLang !== "zh") return s;
  const desc = tDesc(s);
  if (desc !== s) return desc;
  const group = tGroup(s);
  if (group !== s) return group;
  const mitre = tMitre(s);
  if (mitre !== s) return mitre;
  const severity = tSeverity(s);
  if (severity !== s) return severity;
  const fim = tFimEvent(s);
  if (fim !== s) return fim;
  return s;
}

// 告警 / FIM 规则描述：Wazuh 原文为英文，中文模式翻译；精确匹配 + 正则模式兜底
const DESC_ZH: Record<string, string> = {
  "Listened ports status (netstat) changed (new port opened or closed).": "监听端口变化：有端口被打开或关闭，请核查对应进程。",
  "Administrators Group Changed": "管理员组成员发生变更",
  "User account disabled or deleted": "用户账户被禁用或删除",
  "User account enabled or created": "用户账户被启用或创建",
  "User account changed": "用户账户被修改",
  "User account locked out": "用户账户被锁定",
  "Successful sudo to ROOT executed": "成功执行 sudo 提权到 ROOT",
  "syscheck - file modified": "文件被修改（FIM）",
  "Integrity checksum changed.": "文件完整性校验值发生变化",
  "File added to the system.": "系统中新增了文件",
  "File deleted.": "文件被删除",
  "Windows Logon Success.": "Windows 登录成功",
  "Logon Failure - Unknown user or bad password": "登录失败 - 用户名未知或密码错误",
  "Multiple Windows Logon Failures.": "多次 Windows 登录失败",
  "Multiple authentication failures.": "多次认证失败（疑似爆破）",
  "PAM: User login failed.": "PAM：用户登录失败",
  "sshd: Attempt to login using a non-existent user": "sshd：尝试使用不存在的用户登录",
  "sshd: authentication failed.": "sshd：认证失败",
  "New dpkg (Debian Package) installed.": "安装了新的软件包（dpkg）",
  "New Windows software installed.": "安装了新的 Windows 软件",
  "Host-based anomaly detection event (rootcheck).": "主机异常检测事件（rootcheck）",
  "Windows Defender: Antimalware platform detected potential threat.": "Windows Defender：检测到潜在威胁",
  "Windows license activation.": "Windows 许可证激活事件",
  "Windows license activation": "Windows 许可证激活事件",
  "License activation.": "许可证激活事件",
  "License activation": "许可证激活事件",
  "Software Protection Platform Service license activation.": "软件保护平台许可证激活事件",
  "Software Protection Platform Service license activation": "软件保护平台许可证激活事件",
  "Software Protection Service license activation.": "软件保护服务许可证激活事件",
  "Software Protection Service license activation": "软件保护服务许可证激活事件",
  "Software Protection Platform Service.": "软件保护平台服务事件",
  "Software Protection Platform Service": "软件保护平台服务事件",
  "Software Protection Service.": "软件保护服务事件",
  "Software Protection Service": "软件保护服务事件",
  "Software Protection.": "软件保护事件",
  "Software Protection": "软件保护事件",
  "Software protection service scheduled successfully.": "软件保护服务计划任务执行成功",
  "Software protection service scheduled successfully": "软件保护服务计划任务执行成功",
  "License activation (slui.exe) failed.": "许可证激活失败（slui.exe）",
  "License activation (slui.exe) failed": "许可证激活失败（slui.exe）",
  "Wazuh agent disconnected.": "Wazuh Agent 连接断开",
  "Wazuh agent disconnected": "Wazuh Agent 连接断开",
  "Wazuh server started.": "Wazuh 服务端已启动",
  "Wazuh server started": "Wazuh 服务端已启动",
  "Screen locked with userID:.": "屏幕已锁定",
  "Screen locked with userID:": "屏幕已锁定",
  "Screen unlocked with userID:.": "屏幕已解锁",
  "Screen unlocked with userID:": "屏幕已解锁",
  "Windows System error event": "Windows 系统错误事件",
  "Windows System error event.": "Windows 系统错误事件",
  "System time changed.": "系统时间被修改",
  "Audit: Command: /usr/bin/sudo": "审计：执行 sudo 命令",
  "User missed the password to change UID to root.": "用户 sudo 提权密码输入错误",
  "Windows Logon Failure.": "Windows 登录失败",
  "Windows Logon Success": "Windows 登录成功",
  "PAM: Login session opened.": "PAM：登录会话已打开",
  "PAM: Login session closed.": "PAM：登录会话已关闭",
  "sshd: authentication success.": "sshd：认证成功",
  "Package installed.": "软件包已安装",
  "Package removed.": "软件包已卸载",
};
const DESC_PATTERNS: [RegExp, string][] = [
  [/^Multiple authentication failures/i, "多次认证失败（疑似爆破）"],
  [/^Multiple Windows Logon Failures/i, "多次 Windows 登录失败"],
  [/^Listened ports status/i, "监听端口变化：有端口被打开或关闭，请核查对应进程。"],
  [/successful sudo/i, "成功执行 sudo 提权"],
  [/\bsudo\b/i, "检测到 sudo 提权操作"],
  [/login failed|authentication failed/i, "登录/认证失败"],
  [/system time changed/i, "系统时间被修改"],
  [/host-based anomaly detection/i, "主机异常检测事件"],
  [/windows logon failure/i, "Windows 登录失败"],
  [/windows logon success/i, "Windows 登录成功"],
  [/software protection platform.*license.*activation|license.*activation.*software protection platform/i, "软件保护平台许可证激活事件"],
  [/software protection.*license.*activation|license.*activation.*software protection/i, "软件保护许可证激活事件"],
  [/\bspp\b/i, "软件保护平台事件"],
  [/software protection platform/i, "软件保护平台事件"],
  [/software protection service.*scheduled.*success/i, "软件保护服务计划任务执行成功"],
  [/software protection/i, "软件保护事件"],
  [/license.*activation.*fail|activation.*license.*fail/i, "许可证激活失败"],
  [/license.*activation|activation.*license/i, "许可证激活事件"],
  [/windows.*license/i, "Windows 许可证事件"],
  [/wazuh agent.*disconnect/i, "Wazuh Agent 连接断开"],
  [/wazuh server.*start/i, "Wazuh 服务端已启动"],
  [/screen locked/i, "屏幕已锁定"],
  [/screen unlocked/i, "屏幕已解锁"],
  [/service.*started|service control manager/i, "系统服务启动/变更事件"],
  [/service.*stopped/i, "系统服务停止事件"],
  [/application.*installed|software.*installed/i, "软件安装事件"],
  [/application.*removed|software.*removed|software.*uninstalled/i, "软件卸载事件"],
  [/windows.*error|system error/i, "Windows 系统错误事件"],
  [/audit.*success/i, "审计成功事件"],
  [/audit.*failure/i, "审计失败事件"],
  [/login session opened/i, "登录会话已打开"],
  [/login session closed/i, "登录会话已关闭"],
  [/package .*installed|new .*package.*installed/i, "软件包安装事件"],
  [/package .*removed/i, "软件包卸载事件"],
];

function portChangeDescZh(text: string): string | null {
  if (!/^Listened ports status/i.test(text) && !text.includes("监听端口状态发生变化")) return null;
  const port = text.match(/[（(]端口[:：]\s*([^)）]+)[)）]/i)?.[1]
    || text.match(/\b(?:port|dstport|dst_port|dport)[:=]\s*([0-9]+(?:\/[a-z]+)?)/i)?.[1];
  if (port) {
    return `监听端口变化：${port} 被打开或关闭，请核查对应进程。`;
  }
  return "监听端口变化：有端口被打开或关闭，请核查对应进程。";
}

export function tDesc(text: string | null | undefined): string {
  if (!text) return text ?? "";
  if (currentLang === "en") return text;
  const portDesc = portChangeDescZh(text);
  if (portDesc) return portDesc;
  if (DESC_ZH[text]) return DESC_ZH[text];
  for (const [re, zh] of DESC_PATTERNS) {
    if (re.test(text)) return zh;
  }
  return text; // 未收录的描述保持原文（不影响可读性）
}
