import { currentLang } from "../i18n";

const SEVERITY_ZH: Record<string, string> = { Critical: "严重", High: "高危", Medium: "中危", Low: "低危" };
const SEVERITY_EN: Record<string, string> = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low" };
export function tSeverity(s: string): string {
  if (!s) return s;
  return currentLang === "zh" ? (SEVERITY_ZH[s] ?? s) : (SEVERITY_EN[s] ?? s);
}

const FIM_ZH: Record<string, string> = { added: "新增", modified: "修改", deleted: "删除" };
const FIM_EN: Record<string, string> = { added: "Added", modified: "Modified", deleted: "Deleted" };
export function tFimEvent(e: string): string {
  if (!e) return e;
  return currentLang === "zh" ? (FIM_ZH[e] ?? e) : (FIM_EN[e] ?? e);
}

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
  "Wazuh agent started.": "Wazuh Agent 已启动",
  "Wazuh agent started": "Wazuh Agent 已启动",
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
  [/wazuh agent.*start/i, "Wazuh Agent 已启动"],
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
  return text;
}
