import { currentLang } from "../i18n";
import { tDesc } from "./dynamicText";

export function formatTopRuleLabel(raw: string): string {
  const text = String(raw || "").trim();
  if (currentLang === "en") return text;
  const exact: Record<string, string> = {
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
    "Software protection service scheduled successfully.": "软件保护服务计划任务执行成功",
    "Software protection service scheduled successfully": "软件保护服务计划任务执行成功",
    "License activation (slui.exe) failed.": "许可证激活失败（slui.exe）",
    "License activation (slui.exe) failed": "许可证激活失败（slui.exe）",
  };
  if (exact[text]) return exact[text];
  if (/wazuh agent.*disconnect/i.test(text)) return "Wazuh Agent 连接断开";
  if (/wazuh agent.*start/i.test(text)) return "Wazuh Agent 已启动";
  if (/wazuh server.*start/i.test(text)) return "Wazuh 服务端已启动";
  if (/screen locked/i.test(text)) return "屏幕已锁定";
  if (/screen unlocked/i.test(text)) return "屏幕已解锁";
  if (/software protection service.*scheduled.*success/i.test(text)) return "软件保护服务计划任务执行成功";
  if (/license.*activation.*fail|activation.*license.*fail/i.test(text)) return "许可证激活失败";
  if (/windows.*system.*error|system error/i.test(text)) return "Windows 系统错误事件";
  return tDesc(text);
}
