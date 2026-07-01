import type { AlertRow } from "../api";
import { currentLang } from "../i18n";
import { tDesc, tPortRisk } from "./dynamicText";
import { processMeaning } from "./processCatalog";

export function alertDescription(row: AlertRow): string {
  const desc = String(row.description || "");
  if (isTrojanSimulationAlert(row, desc)) {
    return trojanSimulationDescription(row, desc);
  }
  if (isListenedPortsAlert(desc)) {
    return listenedPortsAlertDescription(row);
  }
  return tDesc(desc);
}

function isTrojanSimulationAlert(row: AlertRow, desc: string): boolean {
  const ruleId = String(row.rule_id ?? "");
  const raw = String(row.raw_log || "");
  return (
    ruleId === "100120"
    || ruleId === "100121"
    || /测试木马|GUIZANG_WAZUH_HIGH_ALERT_TEST|attack-sim/i.test(`${desc}\n${raw}`)
  );
}

function trojanSimulationDescription(row: AlertRow, desc: string): string {
  const raw = String(row.raw_log || "");
  const tracking = row.trojan_tracking;
  const event = row.trojan_event;
  const testId = tracking?.tracking_id || event?.tracking_id || raw.match(/\bid=([A-Za-z0-9._:-]+)/)?.[1] || "";
  const stage = event?.stage || raw.match(/\bstage=([A-Za-z0-9._:-]+)/)?.[1] || "sudo_bruteforce";
  const port = String(event?.port || tracking?.ports?.[0] || raw.match(/\bport=([0-9]+)/)?.[1] || "");
  const active = row.issue_status !== "resolved" && tracking?.status !== "cleared";
  const base = currentLang === "en"
    ? "Suspected test trojan behavior"
    : "疑似测试木马行为";
  const stageText = currentLang === "en"
    ? trojanStageTextEn(stage, port)
    : trojanStageTextZh(stage, port);
  const historyText = tracking
    ? (currentLang === "en"
      ? ` Observed stages: ${(tracking.stages || []).join(", ") || stage}; events: ${tracking.events_count || 1}.`
      : `已追踪阶段：${formatStagesZh(tracking.stages || [stage])}；关联事件 ${tracking.events_count || 1} 条。`)
    : "";
  const idText = testId
    ? (currentLang === "en" ? ` Tracking ID: ${testId}.` : `追踪编号：${testId}。`)
    : "";
  const follow = currentLang === "en"
    ? (active
      ? " Status: active tracking."
      : " Status: cleared.")
    : (active
      ? "状态：追踪中。"
      : "状态：已清除。");
  return `${base}：${stageText}${idText}${historyText}${follow}`;
}

function trojanStageTextZh(stage: string, port: string): string {
  if (/sudo|bruteforce|auth/i.test(stage)) {
    return `已观察到连续 sudo 认证失败，表现为本机提权暴力尝试${port ? `；模拟脚本同时打开过临时监听端口 ${port}` : ""}。`;
  }
  if (/port|listen/i.test(stage)) {
    return port ? `已观察到临时监听端口 ${port}，表现为可疑服务暴露。` : "已观察到临时监听行为，表现为可疑服务暴露。";
  }
  if (/fim|file|drop/i.test(stage)) {
    return "已观察到临时文件落地行为，表现为可疑文件写入。";
  }
  if (/clear|cleanup|removed|restored/i.test(stage)) {
    return port ? `已观察到清除木马动作：临时监听端口 ${port} 已关闭，临时文件已清理。` : "已观察到清除木马动作：临时监听和临时文件已清理。";
  }
  return descLikeStage(stage);
}

function trojanStageTextEn(stage: string, port: string): string {
  if (/sudo|bruteforce|auth/i.test(stage)) {
    return `repeated sudo authentication failures were observed, consistent with a local privilege-escalation attempt${port ? `; the simulator also opened temporary listener port ${port}` : ""}.`;
  }
  if (/port|listen/i.test(stage)) {
    return port ? `temporary listener port ${port} was observed, consistent with suspicious service exposure.` : "temporary listener behavior was observed, consistent with suspicious service exposure.";
  }
  if (/fim|file|drop/i.test(stage)) {
    return "temporary file drop behavior was observed.";
  }
  if (/clear|cleanup|removed|restored/i.test(stage)) {
    return port ? `cleanup was observed: temporary listener port ${port} was closed and dropped files were removed.` : "cleanup was observed: temporary listener and dropped files were removed.";
  }
  return `behavior stage observed: ${stage}.`;
}

function descLikeStage(stage: string): string {
  return currentLang === "en" ? `behavior stage observed: ${stage}.` : `已观察到 ${stage} 阶段行为。`;
}

function formatStagesZh(stages: string[]): string {
  const labels: Record<string, string> = {
    start: "启动",
    sudo_bruteforce: "sudo 提权尝试",
    cleared: "清除木马",
    cleanup: "清理恢复",
    file_drop: "文件落地",
    port_listen: "端口监听",
  };
  return stages.map((stage) => labels[stage] || stage).join("、");
}

function isListenedPortsAlert(desc: string): boolean {
  return /^Listened ports status/i.test(desc) || desc.includes("监听端口");
}

function listenedPortsAlertDescription(row: AlertRow): string {
  const changed = Array.isArray(row.changed_ports) ? row.changed_ports : [];
  const ports = changed.length ? changed : [{
    port: row.port,
    protocol: row.protocol,
    address: row.listen_ip,
    process: row.process,
    risky: undefined,
  }];
  const items = ports
    .filter((p) => p && p.port !== undefined && p.port !== null && p.port !== "")
    .slice(0, 3)
    .map((p) => formatPortChangeItem(p));

  if (currentLang === "en") {
    const action = row.port_change === "opened" ? "opened" : row.port_change === "closed" ? "closed" : "changed";
    if (items.length) return `Listening port ${action}: ${items.join("; ")}.`;
    return "Listening port changed, but the exact port/process is missing from the Wazuh netstat log.";
  }

  const action = row.port_change === "opened" ? "打开" : row.port_change === "closed" ? "关闭" : "发生变化";
  if (items.length) return `监听端口已${action}：${items.join("；")}。`;
  return "监听端口发生变化，但 Wazuh netstat 日志未提供具体端口或进程，请查看原始日志确认。";
}

function formatPortChangeItem(p: { port?: number | string; protocol?: string; address?: string; process?: string; risky?: string | null }): string {
  const protocol = p.protocol ? `/${p.protocol}` : "";
  const address = p.address && p.address !== "*" ? `${p.address}:` : "";
  const endpoint = `${address}${p.port}${protocol}`;
  const process = String(p.process || "").trim();
  const risk = p.risky ? (currentLang === "en" ? `, risk: ${tPortRisk(p.risky)}` : `，风险：${tPortRisk(p.risky)}`) : "";
  if (!process) {
    return `${endpoint}${risk}`;
  }
  const meaning = processMeaning(process);
  return currentLang === "en"
    ? `${endpoint}, caused by process ${process}${meaning ? ` (${meaning})` : ""}${risk}`
    : `${endpoint}，由进程 ${process} 导致${meaning ? `（${meaning}）` : ""}${risk}`;
}
