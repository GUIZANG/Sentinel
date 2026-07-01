import { useState } from "react";
import { Button, Collapse, Modal, Spin, Tag, message } from "antd";
import { BugOutlined, CopyOutlined, RobotOutlined } from "@ant-design/icons";
import { streamAdvice, type AdviceResp, type AdviceRunbookStep } from "../api";
import { brand } from "../brand";
import { t, useLang } from "../i18n";

export function AiAdviceButton({ kind, ctx }: { kind: "vuln" | "alert"; ctx: Record<string, any> }) {
  useLang();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AdviceResp | null>(null);
  const [err, setErr] = useState(false);
  const [streamingText, setStreamingText] = useState("");

  async function run(e: React.MouseEvent) {
    e.stopPropagation();
    setOpen(true);
    setLoading(true);
    setErr(false);
    setData(null);
    setStreamingText("");
    try {
      const result = await streamAdvice(kind, ctx, (text) => {
        setStreamingText((prev) => normalizeStreamingText(prev + text));
      });
      setData(result);
    } catch {
      setErr(true);
    } finally {
      setLoading(false);
    }
  }

  const prioTag = (p?: string) => {
    if (p === "immediate") return <Tag color="red">{t("立即处理")}</Tag>;
    if (p === "soon") return <Tag color="orange">{t("尽快处理")}</Tag>;
    if (p === "scheduled") return <Tag color="blue">{t("可计划处理")}</Tag>;
    return null;
  };
  const cleanedSteps = (data?.steps || []).map(cleanAdviceText).filter(Boolean);
  const runbook = normalizeRunbook(data?.runbook || []);
  const runbookCommands = runbook.flatMap((step) => (step.commands || []).map(scoreCommand));
  const commands = (runbook.length ? runbookCommands : extractCommands(cleanedSteps).map(scoreCommand));
  const copyableCommands = commands.filter((cmd) => !cmd.invalidReason);

  return (
    <>
      <Button size="small" type="link" icon={<RobotOutlined />} style={{ padding: 0 }} onClick={run}>
        {t("AI 处理建议")}
      </Button>
      <Modal
        title={<span><RobotOutlined style={{ marginRight: 8 }} />{t("AI 处理建议（由 {name} 生成）", { name: brand.aiName })}</span>}
        open={open}
        onCancel={() => setOpen(false)}
        footer={null}
        width={620}
        destroyOnClose
      >
        {loading ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "12px 4px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <Spin />
              <span className="muted">{t("AI 正在生成处理建议…", { name: brand.aiName })}</span>
            </div>
            <div className="ai-summary" style={{ maxHeight: 360, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {streamingText || t("正在连接模型，准备接收分段结果…")}
            </div>
          </div>
        ) : err ? (
          <div className="text-destructive" style={{ padding: "12px 0" }}>{t("生成失败，请稍后重试。")}</div>
        ) : data ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <div className="section-title" style={{ margin: "0 0 6px" }}>
                {t("风险概述")}
                {data.priority ? <span style={{ marginLeft: 8 }}>{prioTag(data.priority)}</span> : null}
              </div>
              <div className="ai-summary">{data.summary || "—"}</div>
            </div>

            <div>
              <div className="section-title" style={{ margin: "0 0 8px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>{runbook.length ? t("可执行 Runbook") : t("建议处理步骤")}</span>
                <span style={{ display: "flex", gap: 8 }}>
                  <Button size="small" onClick={() => copyLines(cleanedSteps, t("已复制步骤"), true)}>{t("复制步骤")}</Button>
                  {copyableCommands.length ? <Button size="small" type="primary" icon={<CopyOutlined />} onClick={() => copyCommands(copyableCommands)}>{t("复制全部命令")}</Button> : null}
                </span>
              </div>
              {runbook.length ? <RunbookView steps={runbook} /> : (
                <ul className="action-list">
                  {cleanedSteps.map((s, i) => (
                    <li key={i}>
                      <span className="idx">{i + 1}</span>
                      <span>{s}</span>
                    </li>
                  ))}
                </ul>
              )}
              {!runbook.length && commands.length ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 12 }}>
                  <div className="section-title" style={{ margin: 0 }}>{t("可复制命令")}</div>
                  {commands.map((cmd, i) => (
                    <div key={`${cmd.text}-${i}`} style={{ position: "relative" }}>
                      <pre style={{ margin: 0, padding: "12px 42px 12px 12px", borderRadius: 8, background: "#0f172a", color: "#e5e7eb", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                        <code>{cmd.text}</code>
                      </pre>
                      <Button
                        size="small"
                        type="text"
                        icon={<CopyOutlined />}
                        title={t("复制命令")}
                        disabled={!!cmd.invalidReason}
                        onClick={() => copyCommand(cmd)}
                        style={{ position: "absolute", right: 6, top: 6, color: "#e5e7eb" }}
                      />
                      {cmd.invalidReason ? <Tag color="red" style={{ marginTop: 6 }}>{cmd.invalidReason}</Tag> : null}
                    </div>
                  ))}
                </div>
              ) : null}
            </div>

            {data.impact ? (
              <div>
                <div className="section-title" style={{ margin: "0 0 6px" }}>{t("影响范围")}</div>
                <div className="muted">{data.impact}</div>
              </div>
            ) : null}

            <div className="muted" style={{ fontSize: 12 }}>
              {data._source === "guizangai" ? t("AI + 规则步骤", { name: brand.aiName }) : t("规则建议")}
              {data._error ? <span className="text-destructive"> · {data._error}</span> : null}
            </div>

            {data._debug ? (
              <Collapse
                size="small"
                items={[{
                  key: "debug",
                  label: <span><BugOutlined style={{ marginRight: 6 }} />{t("调试信息（校验 AI 收发）")}</span>,
                  children: (
                    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                        <Tag>{t("耗时")}: {data._debug.duration_ms ?? "—"} ms</Tag>
                        <Tag>{t("输入 Tokens")}: {data._debug.input_tokens ?? "—"}</Tag>
                        <Tag>{t("输出 Tokens")}: {data._debug.output_tokens ?? "—"}</Tag>
                      </div>
                      <DebugBlock title={t("① 发送的 context")} text={JSON.stringify(data._debug.context || {}, null, 2)} />
                      <DebugBlock title={t("④ 原始日志（监测引擎记录）")} text={data._debug.source_log ? JSON.stringify(data._debug.source_log, null, 2) : t("未找到对应的原始日志")} />
                    </div>
                  ),
                }]}
              />
            ) : null}
          </div>
        ) : null}
      </Modal>
    </>
  );
}

function cleanAdviceText(value: any): string {
  let text = String(value ?? "").trim().replace(/^[、，,;；。\s]+/, "");
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const extracted = value.step ?? value.text ?? value.action ?? value.content ?? value.suggestion ?? value["建议"] ?? value["处理步骤"];
    if (extracted) return cleanAdviceText(extracted);
  }
  const singleQuotedList = text.match(/^\[\s*'([^']+)'\s*\]$/);
  const doubleQuotedList = text.match(/^\[\s*"([^"]+)"\s*\]$/);
  if (singleQuotedList) text = singleQuotedList[1];
  if (doubleQuotedList) text = doubleQuotedList[1];
  const objectStep = text.match(/^\{\s*['"](?:step|text|action|content|suggestion|建议|处理步骤)['"]\s*:\s*(['"])([\s\S]*)\1\s*\}$/);
  if (objectStep) text = objectStep[2].replace(/\\n/g, "\n").replace(/\\'/g, "'").replace(/\\"/g, '"');
  text = text.replace(/```[A-Za-z0-9_-]*\s*\n?([\s\S]*?)```/g, (_, body) => String(body).trim());
  return text.trim().replace(/^['"]|['"]$/g, "").replace(/^[、，,;；。\s]+/, "");
}

function normalizeStreamingText(value: string): string {
  return value
    .replace(/([。！？!?])\1+/g, "$1")
    .replace(/\.{2,}/g, ".")
    .replace(/。+\./g, "。")
    .replace(/\.+。/g, "。")
    .replace(/([。.!！?？])\s+([。.!！?？])/g, "$1");
}

function normalizeRunbook(value: AdviceRunbookStep[]): AdviceRunbookStep[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => ({
      ...item,
      goal: cleanAdviceText(item.goal || ""),
      where: cleanAdviceText(item.where || ""),
      commands: Array.isArray(item.commands) ? item.commands.map(cleanAdviceText).filter(Boolean) : [],
      expected_result: cleanAdviceText(item.expected_result || ""),
      if_abnormal: cleanAdviceText(item.if_abnormal || ""),
      risk: item.risk || "read",
      phase: item.phase || "check",
    }))
    .filter((item) => item.goal || (item.commands || []).length);
}

function RunbookView({ steps }: { steps: AdviceRunbookStep[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {steps.map((step, i) => {
        const commands = (step.commands || []).map(scoreCommand);
        const risk = step.risk === "danger" ? "danger" : step.risk === "modify" ? "modify" : "read";
        return (
          <div key={`${step.phase}-${i}`} style={{ border: "1px solid hsl(var(--border))", borderRadius: 10, padding: 12, background: "hsl(var(--secondary) / 0.35)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
              {step.phase && step.phase !== "check" ? <Tag color="blue">{phaseLabel(step.phase)}</Tag> : null}
              {risk !== "read" ? <Tag color={risk === "danger" ? "volcano" : "orange"}>{riskLabel(risk)}</Tag> : null}
              {step.requires_confirmation ? <Tag color="red">{t("需确认")}</Tag> : null}
              {step.where ? <span className="muted">{t("执行位置")}：{step.where}</span> : null}
            </div>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>{i + 1}. {step.goal}</div>
            {commands.length ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 8 }}>
                {commands.map((cmd, idx) => (
                  <div key={`${cmd.text}-${idx}`} style={{ position: "relative" }}>
                    <pre style={{ margin: 0, padding: "12px 42px 12px 12px", borderRadius: 8, background: "#0f172a", color: "#e5e7eb", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                      <code>{cmd.text}</code>
                    </pre>
                    <Button
                      size="small"
                      type="text"
                      icon={<CopyOutlined />}
                      title={t("复制命令")}
                      disabled={!!cmd.invalidReason}
                      onClick={() => copyCommand(cmd)}
                      style={{ position: "absolute", right: 6, top: 6, color: "#e5e7eb" }}
                    />
                    {cmd.invalidReason ? <Tag color="red" style={{ marginTop: 6 }}>{cmd.invalidReason}</Tag> : null}
                  </div>
                ))}
              </div>
            ) : null}
            {step.expected_result ? <div className="muted"><b>{t("成功标准")}：</b>{step.expected_result}</div> : null}
            {step.if_abnormal ? <div className="muted"><b>{t("异常处理")}：</b>{step.if_abnormal}</div> : null}
          </div>
        );
      })}
    </div>
  );
}

function phaseLabel(phase?: string) {
  const map: Record<string, string> = {
    check: "核查阶段",
    contain: "隔离阻断",
    remediate: "处置修复",
    verify: "验证复核",
    rollback: "回滚恢复",
  };
  return t(map[phase || "check"] || "核查阶段");
}

function riskLabel(risk?: string) {
  if (risk === "danger") return t("危险操作");
  if (risk === "modify") return t("可能修改系统");
  return t("只读核查");
}

function extractCommands(steps: string[]): string[] {
  const commands: string[] = [];
  for (const step of steps) {
    const inlineCommands = [...step.matchAll(/`([^`\n]+)`/g)].map((m) => m[1].trim()).filter(Boolean);
    const runnableInlineCommands = inlineCommands.map(toRunnableCommand).filter(Boolean);
    if (runnableInlineCommands.length) {
      commands.push(...runnableInlineCommands);
      continue;
    }
    const lines = step
      .split(/\n+/)
      .map((line) => line.trim().replace(/^[-*]\s*/, "").replace(/^\d+[.)]\s*/, ""))
      .filter(Boolean);
    for (const line of lines) {
      const runnable = toRunnableCommand(line);
      if (runnable) commands.push(runnable);
    }
  }
  return [...new Set(commands)];
}

type ScoredCommand = {
  text: string;
  risk: "read" | "modify" | "danger";
  label: string;
  invalidReason?: string;
};

function scoreCommand(text: string): ScoredCommand {
  const invalidReason = commandVariableIssue(text);
  const lower = text.toLowerCase();
  const dangerous = /\b(rm\s+-rf|mkfs|dd\s+|shutdown|reboot|pfctl\s+-f|iptables\s+-f|nft\s+flush|taskkill\b|stop-process\b|remove-item\b|del\s+\/f|format\b)\b/.test(lower);
  const modifying = dangerous || /\b(sudo\s+)?(rm|mv|cp|chmod|chown|kill|pkill|launchctl\s+(bootout|remove|unload)|systemctl\s+(stop|disable|restart)|pfctl\s+(-e|-d|-F|-f)|iptables|nft|ufw|firewall-cmd|new-netfirewallrule|sc\s+(stop|delete)|net\s+stop)\b/i.test(text);
  if (dangerous) return { text, risk: "danger", label: t("危险操作"), invalidReason };
  if (modifying) return { text, risk: "modify", label: t("可能修改系统"), invalidReason };
  return { text, risk: "read", label: t("只读核查"), invalidReason };
}

function commandVariableIssue(text: string): string | undefined {
  const lower = text.toLowerCase();
  if (/<\s*(pid|port|ip|host|hostname|server|user|username|path|file)\s*>/i.test(text)) return t("缺少变量");
  if (/\byour[_-]?(server|ip|host)\b/.test(lower) || /\bexample\.(com|org|net)\b/.test(lower) || /\b1\.2\.3\.4\b/.test(lower)) return t("示例值不可复制");
  if (/\b(kill|taskkill|stop-process|get-process)\b.*\bpid\b/i.test(text) && !/\$|[0-9]/.test(text)) return t("缺少 PID");
  if (/(localport|:|port)\s*(<port>|port)\b/i.test(text)) return t("缺少端口");
  return undefined;
}

function toRunnableCommand(value: string): string {
  const text = value.trim();
  if (!text) return "";
  if (isBareLogPath(text)) return `sudo cat ${quoteShellArg(text)}`;
  if (isBareFilePath(text)) return "";
  return looksLikeCommand(text) ? text : "";
}

function isBareFilePath(value: string): boolean {
  return /^\/[A-Za-z0-9._/@%+=:,~-]+$/.test(value) || /^[A-Za-z]:\\[^<>:"|?*]+$/i.test(value);
}

function isBareLogPath(value: string): boolean {
  return /^\/var\/log\/[A-Za-z0-9._/@%+=:,~-]+$/.test(value);
}

function quoteShellArg(value: string): string {
  return /^[A-Za-z0-9._/@%+=:,~-]+$/.test(value) ? value : `'${value.replace(/'/g, "'\\''")}'`;
}

function looksLikeCommand(value: string): boolean {
  return /^(sudo|curl|wget|systemctl|launchctl|netstat|lsof|ss|ps|grep|awk|sed|find|chmod|chown|rm|mv|cp|kill|pkill|taskkill|sc|net|powershell|Get-|Set-|Stop-|Remove-|Test-NetConnection|Get-Process)\b/i.test(value);
}

async function copyLines(lines: string[], okText: string, numbered = false) {
  const text = (numbered ? lines.map((s, i) => `${i + 1}. ${s}`) : lines).join("\n");
  await copyText(text, okText);
}

async function copyCommand(cmd: ScoredCommand) {
  if (cmd.invalidReason) {
    message.warning(cmd.invalidReason);
    return;
  }
  if (cmd.risk === "danger") {
    Modal.confirm({
      title: t("确认复制危险命令"),
      content: t("该命令可能终止进程、删除文件或修改防火墙，请确认对象无误后再执行。"),
      okText: t("确认复制"),
      cancelText: t("取消"),
      okButtonProps: { danger: true },
      onOk: () => copyText(cmd.text, t("已复制命令")),
    });
    return;
  }
  await copyText(cmd.text, t("已复制命令"));
}

async function copyCommands(cmds: ScoredCommand[]) {
  const dangerous = cmds.some((cmd) => cmd.risk === "danger");
  const run = () => copyText(cmds.map((cmd) => cmd.text).join("\n"), t("已复制命令"));
  if (dangerous) {
    Modal.confirm({
      title: t("确认复制包含危险操作的命令"),
      content: t("命令列表包含可能修改系统的操作，请先确认每条命令的目标对象。"),
      okText: t("确认复制"),
      cancelText: t("取消"),
      okButtonProps: { danger: true },
      onOk: run,
    });
    return;
  }
  await run();
}

async function copyText(text: string, okText: string) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      fallbackCopyText(text);
    }
    message.success(okText);
  } catch {
    try {
      fallbackCopyText(text);
      message.success(okText);
    } catch {
      message.error(t("复制失败，请手动选中复制"));
    }
  }
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

function DebugBlock({ title, text }: { title: string; text: string }) {
  return (
    <div>
      <div className="section-title" style={{ margin: "0 0 6px" }}>{title}</div>
      <pre style={{ margin: 0, maxHeight: 220, overflow: "auto", fontSize: 12, lineHeight: 1.6, background: "hsl(var(--secondary) / 0.6)", border: "1px solid hsl(var(--border))", borderRadius: 8, padding: "10px 12px", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
        {text}
      </pre>
    </div>
  );
}
