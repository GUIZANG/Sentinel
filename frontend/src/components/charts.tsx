import ReactECharts from "echarts-for-react";
import type { Summary } from "../api";
import { t } from "../i18n";
import { formatTopRuleLabel } from "../ai/topRules";

// shadcn zinc 浅色主题配色
const AXIS = "#71717a"; // muted-foreground (zinc-500)
const SPLIT = "#e4e4e7"; // border (zinc-200)
const FG = "#18181b"; // foreground (zinc-900)
const PRIMARY = "#18181b";
const TRACK = "#f4f4f5"; // secondary (zinc-100)

// 语义状态色
const SEV = { low: "#64748b", medium: "#f59e0b", high: "#f97316", critical: "#dc2626" };
// shadcn 图表调色板（chart-1..5）
const CHART = ["#e76e50", "#2a9d90", "#274754", "#e8c468", "#f4a462"];

export function RiskGauge({ score }: { score: number }) {
  const color = score >= 70 ? SEV.critical : score >= 45 ? SEV.high : score >= 25 ? SEV.medium : "#16a34a";
  const option = {
    series: [
      {
        type: "gauge",
        startAngle: 210,
        endAngle: -30,
        min: 0,
        max: 100,
        radius: "100%",
        center: ["50%", "58%"],
        progress: { show: true, width: 14, roundCap: true, itemStyle: { color } },
        axisLine: { lineStyle: { width: 14, color: [[1, TRACK]] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        pointer: { show: false },
        anchor: { show: false },
        detail: {
          valueAnimation: true,
          offsetCenter: [0, "0%"],
          fontSize: 44,
          fontWeight: 800,
          color: FG,
          formatter: "{value}",
        },
        title: { offsetCenter: [0, "32%"], color: AXIS, fontSize: 12 },
        data: [{ value: score, name: t("风险指数 / 100") }],
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: 220 }} />;
}

export function SeverityDonut({ s }: { s: Summary }) {
  const sev = s.alerts.by_severity;
  const data = [
    { name: t("低危"), value: sev.low || 0, itemStyle: { color: SEV.low } },
    { name: t("中危"), value: sev.medium || 0, itemStyle: { color: SEV.medium } },
    { name: t("高危"), value: sev.high || 0, itemStyle: { color: SEV.high } },
    { name: t("严重"), value: sev.critical || 0, itemStyle: { color: SEV.critical } },
  ];
  const option = {
    tooltip: { trigger: "item" },
    legend: { bottom: 0, textStyle: { color: AXIS }, icon: "circle" },
    series: [
      {
        type: "pie",
        radius: ["55%", "78%"],
        center: ["50%", "44%"],
        avoidLabelOverlap: false,
        itemStyle: { borderColor: "#ffffff", borderWidth: 2 },
        label: { show: true, position: "center", formatter: () => `${s.alerts.total}\n${t("告警")}`, color: FG, fontSize: 16, fontWeight: 700, lineHeight: 20 },
        labelLine: { show: false },
        data,
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: 240 }} />;
}

export function OsDistribution({ s }: { s: Summary }) {
  const map: Record<string, string> = { darwin: "macOS", windows: "Windows", linux: "Linux", unknown: t("其他") };
  const data = Object.entries(s.endpoints.by_os).map(([k, v]) => ({ name: map[k] || k, value: v }));
  const option = {
    tooltip: { trigger: "item" },
    legend: { bottom: 0, textStyle: { color: AXIS }, icon: "circle" },
    series: [
      {
        type: "pie",
        roseType: "radius",
        radius: ["35%", "72%"],
        center: ["50%", "44%"],
        itemStyle: { borderRadius: 6, borderColor: "#ffffff", borderWidth: 2 },
        label: { color: AXIS },
        data: data.map((d, i) => ({ ...d, itemStyle: { color: CHART[i % CHART.length] } })),
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: 240 }} />;
}

export function TrendChart({ trend }: { trend: { time: string; risk_score: number; alerts_high: number }[] }) {
  const hourly = trend.length > 0 && trend.length <= 30 && trend.some((d) => new Date(d.time).getHours() !== 0);
  const x = trend.map((d) => {
    const date = new Date(d.time);
    return hourly
      ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
      : date.toLocaleDateString(undefined, { month: "numeric", day: "numeric" });
  });
  const option = {
    grid: { left: 40, right: 16, top: 30, bottom: 28 },
    tooltip: { trigger: "axis" },
    legend: { data: [t("风险指数"), t("高危告警")], textStyle: { color: AXIS }, right: 0 },
    xAxis: { type: "category", data: x, axisLine: { lineStyle: { color: SPLIT } }, axisLabel: { color: AXIS } },
    yAxis: [
      { type: "value", splitLine: { lineStyle: { color: SPLIT } }, axisLabel: { color: AXIS } },
    ],
    series: [
      {
        name: t("风险指数"),
        type: "line",
        smooth: true,
        symbol: "circle",
        data: trend.map((t) => t.risk_score),
        lineStyle: { width: 2.5, color: PRIMARY },
        itemStyle: { color: PRIMARY },
        areaStyle: { color: "rgba(24,24,27,0.06)" },
      },
      {
        name: t("高危告警"),
        type: "bar",
        data: trend.map((t) => t.alerts_high),
        barWidth: 10,
        itemStyle: { color: SEV.high, borderRadius: [4, 4, 0, 0] },
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: 300 }} />;
}

export function TopRulesBar({ s }: { s: Summary }) {
  const entries = Object.entries(s.alerts.top_rules).sort((a, b) => b[1] - a[1]).slice(0, 6).reverse();
  const labels = entries.map((e) => formatTopRuleLabel(e[0]));
  const option = {
    grid: { left: 8, right: 24, top: 10, bottom: 10, containLabel: true },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params: any) => {
        const p = Array.isArray(params) ? params[0] : params;
        return `${p?.axisValue || ""}<br/>${t("触发次数")}：${p?.value ?? 0}`;
      },
    },
    xAxis: { type: "value", splitLine: { lineStyle: { color: SPLIT } }, axisLabel: { color: AXIS } },
    yAxis: { type: "category", data: labels, axisLabel: { color: FG, width: 160, overflow: "truncate" }, axisLine: { lineStyle: { color: SPLIT } } },
    series: [
      {
        name: t("触发次数"),
        type: "bar",
        data: entries.map((e) => e[1]),
        barWidth: 14,
        itemStyle: { borderRadius: [0, 6, 6, 0], color: PRIMARY },
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: 240 }} />;
}
