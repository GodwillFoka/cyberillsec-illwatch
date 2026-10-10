// Barres empilées par niveau (P0–P3) d'une série temporelle. ECharts est importé module par
// module : seul le nécessaire entre dans le paquet.
import { BarChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import type { Series } from "../api/types";
import { formatDay, formatTime, parseDate } from "../lib/format";
import { PRIORITY_ORDER, SEVERITY_ORDER, TONE_COLORS, levelLabel, toneOf } from "../lib/levels";

echarts.use([BarChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

const escapeHtml = (text: string) =>
  text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);

interface TooltipItem {
  axisValueLabel?: string;
  seriesName?: string;
  seriesIndex?: number;
  value?: unknown;
}

function tooltipHtml(raw: unknown, tones: string[]): string {
  const items = (Array.isArray(raw) ? raw : [raw]) as TooltipItem[];
  const title = escapeHtml(String(items[0]?.axisValueLabel ?? ""));
  const rows = items
    .filter((item) => Number(item.value) > 0)
    .map(
      (item) =>
        `<div class="tt-row"><span class="tt-dot ${tones[item.seriesIndex ?? 0] ?? "p3"}"></span>` +
        `<span>${escapeHtml(String(item.seriesName ?? ""))}</span><b>${Number(item.value)}</b></div>`,
    );
  return `<div class="tt-title">${title}</div>${rows.join("") || '<div class="tt-row">Aucun</div>'}`;
}

export function SeriesChart({ series, utc }: { series: Series; utc: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const chart = useRef<ReturnType<typeof echarts.init> | null>(null);

  useEffect(() => {
    if (!host.current) return;
    const instance = echarts.init(host.current, undefined, { renderer: "canvas" });
    chart.current = instance;
    const observer = new ResizeObserver(() => instance.resize());
    observer.observe(host.current);
    return () => {
      observer.disconnect();
      instance.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    const instance = chart.current;
    if (!instance) return;
    const order = series.metric === "alerts" ? PRIORITY_ORDER : SEVERITY_ORDER;
    const tones = order.map((level) => toneOf(level));
    const labels = series.points.map((point) => {
      const date = parseDate(point.at) ?? new Date(0);
      return series.bucket === "hour" ? formatTime(date, utc) : formatDay(date, utc);
    });
    instance.setOption(
      {
        animationDuration: 250,
        textStyle: { fontFamily: "Inter, sans-serif", color: "#A3ACBF" },
        grid: { left: 8, right: 8, top: 32, bottom: 8, containLabel: true },
        legend: {
          top: 0,
          right: 0,
          itemWidth: 10,
          itemHeight: 10,
          textStyle: { color: "#A3ACBF" },
        },
        tooltip: {
          trigger: "axis",
          axisPointer: { type: "shadow" },
          backgroundColor: "#0F1626",
          borderColor: "#222C42",
          textStyle: { color: "#ECEFF5" },
          // Contenu en classes CSS uniquement : la politique `style-src 'self'` de l'interface
          // refuse les attributs style que l'infobulle par défaut d'ECharts insère.
          formatter: (raw: unknown) => tooltipHtml(raw, tones),
        },
        xAxis: {
          type: "category",
          data: labels,
          axisLine: { lineStyle: { color: "#222C42" } },
          axisTick: { show: false },
          axisLabel: { color: "#A3ACBF", hideOverlap: true },
        },
        yAxis: {
          type: "value",
          minInterval: 1,
          splitLine: { lineStyle: { color: "#1A2236" } }, // grille : plus discrète que --line
          axisLabel: { color: "#A3ACBF" },
        },
        series: order.map((level) => ({
          name: levelLabel(level),
          type: "bar",
          stack: "total",
          barMaxWidth: 18,
          itemStyle: { color: TONE_COLORS[toneOf(level)] },
          emphasis: { focus: "series" },
          data: series.points.map((point) => point.by_level[level] ?? 0),
        })),
      },
      { notMerge: true },
    );
  }, [series, utc]);

  return (
    <div
      ref={host}
      className="chart"
      role="img"
      aria-label={`Évolution sur ${series.window} : ${series.total} au total`}
    />
  );
}
