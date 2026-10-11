// Barres empilées par niveau (P0–P3) d'une série temporelle. ECharts est importé module par
// module : seul le nécessaire entre dans le paquet.
import { BarChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import type { Series } from "../api/types";
import { formatDay, formatTime, parseDate } from "../lib/format";
import { CHART, PRIORITY_ORDER, SEVERITY_ORDER, TONE_COLORS, levelLabel, toneOf } from "../lib/levels";

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
    const last = order.length - 1;
    instance.setOption(
      {
        animationDuration: 300,
        animationEasing: "cubicOut",
        textStyle: { fontFamily: CHART.font, color: CHART.text },
        grid: { left: 4, right: 4, top: 36, bottom: 4, containLabel: true },
        legend: {
          top: 0,
          left: 0,
          icon: "roundRect",
          itemWidth: 10,
          itemHeight: 10,
          itemGap: 16,
          textStyle: { color: CHART.text, fontSize: 12 },
        },
        tooltip: {
          trigger: "axis",
          axisPointer: { type: "shadow", shadowStyle: { color: "rgba(142, 128, 255, 0.08)" } },
          backgroundColor: CHART.panel,
          borderColor: CHART.line,
          borderWidth: 1,
          padding: [10, 12],
          textStyle: { color: CHART.strong, fontFamily: CHART.font, fontSize: 12 },
          // Contenu en classes CSS uniquement : la politique `style-src 'self'` de l'interface
          // refuse les attributs style que l'infobulle par défaut d'ECharts insère.
          formatter: (raw: unknown) => tooltipHtml(raw, tones),
        },
        xAxis: {
          type: "category",
          data: labels,
          axisLine: { lineStyle: { color: CHART.line } },
          axisTick: { show: false },
          axisLabel: { color: CHART.text, hideOverlap: true, fontSize: 11, margin: 10 },
        },
        yAxis: {
          type: "value",
          minInterval: 1,
          splitNumber: 4,
          splitLine: { lineStyle: { color: CHART.grid } },
          axisLabel: { color: CHART.text, fontSize: 11 },
        },
        series: order.map((level, index) => ({
          name: levelLabel(level),
          type: "bar",
          stack: "total",
          barMaxWidth: 16,
          barCategoryGap: "38%",
          // Seul le haut de la pile est arrondi : la barre se lit comme un seul total.
          itemStyle: {
            color: TONE_COLORS[toneOf(level)],
            borderRadius: index === last ? [3, 3, 0, 0] : 0,
          },
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
