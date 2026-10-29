// Formats d'affichage selon la langue courante (ADR-027) : nombres, dates courtes, durées.
// L'heure reste sur 24 h dans toutes les langues (convention des centres de veille).
import { currentLocale } from "../i18n/core.js";
import { labels } from "./labels.i18n.js";

const numberFormats = new Map<string, Intl.NumberFormat>();
function numberFormat(maximumFractionDigits = 0): Intl.NumberFormat {
  const key = `${currentLocale()}|${maximumFractionDigits}`;
  let format = numberFormats.get(key);
  if (!format) {
    format = new Intl.NumberFormat(currentLocale(), { maximumFractionDigits });
    numberFormats.set(key, format);
  }
  return format;
}

export function formatNumber(value: number | null | undefined): string {
  return value === null || value === undefined ? "-" : numberFormat(3).format(value);
}

/** Nombre à une décimale au plus, séparateur de la langue (« 3,5 », « 3.5 »). */
export function formatDecimal(value: number, digits = 1): string {
  return numberFormat(digits).format(value);
}

const pad = (n: number) => String(n).padStart(2, "0");

/** Heure HH:MM(:SS), en UTC ou en heure locale. */
export function formatTime(date: Date, utc: boolean, seconds = false): string {
  const h = utc ? date.getUTCHours() : date.getHours();
  const m = utc ? date.getUTCMinutes() : date.getMinutes();
  const s = utc ? date.getUTCSeconds() : date.getSeconds();
  return seconds ? `${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(h)}:${pad(m)}`;
}

const dayFormats = new Map<string, Intl.DateTimeFormat>();

/** Date courte jour et mois dans l'ordre de la langue (« 10/10 », « 10.10. »), UTC ou locale. */
export function formatDay(date: Date, utc: boolean): string {
  const key = `${currentLocale()}|${utc}`;
  let format = dayFormats.get(key);
  if (!format) {
    format = new Intl.DateTimeFormat(currentLocale(), {
      day: "2-digit",
      month: "2-digit",
      timeZone: utc ? "UTC" : undefined,
    });
    dayFormats.set(key, format);
  }
  return format.format(date);
}

export function formatDateTime(date: Date, utc: boolean): string {
  return `${formatDay(date, utc)} ${formatTime(date, utc)}${utc ? " UTC" : ""}`;
}

/** Ancienneté lisible : « à l'instant », « 4 min », « 2 h », « 3 j » (espace insécable : le
 * nombre et son unité ne sont jamais séparés par un retour à la ligne). */
export function formatAge(date: Date, now: Date = new Date()): string {
  const seconds = Math.max(0, Math.round((now.getTime() - date.getTime()) / 1000));
  if (seconds < 60) return labels("time.now");
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return labels("unit.min", { n: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return labels("unit.h", { n: hours });
  return labels("unit.d", { n: Math.floor(hours / 24) });
}

/** Ancienneté en phrase : « il y a 4 min », mais « à l'instant » (jamais « il y a à l'instant »). */
export function formatAgo(date: Date, now: Date = new Date()): string {
  const age = formatAge(date, now);
  return age === labels("time.now") ? age : labels("time.ago", { age });
}

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Durée en heures, lisible : « 45 min », « 3,5 h », « 2,1 j » ; « - » si inconnue. */
export function formatHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined || Number.isNaN(hours)) return "-";
  if (hours < 1) return labels("unit.min", { n: Math.max(1, Math.round(hours * 60)) });
  if (hours < 48) return labels("unit.h", { n: formatDecimal(Math.round(hours * 10) / 10) });
  return labels("unit.d", { n: formatDecimal(Math.round((hours / 24) * 10) / 10) });
}

/** Part (0-1) en pourcentage entier : « 83 % » ; « - » si inconnue. */
export function formatShare(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  return labels("unit.percent", { n: Math.round(value * 100) });
}
