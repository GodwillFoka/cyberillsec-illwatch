const numberFormat = new Intl.NumberFormat("fr-FR");

export function formatNumber(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : numberFormat.format(value);
}

const pad = (n: number) => String(n).padStart(2, "0");

/** Heure HH:MM(:SS), en UTC ou en heure locale. */
export function formatTime(date: Date, utc: boolean, seconds = false): string {
  const h = utc ? date.getUTCHours() : date.getHours();
  const m = utc ? date.getUTCMinutes() : date.getMinutes();
  const s = utc ? date.getUTCSeconds() : date.getSeconds();
  return seconds ? `${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(h)}:${pad(m)}`;
}

/** Date courte JJ/MM, en UTC ou en heure locale. */
export function formatDay(date: Date, utc: boolean): string {
  const d = utc ? date.getUTCDate() : date.getDate();
  const m = (utc ? date.getUTCMonth() : date.getMonth()) + 1;
  return `${pad(d)}/${pad(m)}`;
}

export function formatDateTime(date: Date, utc: boolean): string {
  return `${formatDay(date, utc)} ${formatTime(date, utc)}${utc ? " UTC" : ""}`;
}

/** Ancienneté lisible : « à l'instant », « 4 min », « 2 h », « 3 j ». */
export function formatAge(date: Date, now: Date = new Date()): string {
  const seconds = Math.max(0, Math.round((now.getTime() - date.getTime()) / 1000));
  if (seconds < 60) return "à l'instant";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h`;
  return `${Math.floor(hours / 24)} j`;
}

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}
