#!/usr/bin/env node
// Construction du site de présentation ILL Watch (ADR-027) : Node seul, aucune dépendance.
//   node Website/build.mjs            → Website/dist/
// Variables : ILLWATCH_SITE_URL, ILLWATCH_SITE_BASE, ILLWATCH_SITE_GEO_ENDPOINT,
// ILLWATCH_SITE_COUNTRY, ILLWATCH_SITE_DEFAULT_LANG (src/config.mjs).
// La construction échoue (code 1) si une traduction manque, si une page contient du style ou
// du script en ligne, une ressource tierce, un lien interne cassé, ou dépasse le budget de poids.
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BASE,
  DEFAULT_LANG,
  DEMO_ENDPOINT,
  GEO_ENDPOINT,
  HOME_BUDGET,
  INSTANCE_COUNTRY,
  INSTANCE_LANG,
  LANGS,
  LINKS,
  REFERENCE_LANG,
  SITE_URL,
} from "./src/config.mjs";
import { PAGES } from "./src/pages.mjs";
import { esc, homePage, notFoundPage, rootPage } from "./src/templates.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "src");
const dist = join(here, "dist");
const brand = join(here, "..", "docs", "assets"); // source unique des fichiers de marque (ADR-018)
const problems = [];

// ── Dictionnaires ────────────────────────────────────────────────────────────────────────
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const dictionaries = Object.fromEntries(LANGS.map((l) => [l.code, readJson(join(src, "i18n", `${l.code}.json`))]));
const facts = readJson(join(src, "data", "facts.json"));
const countryLanguages = readJson(join(src, "data", "country-languages.json")).countries;
const legal = readJson(join(src, "data", "legal.json"));
const legalMissing = legal.required.filter((key) => !String(legal[key] || "").trim());
const PUBLIC = process.env.ILLWATCH_SITE_PUBLIC === "1";
if (legalMissing.length) {
  const message = `mentions légales incomplètes (src/data/legal.json) : ${legalMissing.join(", ")}`;
  if (PUBLIC) problems.push(`${message} — publication publique refusée`);
  else console.warn(`⚠ ${message} (pages légales marquées noindex)`);
}

// Formulaire de démonstration : adresse de l'API (même origine ou absolue en HTTPS).
let demoEndpoint = "";
const connect = [];
if (DEMO_ENDPOINT) {
  if (DEMO_ENDPOINT.startsWith("/")) demoEndpoint = DEMO_ENDPOINT;
  else if (/^https:\/\/[^/]+\//.test(DEMO_ENDPOINT)) {
    demoEndpoint = DEMO_ENDPOINT;
    connect.push(new URL(DEMO_ENDPOINT).origin);
  } else problems.push(`ILLWATCH_SITE_DEMO_ENDPOINT invalide (chemin « /… » ou https://…) : ${DEMO_ENDPOINT}`);
}

// Langue de l'instance : explicite, sinon celle du pays de l'instance.
const supportedCodes = LANGS.map((l) => l.code);
if (INSTANCE_LANG && !supportedCodes.includes(INSTANCE_LANG)) {
  problems.push(`ILLWATCH_SITE_DEFAULT_LANG inconnue : ${INSTANCE_LANG}`);
}
if (INSTANCE_COUNTRY && !/^[A-Z]{2}$/.test(INSTANCE_COUNTRY)) {
  problems.push(`ILLWATCH_SITE_COUNTRY invalide (ISO alpha-2 attendu) : ${INSTANCE_COUNTRY}`);
}
const instanceLang = supportedCodes.includes(INSTANCE_LANG)
  ? INSTANCE_LANG
  : (countryLanguages[INSTANCE_COUNTRY] || [])[0] || "";

function flatten(object, prefix = "") {
  return Object.entries(object).flatMap(([key, value]) =>
    value && typeof value === "object" ? flatten(value, `${prefix}${key}.`) : [[`${prefix}${key}`, value]],
  );
}
const placeholders = (text) => [...String(text).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");

const reference = new Map(flatten(dictionaries[REFERENCE_LANG]));
for (const { code } of LANGS) {
  const entries = new Map(flatten(dictionaries[code]));
  for (const [key, value] of reference) {
    if (!entries.has(key)) problems.push(`[${code}] clé manquante : ${key}`);
    else if (!String(entries.get(key)).trim()) problems.push(`[${code}] traduction vide : ${key}`);
    else if (placeholders(entries.get(key)) !== placeholders(value)) problems.push(`[${code}] variables différentes : ${key}`);
  }
  for (const key of entries.keys()) if (!reference.has(key)) problems.push(`[${code}] clé inconnue : ${key}`);
}

// Typographie française : espace fine insécable avant « ; : ! ? % » et dans les guillemets.
function frenchTypography(text) {
  return text
    .replace(/ ([;:!?%»])/g, " $1")
    .replace(/« /g, "« ")
    .replace(/(\d) (h|j|Mo|s)\b/g, "$1 $2");
}

function translator(code) {
  const flat = new Map(flatten(dictionaries[code]));
  return (key, vars = {}, escape = true) => {
    if (!flat.has(key)) {
      problems.push(`[${code}] clé utilisée mais absente : ${key}`);
      return key;
    }
    let text = String(flat.get(key)).replace(/\{(\w+)\}/g, (_, name) => {
      if (!(name in vars)) problems.push(`[${code}] variable non fournie : {${name}} dans ${key}`);
      return name in vars ? String(vars[name]) : `{${name}}`;
    });
    if (code === "fr") text = frenchTypography(text);
    return escape ? esc(text) : text;
  };
}

// ── Pages ────────────────────────────────────────────────────────────────────────────────
rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, "assets"), { recursive: true });

const site = { url: SITE_URL, langs: LANGS, links: LINKS, geo: GEO_ENDPOINT, defaultLang: DEFAULT_LANG, instanceLang, connect, demoEndpoint };
const asset = (path) => `${BASE}assets/${path}`;
const write = (path, content) => {
  mkdirSync(dirname(join(dist, path)), { recursive: true });
  writeFileSync(join(dist, path), content);
};

for (const lang of LANGS) {
  const number = new Intl.NumberFormat(lang.locale, { maximumFractionDigits: 2 });
  const percent = new Intl.NumberFormat(lang.locale, { style: "percent", maximumFractionDigits: 0 });
  const dateFormat = new Intl.DateTimeFormat(lang.locale, { dateStyle: "long", timeZone: "UTC" });
  const ctx = {
    lang,
    path: "",
    legal,
    legalComplete: legalMissing.length === 0,
    site,
    base: BASE,
    asset,
    facts: { ...facts, memory_mb: facts.memory_mb.value },
    t: translator(lang.code),
    n: (value) => number.format(value),
    pct: (value) => percent.format(value),
    date: (iso) => esc(dateFormat.format(new Date(`${iso}T00:00:00Z`))),
  };
  write(`${lang.code}/index.html`, homePage(ctx));
  for (const [slug, render] of PAGES) write(`${lang.code}/${slug}index.html`, render({ ...ctx, path: slug }));
}

const neutral = { site, base: BASE, asset, lang: null, path: "" };
write("index.html", rootPage(neutral, dictionaries));
write("404.html", notFoundPage(neutral, dictionaries));

write("robots.txt", `User-agent: *\nAllow: /\nSitemap: ${SITE_URL}${BASE}sitemap.xml\n`);
const SLUGS = ["", ...PAGES.map(([slug]) => slug).filter((slug) => !["legal/", "privacy/"].includes(slug))];
write(
  "sitemap.xml",
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${SLUGS.flatMap((slug) => {
    const alternates = LANGS.map((l) => `<xhtml:link rel="alternate" hreflang="${l.html}" href="${SITE_URL}${BASE}${l.code}/${slug}"/>`).join("");
    return LANGS.map(
      (l) => `  <url><loc>${SITE_URL}${BASE}${l.code}/${slug}</loc>${alternates}<xhtml:link rel="alternate" hreflang="x-default" href="${SITE_URL}${BASE}"/></url>`,
    );
  }).join("\n")}\n</urlset>\n`,
);

// ── Ressources ───────────────────────────────────────────────────────────────────────────
cpSync(join(src, "assets", "site.css"), join(dist, "assets", "site.css"));
cpSync(join(src, "assets", "js"), join(dist, "assets", "js"), { recursive: true });
// Table pays → langues de l'API (copie vérifiée par tests/test_locale.py), en module.
writeFileSync(
  join(dist, "assets", "js", "countries.js"),
  `// Généré par build.mjs depuis src/data/country-languages.json : ne pas modifier.\nexport const COUNTRY_LANGUAGES = ${JSON.stringify(countryLanguages)};\n`,
);
cpSync(join(src, "static", "img"), join(dist, "assets", "img"), { recursive: true });
for (const file of ["illwatch-logo-endorsed-dark.svg", "illwatch-mark.svg", "favicon.svg"]) {
  cpSync(join(brand, file), join(dist, "assets", "img", file));
}

// ── Contrôles ────────────────────────────────────────────────────────────────────────────
const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });

const pages = walk(dist).filter((p) => p.endsWith(".html"));
for (const page of pages) {
  const html = readFileSync(page, "utf8");
  const name = relative(dist, page);
  for (const bad of ["NaN", "undefined", "[object Object]"]) {
    if (html.includes(bad)) problems.push(`${name} : « ${bad} » dans la page (donnée manquante)`);
  }
  if (/\sstyle\s*=/.test(html)) problems.push(`${name} : attribut style en ligne (interdit par la CSP)`);
  if (/<style[\s>]/.test(html)) problems.push(`${name} : balise <style> (interdite par la CSP)`);
  for (const m of html.matchAll(/<script\b([^>]*)>/g)) {
    if (!/\bsrc=/.test(m[1])) problems.push(`${name} : script en ligne (interdit par la CSP)`);
  }
  if (/\son[a-z]+\s*=/.test(html)) problems.push(`${name} : gestionnaire d'évènement en ligne`);
  for (const m of html.matchAll(/<(?:script|img|link|source)\b[^>]*?\s(?:src|href|srcset)="([^"]+)"/g)) {
    const tag = m[0];
    if (/rel="(?:alternate|canonical)"/.test(tag)) continue;
    for (const url of m[1].split(",").map((s) => s.trim().split(/\s+/)[0])) {
      if (/^https?:/.test(url)) problems.push(`${name} : ressource tierce ${url}`);
    }
  }
  for (const m of html.matchAll(/\s(?:href|src|srcset)="([^"]+)"/g)) {
    for (const url of m[1].split(",").map((s) => s.trim().split(/\s+/)[0])) {
      if (!url.startsWith(BASE) || url.startsWith("//")) continue;
      const target = url.slice(BASE.length).split("#")[0];
      const file = target === "" || target.endsWith("/") ? join(dist, target, "index.html") : join(dist, target);
      if (!existsSync(file)) problems.push(`${name} : lien interne cassé ${url}`);
    }
  }
  for (const m of html.matchAll(/href="#([^"]+)"/g)) {
    if (!html.includes(`id="${m[1]}"`)) problems.push(`${name} : ancre absente #${m[1]}`);
  }
}

// Budget de l'accueil : HTML + CSS + JS + image principale (version grand écran).
for (const lang of LANGS) {
  const home = join(dist, lang.code, "index.html");
  const html = readFileSync(home, "utf8");
  let bytes = statSync(home).size + statSync(join(dist, "assets", "site.css")).size;
  for (const m of html.matchAll(/<script[^>]*src="([^"]+)"/g)) bytes += statSync(join(dist, m[1].slice(BASE.length))).size;
  for (const file of ["lang.js", "score.js"]) bytes += statSync(join(dist, "assets", "js", file)).size;
  bytes += statSync(join(dist, "assets", "img", "screens", "01-vue-ensemble.webp")).size;
  if (bytes > HOME_BUDGET) problems.push(`${lang.code}/ : accueil de ${Math.round(bytes / 1024)} Ko > budget ${HOME_BUDGET / 1024} Ko`);
  else console.log(`  ${lang.code}/  accueil ${Math.round(bytes / 1024)} Ko (budget ${HOME_BUDGET / 1024} Ko)`);
}

if (problems.length) {
  console.error(`\n✘ ${problems.length} problème(s) :\n  - ${problems.join("\n  - ")}`);
  process.exit(1);
}
console.log(`✔ Site construit : ${pages.length} pages, ${LANGS.length} langues → ${relative(process.cwd(), dist) || "."}`);
