// Gabarits HTML du site (ADR-027). Aucun style ni script en ligne : la CSP est
// « style-src 'self'; script-src 'self' », vérifiée à chaque construction.
import { computeRisk } from "./assets/js/score.js";

export const esc = (value) =>
  String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const ICONS = {
  feeds: '<circle cx="6" cy="18" r="2"/><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/>',
  cve: '<path d="M12 3 4 6v6c0 4.5 3.4 8.2 8 9 4.6-.8 8-4.5 8-9V6z"/><path d="M12 8v5"/><path d="M12 16.5v.01"/>',
  corr: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="9" r="2.5"/><circle cx="9" cy="18" r="2.5"/><path d="M8.3 7 15.6 8.4"/><path d="m16.5 11-5.8 5"/><path d="M6.6 8.4 8.4 15.5"/>',
  soc: '<path d="M12 4 2.5 20h19z"/><path d="M12 10v4"/><path d="M12 17v.01"/>',
  hunt: '<circle cx="12" cy="12" r="7"/><path d="M12 2v4"/><path d="M12 18v4"/><path d="M2 12h4"/><path d="M18 12h4"/><circle cx="12" cy="12" r="1.5"/>',
  intel: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  obs: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  open: '<path d="m8 8-5 4 5 4"/><path d="m16 8 5 4-5 4"/><path d="m14 5-4 14"/>',
  ci: '<path d="M4 12.5 9 17 20 6"/>',
  real: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18"/><path d="M8 3v4"/><path d="M16 3v4"/>',
  scan: '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 5 5"/>',
  self: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01"/><path d="M8 16.5h.01"/>',
  light: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
  menu: '<path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h16"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9S9.5 5.5 12 3z"/>',
  external: '<path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
  code: '<path d="m8 8-5 4 5 4"/><path d="m16 8 5 4-5 4"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18 14.2a6.5 6.5 0 0 1 3.5 5.8"/>',
  shield: '<path d="M12 3 4 6v6c0 4.5 3.4 8.2 8 9 4.6-.8 8-4.5 8-9V6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 16 9 5 9-5"/>',
  building: '<path d="M4 21V5l8-3v19"/><path d="M12 8h8v13"/><path d="M2 21h20"/><path d="M8 8v.01"/><path d="M8 12v.01"/><path d="M8 16v.01"/><path d="M16 12v.01"/><path d="M16 16v.01"/>',
};

export const icon = (name, cls = "icon") =>
  `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;

function head(ctx, { title, description, path, alternates = true }) {
  const { lang, site, base, asset } = ctx;
  const links = alternates
    ? site.langs
        .map((l) => `<link rel="alternate" hreflang="${l.html}" href="${site.url}${base}${l.code}/${path}">`)
        .join("\n    ") + `\n    <link rel="alternate" hreflang="x-default" href="${site.url}${base}">`
    : "";
  return `<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <meta name="color-scheme" content="dark">
    <meta name="theme-color" content="#0a0e1a">
    <title>${esc(title)}</title>
    <meta name="description" content="${esc(description)}">
    ${lang ? `<link rel="canonical" href="${site.url}${base}${lang.code}/${path}">` : ""}
    ${links}
    <meta property="og:type" content="website">
    <meta property="og:title" content="${esc(title)}">
    <meta property="og:description" content="${esc(description)}">
    <meta property="og:image" content="${site.url}${asset("img/screens/01-vue-ensemble.webp")}">
    <link rel="icon" href="${asset("img/favicon.svg")}" type="image/svg+xml">
    <link rel="stylesheet" href="${asset("site.css")}">
  </head>`;
}

// ── Contenu de l'accueil ────────────────────────────────────────────────────────────────
// Page de vente inspirée de github.com/home et about.gitlab.com : héros animé, bandeau des
// standards, fonctionnalités en onglets avec captures, chiffres animés, solutions par équipe,
// comparaison, offres, FAQ. Tous les chiffres viennent de data/facts.json (constatés, datés).

const STANDARDS = [
  "STIX 2.1", "TAXII 2.1", "MITRE ATT&CK", "NIST SP 800-61", "CISA KEV", "FIRST EPSS",
  "NVD", "AlienVault OTX", "abuse.ch", "PostgreSQL", "Prometheus", "Grafana", "Docker",
];
// Onglets de fonctionnalités : clé, capture (anglais, CI « Préproduction »), hauteur de la capture.
const FEATURES = [
  ["prioritize", "06-cve", "cve"],
  ["triage", "02-triage", "soc"],
  ["investigate", "04-incident", "corr"],
  ["hunt", "07-chasse", "hunt"],
  ["correlate", "10-correlations", "feeds"],
  ["measure", "12-pilotage", "obs"],
];
// Sources de référence livrées préconfigurées (illwatch/modules/foundation/seed.py).
const FEEDS = ["NVD", "CISA KEV", "FIRST EPSS", "abuse.ch URLhaus", "Feodo Tracker", "C2IntelFeeds", "IPsum", "AlienVault OTX", "STIX 2.1 / TAXII 2.1"];
const MODULES = ["feeds", "cve", "corr", "soc", "hunt", "intel", "obs"];
const TEAMS = [
  ["soc", "users"],
  ["cert", "shield"],
  ["mssp", "layers"],
  ["public", "building"],
];
const COMPLIANCE = ["nis2", "dora", "gdpr", "iso"];
const COMPARE_ROWS = ["cost", "infra", "time", "data", "cve", "ir", "code"];
const TRUST = ["open", "ci", "real", "scan", "self", "light"];
const OFFERS = [
  ["community", "btn--ghost", "code"],
  ["pilot", "btn--primary", "demo"],
  ["support", "btn--ghost", "demo"],
];
const FAQ = ["free", "data", "requirements", "languages", "ready", "integrate"];
const MILESTONES = [
  ["m1", "done"], ["m2", "done"], ["m3", "done"], ["m4", "done"], ["m5", "done"], ["m6", "done"],
  ["m7", "progress"], ["m8", "done"], ["m9", "delivered"], ["m10", "delivered"], ["m11", "delivered"],
];
const PRESETS = {
  critical: { cvss: 9.8, epss: 94, kev: true, exploit: true, ransomware: true },
  theory: { cvss: 9.1, epss: 2, kev: false, exploit: false, ransomware: false },
  floor: { cvss: 6.5, epss: 15, kev: true, exploit: false, ransomware: false },
};
const MAX_PART = { cvss: 30, epss: 25, kev: 25, exploit: 10, ransomware: 10 };
const SIM_START = { cvss: 7.5, epss: 18, kev: true, exploit: true, ransomware: false };

// Hauteur réelle des captures (1440 px de large), pour réserver la place et éviter les sauts.
const SHOT_HEIGHT = { "07-chasse": 908 };

const ctaLink = (site, kind) => (kind === "code" ? site.links.github : site.links.demo);

function announce(ctx) {
  const { t } = ctx;
  return `<div class="announce"><div class="wrap announce__inner">
      <span class="announce__tag">${t("announce.tag")}</span>
      <span>${t("announce.text")}</span>
      <a href="#offres">${t("announce.link")} →</a>
    </div></div>`;
}

function header(ctx) {
  const { t, lang, site, base, asset } = ctx;
  const nav = [
    ["#produit", t("nav.product")],
    ["#solutions", t("nav.solutions")],
    ["#pourquoi", t("nav.why")],
    ["#securite", t("nav.security")],
    ["#offres", t("nav.offers")],
  ];
  const links = nav.map(([href, label]) => `<li><a href="${href}">${label}</a></li>`).join("");
  const langs = site.langs
    .map(
      (l) =>
        `<li><a href="${base}${l.code}/" hreflang="${l.html}" lang="${l.html}" data-lang-choice="${l.code}"${
          l.code === lang.code ? ' aria-current="true"' : ""
        }>${esc(l.name)}</a></li>`,
    )
    .join("");
  return `<a class="skip" href="#contenu">${t("nav.skip")}</a>
  ${announce(ctx)}
  <header class="topbar">
    <div class="wrap topbar__inner">
      <a class="brand" href="${base}${lang.code}/"><img src="${asset("img/illwatch-logo-endorsed-dark.svg")}" alt="ILL Watch" width="129" height="40"></a>
      <nav class="mainnav" aria-label="${t("nav.menu")}">
        <ul>${links}<li><a href="${site.links.docs}">${t("nav.docs")}</a></li></ul>
      </nav>
      <div class="topbar__tools">
        <details class="langmenu">
          <summary aria-label="${t("nav.language")}">${icon("globe")}<span>${lang.code.toUpperCase()}</span></summary>
          <ul>${langs}</ul>
        </details>
        <a class="btn btn--ghost btn--sm hide-sm" href="${site.links.github}">${icon("code", "icon icon--inline")} ${t("nav.code")}</a>
        <a class="btn btn--primary btn--sm hide-xs" href="${site.links.demo}">${t("nav.demo")}</a>
        <details class="navmenu">
          <summary aria-label="${t("nav.menu")}">${icon("menu")}</summary>
          <ul>${links}
            <li><a href="${site.links.docs}">${t("nav.docs")}</a></li>
            <li><a href="${site.links.github}">${t("nav.code")}</a></li>
            <li><a href="${site.links.demo}">${t("nav.demo")}</a></li></ul>
        </details>
      </div>
    </div>
  </header>`;
}

function picture(ctx, file, alt, { eager = false, sizes = "(min-width: 1100px) 1080px, 94vw" } = {}) {
  const { asset } = ctx;
  const small = asset(`img/screens/${file}-720.webp`);
  const large = asset(`img/screens/${file}.webp`);
  return `<img src="${large}" srcset="${small} 720w, ${large} 1440w" sizes="${sizes}" width="1440" height="${
    SHOT_HEIGHT[file] || 1130
  }" alt="${esc(alt)}" ${eager ? 'fetchpriority="high"' : 'loading="lazy"'} decoding="async">`;
}

const frame = (inner, cls = "") =>
  `<div class="shot ${cls}"><div class="shot__frame" aria-hidden="true"><span></span><span></span><span></span><i>illwatch.local</i></div>${inner}</div>`;

function hero(ctx) {
  const { t, site, facts, n } = ctx;
  // Cartes flottantes : extraits du jeu de démonstration (fictif), animées en boucle.
  const pops = [
    ["p0", t("hero.pop1_label"), t("hero.pop1_text")],
    ["signal", t("hero.pop2_label"), t("hero.pop2_text")],
    ["ok", t("hero.pop3_label"), t("hero.pop3_text")],
  ];
  return `<section class="hero" aria-labelledby="hero-title">
    <div class="hero__glow" aria-hidden="true"></div>
    <div class="radar" aria-hidden="true"></div>
    <div class="wrap hero__inner">
      <p class="eyebrow">${t("hero.eyebrow")}</p>
      <h1 id="hero-title">${t("hero.title_a")} <span class="grad">${t("hero.title_b")}</span></h1>
      <p class="lead">${t("hero.lead")}</p>
      <div class="actions">
        <a class="btn btn--primary btn--lg" href="${site.links.demo}">${t("hero.cta_demo")}</a>
        <a class="btn btn--ghost btn--lg" href="${site.links.github}">${icon("code", "icon icon--inline")} ${t("hero.cta_start")}</a>
      </div>
      <ul class="chips" aria-label="${t("hero.chips_label")}">
        <li>${icon("ci", "icon icon--inline")} ${t("hero.chip_license")}</li>
        <li>${icon("ci", "icon icon--inline")} ${t("hero.chip_self")}</li>
        <li>${icon("ci", "icon icon--inline")} ${t("hero.chip_memory", { memory: n(facts.memory_mb) })}</li>
        <li>${icon("ci", "icon icon--inline")} ${t("hero.chip_langs")}</li>
      </ul>
    </div>
    <figure class="wrap hero__visual">
      ${frame(picture(ctx, "01-vue-ensemble", t("hero.img_alt", {}, false), { eager: true }), "shot--hero")}
      <ul class="pops" aria-hidden="true">${pops
        .map(([tone, label, text], i) => `<li class="pop pop--${i + 1} pop--${tone}"><b>${label}</b><span>${text}</span></li>`)
        .join("")}</ul>
      <figcaption>${t("hero.demo_note")}</figcaption>
    </figure>
  </section>`;
}

function standards(ctx) {
  const { t } = ctx;
  const items = STANDARDS.map((s) => `<li>${esc(s)}</li>`).join("");
  return `<section class="standards" aria-labelledby="standards-title">
    <div class="wrap"><h2 class="label" id="standards-title">${t("standards.label")}</h2></div>
    <div class="marquee"><ul class="marquee__track">${items}</ul><ul class="marquee__track" aria-hidden="true">${items}</ul></div>
  </section>`;
}

function features(ctx) {
  const { t } = ctx;
  const tabs = FEATURES.map(
    ([key, , ic], i) =>
      `<button type="button" role="tab" id="tab-${key}" aria-controls="panel-${key}" aria-selected="${i === 0}">${icon(ic, "icon icon--inline")} ${t(`features.${key}_tab`)}</button>`,
  ).join("");
  const panels = FEATURES.map(
    ([key, file]) => `<div role="tabpanel" id="panel-${key}" aria-labelledby="tab-${key}" class="feature" tabindex="0">
        <div class="feature__text">
          <h3>${t(`features.${key}_title`)}</h3>
          <p>${t(`features.${key}_text`)}</p>
          <ul class="ticks">${[1, 2, 3].map((b) => `<li>${t(`features.${key}_b${b}`)}</li>`).join("")}</ul>
        </div>
        ${frame(picture(ctx, file, `${t(`features.${key}_tab`, {}, false)} — ${t(`features.${key}_title`, {}, false)}`), "feature__shot")}
      </div>`,
  ).join("");
  return `<section class="section" id="produit" aria-labelledby="produit-titre">
    <div class="wrap">
      <div class="section__head reveal">
        <p class="label">${t("features.label")}</p>
        <h2 id="produit-titre">${t("features.title")}</h2>
        <p class="lead">${t("features.lead")}</p>
      </div>
      <div class="tabs reveal" data-tabs>
        <div class="tabs__list" role="tablist" aria-label="${t("features.label")}">${tabs}</div>
        ${panels}
      </div>
      <p class="note">${t("features.note")}</p>
    </div>
  </section>`;
}

function stats(ctx) {
  const { t, n, date, facts } = ctx;
  const items = [
    [facts.ioc.value, t("stats.ioc")],
    [facts.cves.value, t("stats.cves")],
    [facts.kev.value, t("stats.kev")],
    [facts.dashboard_s.value, t("stats.dashboard")],
  ];
  return `<section class="stats" aria-labelledby="stats-title">
    <div class="wrap">
      <h2 class="stats__title reveal" id="stats-title">${t("stats.title")}</h2>
      <dl class="stats__grid">${items
        .map(([v, l]) => `<div class="reveal"><dt>${l}</dt><dd data-count="${v}">${n(v)}</dd></div>`)
        .join("")}</dl>
      <p class="note">${t("stats.note", { date: date(facts.ioc.date) })}</p>
    </div>
  </section>`;
}

function platform(ctx) {
  const { t } = ctx;
  return `<section class="section section--alt" id="plateforme" aria-labelledby="plateforme-titre">
    <div class="wrap">
      <div class="section__head reveal">
        <p class="label">${t("platform.label")}</p>
        <h2 id="plateforme-titre">${t("platform.title")}</h2>
        <p class="lead">${t("platform.lead")}</p>
      </div>
      <div class="bento">${MODULES.map(
        (m) => `<article class="card card--module reveal">${icon(m, "icon icon--tile")}<h3>${t(`platform.${m}_title`)}</h3><p>${t(`platform.${m}_text`)}</p>${
          m === "feeds" ? `<ul class="feedlist" aria-hidden="true">${FEEDS.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""
        }</article>`,
      ).join("")}</div>
      <ol class="pipeline reveal" aria-label="${t("platform.pipeline")}">${[1, 2, 3, 4, 5, 6]
        .map((i) => `<li><span class="pipeline__n mono">0${i}</span><strong>${t(`platform.s${i}`)}</strong></li>`)
        .join("")}</ol>
    </div>
  </section>`;
}

function simulator(ctx) {
  const { t, n, pct } = ctx;
  const start = computeRisk({ ...SIM_START, epss: SIM_START.epss / 100 });
  const priorities = Object.fromEntries(["P0", "P1", "P2", "P3"].map((p) => [p, t(`sim.${p.toLowerCase()}`, {}, false)]));
  const sla = Object.fromEntries(["P0", "P1", "P2", "P3"].map((p) => [p, t(`sim.sla_${p.toLowerCase()}`, {}, false)]));
  const parts = ["cvss", "epss", "kev", "exploit", "ransomware"];
  const check = (name, label) =>
    `<label class="check"><input type="checkbox" name="${name}"${SIM_START[name] ? " checked" : ""}><span>${label}</span></label>`;
  return `<section class="section" id="simulateur" aria-labelledby="simulateur-titre">
    <div class="wrap">
      <div class="section__head reveal">
        <p class="label">${t("sim.label")}</p>
        <h2 id="simulateur-titre">${t("sim.title")}</h2>
        <p class="lead">${t("sim.lead")}</p>
      </div>
      <form class="sim reveal" data-simulator data-priorities="${esc(JSON.stringify(priorities))}" data-sla="${esc(JSON.stringify(sla))}">
        <div class="card sim__inputs">
          <div class="presets"><span class="label">${t("sim.presets")}</span>
            ${Object.entries(PRESETS)
              .map(([k, v]) => `<button type="button" class="btn btn--ghost btn--sm" data-preset="${esc(JSON.stringify(v))}">${t(`sim.preset_${k}`)}</button>`)
              .join("")}
          </div>
          <label class="range"><span class="range__head"><span>${t("sim.cvss")}</span><output data-out="cvss-value">${n(SIM_START.cvss)}</output></span>
            <input type="range" name="cvss" min="0" max="10" step="0.1" value="${SIM_START.cvss}" aria-describedby="cvss-help">
            <small id="cvss-help">${t("sim.cvss_help")}</small></label>
          <label class="range"><span class="range__head"><span>${t("sim.epss")}</span><output data-out="epss-value">${pct(SIM_START.epss / 100)}</output></span>
            <input type="range" name="epss" min="0" max="100" step="1" value="${SIM_START.epss}" aria-describedby="epss-help">
            <small id="epss-help">${t("sim.epss_help")}</small></label>
          ${check("kev", t("sim.kev"))}${check("exploit", t("sim.exploit"))}${check("ransomware", t("sim.ransomware"))}
          <noscript><p class="note">${t("sim.noscript")}</p></noscript>
        </div>
        <div class="card sim__result" aria-live="polite">
          <p class="label">${t("sim.score")}</p>
          <p class="sim__score"><output data-out="total">${n(start.total)}</output> <span>${t("sim.out_of")}</span></p>
          <progress class="meter" data-out="meter" max="100" value="${start.total}" aria-hidden="true"></progress>
          <dl class="sim__facts">
            <div><dt>${t("sim.priority")}</dt><dd><span data-out="priority" class="badge badge--${start.priority.toLowerCase()} badge--lg">${start.priority} · ${priorities[start.priority]}</span></dd></div>
            <div><dt>${t("sim.sla")}</dt><dd data-out="sla">${sla[start.priority]}</dd></div>
          </dl>
          <p class="floor" data-out="floor"${start.kevFloor ? "" : " hidden"}>${t("sim.floor")}</p>
          <p class="label">${t("sim.breakdown")}</p>
          <ul class="parts">${parts
            .map(
              (p) =>
                `<li><span>${t(`sim.part_${p}`)}</span><progress class="parts__bar parts--${p}" data-bar="${p}" max="${MAX_PART[p]}" value="${start.parts[p]}" aria-hidden="true"></progress><output data-out="part-${p}">+${n(start.parts[p])}</output></li>`,
            )
            .join("")}</ul>
          <p class="note mono">${t("sim.formula")}</p>
        </div>
      </form>
    </div>
  </section>`;
}

function solutions(ctx) {
  const { t } = ctx;
  return `<section class="section section--alt" id="solutions" aria-labelledby="solutions-titre">
    <div class="wrap">
      <div class="section__head reveal">
        <p class="label">${t("solutions.label")}</p>
        <h2 id="solutions-titre">${t("solutions.title")}</h2>
        <p class="lead">${t("solutions.lead")}</p>
      </div>
      <div class="grid grid--4">${TEAMS.map(
        ([k, ic]) => `<article class="card card--team reveal">${icon(ic, "icon icon--tile")}
          <h3>${t(`solutions.${k}_title`)}</h3>
          <p class="card__hook">${t(`solutions.${k}_hook`)}</p>
          <ul class="ticks ticks--sm">${[1, 2, 3].map((b) => `<li>${t(`solutions.${k}_b${b}`)}</li>`).join("")}</ul>
        </article>`,
      ).join("")}</div>
      <div class="compliance reveal">
        <p class="label">${t("compliance.label")}</p>
        <ul>${COMPLIANCE.map((c) => `<li><strong>${t(`compliance.${c}_title`)}</strong><span>${t(`compliance.${c}_text`)}</span></li>`).join("")}</ul>
        <p class="note">${t("compliance.note")}</p>
      </div>
    </div>
  </section>`;
}

function compare(ctx) {
  const { t, n, facts } = ctx;
  const vars = { memory: n(facts.memory_mb) };
  const cols = ["illwatch", "commercial", "diy"];
  return `<section class="section" id="pourquoi" aria-labelledby="pourquoi-titre">
    <div class="wrap">
      <div class="section__head reveal">
        <p class="label">${t("compare.label")}</p>
        <h2 id="pourquoi-titre">${t("compare.title")}</h2>
        <p class="lead">${t("compare.lead")}</p>
      </div>
      <div class="table-wrap reveal" tabindex="0" role="region" aria-labelledby="pourquoi-titre">
        <table class="compare">
          <thead><tr><th scope="col"><span class="sr-only">${t("compare.criterion")}</span></th>${cols
            .map((c) => `<th scope="col"${c === "illwatch" ? ' class="is-us"' : ""}>${t(`compare.col_${c}`)}</th>`)
            .join("")}</tr></thead>
          <tbody>${COMPARE_ROWS.map(
            (r) =>
              `<tr><th scope="row">${t(`compare.${r}`)}</th>${cols
                .map((c) => `<td${c === "illwatch" ? ' class="is-us"' : ""}>${t(`compare.${r}_${c}`, vars)}</td>`)
                .join("")}</tr>`,
          ).join("")}</tbody>
        </table>
      </div>
      <p class="note">${t("compare.note")}</p>
    </div>
  </section>`;
}

function trust(ctx) {
  const { t, n, facts } = ctx;
  const vars = { tests: n(facts.tests.value), coverage: n(facts.coverage.value), memory: n(facts.memory_mb), dashboard: n(facts.dashboard_s.value) };
  return `<section class="section section--alt" id="securite" aria-labelledby="securite-titre">
    <div class="wrap">
      <div class="section__head reveal">
        <p class="label">${t("trust.label")}</p>
        <h2 id="securite-titre">${t("trust.title")}</h2>
        <p class="lead">${t("trust.lead")}</p>
      </div>
      <div class="grid grid--3">${TRUST.map(
        (k) => `<article class="card card--trust reveal">${icon(k, "icon icon--tile")}<h3>${t(`trust.${k}_title`)}</h3><p>${t(`trust.${k}_text`, vars)}</p></article>`,
      ).join("")}</div>
      <div class="milestones-wrap reveal">
        <p class="label">${t("roadmap.label")}</p>
        <ol class="milestones">${MILESTONES.map(
          ([m, state]) =>
            `<li class="milestone milestone--${state}"><span class="mono">${m.toUpperCase()}</span><span class="milestone__name">${t(`roadmap.${m}`)}</span><span class="status status--${state}">${t(`roadmap.${state}`)}</span></li>`,
        ).join("")}</ol>
        <p class="note">${t("roadmap.lead")} <a href="${ctx.site.links.roadmap}">${t("roadmap.link")} ${icon("external", "icon icon--inline")}</a></p>
      </div>
    </div>
  </section>`;
}

function offers(ctx) {
  const { t, site } = ctx;
  return `<section class="section" id="offres" aria-labelledby="offres-titre">
    <div class="wrap">
      <div class="section__head section__head--center reveal">
        <p class="label">${t("offers.label")}</p>
        <h2 id="offres-titre">${t("offers.title")}</h2>
        <p class="lead">${t("offers.lead")}</p>
      </div>
      <div class="grid grid--3 offers">${OFFERS.map(
        ([k, btn, link]) => `<article class="card offer reveal${k === "pilot" ? " offer--featured" : ""}">
          ${k === "pilot" ? `<p class="offer__flag">${t("offers.featured")}</p>` : ""}
          <h3>${t(`offers.${k}_title`)}</h3>
          <p class="offer__price">${t(`offers.${k}_price`)}</p>
          <p>${t(`offers.${k}_text`)}</p>
          <ul class="ticks ticks--sm">${[1, 2, 3, 4].map((b) => `<li>${t(`offers.${k}_b${b}`)}</li>`).join("")}</ul>
          <a class="btn ${btn}" href="${ctaLink(site, link)}">${t(`offers.${k}_cta`)}</a>
        </article>`,
      ).join("")}</div>
      <p class="note note--center">${t("offers.note")}</p>
    </div>
  </section>`;
}

function faq(ctx) {
  const { t, n, facts } = ctx;
  return `<section class="section section--alt" id="faq" aria-labelledby="faq-titre">
    <div class="wrap faq">
      <div class="section__head reveal">
        <p class="label">${t("faq.label")}</p>
        <h2 id="faq-titre">${t("faq.title")}</h2>
      </div>
      <div class="faq__list">${FAQ.map(
        (k) => `<details class="faq__item reveal"><summary>${t(`faq.${k}_q`)}</summary><p>${t(`faq.${k}_a`, { memory: n(facts.memory_mb) })}</p></details>`,
      ).join("")}</div>
    </div>
  </section>`;
}

function cta(ctx) {
  const { t, site } = ctx;
  return `<section class="cta" aria-labelledby="demarrer">
    <div class="wrap cta__inner">
      <div class="reveal">
        <h2 id="demarrer">${t("cta.title")}</h2>
        <p>${t("cta.text")}</p>
        <div class="actions">
          <a class="btn btn--primary btn--lg" href="${site.links.demo}">${t("cta.demo")}</a>
          <a class="btn btn--ghost btn--lg" href="${site.links.docs}">${t("cta.docs")}</a>
        </div>
      </div>
      <pre class="code reveal" aria-label="${t("cta.code_label")}"><code><span class="code__c"># ${t("cta.step1")}</span>
git clone ${site.links.github}.git
cd cyberillsec-illwatch && cp .env.example .env
<span class="code__c"># ${t("cta.step2")}</span>
docker compose up -d
<span class="code__ok">✔ ${t("cta.step3")}</span></code></pre>
    </div>
  </section>`;
}

function footer(ctx) {
  const { t, site, asset, lang, base } = ctx;
  const langs = site.langs
    .map((l) => `<li><a href="${base}${l.code}/" hreflang="${l.html}" lang="${l.html}" data-lang-choice="${l.code}"${l.code === lang.code ? ' aria-current="true"' : ""}>${esc(l.name)}</a></li>`)
    .join("");
  return `<footer class="footer">
    <div class="wrap footer__inner">
      <div class="footer__brand">
        <img src="${asset("img/illwatch-mark.svg")}" alt="" width="40" height="40">
        <p><strong>ILL Watch</strong> · CYBERILL<br><span class="muted">${t("footer.tagline")}</span></p>
        <a class="btn btn--primary btn--sm" href="${site.links.demo}">${t("nav.demo")}</a>
      </div>
      <nav aria-label="${t("footer.product")}"><p class="label">${t("footer.product")}</p><ul>
        <li><a href="#produit">${t("features.label")}</a></li><li><a href="#solutions">${t("nav.solutions")}</a></li><li><a href="#plateforme">${t("footer.platform")}</a></li>
        <li><a href="#simulateur">${t("footer.simulator")}</a></li><li><a href="#offres">${t("nav.offers")}</a></li></ul></nav>
      <nav aria-label="${t("footer.resources")}"><p class="label">${t("footer.resources")}</p><ul>
        <li><a href="${site.links.docs}">${t("nav.docs")}</a></li><li><a href="${site.links.releases}">${t("footer.releases")}</a></li>
        <li><a href="${site.links.roadmap}">${t("roadmap.label")}</a></li><li><a href="#faq">${t("faq.label")}</a></li></ul></nav>
      <nav aria-label="${t("footer.project")}"><p class="label">${t("footer.project")}</p><ul>
        <li><a href="${site.links.github}">GitHub</a></li><li><a href="${site.links.gitlab}">GitLab</a></li>
        <li><a href="${site.links.license}">${t("footer.license")}</a></li><li><a href="${site.links.security}">${t("footer.security")}</a></li></ul></nav>
      <nav aria-label="${t("nav.language")}"><p class="label">${t("nav.language")}</p><ul>${langs}</ul></nav>
    </div>
    <div class="wrap footer__legal"><p>${t("footer.privacy")}</p><p>${t("footer.legal")}</p><p>© 2026 CYBERILL — Godwill FOKA</p></div>
  </footer>`;
}

export function homePage(ctx) {
  const { t, lang, asset } = ctx;
  return `<!doctype html>
<html lang="${lang.html}" data-lang="${lang.code}" data-locale="${lang.locale}">
  ${head(ctx, { title: t("meta.title", {}, false), description: t("meta.description", {}, false), path: "" })}
  <body>
  ${header(ctx)}
  <main id="contenu">
    ${hero(ctx)}
    ${standards(ctx)}
    ${features(ctx)}
    ${stats(ctx)}
    ${platform(ctx)}
    ${simulator(ctx)}
    ${solutions(ctx)}
    ${compare(ctx)}
    ${trust(ctx)}
    ${offers(ctx)}
    ${faq(ctx)}
    ${cta(ctx)}
  </main>
  ${footer(ctx)}
  <script type="module" src="${asset("js/site.js")}"></script>
  <script type="module" src="${asset("js/tabs.js")}"></script>
  <script type="module" src="${asset("js/simulator.js")}"></script>
  <script type="module" src="${asset("js/motion.js")}"></script>
  </body>
</html>
`;
}

/** Adresse racine : choix automatique de la langue, liste des langues sans JavaScript. */
export function rootPage(ctx, dictionaries) {
  const { site, base, asset } = ctx;
  const items = site.langs
    .map((l) => {
      const d = dictionaries[l.code];
      return `<li><a href="${base}${l.code}/" hreflang="${l.html}" lang="${l.html}" data-lang-choice="${l.code}"><strong>${esc(l.name)}</strong><span>${esc(d.root.choose)}</span></a></li>`;
    })
    .join("");
  const en = dictionaries.en;
  return `<!doctype html>
<html lang="en" data-base="${base}" data-geo="${esc(site.geo)}" data-instance-lang="${esc(site.instanceLang)}">
  ${head({ ...ctx, lang: null }, { title: "ILL Watch", description: en.meta.description, path: "" })}
  <body class="root">
  <main class="root__inner">
    <img src="${asset("img/illwatch-logo-endorsed-dark.svg")}" alt="ILL Watch" width="258" height="80">
    <ul class="root__langs">${items}</ul>
  </main>
  <script type="module" src="${asset("js/root.js")}"></script>
  <script type="module" src="${asset("js/site.js")}"></script>
  </body>
</html>
`;
}

export function notFoundPage(ctx, dictionaries) {
  const { site, base, asset } = ctx;
  const blocks = site.langs
    .map((l) => {
      const d = dictionaries[l.code].notfound;
      return `<p lang="${l.html}"><strong>${esc(d.title)}</strong> — ${esc(d.text)} <a href="${base}${l.code}/">${esc(d.back)}</a></p>`;
    })
    .join("");
  return `<!doctype html>
<html lang="en">
  ${head({ ...ctx, lang: null }, { title: "404 — ILL Watch", description: dictionaries.en.notfound.text, path: "", alternates: false })}
  <body class="root">
  <main class="root__inner root__inner--404">
    <img src="${asset("img/illwatch-mark.svg")}" alt="" width="64" height="64">
    ${blocks}
  </main>
  </body>
</html>
`;
}
