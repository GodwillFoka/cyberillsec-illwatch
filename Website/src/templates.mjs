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
};

export const icon = (name, cls = "icon") =>
  `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;

const MODULES = ["feeds", "cve", "corr", "soc", "hunt", "intel", "obs"];
const TOUR = [
  ["overview", "01-vue-ensemble"],
  ["triage", "02-triage"],
  ["incident", "04-incident"],
  ["cve", "06-cve"],
  ["corr", "10-correlations"],
  ["hunt", "07-chasse"],
  ["campaigns", "13-campagnes"],
  ["pilot", "12-pilotage"],
];
const TRUST = ["open", "ci", "real", "scan", "self", "light"];
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

function header(ctx) {
  const { t, lang, site, base, asset } = ctx;
  const nav = [
    ["#plateforme", t("nav.platform")],
    ["#ecrans", t("nav.tour")],
    ["#simulateur", t("nav.simulator")],
    ["#confiance", t("nav.trust")],
    ["#feuille-de-route", t("nav.roadmap")],
  ];
  const langs = site.langs
    .map(
      (l) =>
        `<li><a href="${base}${l.code}/" hreflang="${l.html}" lang="${l.html}" data-lang-choice="${l.code}"${
          l.code === lang.code ? ' aria-current="true"' : ""
        }>${esc(l.name)}</a></li>`,
    )
    .join("");
  return `<a class="skip" href="#contenu">${t("nav.skip")}</a>
  <header class="topbar">
    <div class="wrap topbar__inner">
      <a class="brand" href="${base}${lang.code}/"><img src="${asset("img/illwatch-logo-endorsed-dark.svg")}" alt="ILL Watch" width="129" height="40"></a>
      <nav class="mainnav" aria-label="${t("nav.menu")}">
        <ul>${nav.map(([href, label]) => `<li><a href="${href}">${label}</a></li>`).join("")}
          <li><a href="${site.links.docs}">${t("nav.docs")}</a></li></ul>
      </nav>
      <div class="topbar__tools">
        <details class="langmenu">
          <summary aria-label="${t("nav.language")}">${icon("globe")}<span>${lang.code.toUpperCase()}</span></summary>
          <ul>${langs}</ul>
        </details>
        <a class="btn btn--ghost btn--sm hide-sm" href="${site.links.gitlab}">${t("nav.code")}</a>
        <details class="navmenu">
          <summary aria-label="${t("nav.menu")}">${icon("menu")}</summary>
          <ul>${nav.map(([href, label]) => `<li><a href="${href}">${label}</a></li>`).join("")}
            <li><a href="${site.links.docs}">${t("nav.docs")}</a></li>
            <li><a href="${site.links.gitlab}">${t("nav.code")}</a></li></ul>
        </details>
      </div>
    </div>
  </header>`;
}

function picture(ctx, file, alt, { eager = false } = {}) {
  const { asset } = ctx;
  const small = asset(`img/screens/${file}-720.webp`);
  const large = asset(`img/screens/${file}.webp`);
  return `<img src="${large}" srcset="${small} 720w, ${large} 1440w" sizes="(min-width: 1100px) 1040px, 94vw" width="1440" height="${
    file === "07-chasse" ? 908 : 1130
  }" alt="${esc(alt)}" ${eager ? 'fetchpriority="high"' : 'loading="lazy"'} decoding="async">`;
}

function hero(ctx) {
  const { t, site, facts } = ctx;
  return `<section class="hero">
    <div class="radar" aria-hidden="true"></div>
    <div class="wrap hero__inner">
      <p class="eyebrow">${t("hero.eyebrow")}</p>
      <h1>${t("hero.title")}</h1>
      <p class="lead">${t("hero.lead")}</p>
      <div class="actions">
        <a class="btn btn--primary" href="${site.links.gitlab}">${t("hero.cta_primary")}</a>
        <a class="btn btn--ghost" href="${site.links.docs}">${t("hero.cta_docs")}</a>
        <a class="btn btn--text" href="#simulateur">${t("hero.cta_sim")} →</a>
      </div>
      <ul class="chips">
        <li>${t("hero.chip_license")}</li><li>${t("hero.chip_stix")}</li><li>${t("hero.chip_attack")}</li>
        <li>${t("hero.chip_memory", { memory: facts.memory_mb })}</li>
      </ul>
    </div>
    <figure class="wrap shot shot--hero">
      <div class="shot__frame"><span></span><span></span><span></span></div>
      ${picture(ctx, "01-vue-ensemble", t("hero.img_alt", {}, false), { eager: true })}
      <figcaption>${t("hero.demo_note")}</figcaption>
    </figure>
  </section>`;
}

function factsBand(ctx) {
  const { t, n, date, facts } = ctx;
  const items = [
    [n(facts.ioc.value), t("facts.ioc")],
    [n(facts.cves.value), t("facts.cves")],
    [n(facts.kev.value), t("facts.kev")],
    [n(facts.sources.value), t("facts.sources")],
    [facts.scenario.value, t("facts.scenario")],
  ];
  return `<section class="facts" aria-labelledby="facts-title">
    <div class="wrap">
      <h2 class="label" id="facts-title">${t("facts.label")}</h2>
      <dl class="facts__grid">${items.map(([v, l]) => `<div><dt>${l}</dt><dd>${v}</dd></div>`).join("")}</dl>
      <p class="note">${t("facts.note", { date: date(facts.ioc.date) })}</p>
    </div>
  </section>`;
}

function problem(ctx) {
  const { t } = ctx;
  return `<section class="section" aria-labelledby="probleme">
    <div class="wrap">
      <p class="label">${t("problem.label")}</p>
      <h2 id="probleme">${t("problem.title")}</h2>
      <div class="grid grid--3">${[1, 2, 3]
        .map((i) => `<article class="card"><h3>${t(`problem.p${i}_title`)}</h3><p>${t(`problem.p${i}_text`)}</p></article>`)
        .join("")}</div>
    </div>
  </section>`;
}

function platform(ctx) {
  const { t } = ctx;
  return `<section class="section section--alt" id="plateforme" aria-labelledby="plateforme-titre">
    <div class="wrap">
      <p class="label">${t("platform.label")}</p>
      <h2 id="plateforme-titre">${t("platform.title")}</h2>
      <p class="lead">${t("platform.lead")}</p>
      <div class="grid grid--modules">${MODULES.map(
        (m) => `<article class="card card--module">${icon(m, "icon icon--tile")}<h3>${t(`platform.${m}_title`)}</h3><p>${t(`platform.${m}_text`)}</p></article>`,
      ).join("")}</div>
    </div>
  </section>`;
}

function tour(ctx) {
  const { t } = ctx;
  const tabs = TOUR.map(
    ([key], i) =>
      `<button type="button" role="tab" id="tab-${key}" aria-controls="panel-${key}" aria-selected="${i === 0}">${t(`tour.${key}`)}</button>`,
  ).join("");
  const panels = TOUR.map(
    ([key, file]) => `<figure role="tabpanel" id="panel-${key}" aria-labelledby="tab-${key}" class="shot" tabindex="0">
        <div class="shot__frame"><span></span><span></span><span></span></div>
        ${picture(ctx, file, `${t(`tour.${key}`, {}, false)} — ${t(`tour.${key}_caption`, {}, false)}`)}
        <figcaption><strong>${t(`tour.${key}`)}</strong> · ${t(`tour.${key}_caption`)}</figcaption>
      </figure>`,
  ).join("");
  return `<section class="section" id="ecrans" aria-labelledby="ecrans-titre">
    <div class="wrap">
      <p class="label">${t("tour.label")}</p>
      <h2 id="ecrans-titre">${t("tour.title")}</h2>
      <p class="lead">${t("tour.lead")}</p>
      <div class="tour" data-tour>
        <div class="tour__tabs" role="tablist" aria-label="${t("tour.label")}">${tabs}</div>
        ${panels}
      </div>
      <p class="note">${t("tour.note")}</p>
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
  return `<section class="section section--alt" id="simulateur" aria-labelledby="simulateur-titre">
    <div class="wrap">
      <p class="label">${t("sim.label")}</p>
      <h2 id="simulateur-titre">${t("sim.title")}</h2>
      <p class="lead">${t("sim.lead")}</p>
      <form class="sim" data-simulator data-priorities="${esc(JSON.stringify(priorities))}" data-sla="${esc(JSON.stringify(sla))}">
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

function how(ctx) {
  const { t } = ctx;
  return `<section class="section" aria-labelledby="fonctionnement">
    <div class="wrap">
      <p class="label">${t("how.label")}</p>
      <h2 id="fonctionnement">${t("how.title")}</h2>
      <ol class="pipeline">${[1, 2, 3, 4, 5, 6]
        .map((i) => `<li><span class="pipeline__n mono">0${i}</span><h3>${t(`how.s${i}_title`)}</h3><p>${t(`how.s${i}_text`)}</p></li>`)
        .join("")}</ol>
    </div>
  </section>`;
}

function trust(ctx) {
  const { t, n, facts } = ctx;
  const vars = { tests: n(facts.tests.value), coverage: n(facts.coverage.value), memory: n(facts.memory_mb), dashboard: n(facts.dashboard_s.value) };
  return `<section class="section section--alt" id="confiance" aria-labelledby="confiance-titre">
    <div class="wrap">
      <p class="label">${t("trust.label")}</p>
      <h2 id="confiance-titre">${t("trust.title")}</h2>
      <div class="grid grid--3">${TRUST.map(
        (k) => `<article class="card card--trust">${icon(k, "icon icon--tile")}<h3>${t(`trust.${k}_title`)}</h3><p>${t(`trust.${k}_text`, vars)}</p></article>`,
      ).join("")}</div>
    </div>
  </section>`;
}

function roadmap(ctx) {
  const { t, site } = ctx;
  return `<section class="section" id="feuille-de-route" aria-labelledby="feuille-titre">
    <div class="wrap">
      <p class="label">${t("roadmap.label")}</p>
      <h2 id="feuille-titre">${t("roadmap.title")}</h2>
      <p class="lead">${t("roadmap.lead")}</p>
      <ol class="milestones">${MILESTONES.map(
        ([m, state]) =>
          `<li class="milestone milestone--${state}"><span class="mono">${m.toUpperCase()}</span><span class="milestone__name">${t(`roadmap.${m}`)}</span><span class="status status--${state}">${t(`roadmap.${state}`)}</span></li>`,
      ).join("")}</ol>
      <p><a href="${site.links.roadmap}">${t("roadmap.link")} ${icon("external", "icon icon--inline")}</a></p>
    </div>
  </section>`;
}

function cta(ctx) {
  const { t, site } = ctx;
  return `<section class="cta" aria-labelledby="deployer">
    <div class="wrap cta__inner">
      <div>
        <h2 id="deployer">${t("cta.title")}</h2>
        <p>${t("cta.text")}</p>
        <div class="actions">
          <a class="btn btn--primary" href="${site.links.gitlab}">${t("cta.primary")}</a>
          <a class="btn btn--ghost" href="${site.links.docs}">${t("cta.secondary")}</a>
        </div>
      </div>
      <pre class="code" aria-label="Docker Compose"><code><span class="code__c"># 1</span>
git clone ${site.links.gitlab}.git
cd cyberillsec-illwatch && cp .env.example .env
<span class="code__c"># 2</span>
docker compose up -d</code></pre>
    </div>
  </section>`;
}

function footer(ctx) {
  const { t, site, asset } = ctx;
  return `<footer class="footer">
    <div class="wrap footer__inner">
      <div class="footer__brand">
        <img src="${asset("img/illwatch-mark.svg")}" alt="" width="40" height="40">
        <p><strong>ILL Watch</strong> · CYBERILL<br><span class="muted">${t("footer.tagline")}</span></p>
      </div>
      <nav aria-label="${t("footer.product")}"><p class="label">${t("footer.product")}</p><ul>
        <li><a href="#plateforme">${t("nav.platform")}</a></li><li><a href="#simulateur">${t("nav.simulator")}</a></li>
        <li><a href="${site.links.docs}">${t("nav.docs")}</a></li><li><a href="${site.links.releases}">${t("footer.releases")}</a></li></ul></nav>
      <nav aria-label="${t("footer.project")}"><p class="label">${t("footer.project")}</p><ul>
        <li><a href="${site.links.gitlab}">GitLab</a></li><li><a href="${site.links.github}">GitHub</a></li>
        <li><a href="${site.links.license}">${t("footer.license")}</a></li><li><a href="${site.links.security}">${t("footer.security")}</a></li></ul></nav>
    </div>
    <div class="wrap footer__legal"><p>${t("footer.privacy")}</p><p>${t("footer.legal")}</p><p>© 2026 CYBERILL — Godwill FOKA</p></div>
  </footer>`;
}

export function homePage(ctx) {
  const { t, lang, site, base, asset } = ctx;
  return `<!doctype html>
<html lang="${lang.html}" data-lang="${lang.code}" data-locale="${lang.locale}">
  ${head(ctx, { title: t("meta.title", {}, false), description: t("meta.description", {}, false), path: "" })}
  <body>
  ${header(ctx)}
  <main id="contenu">
    ${hero(ctx)}
    ${factsBand(ctx)}
    ${problem(ctx)}
    ${platform(ctx)}
    ${tour(ctx)}
    ${simulator(ctx)}
    ${how(ctx)}
    ${trust(ctx)}
    ${roadmap(ctx)}
    ${cta(ctx)}
  </main>
  ${footer(ctx)}
  <script type="module" src="${asset("js/site.js")}"></script>
  <script type="module" src="${asset("js/tour.js")}"></script>
  <script type="module" src="${asset("js/simulator.js")}"></script>
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
