// Pages intérieures du site (ADR-027, lots S2 à S4) : Plateforme, Sécurité, Tarifs, À propos,
// Démonstration, mentions légales, confidentialité. Même mise en page que l'accueil, mêmes
// contraintes (CSP stricte, aucun style ni script en ligne, cinq langues).
import {
  MODULES,
  compareTable,
  complianceBlock,
  ctaBand,
  esc,
  faqList,
  frame,
  href,
  icon,
  layout,
  offerCards,
  pageHero,
  picture,
  sectionHead,
  trustCards,
} from "./templates.mjs";

const title = (ctx, key) => `${ctx.t(key, {}, false)} — ILLWATCH`;

// ── Plateforme ──────────────────────────────────────────────────────────────────────────

// Capture de chaque module (anglais, CI « Préproduction »).
const MODULE_SHOTS = {
  feeds: "08-sources",
  cve: "06-cve",
  corr: "10-correlations",
  soc: "04-incident",
  hunt: "07-chasse",
  intel: "13-campagnes",
  obs: "12-pilotage",
};

// Extrait de MITRE ATT&CK couvert par les règles d'ILLWATCH (illwatch/modules/attack/catalog.py,
// RULE_TECHNIQUES). Noms officiels d'ATT&CK, non traduits.
const TECHNIQUES = [
  ["T1190", "Exploit Public-Facing Application", "Initial Access", ["RULE-05", "CORR-01", "CORR-02"]],
  ["T1566.001", "Phishing: Spearphishing Attachment", "Initial Access", []],
  ["T1090.003", "Proxy: Multi-hop Proxy", "Command and Control", ["RULE-01"]],
  ["T1568", "Dynamic Resolution", "Command and Control", ["RULE-02"]],
  ["T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control", ["RULE-03"]],
  ["T1486", "Data Encrypted for Impact", "Impact", ["RULE-04"]],
];

const attackUrl = (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

function flow(ctx) {
  const { t } = ctx;
  return `<section class="section" aria-labelledby="flux-titre">
    <div class="wrap">
      ${sectionHead({ label: t("platformPage.flow_label"), title: t("platformPage.flow_title"), lead: t("platformPage.flow_lead"), id: "flux-titre" })}
      <ol class="flow reveal">${[1, 2, 3, 4, 5, 6]
        .map(
          (i) => `<li class="flow__step"><span class="flow__n mono">0${i}</span><strong>${t(`platform.s${i}`)}</strong><p>${t(`platformPage.s${i}_text`)}</p></li>`,
        )
        .join("")}</ol>
    </div>
  </section>`;
}

function modules(ctx) {
  const { t } = ctx;
  return `<section class="section section--alt" aria-labelledby="modules-titre">
    <div class="wrap">
      ${sectionHead({ label: t("platform.label"), title: t("platform.title"), lead: t("platform.lead"), id: "modules-titre" })}
      <div class="modules">${MODULES.map(
        (m, i) => `<article class="module reveal${i % 2 ? " module--flip" : ""}" id="module-${m}">
          <div class="module__text">
            ${icon(m, "icon icon--tile")}
            <h3>${t(`platform.${m}_title`)}</h3>
            <p>${t(`platform.${m}_text`)}</p>
            <ul class="ticks">${[1, 2, 3].map((b) => `<li>${t(`platformPage.${m}_b${b}`)}</li>`).join("")}</ul>
          </div>
          ${frame(picture(ctx, MODULE_SHOTS[m], t(`platform.${m}_title`, {}, false), { sizes: "(min-width: 1100px) 640px, 94vw" }), "module__shot")}
        </article>`,
      ).join("")}</div>
    </div>
  </section>`;
}

function explorer(ctx) {
  const { t } = ctx;
  const tabs = TECHNIQUES.map(
    ([id, name, tactic], i) =>
      `<button type="button" role="tab" id="tech-${id}" aria-controls="tech-panel-${id}" aria-selected="${i === 0}"><span class="mono">${id}</span><span>${esc(name)}</span><small>${esc(tactic)}</small></button>`,
  ).join("");
  const panels = TECHNIQUES.map(
    ([id, name, tactic, rules]) => `<div role="tabpanel" id="tech-panel-${id}" aria-labelledby="tech-${id}" class="explorer__panel" tabindex="0">
        <p class="label">${esc(tactic)} · <span class="mono">${id}</span></p>
        <h3>${esc(name)}</h3>
        <p>${t(`explorer.${id.replace(".", "_")}`)}</p>
        <p class="explorer__rules"><span class="label">${t("explorer.rules")}</span>${
          rules.length ? rules.map((r) => `<span class="tag mono">${r}</span>`).join("") : `<span class="muted">${t("explorer.context")}</span>`
        }</p>
        <a class="link-target" href="${attackUrl(id)}">${t("explorer.mitre")} ${icon("external", "icon icon--inline")}</a>
      </div>`,
  ).join("");
  return `<section class="section" id="attack" aria-labelledby="attack-titre">
    <div class="wrap">
      ${sectionHead({ label: "MITRE ATT&CK", title: t("explorer.title"), lead: t("explorer.lead"), id: "attack-titre" })}
      <div class="explorer reveal" data-tabs data-orientation="vertical">
        <div class="explorer__list" role="tablist" aria-orientation="vertical" aria-label="${t("explorer.list")}">${tabs}</div>
        ${panels}
      </div>
      <p class="note">${t("explorer.note")}</p>
    </div>
  </section>`;
}

// Exemple TAXII 2.1 : requêtes réelles du serveur d'ILLWATCH (illwatch/app/api/taxii.py),
// réponses abrégées sur le jeu de démonstration (identifiants calculés comme le serveur).
const TAXII_STEPS = [
  [
    "discovery",
    `curl -s https://illwatch.example/taxii2/ \\
  -u analyst \\
  -H "Accept: application/taxii+json;version=2.1"`,
    `{
  "title": "ILLWATCH — TAXII 2.1",
  "description": "Threat intelligence shared by ILLWATCH (CyberillSec).",
  "default": "https://illwatch.example/taxii2/illwatch/",
  "api_roots": ["https://illwatch.example/taxii2/illwatch/"]
}`,
  ],
  [
    "collections",
    `curl -s https://illwatch.example/taxii2/illwatch/collections/ \\
  -u analyst \\
  -H "Accept: application/taxii+json;version=2.1"`,
    `{
  "collections": [
    {
      "id": "663961a0-f87f-5c0e-92b3-98ba9b2e748b",
      "title": "ILLWATCH indicators",
      "can_read": true,
      "can_write": false,
      "media_types": ["application/stix+json;version=2.1"]
    },
    { "title": "ILLWATCH campaigns", "…": "…" }
  ]
}`,
  ],
  [
    "objects",
    `curl -s "https://illwatch.example/taxii2/illwatch/collections/\\
663961a0-f87f-5c0e-92b3-98ba9b2e748b/objects/?added_after=2026-10-01T00:00:00Z" \\
  -u analyst \\
  -H "Accept: application/taxii+json;version=2.1"`,
    `{
  "more": false,
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--d901da91-36d9-50ab-801b-782ebd76f64e",
      "name": "203.0.113.50",
      "pattern": "[ipv4-addr:value = '203.0.113.50']",
      "pattern_type": "stix",
      "confidence": 78,
      "labels": ["severity:critical"],
      "description": "LockBit 3.0 [demo]"
    }
  ]
}`,
  ],
];

function taxii(ctx) {
  const { t } = ctx;
  const tabs = TAXII_STEPS.map(
    ([key], i) =>
      `<button type="button" role="tab" id="taxii-${key}" aria-controls="taxii-panel-${key}" aria-selected="${i === 0}"><span class="mono">0${i + 1}</span> ${t(`taxii.${key}`)}</button>`,
  ).join("");
  const panels = TAXII_STEPS.map(
    ([key, request, response]) => `<div role="tabpanel" id="taxii-panel-${key}" aria-labelledby="taxii-${key}" class="taxii__panel" tabindex="0">
        <p>${t(`taxii.${key}_text`)}</p>
        <div class="taxii__code">
          <pre class="code" aria-label="${t("taxii.request")}"><code><span class="code__c"># ${t("taxii.request")}</span>
${esc(request)}</code></pre>
          <pre class="code" aria-label="${t("taxii.response")}"><code><span class="code__c"># ${t("taxii.response")}</span>
${esc(response)}</code></pre>
        </div>
      </div>`,
  ).join("");
  return `<section class="section section--alt" id="taxii" aria-labelledby="taxii-titre">
    <div class="wrap">
      ${sectionHead({ label: "STIX 2.1 · TAXII 2.1", title: t("taxii.title"), lead: t("taxii.lead"), id: "taxii-titre" })}
      <div class="tabs reveal" data-tabs>
        <div class="tabs__list" role="tablist" aria-label="${t("taxii.title")}">${tabs}</div>
        ${panels}
      </div>
      <p class="note">${t("taxii.note")}</p>
    </div>
  </section>`;
}

export function platformPage(ctx) {
  const { t, site } = ctx;
  const actions = `<a class="btn btn--primary btn--lg" href="${href(ctx, "demo/")}">${t("nav.demo")}</a>
        <a class="btn btn--ghost btn--lg" href="${site.links.docs}">${t("nav.docs")}</a>`;
  return layout(ctx, {
    title: title(ctx, "platformPage.title"),
    description: t("platformPage.lead", {}, false),
    body: [
      pageHero(ctx, { label: t("nav.platform"), title: t("platformPage.title"), lead: t("platformPage.lead"), actions }),
      flow(ctx),
      modules(ctx),
      explorer(ctx),
      taxii(ctx),
      ctaBand(ctx),
    ].join("\n    "),
    scripts: ["tabs.js"],
  });
}

// ── Sécurité ────────────────────────────────────────────────────────────────────────────

const CONTROLS = [
  ["identity", "key", 4],
  ["data", "lock", 4],
  ["app", "shield", 4],
  ["supply", "box", 4],
  ["ops", "obs", 4],
];

function architecture(ctx) {
  const { t } = ctx;
  const node = (key, cls = "") => `<li class="arch__node ${cls}"><strong>${t(`securityPage.arch_${key}`)}</strong><span>${t(`securityPage.arch_${key}_text`)}</span></li>`;
  return `<section class="section" aria-labelledby="archi-titre">
    <div class="wrap arch-wrap">
      ${sectionHead({ label: t("securityPage.arch_label"), title: t("securityPage.arch_title"), lead: t("securityPage.arch_lead"), id: "archi-titre" })}
      <figure class="arch reveal">
        <div class="arch__outside">
          <p class="label">${t("securityPage.arch_internet")}</p>
          <ul>${node("users")}${node("sources", "arch__node--out")}</ul>
        </div>
        <div class="arch__server">
          <p class="label">${icon("server", "icon icon--inline")} ${t("securityPage.arch_server")}</p>
          <ul>${node("proxy")}${node("app")}${node("worker")}${node("db")}</ul>
        </div>
        <figcaption>${t("securityPage.arch_caption")}</figcaption>
      </figure>
    </div>
  </section>`;
}

function controls(ctx) {
  const { t } = ctx;
  return `<section class="section section--alt" aria-labelledby="controles-titre">
    <div class="wrap">
      ${sectionHead({ label: t("securityPage.controls_label"), title: t("securityPage.controls_title"), lead: t("securityPage.controls_lead"), id: "controles-titre" })}
      <div class="grid grid--controls">${CONTROLS.map(
        ([key, ic, count]) => `<article class="card reveal">${icon(ic, "icon icon--tile")}
          <h3>${t(`securityPage.${key}_title`)}</h3>
          <ul class="ticks ticks--sm">${Array.from({ length: count }, (_, i) => `<li>${t(`securityPage.${key}_b${i + 1}`)}</li>`).join("")}</ul>
        </article>`,
      ).join("")}</div>
    </div>
  </section>`;
}

export function securityPage(ctx) {
  const { t, site } = ctx;
  const actions = `<a class="btn btn--primary btn--lg" href="${href(ctx, "demo/")}">${t("nav.demo")}</a>
        <a class="btn btn--ghost btn--lg" href="${site.links.security}">${t("securityPage.disclosure_cta")}</a>`;
  return layout(ctx, {
    title: title(ctx, "securityPage.title"),
    description: t("securityPage.lead", {}, false),
    body: [
      pageHero(ctx, { label: t("nav.security"), title: t("securityPage.title"), lead: t("securityPage.lead"), actions }),
      architecture(ctx),
      controls(ctx),
      `<section class="section" aria-labelledby="preuves-titre">
    <div class="wrap">
      ${sectionHead({ label: t("trust.label"), title: t("trust.title"), lead: t("trust.lead"), id: "preuves-titre" })}
      ${trustCards(ctx)}
      ${complianceBlock(ctx)}
    </div>
  </section>`,
      `<section class="section section--alt" aria-labelledby="divulgation-titre">
    <div class="wrap narrow reveal">
      <p class="label">${t("securityPage.disclosure_label")}</p>
      <h2 id="divulgation-titre">${t("securityPage.disclosure_title")}</h2>
      <p class="lead">${t("securityPage.disclosure_text")}</p>
      <p><a class="btn btn--ghost" href="${site.links.security}">${t("securityPage.disclosure_cta")} ${icon("external", "icon icon--inline")}</a></p>
    </div>
  </section>`,
      ctaBand(ctx),
    ].join("\n    "),
  });
}

// ── Tarifs ──────────────────────────────────────────────────────────────────────────────

const INCLUDED = [
  ["modules", [1, 1, 1]],
  ["selfhost", [1, 1, 1]],
  ["updates", [1, 1, 1]],
  ["community", [1, 1, 1]],
  ["deploy", [0, 1, 1]],
  ["config", [0, 1, 1]],
  ["onboarding", [0, 1, 0]],
  ["review", [0, 1, 0]],
  ["rules", [0, 0, 1]],
  ["priority", [0, 0, 1]],
];
const PRICING_FAQ = ["indicative", "limited", "start", "data"];

export function pricingPage(ctx) {
  const { t } = ctx;
  const cols = ["community", "pilot", "support"];
  const table = `<div class="table-wrap reveal" tabindex="0" role="region" aria-label="${t("pricingPage.included_title")}">
        <table class="compare compare--check">
          <thead><tr><th scope="col"><span class="sr-only">${t("compare.criterion")}</span></th>${cols
            .map((c) => `<th scope="col"${c === "pilot" ? ' class="is-us"' : ""}>${t(`offers.${c}_title`)}</th>`)
            .join("")}</tr></thead>
          <tbody>${INCLUDED.map(
            ([row, marks]) =>
              `<tr><th scope="row">${t(`pricingPage.row_${row}`)}</th>${marks
                .map(
                  (m, i) =>
                    `<td${cols[i] === "pilot" ? ' class="is-us"' : ""}>${
                      m ? `${icon("ci", "icon icon--yes")}<span class="sr-only">${t("pricingPage.yes")}</span>` : `<span class="muted" aria-label="${t("pricingPage.no")}">—</span>`
                    }</td>`,
                )
                .join("")}</tr>`,
          ).join("")}</tbody>
        </table>
      </div>`;
  return layout(ctx, {
    title: title(ctx, "pricingPage.title"),
    description: t("pricingPage.lead", {}, false),
    body: [
      pageHero(ctx, { label: t("nav.pricing"), title: t("pricingPage.title"), lead: t("pricingPage.lead") }),
      `<section class="section section--tight" aria-label="${t("offers.label")}">
    <div class="wrap">
      ${offerCards(ctx)}
    </div>
  </section>`,
      `<section class="section section--alt" aria-labelledby="inclus-titre">
    <div class="wrap">
      ${sectionHead({ label: t("offers.label"), title: t("pricingPage.included_title"), id: "inclus-titre" })}
      ${table}
    </div>
  </section>`,
      `<section class="section" aria-labelledby="comparer-titre">
    <div class="wrap">
      ${sectionHead({ label: t("compare.label"), title: t("compare.title"), lead: t("compare.lead"), id: "comparer-titre" })}
      ${compareTable(ctx)}
    </div>
  </section>`,
      `<section class="section section--alt" aria-labelledby="faq-tarifs">
    <div class="wrap faq">
      ${sectionHead({ label: t("faq.label"), title: t("pricingPage.faq_title"), id: "faq-tarifs" })}
      ${faqList(ctx, "pricingPage", PRICING_FAQ)}
    </div>
  </section>`,
      ctaBand(ctx),
    ].join("\n    "),
  });
}

// ── À propos ────────────────────────────────────────────────────────────────────────────

const VALUES = [
  ["measured", "real"],
  ["open", "open"],
  ["sovereign", "lock"],
  ["global", "globe"],
];
const MILESTONES = [
  ["m1", "done"], ["m2", "done"], ["m3", "done"], ["m4", "done"], ["m5", "done"], ["m6", "done"],
  ["m7", "progress"], ["m8", "done"], ["m9", "delivered"], ["m10", "delivered"], ["m11", "delivered"],
];

export function aboutPage(ctx) {
  const { t, site } = ctx;
  return layout(ctx, {
    title: title(ctx, "aboutPage.title"),
    description: t("aboutPage.lead", {}, false),
    body: [
      pageHero(ctx, { label: t("nav.about"), title: t("aboutPage.title"), lead: t("aboutPage.lead") }),
      `<section class="section" aria-labelledby="histoire-titre">
    <div class="wrap story">
      <div class="reveal">
        <p class="label">${t("aboutPage.story_label")}</p>
        <h2 id="histoire-titre">${t("aboutPage.story_title")}</h2>
      </div>
      <div class="story__text reveal">
        <p>${t("aboutPage.story_p1")}</p>
        <p>${t("aboutPage.story_p2")}</p>
        <p>${t("aboutPage.story_p3")}</p>
        <div class="founder">
          <img src="${ctx.asset("img/illwatch-mark.svg")}" alt="" width="48" height="48">
          <p><strong>Godwill Foka</strong><span>${t("aboutPage.founder_role")}</span></p>
        </div>
      </div>
    </div>
  </section>`,
      `<section class="section section--alt" aria-labelledby="valeurs-titre">
    <div class="wrap">
      ${sectionHead({ label: t("aboutPage.values_label"), title: t("aboutPage.values_title"), id: "valeurs-titre" })}
      <div class="grid grid--4">${VALUES.map(
        ([k, ic]) => `<article class="card reveal">${icon(ic, "icon icon--tile")}<h3>${t(`aboutPage.${k}_title`)}</h3><p>${t(`aboutPage.${k}_text`)}</p></article>`,
      ).join("")}</div>
    </div>
  </section>`,
      `<section class="section" aria-labelledby="jalons-titre">
    <div class="wrap">
      ${sectionHead({ label: t("roadmap.label"), title: t("aboutPage.roadmap_title"), lead: t("roadmap.lead"), id: "jalons-titre" })}
      <ol class="milestones reveal">${MILESTONES.map(
        ([m, state]) =>
          `<li class="milestone milestone--${state}"><span class="mono">${m.toUpperCase()}</span><span class="milestone__name">${t(`roadmap.${m}`)}</span><span class="status status--${state}">${t(`roadmap.${state}`)}</span></li>`,
      ).join("")}</ol>
      <p><a href="${site.links.roadmap}">${t("roadmap.link")} ${icon("external", "icon icon--inline")}</a></p>
    </div>
  </section>`,
      ctaBand(ctx),
    ].join("\n    "),
  });
}

// ── Démonstration (lot S4) ──────────────────────────────────────────────────────────────

const INTERESTS = ["DEMO", "PILOT", "SUPPORT", "OTHER"];

function countryOptions(locale) {
  // Liste ISO 3166 construite avec les noms localisés du moteur Intl (aucune donnée tierce).
  const names = new Intl.DisplayNames([locale], { type: "region", fallback: "none" });
  const skip = new Set(["EU", "EZ", "UN", "QO", "XA", "XB", "ZZ", "AN", "BU", "CS", "DD", "FX", "NT", "QU", "SU", "TP", "YD", "YU", "ZR", "DY", "HV", "NH", "RH", "VD", "UK"]);
  const out = [];
  for (let a = 65; a <= 90; a++) {
    for (let b = 65; b <= 90; b++) {
      const code = String.fromCharCode(a, b);
      if (skip.has(code)) continue;
      const name = names.of(code);
      if (name && name !== code && !/unknown|inconnu/i.test(name)) out.push([code, name]);
    }
  }
  return out.sort((x, y) => x[1].localeCompare(y[1], locale));
}

function demoForm(ctx) {
  const { t, lang, site } = ctx;
  const field = (name, label, attrs = "", hint = "") =>
    `<label class="field"><span>${label}</span><input name="${name}" ${attrs}>${hint ? `<small>${hint}</small>` : ""}</label>`;
  const messages = { sent: t("demoPage.sent", {}, false), error: t("demoPage.error", {}, false), limited: t("demoPage.limited", {}, false), invalid: t("demoPage.invalid", {}, false) };
  return `<form class="card demo-form" data-demo-form data-endpoint="${esc(site.demoEndpoint)}" data-lang-code="${lang.code}" data-messages="${esc(JSON.stringify(messages))}" novalidate>
        ${field("name", t("demoPage.f_name"), 'required minlength="2" maxlength="120" autocomplete="name"')}
        ${field("email", t("demoPage.f_email"), 'type="email" required maxlength="254" autocomplete="email"')}
        ${field("organisation", t("demoPage.f_org"), 'required minlength="2" maxlength="160" autocomplete="organization"')}
        ${field("job_title", t("demoPage.f_job"), 'maxlength="120" autocomplete="organization-title"')}
        <label class="field"><span>${t("demoPage.f_country")}</span><select name="country" autocomplete="country"><option value="">—</option>${countryOptions(lang.locale)
          .map(([code, name]) => `<option value="${code}">${esc(name)}</option>`)
          .join("")}</select></label>
        <label class="field"><span>${t("demoPage.f_interest")}</span><select name="interest">${INTERESTS.map(
          (i) => `<option value="${i}">${t(`demoPage.interest_${i}`)}</option>`,
        ).join("")}</select></label>
        <label class="field field--wide"><span>${t("demoPage.f_message")}</span><textarea name="message" rows="4" maxlength="2000"></textarea></label>
        <label class="field field--trap" aria-hidden="true"><span>Website</span><input name="website" tabindex="-1" autocomplete="off"></label>
        <label class="check field--wide"><input type="checkbox" name="consent" required><span>${t("demoPage.consent", { privacy: `<a href="${href(ctx, "privacy/")}">${t("footer.privacy_policy", {}, false)}</a>` }, false)}</span></label>
        <div class="field--wide demo-form__actions">
          <button class="btn btn--primary btn--lg" type="submit">${t("demoPage.submit")}</button>
          <p class="demo-form__status" role="status" aria-live="polite"></p>
        </div>
        <noscript><p class="note field--wide">${t("demoPage.noscript")}</p></noscript>
      </form>`;
}

function demoFallback(ctx) {
  const { t, site } = ctx;
  return `<div class="card demo-fallback">
        ${icon("mail", "icon icon--tile")}
        <h2>${t("demoPage.fallback_title")}</h2>
        <p>${t("demoPage.fallback_text")}</p>
        <p><a class="btn btn--primary btn--lg" href="${site.links.demo}">${t("demoPage.fallback_cta")}</a></p>
        <p class="note">${t("demoPage.fallback_note")}</p>
      </div>`;
}

export function demoPage(ctx) {
  const { t, site } = ctx;
  return layout(ctx, {
    title: title(ctx, "demoPage.title"),
    description: t("demoPage.lead", {}, false),
    body: [
      pageHero(ctx, { label: t("nav.demo"), title: t("demoPage.title"), lead: t("demoPage.lead") }),
      `<section class="section section--tight" aria-label="${t("demoPage.title")}">
    <div class="wrap demo">
      <div class="demo__steps reveal">
        <p class="label">${t("demoPage.next_label")}</p>
        <ol class="steps">${[1, 2, 3]
          .map((i) => `<li><strong>${t(`demoPage.step${i}_title`)}</strong><span>${t(`demoPage.step${i}_text`)}</span></li>`)
          .join("")}</ol>
        <p class="note">${t("demoPage.privacy_note")}</p>
      </div>
      <div class="reveal">${site.demoEndpoint ? demoForm(ctx) : demoFallback(ctx)}</div>
    </div>
  </section>`,
    ].join("\n    "),
    scripts: site.demoEndpoint ? ["demo-form.js"] : [],
  });
}

// ── Mentions légales et confidentialité ─────────────────────────────────────────────────

function legalValue(ctx, key) {
  const value = ctx.legal[key];
  return value ? esc(value) : `<span class="todo">${ctx.t("legal.todo")}</span>`;
}

export function legalPage(ctx) {
  const { t, legal } = ctx;
  const v = (key) => legalValue(ctx, key);
  const optional = (key, label) => (legal[key] ? `<dt>${label}</dt><dd>${esc(legal[key])}</dd>` : "");
  return layout(ctx, {
    title: title(ctx, "legal.title"),
    description: t("legal.lead", {}, false),
    noindex: !ctx.legalComplete,
    body: `<section class="section prose-wrap">
    <div class="wrap narrow prose">
      <h1 id="page-title">${t("legal.title")}</h1>
      <p class="lead">${t("legal.lead")}</p>
      <h2>${t("legal.provider")}</h2>
      <p>${v("operator")}<br>${t("legal.represented")} ${v("representative")}<br>${v("street")}<br>${v("postcode_city")}<br>${v("country")}</p>
      <h2>${t("legal.contact")}</h2>
      <dl class="facts-list"><dt>${t("legal.email")}</dt><dd>${v("email")}</dd>${optional("phone", t("legal.phone"))}</dl>
      ${legal.vat_id || legal.register ? `<h2>${t("legal.registration")}</h2><dl class="facts-list">${optional("vat_id", t("legal.vat"))}${optional("register", t("legal.register"))}</dl>` : ""}
      <h2>${t("legal.responsible")}</h2>
      <p>${v("content_responsible")}${legal.street ? `, ${esc(legal.street)}, ${esc(legal.postcode_city)}` : ""}</p>
      <h2>${t("legal.dispute_title")}</h2>
      <p>${t("legal.dispute_text")}</p>
      <h2>${t("legal.liability_title")}</h2>
      <p>${t("legal.liability_text")}</p>
      <p class="note">${t("legal.language_note")}</p>
    </div>
  </section>`,
  });
}

const PRIVACY_SECTIONS = ["controller", "visit", "language", "storage", "demo", "nocookies", "rights", "changes"];

export function privacyPage(ctx) {
  const { t, legal, date } = ctx;
  const vars = {
    operator: legal.operator || t("legal.todo", {}, false),
    email: legal.email || t("legal.todo", {}, false),
    hosting: legal.hosting || t("legal.todo", {}, false),
  };
  return layout(ctx, {
    title: title(ctx, "privacy.title"),
    description: t("privacy.lead", {}, false),
    noindex: !ctx.legalComplete,
    body: `<section class="section prose-wrap">
    <div class="wrap narrow prose">
      <h1 id="page-title">${t("privacy.title")}</h1>
      <p class="lead">${t("privacy.lead")}</p>
      ${PRIVACY_SECTIONS.map((s) => `<h2>${t(`privacy.${s}_title`)}</h2><p>${t(`privacy.${s}_text`, vars)}</p>`).join("\n      ")}
      <p class="note">${t("privacy.updated", { date: date(legal.updated) })}</p>
    </div>
  </section>`,
  });
}

export const PAGES = [
  ["platform/", platformPage],
  ["security/", securityPage],
  ["pricing/", pricingPage],
  ["about/", aboutPage],
  ["demo/", demoPage],
  ["legal/", legalPage],
  ["privacy/", privacyPage],
];
