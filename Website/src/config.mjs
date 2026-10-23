// Configuration du site de présentation ILLWATCH (ADR-027).
// Ajouter une langue : un dictionnaire src/i18n/<code>.json + une ligne dans LANGS.

export const LANGS = [
  { code: "fr", html: "fr", locale: "fr-FR", name: "Français" },
  { code: "en", html: "en", locale: "en-GB", name: "English" },
  { code: "de", html: "de", locale: "de-DE", name: "Deutsch" },
  { code: "es", html: "es", locale: "es-ES", name: "Español" },
  { code: "zh", html: "zh-Hans", locale: "zh-CN", name: "简体中文" },
];

export const DEFAULT_LANG = "en";

// Langue de référence : toutes les autres doivent avoir exactement les mêmes clés.
export const REFERENCE_LANG = "fr";

// Adresse publique du site (liens canoniques, hreflang, plan du site). Domaine non choisi au
// 22/10/2026 : valeur provisoire, à remplacer par ILLWATCH_SITE_URL au moment de la publication.
export const SITE_URL = (process.env.ILLWATCH_SITE_URL || "https://illwatch.example").replace(/\/$/, "");

// Chemin de base si le site est servi sous un sous-dossier (ex. « /site/ »).
export const BASE = (process.env.ILLWATCH_SITE_BASE || "/").replace(/\/?$/, "/");

// Point d'entrée serveur facultatif qui renvoie {"lang": "de"} d'après le pays de l'adresse IP
// (DB-IP Lite locale, ADR-019) ; vide tant que le site est statique (lot S6).
export const GEO_ENDPOINT = process.env.ILLWATCH_SITE_GEO_ENDPOINT || "";

// Pays et langue de l'instance (mêmes rôles que INSTANCE_COUNTRY et DEFAULT_LANGUAGE côté API) :
// dernier recours avant l'anglais quand ni le pays du visiteur ni son navigateur ne décident.
export const INSTANCE_COUNTRY = (process.env.ILLWATCH_SITE_COUNTRY || "").trim().toUpperCase();
export const INSTANCE_LANG = (process.env.ILLWATCH_SITE_DEFAULT_LANG || "").trim().toLowerCase();

// Dépôt public du projet : GitLab (décision du 23/10/2026, tous les liens du site y mènent).
const GITLAB = "https://gitlab.com/GodwillFoka/cyberillsec-illwatch";

// Documentation : publiée par GitLab Pages avec le site (job « pages », sous /docs/) ; à défaut
// d'adresse fournie à la construction, le dossier docs/ du dépôt.
const DOCS = (process.env.ILLWATCH_SITE_DOCS_URL || `${GITLAB}/-/tree/main/docs`).replace(/\/?$/, "/");

// Demande de démonstration (lot S4) :
// - ILLWATCH_SITE_DEMO_ENDPOINT : adresse de `POST /api/v1/demo-requests` de l'application
//   (même origine, ex. « /api/v1/demo-requests », ou absolue) → formulaire sur le site ;
// - ILLWATCH_SITE_CONTACT : « mailto:… » ou « https://… » si aucun formulaire n'est servi ;
// - à défaut : ticket GitLab pré-rempli (modèle .gitlab/issue_templates/Demo.md).
export const DEMO_ENDPOINT = (process.env.ILLWATCH_SITE_DEMO_ENDPOINT || "").trim();
const CONTACT = (process.env.ILLWATCH_SITE_CONTACT || "").trim();
const DEMO_FALLBACK = `${GITLAB}/-/issues/new?issuable_template=Demo`;

export const LINKS = {
  demo: /^(?:https:\/\/|mailto:)/.test(CONTACT) ? CONTACT : DEMO_FALLBACK,
  gitlab: GITLAB,
  clone: `${GITLAB}.git`,
  docs: DOCS,
  releases: `${GITLAB}/-/releases`,
  issues: `${GITLAB}/-/issues`,
  license: `${GITLAB}/-/blob/main/LICENSE`,
  security: `${GITLAB}/-/blob/main/SECURITY.md`,
  roadmap: process.env.ILLWATCH_SITE_DOCS_URL ? `${DOCS}ROADMAP/` : `${GITLAB}/-/blob/main/docs/ROADMAP.md`,
};

// Budget de poids de l'accueil (HTML + CSS + JS + image principale), en octets.
export const HOME_BUDGET = 500 * 1024;
