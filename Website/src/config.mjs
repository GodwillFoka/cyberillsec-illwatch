// Configuration du site de présentation ILL Watch (ADR-027).
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

export const LINKS = {
  gitlab: "https://gitlab.com/GodwillFoka/cyberillsec-illwatch",
  github: "https://github.com/GodwillFoka/cyberillsec-illwatch",
  docs: "https://godwillfoka.github.io/cyberillsec-illwatch/",
  releases: "https://github.com/GodwillFoka/cyberillsec-illwatch/releases",
  license: "https://gitlab.com/GodwillFoka/cyberillsec-illwatch/-/blob/main/LICENSE",
  security: "https://gitlab.com/GodwillFoka/cyberillsec-illwatch/-/blob/main/SECURITY.md",
  roadmap: "https://godwillfoka.github.io/cyberillsec-illwatch/ROADMAP/",
};

// Budget de poids de l'accueil (HTML + CSS + JS + image principale), en octets.
export const HOME_BUDGET = 500 * 1024;
