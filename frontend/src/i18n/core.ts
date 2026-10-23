// Traduction de l'interface (ADR-027) : cinq langues, aucune dépendance.
//
// Chaque écran déclare ses textes dans un fichier `*.i18n.ts`, les cinq langues côte à côte :
//
//   export const t = defineMessages({
//     fr: { title: "Vue d'ensemble", alerts_one: "{count} alerte", alerts_other: "{count} alertes" },
//     en: { title: "Overview", ... }, de: {...}, es: {...}, zh: {...},
//   });
//   t("title"); t.plural("alerts", 3);
//
// Le français fait référence : une clé absente ou en trop dans une autre langue est une erreur
// de compilation. Les textes voyagent avec l'écran qui les utilise (écrans chargés à la demande).
// Ce module n'utilise ni React ni le DOM : il sert aussi aux tests (node --test).

export const LANGS = ["fr", "en", "de", "es", "zh"] as const;
export type Lang = (typeof LANGS)[number];

/** Nom de chaque langue dans cette langue (sélecteur). */
export const LANGUAGE_NAMES: Record<Lang, string> = {
  fr: "Français",
  en: "English",
  de: "Deutsch",
  es: "Español",
  zh: "简体中文",
};

/** Étiquette BCP 47 pour Intl (nombres, dates) et l'attribut lang du document. */
export const LOCALES: Record<Lang, string> = {
  fr: "fr-FR",
  en: "en-GB",
  de: "de-DE",
  es: "es-ES",
  zh: "zh-CN",
};
const HTML_LANG: Record<Lang, string> = { fr: "fr", en: "en", de: "de", es: "es", zh: "zh-Hans" };

let current: Lang = "fr";

export function isLang(value: unknown): value is Lang {
  return typeof value === "string" && (LANGS as readonly string[]).includes(value);
}

export function currentLang(): Lang {
  return current;
}

export function currentLocale(): string {
  return LOCALES[current];
}

/** Change la langue courante (le rendu suivant l'utilise) et l'attribut lang du document. */
export function setCurrentLang(lang: Lang): void {
  current = lang;
  const doc = (globalThis as { document?: { documentElement: { lang: string } } }).document;
  if (doc) doc.documentElement.lang = HTML_LANG[lang];
}

export type Vars = Record<string, string | number>;

const numberFormats = new Map<string, Intl.NumberFormat>();
function formatVar(value: string | number): string {
  if (typeof value === "string") return value;
  const locale = currentLocale();
  let format = numberFormats.get(locale);
  if (!format) {
    format = new Intl.NumberFormat(locale, { maximumFractionDigits: 2 });
    numberFormats.set(locale, format);
  }
  return format.format(value);
}

/** Remplace `{nom}` par la variable ; un nombre est formaté selon la langue (« 1 234 », « 1,234 »). */
export function interpolate(text: string, vars?: Vars): string {
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in vars ? formatVar(vars[name] as string | number) : whole,
  );
}

type Messages<F> = { fr: F } & { [L in Exclude<Lang, "fr">]: { [K in keyof F]: string } };

/** Clés de base des pluriels : `x` quand `x_one` et `x_other` existent. */
export type PluralBase<F> = {
  [K in keyof F & string]: K extends `${infer B}_other` ? (`${B}_one` extends keyof F ? B : never) : never;
}[keyof F & string];

export interface Translator<F> {
  (key: keyof F & string, vars?: Vars): string;
  /** Forme du pluriel selon la langue (le français met 0 au singulier) ; `{count}` est fourni. */
  plural(base: PluralBase<F>, count: number, vars?: Vars): string;
  /** Texte dans une langue donnée (sélecteur de langue, tests). */
  in(lang: Lang, key: keyof F & string, vars?: Vars): string;
}

const pluralRules = new Map<string, Intl.PluralRules>();

export function defineMessages<F extends Record<string, string>>(messages: Messages<F>): Translator<F> {
  const lookup = (lang: Lang, key: keyof F & string): string => {
    const table = messages[lang] as Record<string, string>;
    return table[key] ?? (messages.fr as Record<string, string>)[key] ?? key;
  };
  const t = ((key: keyof F & string, vars?: Vars) => interpolate(lookup(current, key), vars)) as Translator<F>;
  t.in = (lang, key, vars) => interpolate(lookup(lang, key), vars);
  t.plural = (base, count, vars) => {
    const locale = currentLocale();
    let rules = pluralRules.get(locale);
    if (!rules) {
      rules = new Intl.PluralRules(locale);
      pluralRules.set(locale, rules);
    }
    const form = rules.select(count) === "one" ? "one" : "other";
    return interpolate(lookup(current, `${base}_${form}` as keyof F & string), { count, ...vars });
  };
  return t;
}
