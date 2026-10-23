import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { formatAge, formatAgo, formatDay, formatHours, formatNumber, formatShare } from "../lib/format.js";
import { countryName, iocTypeLabel } from "../lib/iocs.js";
import { INCIDENT_STATUS, TIER_LABEL, levelLabel } from "../lib/levels.js";
import { auditLabel, formatBytes, formatDuration } from "../lib/ops.js";
import { LANGS, currentLang, defineMessages, interpolate, isLang, setCurrentLang } from "./core.js";
import { fetchServerLanguage, matchLanguage, pickLanguage, readSaved, saveChoice, STORAGE_KEY } from "./detect.js";

const now = new Date("2026-10-10T12:00:00Z");
const spaces = (text: string) => text.replace(/[  ]/g, " ");

afterEach(() => setCurrentLang("fr"));

describe("noyau de traduction", () => {
  const t = defineMessages({
    fr: { hello: "Bonjour {name}", items_one: "{count} élément", items_other: "{count} éléments" },
    en: { hello: "Hello {name}", items_one: "{count} item", items_other: "{count} items" },
    de: { hello: "Hallo {name}", items_one: "{count} Element", items_other: "{count} Elemente" },
    es: { hello: "Hola {name}", items_one: "{count} elemento", items_other: "{count} elementos" },
    zh: { hello: "你好，{name}", items_one: "{count} 项", items_other: "{count} 项" },
  });

  it("traduit selon la langue courante", () => {
    assert.equal(t("hello", { name: "Ada" }), "Bonjour Ada");
    setCurrentLang("de");
    assert.equal(currentLang(), "de");
    assert.equal(t("hello", { name: "Ada" }), "Hallo Ada");
    assert.equal(t.in("zh", "hello", { name: "Ada" }), "你好，Ada");
  });

  it("pluriels : le français met 0 et 1 au singulier, l'anglais seulement 1", () => {
    assert.equal(t.plural("items", 0), "0 élément");
    assert.equal(t.plural("items", 1), "1 élément");
    assert.equal(spaces(t.plural("items", 1200)), "1 200 éléments");
    setCurrentLang("en");
    assert.equal(t.plural("items", 0), "0 items");
    assert.equal(t.plural("items", 1), "1 item");
    assert.equal(t.plural("items", 1200), "1,200 items");
  });

  it("une variable absente reste visible plutôt que de disparaître", () => {
    assert.equal(interpolate("{a} et {b}", { a: 1 }), "1 et {b}");
  });

  it("langues prises en charge", () => {
    assert.deepEqual([...LANGS], ["fr", "en", "de", "es", "zh"]);
    assert.ok(isLang("zh") && !isLang("ja") && !isLang(undefined));
  });
});

describe("formats dans chaque langue", () => {
  it("nombres", () => {
    setCurrentLang("en");
    assert.equal(formatNumber(528453), "528,453");
    setCurrentLang("de");
    assert.equal(formatNumber(528453), "528.453");
  });

  it("anciennetés et durées", () => {
    setCurrentLang("en");
    assert.equal(formatAgo(new Date("2026-10-10T11:56:00Z"), now), "4 min ago");
    assert.equal(formatAge(new Date("2026-10-07T12:00:00Z"), now), "3 d");
    assert.equal(formatHours(3.46), "3.5 h");
    assert.equal(formatDuration(90_000), "1 d 1 h");
    assert.equal(formatBytes(1536), "1.5 KiB");
    assert.equal(formatShare(0.834), "83%");
    setCurrentLang("de");
    assert.equal(formatAgo(new Date("2026-10-10T11:56:00Z"), now), "vor 4 Min.");
    assert.equal(formatHours(3.46), "3,5 Std.");
    setCurrentLang("zh");
    assert.equal(formatAgo(new Date("2026-10-10T11:59:30Z"), now), "刚刚");
    assert.equal(formatAgo(new Date("2026-10-10T09:00:00Z"), now), "3 小时前");
  });

  it("dates courtes dans l'ordre de la langue", () => {
    const date = new Date("2026-10-03T07:05:09Z");
    assert.equal(formatDay(date, true), "03/10");
    setCurrentLang("de");
    assert.equal(formatDay(date, true), "03.10.");
  });

  it("libellés métier", () => {
    setCurrentLang("en");
    assert.equal(levelLabel("CRITICAL"), "Critical");
    assert.equal(levelLabel("P1_ELEVE"), "P1");
    assert.equal(INCIDENT_STATUS.CLOTURE, "Closed");
    assert.equal(INCIDENT_STATUS.INCONNU, undefined);
    assert.equal(TIER_LABEL.L2, "L2 · investigation");
    assert.equal(auditLabel("user.disable"), "Account disabled");
    assert.equal(iocTypeLabel("DOMAIN"), "Domain");
    assert.equal(iocTypeLabel("HASH_SHA256"), "SHA-256");
    assert.equal(countryName("DE"), "Germany (DE)");
    assert.equal(countryName(null), "unknown");
    setCurrentLang("es");
    assert.equal(INCIDENT_STATUS.CONFINEMENT, "Contención");
    assert.equal(countryName("US"), "Estados Unidos (US)");
    assert.deepEqual(Object.keys(INCIDENT_STATUS).length, 6);
  });
});

describe("langue à l'ouverture", () => {
  it("navigateur : première langue prise en charge", () => {
    assert.equal(matchLanguage(["ja-JP", "de-AT", "en"]), "de");
    assert.equal(matchLanguage(["zh-Hant-TW"]), "zh");
    assert.equal(matchLanguage(["pt-BR", null, undefined]), null);
  });

  it("ordre : choix mémorisé → serveur (pays) → navigateur → anglais", () => {
    assert.equal(pickLanguage({ saved: "es", server: "de", languages: ["fr"] }), "es");
    assert.equal(pickLanguage({ saved: "xx", server: "de", languages: ["fr"] }), "de");
    assert.equal(pickLanguage({ server: null, languages: ["fr-CA"] }), "fr");
    assert.equal(pickLanguage({ languages: ["ja"] }), "en");
  });

  it("stockage refusé : ni erreur ni préférence", () => {
    const refusing = {
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
    };
    assert.equal(readSaved(refusing), null);
    assert.doesNotThrow(() => saveChoice(refusing, "fr"));
    const memory = new Map<string, string>();
    saveChoice({ getItem: (k) => memory.get(k) ?? null, setItem: (k, v) => void memory.set(k, v) }, "zh");
    assert.equal(memory.get(STORAGE_KEY), "zh");
  });

  it("réponse du serveur validée, panne ou lenteur sans conséquence", async () => {
    const answer = (body: unknown, ok = true) =>
      (async () => ({ ok, json: async () => body })) as unknown as typeof fetch;
    assert.equal(await fetchServerLanguage(answer({ lang: "de", source: "country" })), "de");
    assert.equal(await fetchServerLanguage(answer({ lang: "<script>" })), null);
    assert.equal(await fetchServerLanguage(answer({ lang: "de" }, false)), null);
    const failing = (async () => {
      throw new Error("réseau");
    }) as unknown as typeof fetch;
    assert.equal(await fetchServerLanguage(failing), null);
    const slow = ((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("abandon")));
      })) as unknown as typeof fetch;
    assert.equal(await fetchServerLanguage(slow, 20), null);
  });
});
