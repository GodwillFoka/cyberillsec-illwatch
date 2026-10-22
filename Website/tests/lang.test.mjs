// Choix de la langue à la première visite (ADR-027, décision 3).
import assert from "node:assert/strict";
import { test } from "node:test";

import { langFromTimeZone, matchLanguage, pickLanguage, readSaved, saveChoice, STORAGE_KEY } from "../src/assets/js/lang.js";

test("langue du navigateur : première étiquette prise en charge", () => {
  assert.equal(matchLanguage(["de-AT", "en"]), "de");
  assert.equal(matchLanguage(["ja-JP", "zh-Hant-TW", "en"]), "zh");
  assert.equal(matchLanguage(["pt-BR", "es-419"]), "es");
  assert.equal(matchLanguage(["FR_ca"]), "fr");
  assert.equal(matchLanguage(["ja", "ko"]), null);
  assert.equal(matchLanguage([undefined, ""]), null);
});

test("pays déduit du fuseau horaire", () => {
  assert.equal(langFromTimeZone("Europe/Paris"), "fr");
  assert.equal(langFromTimeZone("Africa/Douala"), "fr");
  assert.equal(langFromTimeZone("Europe/Berlin"), "de");
  assert.equal(langFromTimeZone("Europe/Vienna"), "de");
  assert.equal(langFromTimeZone("America/Mexico_City"), "es");
  assert.equal(langFromTimeZone("America/Argentina/Buenos_Aires"), "es");
  assert.equal(langFromTimeZone("Asia/Shanghai"), "zh");
  assert.equal(langFromTimeZone("America/New_York"), null);
  assert.equal(langFromTimeZone(""), null);
});

test("ordre : choix mémorisé → navigateur → pays (IP) → fuseau → anglais", () => {
  const all = { saved: "es", languages: ["de-DE"], countryLang: "fr", timeZone: "Asia/Shanghai" };
  assert.equal(pickLanguage(all), "es");
  assert.equal(pickLanguage({ ...all, saved: null }), "de");
  assert.equal(pickLanguage({ ...all, saved: null, languages: ["ja"] }), "fr");
  assert.equal(pickLanguage({ ...all, saved: null, languages: ["ja"], countryLang: null }), "zh");
  assert.equal(pickLanguage({ languages: ["ja"], timeZone: "Asia/Tokyo" }), "en");
  assert.equal(pickLanguage(), "en");
});

test("un choix mémorisé inconnu est ignoré", () => {
  assert.equal(pickLanguage({ saved: "xx", languages: ["fr"] }), "fr");
});

test("stockage : lecture et écriture tolèrent un navigateur qui refuse", () => {
  const memory = new Map();
  const ok = { getItem: (k) => memory.get(k) ?? null, setItem: (k, v) => memory.set(k, v) };
  saveChoice(ok, "zh");
  assert.equal(memory.get(STORAGE_KEY), "zh");
  saveChoice(ok, "xx");
  assert.equal(readSaved(ok), "zh");
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
  assert.equal(readSaved(null), null);
});
