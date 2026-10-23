// Choix de la langue à la première visite (ADR-027) : même ordre que l'API.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  browserLanguages,
  countryFromTimeZone,
  langForCountry,
  matchLanguage,
  pickLanguage,
  readSaved,
  saveChoice,
  STORAGE_KEY,
} from "../src/assets/js/lang.js";

const { countries } = JSON.parse(readFileSync(new URL("../src/data/country-languages.json", import.meta.url), "utf8"));

test("langues du navigateur : prises en charge, dans l'ordre, sans doublon", () => {
  assert.deepEqual(browserLanguages(["de-AT", "en", "de"]), ["de", "en"]);
  assert.equal(matchLanguage(["ja-JP", "zh-Hant-TW", "en"]), "zh");
  assert.equal(matchLanguage(["pt-BR", "es-419"]), "es");
  assert.equal(matchLanguage(["FR_ca"]), "fr");
  assert.equal(matchLanguage(["ja", "ko"]), null);
  assert.equal(matchLanguage([undefined, ""]), null);
});

test("fuseau horaire → pays", () => {
  assert.equal(countryFromTimeZone("Europe/Paris"), "FR");
  assert.equal(countryFromTimeZone("Africa/Douala"), "CM");
  assert.equal(countryFromTimeZone("Europe/Berlin"), "DE");
  assert.equal(countryFromTimeZone("America/Argentina/Buenos_Aires"), "AR");
  assert.equal(countryFromTimeZone("America/Indiana/Indianapolis"), "US");
  assert.equal(countryFromTimeZone("Asia/Tokyo"), null);
  assert.equal(countryFromTimeZone(""), null);
});

test("tout pays du fuseau horaire figure dans la table de l'API", () => {
  for (const zone of ["Europe/Paris", "Europe/Zurich", "America/Toronto", "Asia/Singapore", "Africa/Malabo"]) {
    assert.ok(countries[countryFromTimeZone(zone)], zone);
  }
});

test("langue d'un pays ; le navigateur départage un pays bilingue", () => {
  assert.equal(langForCountry("DE", ["en-US"], countries), "de");
  assert.equal(langForCountry("CH", ["fr-CH", "en"], countries), "fr");
  assert.equal(langForCountry("CH", ["ja"], countries), "de");
  assert.equal(langForCountry("CH", ["ja"], countries, "fr"), "fr");
  assert.equal(langForCountry("CM", ["en-GB"], countries), "en");
  assert.equal(langForCountry("CM", [], countries), "fr");
  assert.equal(langForCountry("JP", ["de"], countries), null);
});

test("ordre : choix mémorisé → serveur → pays → navigateur → instance → anglais", () => {
  const all = {
    saved: "es",
    serverLang: "zh",
    timeZone: "Europe/Paris",
    languages: ["de-DE"],
    instanceLang: "fr",
    countries,
  };
  assert.equal(pickLanguage(all), "es");
  assert.equal(pickLanguage({ ...all, saved: null }), "zh");
  // Pays d'abord : un visiteur en France avec un navigateur allemand lit le français.
  assert.equal(pickLanguage({ ...all, saved: null, serverLang: null }), "fr");
  assert.equal(pickLanguage({ ...all, saved: null, serverLang: null, timeZone: "Asia/Tokyo" }), "de");
  assert.equal(
    pickLanguage({ ...all, saved: null, serverLang: null, timeZone: "Asia/Tokyo", languages: ["ja"] }),
    "fr",
  );
  assert.equal(pickLanguage({ languages: ["ja"], timeZone: "Asia/Tokyo", countries }), "en");
  assert.equal(pickLanguage(), "en");
});

test("valeurs inconnues ignorées", () => {
  assert.equal(pickLanguage({ saved: "xx", serverLang: "<b>", languages: ["fr"], countries }), "fr");
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
