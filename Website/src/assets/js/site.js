// Commun à toutes les pages : un choix de langue fait dans le sélecteur est mémorisé, il
// l'emporte ensuite sur toute détection automatique (ADR-027).
import { saveChoice } from "./lang.js";

let storage = null;
try {
  storage = window.localStorage;
} catch {
  storage = null;
}

for (const link of document.querySelectorAll("[data-lang-choice]")) {
  link.addEventListener("click", () => saveChoice(storage, link.dataset.langChoice));
}

