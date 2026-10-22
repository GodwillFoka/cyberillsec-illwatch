// Simulateur de priorité CVE de l'accueil. Les libellés viennent de la page (data-*),
// déjà traduits à la construction : ce script ne contient aucun texte affiché.
import { computeRisk } from "./score.js";

const form = document.querySelector("[data-simulator]");
if (form) {
  const locale = document.documentElement.dataset.locale || "en";
  const number = new Intl.NumberFormat(locale, { maximumFractionDigits: 2 });
  const percent = new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: 0 });
  const out = (name) => form.querySelector(`[data-out="${name}"]`);
  const field = (name) => form.elements.namedItem(name);
  const priorityBadge = out("priority");
  const priorityLabels = JSON.parse(form.dataset.priorities);
  const slaLabels = JSON.parse(form.dataset.sla);

  function render() {
    const input = {
      cvss: Number(field("cvss").value),
      epss: Number(field("epss").value) / 100,
      kev: field("kev").checked,
      exploit: field("exploit").checked,
      ransomware: field("ransomware").checked,
    };
    const result = computeRisk(input);
    out("cvss-value").textContent = number.format(input.cvss);
    out("epss-value").textContent = percent.format(input.epss);
    out("total").textContent = number.format(result.total);
    priorityBadge.className = `badge badge--${result.priority.toLowerCase()} badge--lg`;
    priorityBadge.textContent = `${result.priority} · ${priorityLabels[result.priority]}`;
    out("sla").textContent = slaLabels[result.priority];
    out("floor").hidden = !result.kevFloor;
    for (const [key, value] of Object.entries(result.parts)) {
      const cell = out(`part-${key}`);
      cell.textContent = `+${number.format(value)}`;
      const bar = form.querySelector(`[data-bar="${key}"]`);
      if (bar) bar.value = value;
    }
    out("meter").value = result.total;
  }

  form.addEventListener("input", render);
  form.addEventListener("submit", (event) => event.preventDefault());
  for (const button of form.querySelectorAll("[data-preset]")) {
    button.addEventListener("click", () => {
      const preset = JSON.parse(button.dataset.preset);
      field("cvss").value = String(preset.cvss);
      field("epss").value = String(preset.epss);
      field("kev").checked = preset.kev;
      field("exploit").checked = preset.exploit;
      field("ransomware").checked = preset.ransomware;
      render();
    });
  }
  form.classList.add("is-live");
  render();
}
