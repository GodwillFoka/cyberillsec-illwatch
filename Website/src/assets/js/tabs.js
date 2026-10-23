// Onglets accessibles (fonctionnalités, explorateur ATT&CK, exemple TAXII). Sans JavaScript, tous les panneaux sont
// affichés l'un sous l'autre ; avec, ils deviennent des onglets (flèches, Début, Fin).
for (const root of document.querySelectorAll("[data-tabs]")) {
  const tabs = [...root.querySelectorAll('[role="tab"]')];
  const panels = [...root.querySelectorAll('[role="tabpanel"]')];

  function select(index, focus = false) {
    tabs.forEach((tab, i) => {
      const active = i === index;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      panels[i].hidden = !active;
      panels[i].classList.toggle("is-active", active);
    });
    if (focus) tabs[index].focus();
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => select(index));
    tab.addEventListener("keydown", (event) => {
      const last = tabs.length - 1;
      const next = index === last ? 0 : index + 1;
      const previous = index === 0 ? last : index - 1;
      const moves = { ArrowRight: next, ArrowDown: next, ArrowLeft: previous, ArrowUp: previous, Home: 0, End: last };
      if (event.key in moves) {
        event.preventDefault();
        select(moves[event.key], true);
      }
    });
  });
  root.classList.add("is-live");
  select(0);
}
