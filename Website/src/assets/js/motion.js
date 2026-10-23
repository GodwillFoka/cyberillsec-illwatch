// Mouvements de l'accueil : apparition des sections au défilement et chiffres qui s'incrémentent.
// Rien ne bouge si le visiteur a demandé à réduire les animations ; sans JavaScript, tout est
// affiché d'emblée (la classe « motion » n'est posée qu'ici).
const root = document.documentElement;
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (!reduced && "IntersectionObserver" in window) {
  const locale = root.dataset.locale || "en";

  function countUp(el) {
    const target = Number(el.dataset.count);
    if (!Number.isFinite(target)) return;
    const decimals = String(el.dataset.count).split(".")[1]?.length || 0;
    const format = new Intl.NumberFormat(locale, { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
    const final = el.textContent;
    const duration = 1400;
    let start = null;
    function frame(now) {
      start ??= now;
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - progress) ** 3;
      el.textContent = progress < 1 ? format.format(target * eased) : final;
      if (progress < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add("is-visible");
        for (const counter of entry.target.querySelectorAll("[data-count]")) countUp(counter);
        observer.unobserve(entry.target);
      }
    },
    { rootMargin: "0px 0px -8% 0px", threshold: 0.12 },
  );

  // Ce qui est déjà à l'écran reste visible : aucun clignotement au chargement.
  const fold = window.innerHeight;
  for (const el of document.querySelectorAll(".reveal")) {
    if (el.getBoundingClientRect().top < fold) el.classList.add("is-visible");
    else observer.observe(el);
  }
  root.classList.add("motion");
}
