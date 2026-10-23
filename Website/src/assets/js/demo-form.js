// Formulaire de demande de démonstration (lot S4) : envoi en JSON à `POST /api/v1/demo-requests`
// de l'application. Les messages viennent de la page (data-messages), déjà traduits.
const form = document.querySelector("[data-demo-form]");
if (form) {
  const status = form.querySelector(".demo-form__status");
  const button = form.querySelector('button[type="submit"]');
  const messages = JSON.parse(form.dataset.messages);

  function say(text, tone) {
    status.textContent = text;
    status.dataset.tone = tone;
  }

  function markInvalid() {
    let first = null;
    for (const field of form.querySelectorAll("input, select, textarea")) {
      const invalid = !field.checkValidity();
      field.toggleAttribute("aria-invalid", invalid);
      if (invalid && !first) first = field;
    }
    if (first) first.focus();
    return first === null;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!markInvalid()) {
      say(messages.invalid, "error");
      return;
    }
    const data = new FormData(form);
    const text = (name) => String(data.get(name) || "").trim();
    const payload = {
      name: text("name"),
      email: text("email"),
      organisation: text("organisation"),
      job_title: text("job_title") || null,
      country: text("country") || null,
      interest: text("interest") || "DEMO",
      message: text("message") || null,
      language: form.dataset.langCode,
      consent: data.get("consent") === "on",
      website: text("website") || null,
    };
    button.disabled = true;
    try {
      const response = await fetch(form.dataset.endpoint, {
        method: "POST",
        credentials: "omit",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(payload),
      });
      if (response.status === 202) {
        form.reset();
        say(messages.sent, "ok");
      } else if (response.status === 429) {
        say(messages.limited, "error");
      } else if (response.status === 422) {
        say(messages.invalid, "error");
      } else {
        say(messages.error, "error");
      }
    } catch {
      say(messages.error, "error");
    } finally {
      button.disabled = false;
    }
  });
  form.classList.add("is-live");
}
