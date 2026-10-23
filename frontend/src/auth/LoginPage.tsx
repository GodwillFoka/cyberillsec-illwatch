// Connexion (brand book v2) : le logotype ILLWATCH et la signature à gauche, le formulaire
// à droite. Le motif radar du fond fait un seul balayage de 1,2 s au chargement, jamais sous
// le texte, et aucun si l'utilisateur a réduit les animations.
import { useState, type FormEvent } from "react";

import { ApiError } from "../api/http";
import { BrandLogo } from "../components/Logo";
import { messages } from "../i18n/common.i18n";
import { LanguageSelect } from "../i18n/LanguageSelect";
import { shell } from "../layout/shell.i18n";
import { useAuth } from "./AuthProvider";

export function LoginPage() {
  const { signIn } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(username.trim(), password);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : messages("serverDown"));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <section className="login-brand" aria-hidden="true">
        <div className="radar" />
        <div className="login-identity">
          <BrandLogo />
          <p className="brand-signature">{shell("signature")}</p>
          <p className="tagline">{shell("tagline")}</p>
        </div>
        <p className="login-owner">{shell("owner")}</p>
      </section>
      <section className="login-panel">
        <div className="login-lang">
          <LanguageSelect />
        </div>
        <form className="login-form" onSubmit={submit} aria-labelledby="login-title">
          <div className="login-mobile-brand">
            <BrandLogo />
          </div>
          <h1 id="login-title">{shell("loginTitle")}</h1>
          <p className="muted">{shell("loginNotice")}</p>
          <label className="field">
            {shell("username")}
            <input
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label className="field">
            {shell("password")}
            <input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {error && (
            <p className="notice error" role="alert">
              {error}
            </p>
          )}
          <button className="btn primary wide" type="submit" disabled={busy}>
            {busy ? shell("signingIn") : shell("signIn")}
          </button>
        </form>
      </section>
    </main>
  );
}
