// Connexion (brand book v2) : le logotype ILL Watch et la signature à gauche, le formulaire
// à droite. Le motif radar du fond fait un seul balayage de 1,2 s au chargement, jamais sous
// le texte, et aucun si l'utilisateur a réduit les animations.
import { useState, type FormEvent } from "react";

import { ApiError } from "../api/http";
import { BrandLogo } from "../components/Logo";
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
      setError(exc instanceof ApiError ? exc.message : "Serveur injoignable. Vérifiez qu'ILL Watch tourne, puis réessayez.");
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
          <p className="brand-signature">Voir la menace avant qu'elle ne vous voie.</p>
          <p className="tagline">
            Renseignement sur les menaces, priorisation des vulnérabilités et réponse aux
            incidents, sur un seul poste de veille.
          </p>
        </div>
        <p className="login-owner">Veille CTI · triage · réponse aux incidents</p>
      </section>
      <section className="login-panel">
        <form className="login-form" onSubmit={submit} aria-labelledby="login-title">
          <div className="login-mobile-brand">
            <BrandLogo />
          </div>
          <h1 id="login-title">Connexion</h1>
          <p className="muted">Accès réservé aux analystes autorisés. Chaque connexion est journalisée.</p>
          <label className="field">
            Identifiant
            <input
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label className="field">
            Mot de passe
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
            {busy ? "Connexion…" : "Se connecter"}
          </button>
        </form>
      </section>
    </main>
  );
}
