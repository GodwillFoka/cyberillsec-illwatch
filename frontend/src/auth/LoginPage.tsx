// Connexion (v7) : l'identité ILLWATCH à gauche, le formulaire à droite. Le balayage radar
// du fond fait un seul tour au chargement (aucun mouvement si l'utilisateur l'a désactivé).
import { useState, type FormEvent } from "react";

import { ApiError } from "../api/http";
import { Logo } from "../components/Logo";
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
      setError(exc instanceof ApiError ? exc.message : "Serveur injoignable. Vérifiez qu'ILLWATCH tourne, puis réessayez.");
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
          <Logo size={72} />
          <p className="wordmark">ILLWATCH</p>
          <p className="tagline">
            Renseignement sur les menaces, priorisation des vulnérabilités et réponse aux
            incidents, sur un seul poste de veille.
          </p>
        </div>
        <p className="login-owner">CYBERILLSEC</p>
      </section>
      <section className="login-panel">
        <form className="login-form" onSubmit={submit} aria-labelledby="login-title">
          <div className="login-mobile-brand">
            <Logo size={40} />
            <span className="wordmark">ILLWATCH</span>
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
