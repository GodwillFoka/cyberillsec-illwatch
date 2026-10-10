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
      setError(exc instanceof ApiError ? exc.message : "Serveur injoignable. Réessayez.");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="card" onSubmit={submit} aria-labelledby="login-title">
        <div className="nav-brand">
          <Logo />
          <div>
            <strong id="login-title">ILLWATCH</strong>
            <small>BY CYBERILLSEC</small>
          </div>
        </div>
        <label>
          Identifiant
          <input
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label>
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
        <button className="btn primary" type="submit" disabled={busy}>
          {busy ? "Connexion…" : "Se connecter"}
        </button>
      </form>
    </main>
  );
}
