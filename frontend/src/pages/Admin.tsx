// Administration (ADMIN) : comptes, journal d'audit, paramètres en vigueur. L'onglet est dans
// l'adresse (?onglet=comptes|audit|parametres). Chaque action est consignée au journal
// d'audit par le serveur ; l'interface ne fait qu'en montrer le résultat.
import { KeyRound, LogOut, RefreshCw, UserPlus } from "lucide-react";
import { useState, type FormEvent, type KeyboardEvent } from "react";

import { useCreateAccount, useResetPassword, useRevokeSessions, useUpdateAccount } from "../api/mutations";
import { AUDIT_PAGE_SIZE, useAccounts, useAudit, useSettingsInfo, type AuditFilters } from "../api/queries";
import type { Account, AuditEvent } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { Pager } from "../components/Pager";
import { QueryState } from "../components/QueryState";
import { formatAge, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { levelLabel } from "../lib/levels";
import { auditLabel, formatBytes, formatDuration, generatePassword } from "../lib/ops";
import { useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";

const ROLES: [string, string, string][] = [
  ["ADMIN", "Administrateur", "Tout, y compris les comptes et les sources"],
  ["ANALYST", "Analyste", "Trie, enquête, ouvre des incidents, lance des chasses"],
  ["VIEWER", "Lecteur", "Consulte, sans rien modifier"],
];
const ROLE_LABEL = Object.fromEntries(ROLES.map(([value, label]) => [value, label]));

type Tab = "comptes" | "audit" | "parametres";
const TABS: [Tab, string][] = [
  ["comptes", "Comptes"],
  ["audit", "Journal d'audit"],
  ["parametres", "Paramètres"],
];

// --- Comptes -------------------------------------------------------------------------------

function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="field">
      <label htmlFor="mdp">Mot de passe (12 caractères au moins)</label>
      <div className="row">
        <input
          id="mdp"
          className="mono grow"
          required
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
        <button className="btn" type="button" onClick={() => onChange(generatePassword())}>
          <RefreshCw size={16} aria-hidden="true" />
          Générer
        </button>
      </div>
    </div>
  );
}

function NewAccount({ onClose }: { onClose: () => void }) {
  const create = useCreateAccount();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("ANALYST");
  const [password, setPassword] = useState(() => generatePassword());
  const [created, setCreated] = useState<{ name: string; password: string } | null>(null);

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate(
      { username: username.trim(), email: email.trim(), role, password },
      { onSuccess: (account) => setCreated({ name: account.username, password }) },
    );
  }

  if (created) {
    return (
      <section className="card form" aria-labelledby="compte-cree">
        <h2 id="compte-cree">Compte « {created.name} » créé</h2>
        <p className="muted">
          Transmettez ce mot de passe par un canal sûr (pas par le même canal que l'identifiant).
          Il ne sera plus affiché.
        </p>
        <p className="value-box mono">{created.password}</p>
        <div className="actions">
          <button className="btn primary" type="button" onClick={onClose}>
            Terminé
          </button>
        </div>
      </section>
    );
  }

  return (
    <form className="card form" onSubmit={submit} aria-labelledby="nouveau-compte">
      <h2 id="nouveau-compte">Nouveau compte</h2>
      <div className="row">
        <label className="field grow">
          Identifiant
          <input
            required
            minLength={3}
            maxLength={50}
            pattern="[A-Za-z0-9._\-]+"
            title="Lettres, chiffres, point, tiret, tiret bas"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label className="field grow">
          E-mail
          <input required type="email" maxLength={255} value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
      </div>
      <fieldset className="rules">
        <legend>Rôle</legend>
        {ROLES.map(([value, label, help]) => (
          <label key={value} className="check rule">
            <input type="radio" name="role" checked={role === value} onChange={() => setRole(value)} />
            <span>
              <strong>{label}</strong>
              <br />
              <span className="muted">{help}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <PasswordField value={password} onChange={setPassword} />
      {create.error && (
        <p className="notice error" role="alert">
          Création refusée : {create.error.message}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          Annuler
        </button>
        <button className="btn primary" type="submit" disabled={create.isPending}>
          {create.isPending ? "Création…" : "Créer le compte"}
        </button>
      </div>
    </form>
  );
}

function AccountPanel({ account, isSelf }: { account: Account; isSelf: boolean }) {
  const { utc } = useTimeZone();
  const update = useUpdateAccount(account.id);
  const reset = useResetPassword(account.id);
  const revoke = useRevokeSessions(account.id);
  const [password, setPassword] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const created = parseDate(account.created_at);
  const error = update.error ?? reset.error ?? revoke.error;

  return (
    <aside className="card detail" aria-label={`Compte ${account.username}`}>
      <section>
        <div className="title">
          <span className="avatar" aria-hidden="true">
            {account.username.slice(0, 2).toUpperCase()}
          </span>
          <span className="ellipsis">{account.username}</span>
          {account.is_active ? null : <span className="badge p3">Désactivé</span>}
        </div>
        <dl className="facts" style={{ marginTop: 12 }}>
          <dt>E-mail</dt>
          <dd>{account.email}</dd>
          <dt>Créé</dt>
          <dd>{created ? formatDateTime(created, utc) : "—"}</dd>
          <dt>Sessions ouvertes</dt>
          <dd>{formatNumber(account.active_sessions)}</dd>
        </dl>
      </section>

      <section>
        <h3>Rôle</h3>
        <div className="seg" role="group" aria-label="Rôle">
          {ROLES.map(([value, label]) => (
            <button
              key={value}
              type="button"
              aria-pressed={account.role === value}
              disabled={update.isPending || (isSelf && value !== "ADMIN")}
              onClick={() =>
                value !== account.role &&
                update.mutate({ role: value }, { onSuccess: () => setNotice(`Rôle : ${label}. Sessions ouvertes révoquées.`) })
              }
            >
              {label}
            </button>
          ))}
        </div>
        {isSelf && <p className="reason">Votre propre rôle ne se modifie pas ici (garde-fou).</p>}
      </section>

      <section>
        <h3>Accès</h3>
        {password && (
          <>
            <p className="muted">Nouveau mot de passe, à transmettre par un canal sûr :</p>
            <p className="value-box mono">{password}</p>
          </>
        )}
        {notice && (
          <p className="notice ok" role="status">
            {notice}
          </p>
        )}
        {error && (
          <p className="notice error" role="alert">
            Refusé : {error.message}
          </p>
        )}
        <div className="actions">
          <button
            className="btn"
            type="button"
            disabled={revoke.isPending}
            onClick={() =>
              revoke.mutate(undefined, {
                onSuccess: (r) => setNotice(`${formatNumber(r.revoked)} session(s) révoquée(s).`),
              })
            }
          >
            <LogOut size={16} aria-hidden="true" />
            Révoquer les sessions
          </button>
          <button
            className="btn"
            type="button"
            disabled={reset.isPending}
            onClick={() => {
              const next = generatePassword();
              reset.mutate(next, {
                onSuccess: (r) => {
                  setPassword(next);
                  setNotice(`Mot de passe réinitialisé, ${formatNumber(r.revoked)} session(s) révoquée(s).`);
                },
              });
            }}
          >
            <KeyRound size={16} aria-hidden="true" />
            Réinitialiser le mot de passe
          </button>
          {!isSelf && (
            <button
              className={account.is_active ? "btn danger" : "btn primary"}
              type="button"
              disabled={update.isPending}
              onClick={() =>
                update.mutate(
                  { is_active: !account.is_active },
                  { onSuccess: (a) => setNotice(a.is_active ? "Compte réactivé." : "Compte désactivé, sessions révoquées.") },
                )
              }
            >
              {account.is_active ? "Désactiver le compte" : "Réactiver le compte"}
            </button>
          )}
        </div>
      </section>
    </aside>
  );
}

function Accounts() {
  const { user } = useAuth();
  const query = useAccounts();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const accounts = query.data ?? [];
  const selected = accounts.find((a) => a.id === selectedId) ?? accounts[0];

  function onKey(event: KeyboardEvent<HTMLTableRowElement>, index: number) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      setSelectedId(accounts[index].id);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = accounts[index + (event.key === "ArrowDown" ? 1 : -1)];
      if (next) {
        setSelectedId(next.id);
        document.getElementById(`compte-${next.id}`)?.focus();
      }
    }
  }

  return (
    <>
      <div className="toolbar">
        <span className="muted">
          {query.data ? `${formatNumber(accounts.length)} compte${accounts.length > 1 ? "s" : ""}` : " "}
        </span>
        {!creating && (
          <button className="btn primary" type="button" onClick={() => setCreating(true)}>
            <UserPlus size={16} aria-hidden="true" />
            Nouveau compte
          </button>
        )}
      </div>
      {creating && (
        <div className="gap-bottom">
          <NewAccount onClose={() => setCreating(false)} />
        </div>
      )}
      <div className="split">
        <section className="card flush">
          <QueryState query={query} empty={(items) => items.length === 0}>
            {() => (
              <table className="table selectable" aria-label="Comptes">
                <thead>
                  <tr>
                    <th>Compte</th>
                    <th>Rôle</th>
                    <th>État</th>
                    <th className="num">Sessions</th>
                  </tr>
                </thead>
                <tbody>
                  {accounts.map((account, index) => (
                    <tr
                      key={account.id}
                      id={`compte-${account.id}`}
                      tabIndex={0}
                      aria-current={account.id === selected?.id ? "true" : undefined}
                      className={account.is_active ? undefined : "done"}
                      onClick={() => setSelectedId(account.id)}
                      onKeyDown={(event) => onKey(event, index)}
                    >
                      <td>
                        <div className="cell-title">
                          {account.username}
                          {account.id === user?.id ? <span className="muted"> (vous)</span> : null}
                        </div>
                        <div className="cell-sub">{account.email}</div>
                      </td>
                      <td>{ROLE_LABEL[account.role] ?? account.role}</td>
                      <td>
                        {account.is_active ? <span className="badge ok">Actif</span> : <span className="badge p3">Désactivé</span>}
                      </td>
                      <td className="num mono">{formatNumber(account.active_sessions)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </QueryState>
        </section>
        {selected && <AccountPanel key={selected.id} account={selected} isSelf={selected.id === user?.id} />}
      </div>
    </>
  );
}

// --- Journal d'audit -----------------------------------------------------------------------

const AUDIT_FAMILIES: [string, string][] = [
  ["", "Toutes les actions"],
  ["auth.", "Connexions"],
  ["authz.", "Accès refusés"],
  ["user.", "Comptes"],
  ["feed.", "Sources"],
  ["data.export", "Exports"],
  ["indicator.", "IOC soumis"],
  ["alert.", "Alertes"],
  ["hunt.", "Chasses"],
];

const OUTCOME: Record<string, [string, string]> = {
  SUCCESS: ["Réussi", "ok"],
  FAILURE: ["Échec", "p1"],
  DENIED: ["Refusé", "p0"],
};

function detailText(event: AuditEvent): string {
  if (!event.detail) return "";
  return Object.entries(event.detail)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `${k} : ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(", ");
}

function AuditLog() {
  const { utc } = useTimeZone();
  const [filters, setFilters] = useState<AuditFilters>({});
  const [offset, setOffset] = useState(0);
  const query = useAudit(filters, offset);
  const change = (next: AuditFilters) => {
    setFilters(next);
    setOffset(0);
  };

  return (
    <section className="card">
      <div className="toolbar">
        <span className="muted">
          {query.data ? `${formatNumber(query.data.total)} événement${query.data.total > 1 ? "s" : ""}` : " "}
        </span>
        <div className="row">
          <select
            className="compact"
            aria-label="Famille d'actions"
            value={filters.action ?? ""}
            onChange={(e) => change({ ...filters, action: e.target.value || undefined })}
          >
            {AUDIT_FAMILIES.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <div className="seg" role="group" aria-label="Résultat">
            {[["", "Tous"], ["SUCCESS", "Réussis"], ["FAILURE", "Échecs"], ["DENIED", "Refus"]].map(([value, label]) => (
              <button
                key={value}
                type="button"
                aria-pressed={(filters.outcome ?? "") === value}
                onClick={() => change({ ...filters, outcome: value || undefined })}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <QueryState query={query} empty={(page) => page.items.length === 0}>
        {(page) => (
          <>
            <table className="table" aria-label="Journal d'audit">
              <thead>
                <tr>
                  <th>Quand</th>
                  <th>Action</th>
                  <th>Résultat</th>
                  <th>Par</th>
                  <th>Détail</th>
                  <th>Adresse</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((event) => {
                  const at = parseDate(event.occurred_at);
                  const [label, tone] = OUTCOME[event.outcome] ?? [event.outcome, "p3"];
                  const detail = detailText(event);
                  return (
                    <tr key={event.id}>
                      <td className="mono muted" title={at ? `il y a ${formatAge(at)}` : undefined}>
                        {at ? formatDateTime(at, utc) : "—"}
                      </td>
                      <td>{auditLabel(event.action)}</td>
                      <td>
                        <span className={`badge ${tone}`}>{label}</span>
                      </td>
                      <td>{event.actor_name ?? "—"}</td>
                      <td className="ellipsis muted" style={{ maxWidth: 320 }} title={detail}>
                        {detail || "—"}
                      </td>
                      <td className="mono muted">{event.ip ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <Pager
              pageSize={AUDIT_PAGE_SIZE}
              offset={offset}
              shown={page.items.length}
              total={page.total}
              busy={query.isPlaceholderData}
              onOffset={setOffset}
            />
          </>
        )}
      </QueryState>
    </section>
  );
}

// --- Paramètres ----------------------------------------------------------------------------

const SECRET_LABELS: Record<string, string> = {
  nvd_api_key: "Clé API NVD (débit CVE ×10)",
  otx_api_key: "Clé AlienVault OTX",
  abusech_auth_key: "Clé abuse.ch",
  alert_webhook_url: "Webhook des alertes",
  secret_key_previous: "Clé de signature précédente (rotation)",
};

function SettingsView() {
  const query = useSettingsInfo();
  return (
    <QueryState query={query}>
      {(s) => (
        <div className="grid three">
          <section className="card">
            <h2>Sécurité des sessions</h2>
            <dl className="facts settings">
              <dt>Environnement</dt>
              <dd>{s.environment}</dd>
              <dt>Version</dt>
              <dd className="mono">{s.version}</dd>
              <dt>Jeton d'accès</dt>
              <dd>{formatDuration(s.access_token_minutes * 60)}</dd>
              <dt>Session (rafraîchissement)</dt>
              <dd>{formatDuration(s.refresh_token_days * 86_400)}</dd>
              <dt>Verrouillage</dt>
              <dd>
                {s.login_max_failures} échecs en {formatDuration(s.login_window_seconds)}
              </dd>
              <dt>HSTS</dt>
              <dd>{s.hsts_enabled ? "envoyé" : "non envoyé"}</dd>
              <dt>Documentation de l'API</dt>
              <dd>{s.docs_enabled ? "exposée" : "masquée"}</dd>
            </dl>
          </section>
          <section className="card">
            <h2>Collecte et analyse</h2>
            <dl className="facts settings">
              <dt>Fréquence par défaut</dt>
              <dd>{formatDuration(s.default_polling_interval)}</dd>
              <dt>Cycle du worker</dt>
              <dd>{formatDuration(s.worker_tick_seconds)}</dd>
              <dt>Synchronisation CVE</dt>
              <dd>{formatDuration(s.cve_sync_interval_seconds)}</dd>
              <dt>Chasse planifiée</dt>
              <dd>{s.hunt_interval_seconds ? `toutes les ${formatDuration(s.hunt_interval_seconds)}` : "désactivée"}</dd>
              <dt>Délai réseau</dt>
              <dd>{formatDuration(s.http_timeout_seconds)}</dd>
              <dt>Taille maximale d'un flux</dt>
              <dd>{formatBytes(s.feed_max_bytes)}</dd>
              <dt>Seuil d'alerte CVE</dt>
              <dd>{s.risk_alert_threshold} / 100</dd>
            </dl>
          </section>
          <section className="card">
            <h2>Délais de remédiation</h2>
            <dl className="facts settings">
              {Object.entries(s.remediation_sla_hours).map(([priority, hours]) => (
                <div key={priority} className="contents">
                  <dt>
                    <span className={`badge ${priority.slice(0, 2).toLowerCase()}`}>{levelLabel(priority)}</span>
                  </dt>
                  <dd>{formatDuration(hours * 3600)}</dd>
                </div>
              ))}
            </dl>
            <h2 className="spaced">Secrets configurés</h2>
            <ul className="list">
              {Object.entries(s.secrets_configured).map(([key, present]) => (
                <li key={key}>
                  <span className="grow">{SECRET_LABELS[key] ?? key}</span>
                  {present ? <span className="badge ok">Oui</span> : <span className="badge p3">Non</span>}
                </li>
              ))}
            </ul>
            <p className="muted small">Valeurs jamais affichées : seule leur présence est vérifiée. Modification dans .env, puis redémarrage.</p>
          </section>
        </div>
      )}
    </QueryState>
  );
}

// --- Page ----------------------------------------------------------------------------------

export function Admin() {
  const { user } = useAuth();
  const { search, navigate } = useLocation();
  const requested = new URLSearchParams(search).get("onglet");
  const tab: Tab = TABS.some(([t]) => t === requested) ? (requested as Tab) : "comptes";
  const open = (value: Tab) => navigate(`/administration?onglet=${value}`, { replace: true });

  // Onglets au clavier (motif ARIA « tabs ») : flèches gauche/droite, Début, Fin.
  function onTabKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = TABS.length - 1;
    const target =
      event.key === "ArrowRight" ? (index === last ? 0 : index + 1)
      : event.key === "ArrowLeft" ? (index === 0 ? last : index - 1)
      : event.key === "Home" ? 0
      : event.key === "End" ? last
      : null;
    if (target === null) return;
    event.preventDefault();
    open(TABS[target][0]);
    document.getElementById(`onglet-${TABS[target][0]}`)?.focus();
  }

  if (user?.role !== "ADMIN") {
    return (
      <div className="card">
        <p className="empty">L'administration est réservée aux administrateurs.</p>
      </div>
    );
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>Comptes et accès, journal d'audit de sécurité, paramètres en vigueur</p>
        </div>
      </div>
      <div className="tabs" role="tablist" aria-label="Rubriques">
        {TABS.map(([value, label], index) => (
          <button
            key={value}
            id={`onglet-${value}`}
            role="tab"
            type="button"
            aria-selected={tab === value}
            aria-controls={tab === value ? `panneau-${value}` : undefined}
            tabIndex={tab === value ? 0 : -1}
            className="tab"
            onClick={() => open(value)}
            onKeyDown={(event) => onTabKey(event, index)}
          >
            {label}
          </button>
        ))}
      </div>
      <div id={`panneau-${tab}`} role="tabpanel" aria-labelledby={`onglet-${tab}`}>
        {tab === "comptes" && <Accounts />}
        {tab === "audit" && <AuditLog />}
        {tab === "parametres" && <SettingsView />}
      </div>
    </>
  );
}
