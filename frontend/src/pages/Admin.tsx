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
import { formatAgo, formatDateTime, formatNumber, parseDate } from "../lib/format";
import { ROLE_LABEL, levelLabel } from "../lib/levels";
import { auditLabel, formatBytes, formatDuration, generatePassword } from "../lib/ops";
import { useLocation } from "../lib/router";
import { useTimeZone } from "../lib/time";
import { t } from "./Admin.i18n";

type Key = Parameters<typeof t>[0];

const ROLE_CODES = ["ADMIN", "ANALYST", "VIEWER"];
/** [code, libellé, aide] dans la langue courante. */
const roles = (): [string, string, string][] =>
  ROLE_CODES.map((code) => [code, ROLE_LABEL[code] ?? code, t(`roleHelp.${code}` as Key)]);

type Tab = "comptes" | "audit" | "parametres";
const TAB_CODES: Tab[] = ["comptes", "audit", "parametres"];
const tabs = (): [Tab, string][] => [
  ["comptes", t("tabAccounts")],
  ["audit", t("tabAudit")],
  ["parametres", t("tabSettings")],
];

// --- Comptes -------------------------------------------------------------------------------

function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="field">
      <label htmlFor="mdp">{t("password")}</label>
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
          {t("generate")}
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
        <h2 id="compte-cree">{t("accountCreated", { name: created.name })}</h2>
        <p className="muted">
          {t("passwordNote")}
        </p>
        <p className="value-box mono">{created.password}</p>
        <div className="actions">
          <button className="btn primary" type="button" onClick={onClose}>
            {t("done")}
          </button>
        </div>
      </section>
    );
  }

  return (
    <form className="card form" onSubmit={submit} aria-labelledby="nouveau-compte">
      <h2 id="nouveau-compte">{t("newAccount")}</h2>
      <div className="row">
        <label className="field grow">
          {t("username")}
          <input
            required
            minLength={3}
            maxLength={50}
            pattern="[A-Za-z0-9._\-]+"
            title={t("usernameRule")}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label className="field grow">
          {t("email")}
          <input required type="email" maxLength={255} value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
      </div>
      <fieldset className="rules">
        <legend>{t("role")}</legend>
        {roles().map(([value, label, help]) => (
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
          {t("createRefused", { message: create.error.message })}
        </p>
      )}
      <div className="actions">
        <button className="btn quiet" type="button" onClick={onClose}>
          {t("cancel")}
        </button>
        <button className="btn primary" type="submit" disabled={create.isPending}>
          {create.isPending ? t("creating") : t("create")}
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
    <aside className="card detail" aria-label={t("accountLabel", { name: account.username })}>
      <section>
        <div className="title">
          <span className="avatar" aria-hidden="true">
            {account.username.slice(0, 2).toUpperCase()}
          </span>
          <span className="ellipsis">{account.username}</span>
          {account.is_active ? null : <span className="badge p3">{t("disabled")}</span>}
        </div>
        <dl className="facts" style={{ marginTop: 12 }}>
          <dt>{t("email")}</dt>
          <dd>{account.email}</dd>
          <dt>{t("created")}</dt>
          <dd>{created ? formatDateTime(created, utc) : "—"}</dd>
          <dt>{t("sessions")}</dt>
          <dd>{formatNumber(account.active_sessions)}</dd>
        </dl>
      </section>

      <section>
        <h3>{t("role")}</h3>
        <div className="seg" role="group" aria-label={t("role")}>
          {roles().map(([value, label]) => (
            <button
              key={value}
              type="button"
              aria-pressed={account.role === value}
              disabled={update.isPending || (isSelf && value !== "ADMIN")}
              onClick={() =>
                value !== account.role &&
                update.mutate({ role: value }, { onSuccess: () => setNotice(t("roleChanged", { role: label })) })
              }
            >
              {label}
            </button>
          ))}
        </div>
        {isSelf && <p className="reason">{t("ownRole")}</p>}
      </section>

      <section>
        <h3>{t("access")}</h3>
        {password && (
          <>
            <p className="muted">{t("newPassword")}</p>
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
            {t("refused", { message: error.message })}
          </p>
        )}
        <div className="actions">
          <button
            className="btn"
            type="button"
            disabled={revoke.isPending}
            onClick={() =>
              revoke.mutate(undefined, {
                onSuccess: (r) => setNotice(t("revoked", { count: r.revoked })),
              })
            }
          >
            <LogOut size={16} aria-hidden="true" />
            {t("revokeSessions")}
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
                  setNotice(t("passwordReset", { count: r.revoked }));
                },
              });
            }}
          >
            <KeyRound size={16} aria-hidden="true" />
            {t("resetPassword")}
          </button>
          {!isSelf && (
            <button
              className={account.is_active ? "btn danger" : "btn primary"}
              type="button"
              disabled={update.isPending}
              onClick={() =>
                update.mutate(
                  { is_active: !account.is_active },
                  { onSuccess: (a) => setNotice(a.is_active ? t("reactivated") : t("deactivated")) },
                )
              }
            >
              {account.is_active ? t("disable") : t("enable")}
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
          {query.data ? t.plural("count", accounts.length) : " "}
        </span>
        {!creating && (
          <button className="btn primary" type="button" onClick={() => setCreating(true)}>
            <UserPlus size={16} aria-hidden="true" />
            {t("newAccount")}
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
              <table className="table selectable" aria-label={t("accountsTable")}>
                <thead>
                  <tr>
                    <th>{t("colAccount")}</th>
                    <th>{t("colRole")}</th>
                    <th>{t("colState")}</th>
                    <th className="num">{t("colSessions")}</th>
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
                          {account.id === user?.id ? <span className="muted">{t("you")}</span> : null}
                        </div>
                        <div className="cell-sub">{account.email}</div>
                      </td>
                      <td>{ROLE_LABEL[account.role] ?? account.role}</td>
                      <td>
                        {account.is_active ? <span className="badge ok">{t("active")}</span> : <span className="badge p3">{t("disabled")}</span>}
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

const auditFamilies = (): [string, string][] => [
  ["", t("family.all")],
  ["auth.", t("family.auth")],
  ["authz.", t("family.authz")],
  ["user.", t("family.user")],
  ["feed.", t("family.feed")],
  ["data.export", t("family.export")],
  ["indicator.", t("family.indicator")],
  ["alert.", t("family.alert")],
  ["hunt.", t("family.hunt")],
  ["enrichment.", t("family.enrichment")],
  ["asset.", t("family.asset")],
  ["correlation.", t("family.correlation")],
  ["incident.", t("family.incident")],
  ["exclusion.", t("family.exclusion")],
];

const OUTCOME_TONE: Record<string, string> = { SUCCESS: "ok", FAILURE: "p1", DENIED: "p0" };

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
          {query.data ? t.plural("events", query.data.total) : " "}
        </span>
        <div className="row">
          <select
            className="compact"
            aria-label={t("family")}
            value={filters.action ?? ""}
            onChange={(e) => change({ ...filters, action: e.target.value || undefined })}
          >
            {auditFamilies().map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <div className="seg" role="group" aria-label={t("result")}>
            {[
              ["", t("filterAll")],
              ["SUCCESS", t("filterSuccess")],
              ["FAILURE", t("filterFailure")],
              ["DENIED", t("filterDenied")],
            ].map(([value, label]) => (
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
            <table className="table" aria-label={t("auditTable")}>
              <thead>
                <tr>
                  <th>{t("colWhen")}</th>
                  <th>{t("colAction")}</th>
                  <th>{t("colResult")}</th>
                  <th>{t("colBy")}</th>
                  <th>{t("colDetail")}</th>
                  <th>{t("colAddress")}</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((event) => {
                  const at = parseDate(event.occurred_at);
                  const tone = OUTCOME_TONE[event.outcome] ?? "p3";
                  const label = event.outcome in OUTCOME_TONE ? t(`outcome.${event.outcome}` as Key) : event.outcome;
                  const detail = detailText(event);
                  return (
                    <tr key={event.id}>
                      <td className="mono muted" title={at ? `${formatAgo(at)}` : undefined}>
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

const SECRETS = new Set(["nvd_api_key", "otx_api_key", "abusech_auth_key", "alert_webhook_url", "secret_key_previous"]);
const secretLabel = (key: string) => (SECRETS.has(key) ? t(`secret.${key}` as Key) : key);

function SettingsView() {
  const query = useSettingsInfo();
  return (
    <QueryState query={query}>
      {(s) => (
        <div className="grid three">
          <section className="card">
            <h2>{t("sessionSecurity")}</h2>
            <dl className="facts settings">
              <dt>{t("environment")}</dt>
              <dd>{s.environment}</dd>
              <dt>{t("version")}</dt>
              <dd className="mono">{s.version}</dd>
              <dt>{t("accessToken")}</dt>
              <dd>{formatDuration(s.access_token_minutes * 60)}</dd>
              <dt>{t("refresh")}</dt>
              <dd>{formatDuration(s.refresh_token_days * 86_400)}</dd>
              <dt>{t("lockout")}</dt>
              <dd>{t("lockoutValue", { failures: s.login_max_failures, window: formatDuration(s.login_window_seconds) })}</dd>
              <dt>HSTS</dt>
              <dd>{s.hsts_enabled ? t("hstsSent") : t("hstsNotSent")}</dd>
              <dt>{t("apiDocs")}</dt>
              <dd>{s.docs_enabled ? t("exposed") : t("hidden")}</dd>
            </dl>
          </section>
          <section className="card">
            <h2>{t("collection")}</h2>
            <dl className="facts settings">
              <dt>{t("defaultFrequency")}</dt>
              <dd>{formatDuration(s.default_polling_interval)}</dd>
              <dt>{t("workerCycle")}</dt>
              <dd>{formatDuration(s.worker_tick_seconds)}</dd>
              <dt>{t("cveSync")}</dt>
              <dd>{formatDuration(s.cve_sync_interval_seconds)}</dd>
              <dt>{t("scheduledHunt")}</dt>
              <dd>{s.hunt_interval_seconds ? t("every", { duration: formatDuration(s.hunt_interval_seconds) }) : t("off")}</dd>
              <dt>{t("networkTimeout")}</dt>
              <dd>{formatDuration(s.http_timeout_seconds)}</dd>
              <dt>{t("maxFeed")}</dt>
              <dd>{formatBytes(s.feed_max_bytes)}</dd>
              <dt>{t("alertThreshold")}</dt>
              <dd>{s.risk_alert_threshold} / 100</dd>
            </dl>
          </section>
          <section className="card">
            <h2>{t("remediation")}</h2>
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
            <h2 className="spaced">{t("secrets")}</h2>
            <ul className="list">
              {Object.entries(s.secrets_configured).map(([key, present]) => (
                <li key={key}>
                  <span className="grow">{secretLabel(key)}</span>
                  {present ? <span className="badge ok">{t("yes")}</span> : <span className="badge p3">{t("no")}</span>}
                </li>
              ))}
            </ul>
            <p className="muted small">{t("secretsNote")}</p>
          </section>
          <section className="card">
            <h2>{t("ipEnrichment")}</h2>
            {s.enrichment.length === 0 ? (
              <p className="muted">
                {t("noDataset")}
                <span className="mono">illwatch enrich update</span>
                {t("monthly")}
              </p>
            ) : (
              <dl className="facts settings">
                {s.enrichment.map((d) => {
                  const at = parseDate(d.imported_at);
                  return (
                    <div key={d.dataset} className="contents">
                      <dt>{d.dataset === "country" ? t("countries") : t("asns")}</dt>
                      <dd>
                        {t("ranges", { count: d.ranges, ago: at ? formatAgo(at) : "—" })}
                        <span className="cell-sub mono">{d.source}</span>
                      </dd>
                    </div>
                  );
                })}
              </dl>
            )}
            <p className="muted small">
              {t("dbipNote")}
              <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">
                IP Geolocation by DB-IP
              </a>
            </p>
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
  const tab: Tab = TAB_CODES.some((code) => code === requested) ? (requested as Tab) : "comptes";
  const open = (value: Tab) => navigate(`/administration?onglet=${value}`, { replace: true });

  // Onglets au clavier (motif ARIA « tabs ») : flèches gauche/droite, Début, Fin.
  function onTabKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = TAB_CODES.length - 1;
    const target =
      event.key === "ArrowRight" ? (index === last ? 0 : index + 1)
      : event.key === "ArrowLeft" ? (index === 0 ? last : index - 1)
      : event.key === "Home" ? 0
      : event.key === "End" ? last
      : null;
    if (target === null) return;
    event.preventDefault();
    open(TAB_CODES[target]);
    document.getElementById(`onglet-${TAB_CODES[target]}`)?.focus();
  }

  if (user?.role !== "ADMIN") {
    return (
      <div className="card">
        <p className="empty">{t("adminOnly")}</p>
      </div>
    );
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
      </div>
      <div className="tabs" role="tablist" aria-label={t("sections")}>
        {tabs().map(([value, label], index) => (
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
