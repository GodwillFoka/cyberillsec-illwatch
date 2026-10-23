// Campagnes (M10, ADR-024) : l'infrastructure d'une opération adverse (IOC rattachés) et
// son acteur ATT&CK. Une détection qui touche cette infrastructure hérite de la campagne et de
// l'acteur. La campagne choisie est dans l'adresse (?campagne=…).
import { Plus } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { useAttachToCampaign, useCreateCampaign, useDeleteCampaign } from "../api/mutations";
import { useCampaign, useCampaigns } from "../api/queries";
import type { Campaign } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { attackAttribution } from "../components/Attack";
import { LevelBadge } from "../components/Badge";
import { QueryState } from "../components/QueryState";
import { messages } from "../i18n/common.i18n";
import { formatAgo, formatNumber, parseDate } from "../lib/format";
import { iocTypeLabel, splitBatch } from "../lib/iocs";
import { asUuid, Link, useLocation } from "../lib/router";
import { t } from "./Campaigns.i18n";

const EDITORS = new Set(["ADMIN", "ANALYST"]);
// Au-delà, la liste se replie : une campagne réelle compte souvent des centaines d'IOC.
const PREVIEW = 20;

function NewCampaign({ onCreated }: { onCreated: (c: Campaign) => void }) {
  const create = useCreateCampaign();
  const [name, setName] = useState("");
  const [actor, setActor] = useState("");
  const [description, setDescription] = useState("");
  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate(
      { name: name.trim(), actor_id: actor.trim() || undefined, description: description.trim() || undefined },
      { onSuccess: onCreated },
    );
  }
  return (
    <form className="card detail form" onSubmit={submit} aria-labelledby="nouvelle-campagne">
      <section className="form">
        <h3 id="nouvelle-campagne">{t("newCampaign")}</h3>
        <label className="field">
          {t("name")}
          <input required minLength={3} maxLength={160} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          {t("actorField")}
          <input
            className="mono"
            maxLength={16}
            placeholder="G0102, S0650"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
          />
        </label>
        <label className="field">
          {t("description")}
          <textarea maxLength={4000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        {create.error && (
          <p className="notice error" role="alert">
            {create.error.message}
          </p>
        )}
        <div className="actions">
          <button className="btn primary" type="submit" disabled={create.isPending}>
            {create.isPending ? t("creating") : t("create")}
          </button>
        </div>
      </section>
    </form>
  );
}

function Attach({ campaignId }: { campaignId: string }) {
  const attach = useAttachToCampaign(campaignId);
  const [contains, setContains] = useState("");
  const [values, setValues] = useState("");
  useEffect(() => {
    setContains("");
    setValues("");
    attach.reset();
  }, [campaignId]);
  function submit(event: FormEvent) {
    event.preventDefault();
    const list = splitBatch(values, 5000).values;
    attach.mutate(
      { values: list.length ? list : undefined, description_contains: contains.trim() || undefined },
      {
        onSuccess: () => {
          setContains("");
          setValues("");
        },
      },
    );
  }
  return (
    <form className="form" onSubmit={submit}>
      <h3>{t("attachTitle")}</h3>
      <label className="field">
        {t("contains")}
        <input minLength={4} maxLength={200} value={contains} onChange={(e) => setContains(e.target.value)} />
      </label>
      <label className="field">
        {t("knownValues")}
        <textarea className="mono" rows={3} value={values} onChange={(e) => setValues(e.target.value)} />
      </label>
      {attach.error && (
        <p className="notice error" role="alert">
          {attach.error.message}
        </p>
      )}
      {attach.data && (
        <p className="notice ok" role="status">
          {t("attached", { count: attach.data.attached })}
          {attach.data.unknown ? t("unknownValues", { count: attach.data.unknown }) : ""}.
        </p>
      )}
      <div className="actions">
        <button
          className="btn"
          type="submit"
          disabled={attach.isPending || (contains.trim().length < 4 && !values.trim())}
        >
          {attach.isPending ? t("attaching") : t("attach")}
        </button>
      </div>
    </form>
  );
}

function CampaignPanel({ campaignId, onDeleted }: { campaignId: string; onDeleted: () => void }) {
  const query = useCampaign(campaignId);
  const { user } = useAuth();
  const remove = useDeleteCampaign();
  const [confirming, setConfirming] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const canEdit = user ? EDITORS.has(user.role) : false;
  useEffect(() => {
    setConfirming(false);
    setExpanded(false);
  }, [campaignId]);
  return (
    <aside className="card detail" aria-label={t("panelLabel")}>
      <QueryState query={query}>
        {(c) => (
          <>
            <section>
              <div className="title">
                <span>{c.name}</span>
              </div>
              {c.description && <p className="description">{c.description}</p>}
            </section>
            <section>
              <h3>{t("actor")}</h3>
              {c.actor ? (
                <p>
                  <a href={c.actor.url} target="_blank" rel="noopener noreferrer">
                    {c.actor.name}
                  </a>{" "}
                  <span className="mono muted">{c.actor.id}</span>{" "}
                  <span className="cell-sub">{c.actor.kind === "group" ? t("group") : t("software")}</span>
                </p>
              ) : (
                <p className="muted">{c.actor_id ? t("notImported", { id: c.actor_id }) : t("unattributed")}</p>
              )}
              <p className="muted small">{attackAttribution()}</p>
            </section>
            <section>
              <h3>{t("infrastructure", { count: c.indicators })}</h3>
              {c.infrastructure.length === 0 ? (
                <p className="empty">{t("noIoc")}</p>
              ) : (
                <ul className="list">
                  {(expanded ? c.infrastructure : c.infrastructure.slice(0, PREVIEW)).map((i) => {
                    const seen = parseDate(i.last_seen);
                    return (
                      <li key={i.id}>
                        <LevelBadge level={i.severity} />
                        <span className="grow">
                          <Link className="mono" to={`/indicateurs?ioc=${i.id}`}>
                            {i.value}
                          </Link>
                          <span className="cell-sub">
                            {" "}
                            · {iocTypeLabel(i.type)}
                            {seen ? t("seen", { ago: formatAgo(seen) }) : ""}
                          </span>
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
              {c.infrastructure.length > PREVIEW && (
                <div className="actions">
                  <button className="btn quiet small" type="button" onClick={() => setExpanded(!expanded)}>
                    {expanded
                      ? t("collapse")
                      : t("showAll", { count: c.infrastructure.length })}
                  </button>
                </div>
              )}
            </section>
            {canEdit && (
              <section>
                <Attach campaignId={c.id} />
              </section>
            )}
            {user?.role === "ADMIN" && (
              <section>
                <div className="actions">
                  <button
                    className={confirming ? "btn danger" : "btn quiet"}
                    type="button"
                    disabled={remove.isPending}
                    onClick={() => (confirming ? remove.mutate(c.id, { onSuccess: onDeleted }) : setConfirming(true))}
                  >
                    {confirming ? t("confirmDelete") : t("delete")}
                  </button>
                </div>
                {confirming && <p className="reason">{t("deleteNote")}</p>}
              </section>
            )}
          </>
        )}
      </QueryState>
    </aside>
  );
}

export function Campaigns() {
  const { search, navigate } = useLocation();
  const { user } = useAuth();
  const query = useCampaigns();
  const params = new URLSearchParams(search);
  const creating = params.get("nouvelle") === "1";
  const requested = asUuid(params.get("campagne"));
  const campaigns = query.data ?? [];
  const selected = requested ?? campaigns[0]?.id ?? null;
  const canEdit = user ? EDITORS.has(user.role) : false;
  const select = (id: string) => navigate(`/campagnes?campagne=${encodeURIComponent(id)}`, { replace: true });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
        {canEdit && (
          <button className="btn primary" type="button" onClick={() => navigate("/campagnes?nouvelle=1", { replace: true })}>
            <Plus size={20} strokeWidth={1.5} aria-hidden="true" />
            {t("newCampaign")}
          </button>
        )}
      </div>
      <div className="split">
        <section className="card">
          <QueryState query={query}>
            {() =>
              campaigns.length === 0 ? (
                <p className="empty">
                  {t("empty")}
                </p>
              ) : (
                <table className="table selectable" aria-label={t("tableLabel")}>
                  <thead>
                    <tr>
                      <th>{t("colCampaign")}</th>
                      <th>{t("colActor")}</th>
                      <th className="num">{t("colIoc")}</th>
                      <th className="hide-narrow">{t("colActivity")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {campaigns.map((c) => {
                      const seen = parseDate(c.last_seen);
                      return (
                        <tr
                          key={c.id}
                          tabIndex={0}
                          aria-current={!creating && c.id === selected ? "true" : undefined}
                          onClick={() => select(c.id)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              select(c.id);
                            }
                          }}
                        >
                          <td className="cell-title">{c.name}</td>
                          <td>{c.actor ? c.actor.name : <span className="muted">{c.actor_id ?? "—"}</span>}</td>
                          <td className="num mono">{formatNumber(c.indicators)}</td>
                          <td className="muted hide-narrow">{seen ? formatAgo(seen) : "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )
            }
          </QueryState>
        </section>
        {creating && canEdit ? (
          <NewCampaign onCreated={(c) => select(c.id)} />
        ) : selected ? (
          <CampaignPanel campaignId={selected} onDeleted={() => navigate("/campagnes", { replace: true })} />
        ) : (
          <aside className="card detail">
            <p className="empty">{query.isPending ? messages("loading") : t("noneSelected")}</p>
          </aside>
        )}
      </div>
    </>
  );
}
