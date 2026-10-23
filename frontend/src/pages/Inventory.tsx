// Inventaire d'actifs (M8, ADR-020) : ce que l'organisation exploite. Le produit est cherché
// dans les CVE (KEV, exploits publics), les adresses et domaines dans les IOC. L'actif choisi
// est dans l'adresse (?actif=…) ; « Nouvel actif » ouvre un formulaire vide.
import { Plus, Trash2 } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { useDeleteAsset, useSaveAsset } from "../api/mutations";
import { useAssets } from "../api/queries";
import type { Asset, AssetWrite } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { LevelBadge } from "../components/Badge";
import { QueryState } from "../components/QueryState";
import { messages } from "../i18n/common.i18n";
import { asUuid, Link, useLocation } from "../lib/router";
import { t } from "./Inventory.i18n";

const criticalities = (): [AssetWrite["criticality"], string][] => [
  ["CRITICAL", t("crit.CRITICAL")],
  ["HIGH", t("crit.HIGH")],
  ["MEDIUM", t("crit.MEDIUM")],
  ["LOW", t("crit.LOW")],
];

const EDITOR_ROLES = new Set(["ADMIN", "ANALYST"]);

function lines(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function AssetForm({ asset, onSaved, onDeleted }: { asset: Asset | null; onSaved: (a: Asset) => void; onDeleted: () => void }) {
  const { user } = useAuth();
  const save = useSaveAsset(asset?.id ?? null);
  const remove = useDeleteAsset();
  const [name, setName] = useState("");
  const [product, setProduct] = useState("");
  const [vendor, setVendor] = useState("");
  const [version, setVersion] = useState("");
  const [platform, setPlatform] = useState("");
  const [criticality, setCriticality] = useState<AssetWrite["criticality"]>("MEDIUM");
  const [addresses, setAddresses] = useState("");
  const [domains, setDomains] = useState("");
  const [notes, setNotes] = useState("");
  const [active, setActive] = useState(true);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    setName(asset?.name ?? "");
    setProduct(asset?.product ?? "");
    setVendor(asset?.vendor ?? "");
    setVersion(asset?.version ?? "");
    setPlatform(asset?.platform ?? "");
    setCriticality(asset?.criticality ?? "MEDIUM");
    setAddresses((asset?.addresses ?? []).join("\n"));
    setDomains((asset?.domains ?? []).join("\n"));
    setNotes(asset?.notes ?? "");
    setActive(asset?.is_active ?? true);
    setConfirming(false);
    save.reset();
    remove.reset();
  }, [asset?.id]);

  const canEdit = user ? EDITOR_ROLES.has(user.role) : false;
  const canDelete = user?.role === "ADMIN";
  const error = save.error ?? remove.error;

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate(
      {
        name,
        product,
        vendor: vendor || null,
        version: version || null,
        platform: platform || null,
        criticality,
        addresses: lines(addresses),
        domains: lines(domains),
        notes: notes || null,
        is_active: active,
      },
      { onSuccess: onSaved },
    );
  }

  return (
    <form className="card detail form" onSubmit={submit} aria-labelledby="actif-titre">
      <section>
        <div className="title" id="actif-titre">
          {asset ? <LevelBadge level={asset.criticality} /> : null}
          <span>{asset ? asset.name : t("newAsset")}</span>
        </div>
        {asset && (
          <p className="small">
            <Link to={`/correlations?actif=${encodeURIComponent(asset.id)}`}>{t("seeCorrelations")}</Link>
          </p>
        )}
      </section>
      <section className="form">
        <h3>{t("identity")}</h3>
        <label className="field">
          {t("name")}
          <input required maxLength={120} value={name} disabled={!canEdit} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          {t("product")}
          <input
            required
            minLength={3}
            maxLength={120}
            placeholder={t("productPlaceholder")}
            value={product}
            disabled={!canEdit}
            onChange={(e) => setProduct(e.target.value)}
          />
        </label>
        <div className="row">
          <label className="field grow">
            {t("vendor")}
            <input maxLength={120} value={vendor} disabled={!canEdit} onChange={(e) => setVendor(e.target.value)} />
          </label>
          <label className="field grow">
            {t("version")}
            <input maxLength={60} value={version} disabled={!canEdit} onChange={(e) => setVersion(e.target.value)} />
          </label>
        </div>
        <label className="field">
          {t("platform")}
          <input
            maxLength={80}
            placeholder={t("platformPlaceholder")}
            value={platform}
            disabled={!canEdit}
            onChange={(e) => setPlatform(e.target.value)}
          />
        </label>
        <label className="field">
          {t("criticality")}
          <select
            value={criticality}
            disabled={!canEdit}
            onChange={(e) => setCriticality(e.target.value as AssetWrite["criticality"])}
          >
            {criticalities().map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </section>
      <section className="form">
        <h3>{t("exposure")}</h3>
        <label className="field">
          {t("addresses")}
          <textarea className="mono" value={addresses} disabled={!canEdit} onChange={(e) => setAddresses(e.target.value)} />
        </label>
        <label className="field">
          {t("domains")}
          <textarea className="mono" value={domains} disabled={!canEdit} onChange={(e) => setDomains(e.target.value)} />
        </label>
        <label className="field">
          {t("notes")}
          <textarea maxLength={2000} value={notes} disabled={!canEdit} onChange={(e) => setNotes(e.target.value)} />
        </label>
        <label className="check">
          <input type="checkbox" checked={active} disabled={!canEdit} onChange={(e) => setActive(e.target.checked)} />
          {t("inService")}
        </label>
      </section>
      <section>
        {error && (
          <p className="notice error" role="alert">
            {t("refused", { message: error.message })}
          </p>
        )}
        <div className="actions">
          {asset && canDelete && (
            <button
              className={confirming ? "btn danger" : "btn"}
              type="button"
              disabled={remove.isPending}
              onClick={() =>
                confirming ? remove.mutate(asset.id, { onSuccess: onDeleted }) : setConfirming(true)
              }
            >
              <Trash2 size={20} strokeWidth={1.5} aria-hidden="true" />
              {confirming ? t("confirmDelete") : t("delete")}
            </button>
          )}
          <button className="btn primary" type="submit" disabled={!canEdit || save.isPending}>
            {save.isPending ? t("saving") : asset ? t("save") : t("declare")}
          </button>
        </div>
        {confirming && (
          <p className="reason">{t("deleteNote")}</p>
        )}
        {!canEdit && <p className="reason">{t("rolesOnly")}</p>}
      </section>
    </form>
  );
}

export function Inventory() {
  const { search, navigate } = useLocation();
  const { user } = useAuth();
  const query = useAssets();
  const params = new URLSearchParams(search);
  const creating = params.get("nouveau") === "1";
  const requested = asUuid(params.get("actif"));
  const assets = query.data ?? [];
  const selected = creating ? null : (assets.find((a) => a.id === requested) ?? (requested ? null : assets[0] ?? null));
  const canEdit = user ? EDITOR_ROLES.has(user.role) : false;
  const [flash, setFlash] = useState<string | null>(null);

  const select = (id: string) => {
    setFlash(null);
    navigate(`/inventaire?actif=${encodeURIComponent(id)}`, { replace: true });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("title")}</h1>
          <p>{t("subtitle")}</p>
        </div>
        {canEdit && (
          <button className="btn primary" type="button" onClick={() => navigate("/inventaire?nouveau=1", { replace: true })}>
            <Plus size={20} strokeWidth={1.5} aria-hidden="true" />
            {t("newAsset")}
          </button>
        )}
      </div>

      {flash && (
        <p className="notice ok gap-bottom" role="status">
          {flash}
        </p>
      )}
      <div className="split">
        <section className="card">
          <div className="toolbar">
            <span className="muted">{query.data ? t.plural("count", assets.length) : " "}</span>
          </div>
          <QueryState query={query}>
            {() =>
              assets.length === 0 ? (
                <p className="empty">
                  {t("empty")}
                </p>
              ) : (
                <table className="table selectable" aria-label={t("tableLabel")}>
                  <thead>
                    <tr>
                      <th>{t("colCriticality")}</th>
                      <th>{t("colAsset")}</th>
                      <th>{t("colProduct")}</th>
                      <th className="num">{t("colExposure")}</th>
                      <th>{t("colState")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.map((asset) => (
                      <tr
                        key={asset.id}
                        tabIndex={0}
                        aria-current={asset.id === selected?.id ? "true" : undefined}
                        className={asset.is_active ? undefined : "done"}
                        onClick={() => select(asset.id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            select(asset.id);
                          }
                        }}
                      >
                        <td>
                          <LevelBadge level={asset.criticality} />
                        </td>
                        <td className="cell-title">{asset.name}</td>
                        <td>
                          {asset.product}
                          {asset.vendor ? <span className="cell-sub"> · {asset.vendor}</span> : null}
                        </td>
                        <td className="num mono">{asset.addresses.length + asset.domains.length}</td>
                        <td className="muted">{asset.is_active ? t("active") : t("retired")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            }
          </QueryState>
        </section>

        {selected || creating || canEdit ? (
          <AssetForm
            asset={selected}
            onSaved={(saved) => {
              select(saved.id);
              setFlash(t("saved", { name: saved.name }));
            }}
            onDeleted={() => {
              navigate("/inventaire", { replace: true });
              setFlash(t("deleted"));
            }}
          />
        ) : (
          <aside className="card detail">
            <p className="empty">{query.isPending ? messages("loading") : t("noAsset")}</p>
          </aside>
        )}
      </div>
    </>
  );
}
