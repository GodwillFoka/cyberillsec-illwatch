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
import { formatNumber } from "../lib/format";
import { asUuid, Link, useLocation } from "../lib/router";

const CRITICALITIES: [AssetWrite["criticality"], string][] = [
  ["CRITICAL", "Critique — arrêt de l'activité"],
  ["HIGH", "Élevée — service exposé ou sensible"],
  ["MEDIUM", "Moyenne"],
  ["LOW", "Faible — poste ou service secondaire"],
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
          <span>{asset ? asset.name : "Nouvel actif"}</span>
        </div>
        {asset && (
          <p className="small">
            <Link to={`/correlations?actif=${encodeURIComponent(asset.id)}`}>Voir ses corrélations</Link>
          </p>
        )}
      </section>
      <section className="form">
        <h3>Identité</h3>
        <label className="field">
          Nom
          <input required maxLength={120} value={name} disabled={!canEdit} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          Produit (tel que nommé dans les avis de sécurité)
          <input
            required
            minLength={3}
            maxLength={120}
            placeholder="FortiOS, Exchange Server, Confluence…"
            value={product}
            disabled={!canEdit}
            onChange={(e) => setProduct(e.target.value)}
          />
        </label>
        <div className="row">
          <label className="field grow">
            Éditeur
            <input maxLength={120} value={vendor} disabled={!canEdit} onChange={(e) => setVendor(e.target.value)} />
          </label>
          <label className="field grow">
            Version
            <input maxLength={60} value={version} disabled={!canEdit} onChange={(e) => setVersion(e.target.value)} />
          </label>
        </div>
        <label className="field">
          Plateforme (système hôte : tranche les CVE propres à une distribution)
          <input
            maxLength={80}
            placeholder="Debian 12, Ubuntu 22.04, Windows Server 2022…"
            value={platform}
            disabled={!canEdit}
            onChange={(e) => setPlatform(e.target.value)}
          />
        </label>
        <label className="field">
          Criticité
          <select
            value={criticality}
            disabled={!canEdit}
            onChange={(e) => setCriticality(e.target.value as AssetWrite["criticality"])}
          >
            {CRITICALITIES.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </section>
      <section className="form">
        <h3>Exposition</h3>
        <label className="field">
          Adresses IP publiques (une par ligne)
          <textarea className="mono" value={addresses} disabled={!canEdit} onChange={(e) => setAddresses(e.target.value)} />
        </label>
        <label className="field">
          Domaines (une par ligne ; les sous-domaines sont couverts)
          <textarea className="mono" value={domains} disabled={!canEdit} onChange={(e) => setDomains(e.target.value)} />
        </label>
        <label className="field">
          Notes
          <textarea maxLength={2000} value={notes} disabled={!canEdit} onChange={(e) => setNotes(e.target.value)} />
        </label>
        <label className="check">
          <input type="checkbox" checked={active} disabled={!canEdit} onChange={(e) => setActive(e.target.checked)} />
          Actif en service (un actif retiré n'est plus corrélé)
        </label>
      </section>
      <section>
        {error && (
          <p className="notice error" role="alert">
            Refusé : {error.message}
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
              {confirming ? "Confirmer la suppression" : "Supprimer"}
            </button>
          )}
          <button className="btn primary" type="submit" disabled={!canEdit || save.isPending}>
            {save.isPending ? "Enregistrement…" : asset ? "Enregistrer" : "Déclarer l'actif"}
          </button>
        </div>
        {confirming && (
          <p className="reason">Ses évènements corrélés seront supprimés ; les incidents restent.</p>
        )}
        {!canEdit && <p className="reason">Modification réservée aux rôles analyste et administrateur.</p>}
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
          <h1>Inventaire</h1>
          <p>Produits, adresses et domaines de l'organisation : la base de la corrélation</p>
        </div>
        {canEdit && (
          <button className="btn primary" type="button" onClick={() => navigate("/inventaire?nouveau=1", { replace: true })}>
            <Plus size={20} strokeWidth={1.5} aria-hidden="true" />
            Nouvel actif
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
            <span className="muted">{query.data ? `${formatNumber(assets.length)} actif${assets.length > 1 ? "s" : ""}` : " "}</span>
          </div>
          <QueryState query={query}>
            {() =>
              assets.length === 0 ? (
                <p className="empty">
                  Inventaire vide. Déclarez vos produits exposés (pare-feu, messagerie, VPN…) : ILL Watch vous
                  signalera les CVE exploitées qui les touchent et vos adresses présentes dans les IOC.
                </p>
              ) : (
                <table className="table selectable" aria-label="Actifs">
                  <thead>
                    <tr>
                      <th>Criticité</th>
                      <th>Actif</th>
                      <th>Produit</th>
                      <th className="num">Exposition</th>
                      <th>État</th>
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
                        <td className="muted">{asset.is_active ? "en service" : "retiré"}</td>
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
              setFlash(`« ${saved.name} » enregistré : la prochaine passe de corrélation en tiendra compte.`);
            }}
            onDeleted={() => {
              navigate("/inventaire", { replace: true });
              setFlash("Actif supprimé, avec ses évènements corrélés.");
            }}
          />
        ) : (
          <aside className="card detail">
            <p className="empty">{query.isPending ? "Chargement…" : "Aucun actif déclaré."}</p>
          </aside>
        )}
      </div>
    </>
  );
}
