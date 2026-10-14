// Contexte MITRE ATT&CK d'une détection (M10, ADR-023) : techniques révélées par la règle,
// groupes ou logiciels cités dans le renseignement, avec leurs techniques connues. Les liens
// ouvrent attack.mitre.org dans un nouvel onglet, sans transmettre l'adresse d'ILL Watch.
import type { AttackContext, TechniqueRef } from "../api/types";
import { Link } from "../lib/router";

export const ATTACK_ATTRIBUTION = "ATT&CK® © The MITRE Corporation, reproduit avec son autorisation.";

export function TechniqueChip({ technique }: { technique: TechniqueRef }) {
  return (
    <a
      className="badge attack"
      href={technique.url}
      target="_blank"
      rel="noopener noreferrer"
      title={`${technique.id} · ${technique.name}`}
    >
      {technique.id}
    </a>
  );
}

/** Puces seules (listes denses : correspondances de chasse). */
export function TechniqueChips({ context }: { context: AttackContext | null | undefined }) {
  if (!context || (context.techniques.length === 0 && context.actors.length === 0)) return null;
  return (
    <span className="attack-chips">
      {context.campaigns.map((c) => (
        <Link key={c.id} className="badge attack campaign" to={`/campagnes?campagne=${c.id}`} title="Campagne">
          {c.name}
        </Link>
      ))}
      {context.techniques.map((t) => (
        <TechniqueChip key={t.id} technique={t} />
      ))}
      {context.actors.map((a) => (
        <a
          key={a.id}
          className="badge attack actor"
          href={a.url}
          target="_blank"
          rel="noopener noreferrer"
          title={`${a.id} · ${a.name}`}
        >
          {a.name}
        </a>
      ))}
    </span>
  );
}

/** Section complète (panneaux de détail). */
export function AttackSection({ context }: { context: AttackContext | null | undefined }) {
  const empty =
    !context ||
    (context.techniques.length === 0 && context.actors.length === 0 && context.campaigns.length === 0);
  return (
    <section>
      <h3>MITRE ATT&amp;CK</h3>
      {empty ? (
        <p className="muted small">
          Aucune technique attribuable à cette détection, aucun acteur connu cité dans le renseignement.
        </p>
      ) : (
        <dl className="facts">
          {context.techniques.length > 0 && (
            <>
              <dt>Technique</dt>
              <dd>
                {context.techniques.map((t) => (
                  <span key={t.id} className="attack-line">
                    <TechniqueChip technique={t} /> {t.name}
                  </span>
                ))}
              </dd>
            </>
          )}
          {context.campaigns.length > 0 && (
            <>
              <dt>Campagne</dt>
              <dd>
                {context.campaigns.map((c) => (
                  <span key={c.id} className="attack-line">
                    <Link to={`/campagnes?campagne=${c.id}`}>{c.name}</Link>
                    {c.actor_id ? <span className="mono muted">{c.actor_id}</span> : null}
                  </span>
                ))}
              </dd>
            </>
          )}
          {context.actors.map((a) => (
            <div key={a.id} className="attack-actor">
              <dt>{a.kind === "group" ? "Groupe" : "Logiciel"}</dt>
              <dd>
                <a href={a.url} target="_blank" rel="noopener noreferrer">
                  {a.name}
                </a>{" "}
                <span className="mono muted">{a.id}</span>
                <span className="cell-sub"> · cité : « {a.matched} »</span>
                {a.techniques.length > 0 && (
                  <span className="attack-chips">
                    {a.techniques.map((t) => (
                      <TechniqueChip key={t.id} technique={t} />
                    ))}
                  </span>
                )}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <p className="muted small">{ATTACK_ATTRIBUTION}</p>
    </section>
  );
}
