# ADR-014 — Score composite : dépendance à EPSS et plancher KEV (proposition pour M8)

- **Statut :** **à trancher** (aucune modification du score n'est faite sans décision)
- **Date :** 2026-10-04
- **Concerne :** ADR-001 (formule du score), `sentry/modules/cve_tracker/scoring.py`

## Constat sur données réelles

Calcul déterministe sur les 1 733 CVE du catalogue KEV, CVSS issu des flux NVD réels, sans
EPSS (bilan M7 lot 2, § 4) :

| Priorité | CVE |
|---|---|
| P0 | 0 |
| P1 | 617 |
| P2 | 1 100 |
| P3 | 16 |

Sans EPSS, `R = CVSS×3 + KEV×25 + Exploit×10 + Ransomware×10` plafonne à **75** : aucune CVE
n'atteint P0 (≥ 80), pas même Log4Shell (75). Avec son EPSS (≈ 0,94), elle passerait à ≈ 98.
Une panne de l'API FIRST suffit donc à faire disparaître toutes les P0.

16 CVE exploitées (KEV) sont classées P3, c'est-à-dire en « maintenance standard ».

## Options

| # | Option | Effet | Coût |
|---|---|---|---|
| A | Statu quo + signal (fait en M7 lot 3 : `cve.epss_stale`, `sentry status`) | panne visible | P0 toujours absentes pendant la panne |
| B | Plancher **KEV ⇒ au moins P1** | plus aucune CVE exploitée en P2/P3 ; aligné sur les délais de la directive CISA BOD 22-01 | priorité qui ne découle plus seulement de la formule (règle à documenter) |
| C | EPSS manquant remplacé par la **dernière valeur connue**, puis par le percentile médian | score stable pendant une panne courte | valeur potentiellement périmée |
| D | Repondérer la formule (ex. KEV × 35) | P0 atteignable sans EPSS | rupture de la comparabilité avec l'historique, contredit ADR-001 |

## Recommandation (à valider)

**A + B + C**, et rejet de D. B corrige une incohérence métier (une vulnérabilité exploitée ne
peut pas être en maintenance standard) sans toucher à la formule ; C rend le score robuste à une
panne de quelques jours ; A est déjà en place. Confiance : élevée sur le diagnostic, moyenne sur
C (dépend de la volatilité réelle d'EPSS, à mesurer sur 30 jours de données).

## Si accepté

- `scoring.py` : plancher appliqué après le calcul, raison historisée (`floor_kev`).
- `sync_cves` : conservation de la dernière valeur EPSS connue, horodatée.
- Tests sur le jeu réel des 1 733 CVE KEV : 0 CVE KEV en P2/P3.
