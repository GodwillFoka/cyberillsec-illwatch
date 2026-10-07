# ADR-014 — Score composite : dépendance à EPSS et plancher KEV

- **Statut :** **accepté le 07/10/2026** — options **A + B + C** (décision de Godwill FOKA)
- **Date :** 2026-10-04
- **Concerne :** ADR-001 (formule du score), `illwatch/modules/cve_tracker/scoring.py`

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
| A | Statu quo + signal (fait en M7 lot 3 : `cve.epss_stale`, `illwatch status`) | panne visible | P0 toujours absentes pendant la panne |
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

## Décision (07/10/2026)

**A + B + C retenues, D rejetée**, après chiffrage sur la base réelle du poste Kali (26 416 CVE) :

| Priorité | CVE | dont KEV | sans EPSS |
|---|---|---|---|
| P0 | 495 | 495 | 0 |
| P1 | 627 | 627 | 0 |
| P2 | 638 | **602** | 0 |
| P3 | 24 656 | **10** | 109 |

612 CVE exploitées (KEV) sur 1 734 étaient en P2 ou P3. Effet attendu de B : P1 passe de 627 à
1 239 ; plus aucune CVE KEV sous P1.

## Mise en œuvre

- **B — plancher KEV** : `compute_risk_breakdown` relève la priorité à P1 pour une CVE KEV que la
  formule classe P2 ou P3. **Le score n'est pas modifié** (formule de l'ADR-001 intacte,
  historique comparable) ; `RiskBreakdown.kev_floor` le signale, l'API l'expose
  (`breakdown.kev_floor`) et `illwatch cves show` l'affiche. Chaque changement de priorité dû au
  plancher est historisé avec le motif suffixé `+floor_kev` (ex. `kev+floor_kev`).
- **Reclassement de l'existant** : `illwatch cves rescore` recalcule toutes les priorités une fois,
  sans alerte (le score ne change pas, aucun seuil ne peut être franchi).
- **C — dernière valeur EPSS connue** : la synchronisation n'efface jamais un score EPSS ; une
  panne de l'API FIRST laisse donc les scores et les P0 en place. Ce comportement est désormais
  verrouillé par un test (`test_panne_epss_ne_fait_pas_tomber_les_p0`). L'âge de la donnée est
  suivi globalement (`collector_state` `epss`, alerte `cve.epss_stale`, `illwatch status`) : un
  horodatage par CVE n'apporterait pas d'information utile au SOC.
- **C, second volet (percentile médian pour une CVE jamais notée)** : **non retenu**. L'EPSS
  médian est très faible (bien en dessous de 0,01), soit moins de 0,25 point de score : la règle
  compliquerait la formule sans effet mesurable (à vérifier sur la base : médiane de `epss_score`). Les 109 CVE sans EPSS sont toutes hors KEV et en P3.
