# ADR-001 — Formule du score de risque composite

- **Statut :** accepté
- **Date :** 2026-09-19
- **Décideurs :** Lead Architect (Godwill FOKA)
- **Concerne :** MOD-03, RF-14

## Contexte

Deux documents fondateurs décrivent le score de risque composite avec des pondérations et des seuils
différents.

**Cahier des charges v1.0.0** (statut : *approuvé pour développement*) :

```
R = min(100, CVSS × 3.0 + EPSS × 100 × 0.25 + K × 25 + E × 10 + A × 10)
```

Seuils : 80 / 60 / 40.

**Product Vision Document v1.0** (statut : document stratégique) :

```
CVSS 30 % + EPSS 25 % + KEV 25 % + Exploit 10 % + Ransomware 5 % + CWE 5 %
```

Seuils : 70 / 40 / 20.

Trois écarts concrets :

1. le poids du facteur ransomware — 10 points contre 5 ;
2. l'existence d'un sixième facteur CWE valant 5 points, absent du CdC ;
3. les seuils de la grille de décision SOC, qui déplacent la frontière du « critique » de 80 à 70.

Le troisième écart n'est pas cosmétique : avec les seuils de la vision, une CVE à CVSS 9.8 présente
au KEV mais à EPSS modeste bascule en P0 et déclenche un patch sous 24 heures. Avec ceux du CdC,
elle reste en P1. Sur un volume de plusieurs centaines de CVE par semaine, cela change le nombre
d'astreintes déclenchées.

## Décision

**La formule et les seuils du Cahier des charges font foi pour la v1.0.**

Le facteur CWE n'est pas implémenté en v1.0 et part au backlog v2.0.

## Justification

1. **Statut documentaire.** Le CdC est le seul des deux documents marqué « approuvé pour
   développement ». Le PVD est un document stratégique destiné aux parties prenantes externes, pas
   une spécification opposable.
2. **Le facteur CWE n'est pas alimentable en v1.0.** Aucun des collecteurs prévus aux phases 2 et 3
   (NVD, KEV, EPSS, OTX) ne fournit de pondération de dangerosité par CWE exploitable directement.
   L'implémenter en v1.0 reviendrait à inventer un barème arbitraire — ce qui contredirait le
   caractère *déterministe* exigé par RF-14.
3. **Somme normalisée.** Les contributions maximales du CdC somment exactement à 100
   (30 + 25 + 25 + 10 + 10), ce qui rend la borne `min(100, …)` défensive plutôt qu'écrêtante. La
   variante du PVD sans CWE implémenté sommerait à 95, produisant un score maximal inatteignable.
4. **Conservatisme des seuils.** Des seuils plus hauts génèrent moins de P0. Pour une v1.0 dont la
   précision de collecte n'est pas encore éprouvée, le coût d'un faux positif en astreinte de nuit
   dépasse celui d'un vrai positif traité en J+1 sur une CVE déjà couverte par d'autres contrôles.

## Conséquences

**Positives**

- Une seule source de vérité pour l'implémentation, testable et auditable.
- `compute_risk_breakdown()` retourne la contribution de chaque facteur : tout score affiché à un
  analyste est explicable ligne par ligne, ce qu'exige un usage en audit de conformité NIS 2.
- Le seuil d'alerte reste configurable via `RISK_ALERT_THRESHOLD` : un opérateur qui veut le
  comportement de la vision (70) peut l'obtenir sans modifier le code.

**Négatives**

- Le Product Vision Document reste en écart tant qu'il n'est pas révisé. Le fichier
  [`../PRODUCT_VISION.md`](../PRODUCT_VISION.md) porte un avertissement explicite à cet endroit.
- Le facteur CWE devra faire l'objet d'un ADR de suivi lors de son introduction en v2.0, avec un
  rééquilibrage de la somme des poids.

## Suivi

- [ ] Réviser le PVD v1.1 pour aligner sa section scoring sur cet ADR.
- [ ] ADR-002 à rédiger si le facteur CWE est retenu pour la v2.0, incluant la source de données et
      le rééquilibrage des poids.
- [ ] Valider empiriquement les seuils sur 30 jours de collecte réelle après le jalon M3, et
      documenter le taux de P0 observé.

## Références

- [Cahier des charges §3.3.3](../CAHIER_DES_CHARGES.md#mod-03--cve-tracker--vulnerability-intelligence)
- [Product Vision Document, Tome 3](../PRODUCT_VISION.md#tome-3--architecture-fonctionnelle)
- Implémentation : [`illwatch/modules/cve_tracker/scoring.py`](../../illwatch/modules/cve_tracker/scoring.py)
- Tests : [`tests/test_scoring.py`](../../tests/test_scoring.py)
