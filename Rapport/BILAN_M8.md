# ILLWATCH : bilan de M8 « Detection & Correlation », clos le 14/10/2026

## Critère de sortie

> Sur un jeu de données figé, 100 % des cas de corrélation attendus produisent une alerte ;
> taux de faux positifs mesuré et publié.

| Constat | Résultat | Preuve |
|---|---|---|
| Jeu figé (18 cas, 8 attendus, 10 pièges dont 3 de version) | **100 % détectés, 0 % de faux positifs**, rejoué par la CI à chaque modification | `Rapport/M8_MESURE_13-10-2026.md`, `tests/test_correlation.py` |
| Données réelles (Kali, 5 actifs, 1 741 CVE avec plages NVD) | **38 évènements → 0 vrai positif** : 37 clos automatiquement (hors des versions vulnérables ou autre produit), CVE-2022-0543 requalifiée « selon plateforme » | `Rapport/M8_MESURE_REELLE_13-10-2026.md`, sortie `illwatch correlate list --all` du 14/10 |

**M8 est clos** : le critère est constaté sur le jeu figé et confirmé sur données réelles.

## Livré

| Incrément | Contenu | ADR | PR |
|---|---|---|---|
| 1 | Confiance des IOC 0-100 (fiabilité des sources A-F, fraîcheur par type, récurrence) | 017 | #31-32 |
| 2 | Enrichissement hors ligne des IP (pays, système autonome, DB-IP Lite, mise à jour mensuelle) | 019 | #34-35 |
| 3 | Inventaire d'actifs, corrélation CORR-01 (KEV × actif), CORR-02 (exploit × actif), CORR-03 (actif dans un IOC), score justifié | 020 | #36 |
| 4 | Mesure sur jeu figé, `illwatch correlate evaluate` | 020 | #36 |
| Après mesure réelle | Corrélation par version (plages NVD), verdict « conditionnel » (plateformes), plateforme de l'actif, état et version dans la CLI et l'écran | 021 | #38-43 |
| Points en attente | Plages CIDR (type `NETWORK`, CORR-03 et RULE-06 par inclusion), calibration de RULE-03 (Tranco), plateforme de l'actif | 021 | #45 |

## Ce que la mesure réelle a appris

1. **Le nom du produit ne suffit pas** : ≈ 80 % de faux positifs sur un parc à jour. La version
   déclarée et les plages vulnérables de la NVD sont indispensables (ADR-021).
2. **Les configurations NVD ont une logique ET** : « Redis *sur* Debian 9 à 11 ». Les aplatir
   fabrique des faux positifs ; elles sont désormais conservées et tranchées par la plateforme
   déclarée de l'actif.
3. **Le doute reste du côté de l'alerte** : seuls les cas démontrés hors d'atteinte sont
   écartés ; « plages inconnues », « version non déclarée » et « selon plateforme » restent
   visibles, avec leur raison.

## Limites connues

- Les CPE de la NVD sont parfois tardifs ou incomplets : une CVE sans configuration garde le
  verdict « à vérifier ».
- RULE-03 (DGA) ne vise que les domaines aléatoires ; les DGA à dictionnaire lui échappent par
  construction (calibration : workflow « Calibration DGA »).
- Le parc mesuré (5 actifs) est petit ; la mesure sera reprise sur l'inventaire d'un pilote.
