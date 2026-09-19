# ADR-002 — GitLab comme dépôt principal, abandon de GitHub

- **Statut :** accepté
- **Date :** 2026-09-19
- **Décideurs :** Godwill FOKA, Belrick Stephane
- **Remplace :** la clause « Dépôt GitHub + miroir GitLab » du Cahier des charges v1.0.0

## Contexte

Les deux documents fondateurs désignaient GitHub comme dépôt principal :

- le Cahier des charges v1.0.0 en en-tête — *« DÉPÔT GITHUB : github.com/GodwillFoka/sentry
  (Miroir GitLab : gitlab.com/GodwillFoka/sentry) »* ;
- son critère de validation du jalon v1.0 — *« tag Git v1.0.0 poussé sur GitHub et GitLab »* ;
- le Product Vision Document, Tome 10, qui liste GitHub comme canal de communication principal.

Or SENTRY se positionne explicitement sur la souveraineté numérique européenne. Le Tome 1 fait de
la souveraineté l'une des six valeurs de CYBERILL. Le Tome 2 oppose SENTRY aux solutions
américaines sur le critère « Hébergement UE ». Le PVD identifie la « dépendance américaine » comme
l'un des cinq problèmes majeurs que la plateforme entend résoudre.

Héberger le code source d'une plateforme vendue sur son indépendance vis-à-vis des solutions
propriétaires américaines chez un éditeur américain est une contradiction visible par tout prospect
qui ouvre le README, et par tout auditeur qui instruit un dossier NIS 2.

## Décision

**GitLab devient le dépôt unique et principal du projet. GitHub est abandonné, sans miroir.**

Dépôt de référence : `gitlab.com/GodwillFoka/CYBERILLSEC-SENTRY`.

## Justification

1. **Cohérence du discours produit.** L'argument de souveraineté est le principal différenciateur de
   SENTRY face à CrowdStrike et Recorded Future. Un différenciateur que le projet ne s'applique pas
   à lui-même est un différenciateur qui ne tient pas en réunion commerciale.
2. **GitLab est de droit européen sur l'offre SaaS UE**, et l'édition Community est auto-hébergeable
   — ce qui laisse ouverte la migration vers une instance CYBERILL sans changer d'outillage.
3. **La CI est native et intégrée.** `.gitlab-ci.yml` couvre en un fichier ce que GitHub Actions
   faisait en un workflow plus Dependabot, et GitLab fournit nativement le SAST, la détection de
   secrets et le scan de dépendances — pertinent pour un projet de sécurité qui doit pouvoir montrer
   qu'il s'applique ses propres contrôles.
4. **Un seul dépôt plutôt qu'un dépôt et son miroir.** Un miroir se désynchronise, personne ne sait
   lequel fait foi, et les issues se dispersent sur deux plateformes. Le coût de maintenance d'un
   miroir n'était justifié par aucun besoin identifié.

## Conséquences

**Positives**

- Le discours de souveraineté devient vérifiable plutôt que déclaratif.
- Une seule source de vérité : un dépôt, un pipeline, un tracker d'issues.
- Analyses de sécurité (SAST, secrets, dépendances) acquises sans outillage tiers.

**Négatives — et elles sont réelles**

- **Découvrabilité.** L'écrasante majorité des contributeurs open source est sur GitHub. La vision
  2035 vise « 5 000+ contributeurs » ; ce choix rend cet objectif nettement plus difficile. C'est le
  coût assumé de la décision, pas un effet secondaire négligeable.
- Les documents fondateurs sont en écart tant qu'ils ne sont pas amendés (fait pour les conversions
  Markdown ; les PDF d'origine restent à réviser).
- Perte de l'écosystème d'intégrations GitHub, plus fourni.

**Atténuation de la découvrabilité**

Si la traction contributeurs devient un blocage mesuré — et seulement à ce moment-là — un miroir
GitHub en lecture seule pourra être remis en place, avec un README y renvoyant explicitement vers
GitLab pour les issues et les merge requests. Cette réintroduction éventuelle fera l'objet d'un ADR
de suivi, pas d'une dérive silencieuse.

## Suivi

- [ ] Amender les PDF d'origine (CdC en-tête, critère du jalon v1.0 ; PVD Tome 10).
- [ ] Faire autoriser `gitlab.com` par la politique de sortie réseau de l'organisation, faute de
      quoi aucune session Claude ne peut travailler sur le dépôt.
- [ ] Mesurer la traction contributeurs à 6 mois ; rouvrir la question du miroir si elle est nulle.

## Références

- [Cahier des charges — en-tête et §5.2](../CAHIER_DES_CHARGES.md)
- [Product Vision Document — Tomes 1, 2 et 10](../PRODUCT_VISION.md)
- Pipeline : [`.gitlab-ci.yml`](../../.gitlab-ci.yml)
