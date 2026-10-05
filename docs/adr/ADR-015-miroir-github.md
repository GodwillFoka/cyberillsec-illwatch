# ADR-015 — Miroir GitHub : CI, documentation publiée, image Docker et releases

- **Statut :** accepté
- **Date :** 2026-10-06
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-002 (hébergement GitLab), CI/CD, distribution

## Contexte

L'ADR-002 a fait de GitLab la plateforme unique du projet et en a documenté le coût : une moindre
découvrabilité auprès des contributeurs. Le 05/10/2026, le code a été publié sur
`github.com/GodwillFoka/cyberillsec-sentry` (dépôt public). Deux faits pèsent :

- les sessions d'assistance ne peuvent pas joindre `gitlab.com` (refus réseau), alors qu'elles
  poussent sur GitHub ;
- les runners GitHub ont accès à Internet : la validation sur données réelles (NVD, EPSS, flux
  publics), impossible depuis le bac à sable d'audit, y devient automatisable.

## Décision

GitLab reste le dépôt de référence ; GitHub devient un **miroir public complet** qui exécute la
même CI, publie la documentation, l'image Docker et les releases.

## Justification

- Découvrabilité : GitHub est l'endroit où l'on cherche un outil CTI open source (topics,
  recherche, GHCR) ; l'ADR-002 identifiait ce manque.
- Vérification : un second pipeline, indépendant, rejoue qualité, tests, migrations et sécurité ;
  la validation réelle hebdomadaire ferme la dette D3 de l'audit du 03/10.
- Distribution : une image versionnée sur `ghcr.io` évite de construire sur le serveur de
  production (`SENTRY_IMAGE`, `--no-build`).

Option écartée : basculer entièrement sur GitHub — contredirait l'argument de souveraineté de
l'ADR-002 sans nécessité.

## Conséquences

- Positives : CI doublée, site de documentation public, image prête à déployer, releases avec
  notes issues du CHANGELOG.
- Négatives : deux dépôts à garder synchronisés (`git push origin` **et** `git push github`) ;
  deux CI à maintenir (`.gitlab-ci.yml` et `.github/workflows/`) ; une dérive est possible si
  un commit n'est poussé que d'un côté.

## Suivi

- Pousser vers les deux remotes à chaque fusion (`git push origin main && git push github main`).
- Ajouter les clés `NVD_API_KEY`, `OTX_API_KEY`, `TAXII_AUTH` aux secrets GitHub pour que la
  validation réelle couvre aussi les sources sous clé.
- Réévaluer à la v0.2.0 : miroir automatique GitLab → GitHub (fonction « push mirror » de GitLab).
