# ADR-013 — Déploiement de production : TLS par Caddy, migrations isolées, analyse d'image (M7, lot 3)

- **Statut :** proposé
- **Date :** 2026-10-04
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** `docker-compose.prod.yml`, `deploy/Caddyfile`, `.gitlab-ci.yml`,
  `illwatch/cli/feeds.py` (entretien quotidien), `illwatch/modules/foundation/status.py`

## Contexte

Après les lots 1 et 2, trois manques empêchaient encore une mise en ligne :

1. aucune terminaison TLS : l'API servait du HTTP en clair, l'en-tête HSTS n'avait de sens que
   derrière un proxy qui n'existait pas ;
2. l'API exécutait les migrations à son démarrage, donc détenait le mot de passe du
   propriétaire des tables, ce qui annulait en partie la séparation des rôles d'ADR-012 ;
3. l'image Docker n'était analysée par aucun outil.

Deux constats d'exploitation s'y ajoutent : `refresh_tokens` croît sans limite, et une panne
d'EPSS rend P0 inatteignable sans aucun signal (bilan du lot 2, § 4).

## Décision

1. **Caddy** termine TLS (Let's Encrypt automatique ; autorité interne pour `localhost`),
   compresse, retire l'en-tête `Server`, réécrit `X-Forwarded-For` avec l'adresse réelle du
   client. Il est le seul service publié (80, 443, 443/udp pour HTTP/3).
2. **Overlay de production** `docker-compose.prod.yml` : conteneur éphémère `migrate`
   (propriétaire), API et worker en rôle applicatif sans `MIGRATION_DATABASE_URL`, ports de
   PostgreSQL, Redis et de l'API retirés de l'hôte, secrets obligatoires (`${VAR:?}`), adresse
   fixe de Caddy (`172.30.0.10`) seule autorisée à transmettre `X-Forwarded-For`.
3. **Production refusée** avec un mot de passe de base absent ou de développement.
4. **CI** : l'image est poussée dans le registre du projet sous son SHA et analysée par le
   gabarit GitLab *Container Scanning* (non bloquant au départ) ; les deux fichiers Compose
   sont validés à chaque pipeline (`compose-config`).
5. **Entretien quotidien** par le worker : purge des jetons de rafraîchissement expirés ou
   révoqués depuis plus de 30 jours ; journal `cve.epss_stale` si EPSS date de plus de 48 h.
   `illwatch status` affiche le même avertissement.

## Justification

- *nginx* : écarté, il exige une gestion manuelle des certificats (certbot) ; Caddy les obtient
  et les renouvelle seul, pour un fichier de configuration de quinze lignes.
- *Traefik* : écarté, configuration par étiquettes Docker plus diffuse, intérêt surtout en
  orchestrateur multi-services.
- *Migrations au démarrage de l'API* (comportement de l'image par défaut, conservé pour le
  développement) : écartées en production pour la raison 2 du contexte.
- *Analyse Trivy en job dédié* : écartée, les binaires et la base de vulnérabilités sont
  distribués hors du registre GitLab ; le gabarit officiel est maintenu par GitLab.

## Conséquences

- Positives : HTTPS/2 et HTTP/3 sans gestion de certificats ; l'API ne peut plus modifier la
  structure de la base, même compromise ; adresse client fiable pour la limitation de débit et
  l'audit ; vulnérabilités de l'image visibles dans chaque MR ; plus de croissance infinie des
  sessions ; panne EPSS visible.
- **Négatives :**
  - Compose v2.24 ou plus requis pour l'overlay (`!reset`) ; l'ancien `docker-compose` v1 de
    certaines distributions ne convient pas ;
  - une image par commit dans le registre : prévoir une politique de nettoyage GitLab ;
  - `container_scanning` non bloquant tant que le registre n'est pas confirmé actif ;
  - Let's Encrypt exige un nom DNS public et les ports 80/443 ouverts.

## Suivi

- Rendre `container_scanning` bloquant pour les vulnérabilités CRITICAL corrigibles.
- Déployer en préproduction (VPS UE), constater 7 jours de collecte (M11).
