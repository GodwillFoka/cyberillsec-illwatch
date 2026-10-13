# ILL Watch — Feuille de route après la v1.0 fonctionnelle (M7 → M11)

**Version :** 10/10/2026 · **Point de départ :** baseline `v0.1.1` (M1–M6 intégrés dans `main`,
audit `Rapport/ETAT_GLOBAL_SENTRY_2026-10-03.md`)

**État au 06/10/2026 :** `v0.1.1` taguée ; M7 (lots 1 à 3) **fusionné dans `main`**, qui porte
la version de développement `0.2.0.dev0`. Validation sur données réelles automatisée sur GitHub
Actions (hebdomadaire). Décision du 08/10 (ADR-016) : l'interface web passe avant l'hébergement.
Interface complète (lot 1 et écrans Sources CTI, Administration), identité ILL Watch v2 (brand book, ADR-018). Préproduction
publique sur VPS **reportée le 11/10** : une préproduction locale identique tourne en CI à chaque
modification ; M7 se clôt au passage sur le VPS. M8 démarré en parallèle (ADR-017).

Règle de conduite : un jalon est clos quand ses **critères de sortie sont constatés**, pas quand
le code est fusionné. Chaque jalon part d'une branche créée depuis `main` à jour et se termine par
un bilan dans `Rapport/` et un tag.

```
M1–M6 intégrés ─▶ audit global ─▶ v0.1.1 ─▶ M7 ─▶ M8 ─▶ M9 ─▶ M10 ─▶ M11 ─▶ v0.2.0
                                            durcir  corréler  opérer  contextualiser  exploiter
```

## Test d'acceptation principal

Le parcours ci-dessous devient le test d'acceptation de la v0.2.0. Les étapes 1–3, 7–10, 12–14
sont déjà automatisées par `scripts/scenario_soc.py` ; M8 à M10 ajoutent les étapes 4–6 et 11.

1. Threat feed → 2. ingestion → 3. normalisation → 4. enrichissement → 5. corrélation →
6. détection → 7. alerte → 8. incident → 9. investigation → 10. chasse → 11. ATT&CK →
12. dashboard → 13. résolution → 14. piste d'audit.

## M7 — Production Hardening

**But.** Rendre ILL Watch déployable sans réserve de sécurité connue.

| Lot | Contenu | Critère de sortie |
|---|---|---|
| 1 ✅ codé, fusionné | Immuabilité étendue (`TRUNCATE`), journal d'audit append-only, `/ready` distinct de `/health`, en-têtes HTTP, identifiant de requête et erreurs JSON uniformes, verrouillage par couple compte/IP, ports Compose sur 127.0.0.1, contraintes de dépendances, sauvegarde/restauration | tests verts ; scénario 44/44 ; audit § 7 sans ✘ — **constaté en local le 03/10** (`Rapport/BILAN_M7_LOT1.md`) |
| 2 ✅ codé, fusionné | Rôle PostgreSQL applicatif non propriétaire, rôle de migration séparé ; Redis avec mot de passe ; rotation de `SECRET_KEY` (clé courante + clé précédente) ; jetons de rafraîchissement révocables | test : le compte applicatif ne peut ni `ALTER` ni `DROP` — **constaté le 04/10** (`Rapport/BILAN_M7_LOT2.md`) |
| 3 ✅ codé, fusionné | Reverse proxy TLS (Caddy), analyse d'image (Container Scanning GitLab), migrations en conteneur éphémère, entretien quotidien (sessions, EPSS) | `docker compose -f … -f docker-compose.prod.yml --profile full up` sur un VPS UE, note SSL Labs ≥ A — **TLS constaté en local le 04/10, VPS à faire** |
| Interface 🟡 en cours (ADR-016) | Socle React + TypeScript, temps réel SSE, journal de collecte, séries temporelles ; écrans vue d'ensemble, triage, incidents, IOC, CVE, chasse (lot 1 fusionné) | écrans du lot 1 utilisés sur Kali sur données réelles ; CI « Interface web » verte (GitHub et GitLab) |

## M8 — Detection & Correlation

**But.** Passer de l'agrégation à la détection : un évènement corrélé produit une alerte priorisée.

**Démarré le 11/10/2026** (ADR-017), en quatre incréments, **tous livrés le 13/10** :
1. confiance des IOC ✅ (score 0–100 décomposé : sources pondérées par leur fiabilité A–F,
fraîcheur par type, récurrence) ; 2. enrichissement local (ASN, pays) ✅ (DB-IP Lite importée,
mise à jour mensuelle automatique, ADR-019) ; 3. corrélation ✅ (inventaire d'actifs, CORR-01
KEV × actif, CORR-02 exploit × actif, CORR-03 actif dans un IOC, ADR-020) ; 4. mesure ✅ (jeu
figé versionné : 100 % détectés, 0 % de faux positifs, vérifié par la CI).

- Enrichissement des IOC : ASN/pays ✅ ; réputation multi-sources ✅ (confiance) ; âge des domaines (reporté).
- Score de confiance d'un IOC ✅.
- Règles de corrélation : IOC × CVE × actif × KEV → évènement corrélé ✅.
- Plancher « KEV ⇒ au moins P1 » et EPSS manquant : ✅ ADR-014 accepté (A + B + C) et appliqué.
- Corrélation par version (plages vulnérables NVD) ✅ ADR-021.
- Plages CIDR (type réseau) ✅ ; plateforme de l'actif ✅ ; calibration DGA sur Tranco ✅ (workflow mensuel).

**Critère de sortie :** sur un jeu de données figé, 100 % des cas de corrélation attendus produisent
une alerte, taux de faux positifs mesuré et publié. ✅ **M8 clos le 14/10/2026** : jeu figé
100 % / 0 % (`Rapport/M8_MESURE_13-10-2026.md`) ; données réelles Kali 38 évènements → 0 vrai
positif après corrélation par version (ADR-021, `Rapport/M8_MESURE_REELLE_13-10-2026.md`).
Bilan : `Rapport/BILAN_M8.md`.

## M9 — SOC Operations

**But.** Outiller le travail des analystes L1/L2/L3. **Livré le 14/10/2026** (ADR-022).

- File de triage L1 : alerte → faux positif (liste d'exclusion, tâche 3.6) ✅ ou escalade ✅.
- Investigation L2 : enrichissement à la demande ✅, chasse lancée depuis l'incident ✅.
- L3 : ingénierie de détection (règles versionnées) ✅, recommandations de réponse ✅.
- Dashboard : séries 7 et 30 jours, charge par analyste, SLA par priorité ✅ (écran Pilotage).

**Critère de sortie :** un incident traverse L1 → L2 → L3 sans quitter ILL Watch, MTTR mesuré.
✅ **Constaté en CI** (test de bout en bout et scénario d'acceptation) ; à constater sur Kali
(`Rapport/BILAN_M9.md`).

## M10 — CTI Intelligence Layer

**But.** Donner un contexte adverse à chaque détection.

- Modèle : acteur de menace → campagne → malware → infrastructure → IOC → TTP.
- Import MITRE ATT&CK (collection Enterprise, TAXII public déjà identifié dans ADR-010).
- Rattachement détection → technique → acteur → campagne.
- Export STIX 2.1 et serveur TAXII sortant.

**Critère de sortie :** une alerte affiche sa technique ATT&CK et, si connu, l'acteur associé.

## M11 — Observability & Deployment

**But.** Exploiter ILL Watch comme un service.

- Métriques Prometheus (API, worker, collecte, base, Redis), tableaux Grafana, alertes.
- Journaux JSON corrélés par identifiant de requête (amorcé en M7).
- Environnements dev → staging → production ; job d'acceptation en CI sur jeu figé (le scénario
  tourne déjà chaque semaine sur données réelles : workflow GitHub « Validation réelle »).
- Procédure de sauvegarde testée par restauration mensuelle.

**Critère de sortie :** 7 jours de collecte continue en staging sans intervention, tableaux de bord
complets, restauration testée.

## Au-delà de v0.2.0

Assistant IA (LLM + RAG) sur bulletins et incidents, multi-tenant et SSO (OIDC), Cyberill TI Cloud
hébergé en UE.
