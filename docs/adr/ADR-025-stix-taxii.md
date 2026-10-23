# ADR-025 — M10, incrément 3 : export STIX 2.1 et serveur TAXII 2.1

- **Statut :** **accepté le 15/10/2026** (décision de Godwill FOKA : « attaque M10 »)
- **Date :** 2026-10-15
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-017 (confiance), ADR-022 (exclusions), ADR-024 (campagnes), ROADMAP M10
  (« partage du renseignement au format standard »)

## Contexte

ILLWATCH consomme du STIX et du TAXII (flux, ATT&CK) mais ne savait rien partager : un SIEM,
un pare-feu ou une autre plateforme CTI (OpenCTI, MISP) devait recopier les IOC à la main.

## Décision

1. **Export STIX 2.1** (`illwatch.modules.stix.export`) :
   - un `indicator` par IOC **actif** (non expiré, non exclu : un faux positif qualifié n'est
     jamais partagé), motif STIX selon le type (une plage `NETWORK` en `ipv4-addr` ou
     `ipv6-addr`), confiance 0–100 d'ADR-017, sévérité en étiquette `severity:…`,
     `valid_until` à l'expiration ;
   - campagnes, acteur (`intrusion-set` pour un groupe, `malware` pour un logiciel, avec la
     référence `mitre-attack`), relations `attributed-to` / `uses` et `indicates` ;
   - identifiants **déterministes** (UUID v5 d'un espace de noms propre à ILLWATCH) : un IOC
     garde le même identifiant d'un export à l'autre, les consommateurs dédupliquent ;
   - chaque objet signé par l'identité « ILLWATCH » (`created_by_ref`).
2. **Serveur TAXII 2.1 en lecture seule**, monté hors de `/api` (`/taxii2/`) : découverte,
   API root `illwatch`, collections **indicateurs** (paginée par curseur stable sur la date de
   dernière observation, filtre `added_after`, en-têtes `X-TAXII-Date-Added-First/Last`) et
   **campagnes** ; `objects/`, `manifest/`, `match[type]` ; erreurs au format TAXII ;
   `can_write` toujours faux.
3. **Authentification** : jeton Bearer de l'API ou **HTTP Basic** (les clients TAXII courants ne
   savent faire que cela). Le Basic passe par le limiteur de tentatives de la connexion ; les
   échecs sont consignés (`taxii.auth`). Recommandation : un compte LECTEUR par consommateur,
   révocable sans toucher aux autres.
4. **Bundle à la demande** : `GET /api/v1/stix/bundle?contenu=tout|indicateurs|campagnes`,
   `illwatch stix export` ; chaque export est consigné (`stix.export`).

Écartés : la bibliothèque `stix2` (dépendance lourde pour produire du JSON simple ; le
format est vérifié par l'aller-retour avec notre propre analyseur STIX) ; `medallion`
(serveur TAXII de référence, mais une seconde application et une seconde base à exploiter).

## Conséquences

- Positives : ILLWATCH devient une source TAXII qu'OpenCTI, MISP ou `taxii2-client`
  consomment sans développement ; le partage respecte les exclusions et la confiance.
- Négatives : la lecture d'un objet par identifiant (`objects/{id}/`) et les filtres
  `match[id]` / `match[version]` ne sont pas servis (identifiants dérivés, non stockés) ;
  la « date d'ajout » TAXII est la dernière observation de l'IOC (un IOC revu réapparaît dans
  `added_after`, ce que les consommateurs absorbent grâce à l'identifiant stable) ; le Basic
  coûte un hachage de mot de passe par requête (le limiteur borne l'abus).
- Le TLP n'est pas encore porté (marquages `marking-definition`) : tout est partagé en
  l'état aux comptes autorisés.

## Suivi

- Marquages TLP par source et par campagne (TLP:CLEAR par défaut, TLP:AMBER non exporté).
- `objects/{id}/` par table de correspondance si un consommateur l'exige.
