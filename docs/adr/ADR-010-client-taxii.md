# ADR-010 — Client TAXII 2.1 : `taxii2-client` durci, transport maison en repli

- **Statut :** proposé
- **Date :** 2026-10-03
- **Décideurs :** à valider par le porteur du projet
- **Concerne :** MOD-02, tâche 1.8, `illwatch/modules/threat_feeds/taxii.py`

## Contexte

ILLWATCH disposait d'un client TAXII maison (async, `httpx`) protégé contre le SSRF. La décision
a été prise d'utiliser la bibliothèque de référence OASIS `taxii2-client` 2.3.0 pour la
conformité au protocole. Or cette bibliothèque repose sur `requests`, qui par défaut **suit les
redirections**, n'a **aucun délai** et lit la réponse **sans limite de taille** : l'adopter telle
quelle aurait réintroduit trois failles que le transport maison fermait.

## Décision

1. `taxii2-client` est le client de production (`TAXII_CLIENT=library`), utilisé avec une
   connexion dérivée (`_GuardedConnection`) : redirections refusées (`max_redirects = 0`),
   délai `HTTP_TIMEOUT_SECONDS`, lecture en flux plafonnée à `FEED_MAX_BYTES`, contrôle SSRF par
   résolution DNS avant toute requête, identifiants par hôte exact.
2. Les appels synchrones s'exécutent dans `asyncio.to_thread` ; les erreurs de `requests` et de
   la bibliothèque sont traduites en erreurs ILLWATCH typées.
3. Le transport maison reste disponible (`TAXII_CLIENT=builtin`, et pour les tests) : la
   bibliothèque exige un `Content-Type` strictement conforme, que certains serveurs ne
   respectent pas.
4. Avant d'intégrer une source, on la **vérifie** : `illwatch taxii discover` (API roots et
   collections) et `illwatch feeds probe` (collecte d'essai sans écriture, IOC par type).

## Vérification des sources TAXII proposées (03/10/2026)

| Source | Constat | Décision |
|---|---|---|
| DigitalSide (invité) | Délai de connexion dépassé depuis deux réseaux | Semée **inactive** |
| RedEye Threat Indicators | Jeton gratuit (e-mail), 100 req/h ; API root `…/taxii2/feed/` | Semée, `TAXII_AUTH=…=bearer:…` |
| MITRE ATT&CK | Public, 50 req / 10 min ; collection Enterprise `x-mitre-collection--1f5f1533-…` | Non semée : techniques, **aucun IOC** |
| CrowdSec CTI | TAXII réservé aux offres payantes (contact commercial) | Non semée ; `header:x-api-key` prêt |
| Zedmos | Inscription + validation par un administrateur, jeton Bearer | Non semée |
| CISA AIS 2.0 | Certificat PKI et accord d'adhésion ; pas d'accès anonyme | Non semée |

## Conséquences

- **Positives** : conformité TAXII de la bibliothèque OASIS sans régression de sécurité ;
  sources vérifiées avant d'être proposées.
- **Négatives** : un thread par page lue (sans incidence au volume visé) ; dépendance à une
  bibliothèque peu active (2.3.0 date de 2021), d'où le repli maison conservé.
