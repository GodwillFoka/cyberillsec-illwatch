# 🛡️ SENTRY — Bilan d'étape : TAXII 2.1 réel, phases 4, 5 et 6

**Date :** 03/10/2026 · **Branche :** `feature/phases-4-6` (empilée sur `feature/phase3-cve-v2`,
elle-même sur `feature/taxii-v2`) · **Base :** `9402bb1`
**Verdict :** code des six modules livré et testé ; **aucun jalon M2–M6 n'est constaté** tant
que la branche n'est pas fusionnée et que le worker n'a pas tourné sur données réelles.

---

## 1. Résumé

| Volet | Livré | Statut |
|---|---|---|
| Backend TAXII 2.1 (`taxii2-client` 2.3.0) | T1–T11 du cahier de la tâche | ✅ codé, testé hors ligne ; test réel prêt (`-m live`) |
| Vérification des sources TAXII | 6 sources examinées, 1 retenue (RedEye), DigitalSide désactivée | ✅ |
| Phase 4 — Incidents | API, CLI, liaisons IOC/CVE, chronologie immuable par trigger PostgreSQL, alerte → incident | ✅ (3.6 faux positifs ❌) |
| Phase 5 — Dashboard SOC | synthèse, activité 24 h, exports JSON/CSV en flux, console Rich | ✅ (séries 7 j ❌) |
| Phase 6 — Threat Hunting | 6 règles, sessions enregistrées, API, CLI, chasse planifiée dans le worker | ✅ |
| Sécurité | limitation des connexions (429 + Retry-After), anti-injection CSV, SSRF TAXII | ✅ (HTTPS/en-têtes ❌) |

## 2. TAXII 2.1 — résultats par sous-tâche

| # | Exigence | Réalisation | Preuve |
|---|---|---|---|
| T1 | Dépendance | `taxii2-client==2.3.0` épinglée, `types-requests` en dev, override mypy | `pyproject.toml` |
| T2 | Inspection de l'API | `Collection(url, conn=…, collection_info=…)` évite la découverte ; `_HTTPConnection.get` valide le Content-Type | ADR-010 |
| T3 | Backend | `Collection.get_objects` dans `asyncio.to_thread` | `taxii.py::_fetch_with_library` |
| T4 | Authentification par hôte | `TAXII_AUTH` : `hote=user:pass`, `bearer:`, `header:NOM:VALEUR` ; correspondance **exacte** de l'hôte | 6 tests |
| T5 | Pagination | `more`/`next`, plafond `TAXII_MAX_PAGES`, avertissement de troncature | 4 tests |
| T6 | `added_after` | dernier succès − 15 min | test dédié |
| T7 | Fetch injectable | `fetch: HeaderFetcher | None = None` | tests |
| T8 | Branchement du collecteur | `use_library = fetch is fetch_feed_content and settings.taxii_client == "library"` | `collector.py` |
| T9 | Test réel | `tests/test_live_sources.py`, marqueur `live`, `SENTRY_LIVE_TESTS=1` | **à exécuter sur Kali** |
| T10 | Validation | pagination, `added_after`, plafond de pages | 27 tests `test_taxii_client.py` |
| T11 | Sécurité | voir § 3 | tests |

**Écart à votre suggestion T8.** La ligne proposée
`taxii_fetch = None if fetch is fetch_feed_content else fetch` a été enrichie d'un interrupteur
`TAXII_CLIENT=library|builtin` : il permet de revenir au client interne sans redéploiement si la
bibliothèque se comporte mal sur un serveur réel. Comportement par défaut identique au vôtre.

## 3. Sécurité du client TAXII (T11)

`taxii2-client` s'appuie sur `requests`, qui **suit les redirections et n'a aucun délai par
défaut**. Brancher la bibliothèque telle quelle aurait fait régresser trois protections déjà
acquises par le client interne. `_GuardedConnection` les rétablit :

| Risque | Parade | Test |
|---|---|---|
| Redirection vers une IP interne (contournement SSRF) | `max_redirects = 0` ; contrôle `assert_public_destination` avant chaque requête | ✅ |
| Serveur lent qui bloque le worker | délai imposé via `functools.partial(session.request, timeout=…)` | ✅ |
| Réponse géante (épuisement mémoire) | `stream=True` + lecture plafonnée dans un hook de réponse | ✅ |
| Fuite d'identifiants | secret attaché à l'hôte exact, jamais relayé ; masqué dans les journaux (`mask_secrets`) | ✅ |
| Collection publique | aucun en-tête d'authentification si l'hôte n'est pas dans `TAXII_AUTH` | ✅ |
| Erreurs hétérogènes | `requests`/`TAXIIServiceException` → `FetchError` typée ; 429/5xx réessayés avec backoff | ✅ |
| Connexion orpheline | `collection.close()` dans `finally` | ✅ |
| API root sur un autre hôte (découverte) | refusée | ✅ |

## 4. Vérification préalable des sources

Règle appliquée : aucune source n'entre dans le seed sans avoir été vérifiée existante et
accessible. Outils livrés : `sentry taxii discover <url>` et `sentry feeds probe <url>` (collecte
d'essai d'une page, sans écriture en base).

| Source | Constat | Décision |
|---|---|---|
| DigitalSide (invité) | délai de connexion dépassé depuis deux réseaux | semée **inactive** |
| RedEye Threat Indicators | jeton gratuit sur e-mail, 100 req/h | semée, nécessite `TAXII_AUTH` |
| MITRE ATT&CK | public, mais techniques et groupes, **aucun IOC** | non semée |
| CrowdSec CTI | TAXII réservé aux offres payantes | non semée (format d'auth prêt) |
| Zedmos | inscription validée par un administrateur | non semée |
| CISA AIS 2.0 | certificat PKI + accord d'adhésion | non semée |
| IPsum niveau 5 (texte) | accessible, sans clé, ~volume suffisant pour M2 | **ajoutée** |

Confiance : élevée pour DigitalSide, MITRE, CISA (constats directs ou documentation officielle) ;
moyenne pour RedEye (documentation lue, jeton non obtenu, donc format réel non éprouvé).

## 5. Phases 4 à 6 — contenu

**Incidents (ADR-008).** Machine d'état NIST SP 800-61 à 6 étapes ; transition interdite → 409 ;
clôture exigeant un post-mortem ; chronologie immuable doublement verrouillée (écouteurs ORM
`before_update`/`before_delete` + trigger plpgsql `trg_incident_events_immutable`) ; tables de
liaison IOC et CVE ; ouverture d'incident depuis une alerte CVE, idempotente par
`source_alert_id` unique ; contraintes CHECK nommées.

**Dashboard.** `/dashboard/summary` (IOC actifs, CVE P0/P1, incidents ouverts, santé des flux),
`/dashboard/recent` (24 h), exports en flux (pas de chargement en mémoire), CSV conforme RFC 4180
avec neutralisation des formules (CWE-1236).

**Threat Hunting (ADR-009).** Deux modes : chasse sur observables soumis (journaux pare-feu,
proxy, EDR) ou sur la base d'IOC. Six règles : relais Tor (liste officielle), DNS dynamique, DGA
par entropie de Shannon, IP ransomware, CVE exploitable × inventaire d'actifs, IOC connu. Une
règle en échec rend la session `PARTIELLE` sans bloquer les autres. Chasse planifiée dans le
worker (`HUNT_INTERVAL_SECONDS`, 24 h par défaut).

## 6. Métriques

| Indicateur | 29/09 | 03/10 |
|---|---|---|
| Tests (PostgreSQL 16) | 326 | **388** (+4 ignorés : tests réels) |
| Couverture | ≈ 95 % | **94 %** |
| Python | 3.12, 3.14 | 3.12, 3.14 ✅ |
| Routes `/api/v1` | 14 | **28** |
| Commandes CLI | 19 | **34** |
| Tables | 10 | **14** |
| Migrations | 4 | **6** |
| ADR | 7 | **10** |
| Lignes de code applicatif / de tests | — | ≈ 10 100 / ≈ 5 800 |

`ruff check`, `ruff format --check`, `mypy --strict` : propres.

## 7. Défauts trouvés et corrigés pendant l'étape

| Défaut | Gravité | Correctif |
|---|---|---|
| `requests` suit les redirections et n'a pas de délai (régression SSRF/DoS en adoptant la bibliothèque) | Haute | `_GuardedConnection` |
| `if exc.response:` faux pour une réponse 4xx/5xx (Response.__bool__) | Moyenne | `is not None` |
| Chasse : `hunt.matches.append` déclenchait un chargement paresseux hors greenlet | Moyenne | insertion directe `HuntingMatch(session_id=…)` |
| Règle inconnue détectée après l'indexation du catalogue (KeyError) | Faible | contrôle déplacé avant |
| Test du trigger laissant le moteur lié à une boucle fermée | Faible (tests) | `dispose()` en `finally` + remise à zéro du schéma |
| Override mypy ayant absorbé `exclude` dans `pyproject.toml` | Faible | restauré |

## 8. Défauts connus, non bloquants

- Construction de l'image Docker non vérifiée ici (proxy Docker Hub bloqué dans le bac à sable).
- Test réel TAXII non exécuté : DigitalSide injoignable, jeton RedEye non obtenu.
- Heuristique DGA non calibrée sur un corpus réel : taux de faux positifs inconnu.
- RULE-05 rapproche actifs et CVE par mot dans la description : rappel limité sans CPE.

## 9. SWOT de l'étape

| Forces | Faiblesses |
|---|---|
| Six modules testés, sécurité traitée dès la conception | Aucun constat sur données réelles |
| Sources vérifiées avant intégration | Une seule source STIX exploitable, et sous jeton |
| **Opportunités** | **Menaces** |
| Démonstration complète possible dès la fusion | Pile de trois branches à fusionner dans l'ordre |
| RedEye + OTX suffisent à M2 complet | Dépendance à des flux gratuits instables |

## 10. Prochaines étapes (dans l'ordre)

1. Récupérer le bundle et fusionner `feature/taxii-v2` → `phase3-cve-v2` → `phases-4-6`
   (`ETAPES_POUSSER_SUR_MAIN.md`). **Vérification :** pipeline GitLab vert à chaque MR.
2. `sentry db upgrade && sentry seed`. **Vérification :** `sentry db current` = révision cible.
3. Demander le jeton RedEye et la clé OTX ; les mettre dans `.env`.
4. Sur Kali : `SENTRY_LIVE_TESTS=1 pytest tests/test_live_sources.py --no-cov`, puis
   `sentry feeds probe` sur RedEye. **Vérification :** `usable: true`.
5. `sentry feeds worker` pendant 24 h. **Vérification :** `sentry status` → M2 et M3 ✅.
6. Ouvrir 3.6 (faux positifs), 4.2 (séries 7 j), 4.5 (HTTPS + en-têtes), 5.6 (audit).
