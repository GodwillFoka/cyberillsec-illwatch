# Environnements : développement → staging → production (M11, ADR-026)

Une seule image, une seule base de code ; seuls changent la configuration (`ENVIRONMENT`,
secrets, domaine) et les données.

| | Développement | Staging | Production |
|---|---|---|---|
| Où | Poste Kali (`uvicorn --reload`, worker) | VPS UE, sous-domaine `staging.` | VPS UE, domaine principal |
| `ENVIRONMENT` | `development` | `staging` | `production` |
| Lancement | `illwatch` + `uvicorn` dans `.venv` | `scripts/deploy-vps.sh install staging.<domaine>` | `scripts/deploy-vps.sh install <domaine>` |
| Données | Réelles (collecte locale) ou démonstration | **Réelles**, collecte continue | Réelles |
| TLS | Aucun (127.0.0.1) | Let's Encrypt (Caddy) | Let's Encrypt (Caddy) |
| Documentation `/docs` | Exposée | Masquée | Masquée |
| Observabilité | `/metrics` en local | Prometheus + Grafana (tunnel SSH) | Prometheus + Grafana (tunnel SSH) |
| Sauvegarde | Manuelle (`scripts/backup.sh`) | Quotidienne, test de restauration mensuel | Quotidienne, test de restauration mensuel |
| Mise à jour | `git pull` | `deploy-vps.sh update` depuis `main` | `deploy-vps.sh update` depuis un **tag** déjà validé en staging |

## Contrôles automatiques (CI, à chaque modification)

La préproduction locale (workflow « Préproduction ») monte l'image de production derrière
Caddy, charge le **jeu de démonstration figé**, puis : contrôles HTTPS et sécurité, captures
d'écran, **scénario d'acceptation SOC** (`scripts/scenario_soc.py`), sauvegarde et restauration,
Prometheus (configuration, collecte, alertes) et Grafana (tableaux provisionnés et capturés).
La validation sur **données réelles** tourne chaque semaine (workflow « Validation réelle »).

## Passage en production

1. Le tag candidat tourne **7 jours** en staging sans intervention (critère de sortie de M11) :
   aucune alerte `IllwatchFeedStale` / `IllwatchNoCollection` non expliquée, tableaux remplis.
2. Test de restauration du mois passé (`/var/log/illwatch-restore-test.log`).
3. `deploy-vps.sh update` en production (sauvegarde automatique avant mise à jour).

## Accès à Grafana et Prometheus

Ils n'écoutent que sur la boucle locale du VPS :

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 <utilisateur>@<vps>
# puis http://localhost:3000 (admin, mot de passe : sudo grep GRAFANA /opt/illwatch/.env)
```
