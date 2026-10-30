# Environnements : développement → staging → production (M11, ADR-026)

Un principe guide tout ce qui suit : ce qui part en production est exactement ce qui a été
éprouvé avant. Il n'existe donc qu'une seule image et une seule base de code. D'un environnement
à l'autre, seuls changent la configuration (`ENVIRONMENT`, secrets, domaine) et les données.

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

Le staging travaille sur des données **réelles**, et ce n'est pas un détail : c'est là que se
révèlent les sources qui changent de format, les volumes qui grossissent et les lenteurs qu'aucun
jeu de test n'anticipe.

## Contrôles automatiques (CI, à chaque modification)

Avant même d'atteindre un serveur, chaque modification passe par une répétition générale. La
préproduction locale (workflow « Préproduction ») monte l'image de production derrière Caddy,
charge le **jeu de démonstration figé**, puis enchaîne : contrôles HTTPS et sécurité, captures
d'écran, **scénario d'acceptation SOC** (`scripts/scenario_soc.py`), sauvegarde et restauration,
Prometheus (configuration, collecte, alertes) et Grafana (tableaux provisionnés et capturés).
Une fois par semaine, la validation sur **données réelles** prend le relais (workflow
« Validation réelle »).

## Passage en production

Une version ne monte en production qu'après avoir fait ses preuves :

1. Le tag candidat tourne **7 jours** en staging sans intervention (critère de sortie de M11) :
   aucune alerte `IllwatchFeedStale` / `IllwatchNoCollection` restée sans explication, et des
   tableaux remplis.
2. La restauration du mois écoulé a réussi (`/var/log/illwatch-restore-test.log`).
3. `deploy-vps.sh update` en production, qui prend de lui-même une sauvegarde avant la mise à jour.

## Accès à Grafana et Prometheus

Par prudence, ils n'écoutent que sur la boucle locale du VPS : rien n'est exposé sur Internet.
Pour les consulter, ouvrez un tunnel SSH :

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 <utilisateur>@<vps>
# puis http://localhost:3000 (admin, mot de passe : sudo grep GRAFANA /opt/illwatch/.env)
```
