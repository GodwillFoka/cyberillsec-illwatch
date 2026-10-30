# ILLWATCH : mesure de la corrélation sur données réelles (M8, Kali, 13/10/2026)

## Conditions

- Base réelle (flux CTI, NVD, KEV) sur la VM Kali de Godwill FOKA.
- 5 actifs déclarés (`inventaire.csv`) : noyau Linux 7.1.5, OpenSSH 10.5p1, PostgreSQL 18.6,
  Redis 8.0.6, adresse publique de l'hôte.
- `illwatch correlate run` avec les règles d'ADR-020.

## Résultat avant correction

| Mesure | Valeur |
|---|---|
| Évènements produits | 38 (tous CORR-01) |
| Faux positifs estimés | ≈ 80 % |
| CORR-03 (adresse dans un IOC) | 0 |

Causes des faux positifs, par famille :

- **noyau Linux** : CVE KEV anciennes (corrigées en 4.x/5.x) citant « Linux kernel » ;
- **OpenSSH** : CVE d'autres produits dont la description mentionne OpenSSH (Shellshock, bash) ;
- **Redis** : CVE-2022-0543, propre au paquet Debian de Redis 5/6.

Toutes tiennent au même défaut : **la version déclarée n'était pas comparée**.

## Correction (ADR-021)

Plages vulnérables NVD conservées (`cves.affected`), verdict par version, évènements écartés
quand la version est hors plage ou que les plages visent un autre produit. Le jeu figé est
étendu (18 cas, 8 attendus) : 100 % détectés, 0 % de faux positifs en CI.

## À refaire sur Kali

```bash
illwatch cves refresh-affected   # relit les plages NVD des CVE concernées
illwatch correlate run
illwatch correlate list
```

Les évènements devenus faux sont **résolus automatiquement** à la passe suivante.

## Résultat après correction (Kali, 13/10/2026, 23 h)

| Mesure | Avant | Après |
|---|---|---|
| CVE dont les plages NVD sont connues | 0 | 1 740 |
| Correspondances CORR-01 | 38 | 1 |
| Évènements ouverts | 38 | **0** |

Les 37 correspondances écartées étaient hors des versions vulnérables ou visaient un autre
produit (état « clos (auto) »).

La correspondance restante (`correlate list --all`, 14/10) est **CVE-2022-0543 sur Redis
8.0.6**, jugée « vulnérable » et acquittée. C'est un **faux positif** : la faille vient de
l'empaquetage Debian/Ubuntu de Redis (bac à sable Lua), la NVD la décrit par une
configuration ET (`redis:redis:-` sur `debian_linux` 9 à 11) que le premier analyseur
aplatissait. Correction : verdict « conditionnel », plateformes requises affichées (à
constater sur Kali après `illwatch cves refresh-affected`).

**Bilan : 38 évènements → 0 vrai positif ; 37 écartés automatiquement, 1 requalifié
« conditionnel » (à vérifier : Kali n'est pas Debian 9 à 11).** Sur un inventaire à jour
(noyau 7.1, OpenSSH 10.5, PostgreSQL 18, Redis 8), aucune CVE exploitée connue ne s'applique.
