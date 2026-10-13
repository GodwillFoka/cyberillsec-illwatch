# ADR-021 — Corrélation par version : plages vulnérables NVD

- **Statut :** **accepté le 13/10/2026** (décision de Godwill FOKA : « Va y fait ce que tu dois faire »)
- **Date :** 2026-10-13
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-020 (corrélation), ADR-001 (score des CVE)

## Contexte

Première passe sur données réelles (Kali, 13/10/2026, 5 actifs) : **38 évènements CORR-01,
environ 80 % de faux positifs** (`Rapport/M8_MESURE_REELLE_13-10-2026.md`). Cause unique :
ADR-020 rapproche le **nom** du produit cité dans la description, sans regarder la **version**.
Exemples : d'anciennes CVE du noyau Linux (corrigées en 5.x) remontées sur un noyau 7.1.5,
Shellshock (bash) remonté sur OpenSSH, CVE-2022-0543 (paquet Debian de Redis 5/6) sur Redis 8.

## Décision

1. **Plages vulnérables conservées** : à la synchronisation NVD, les `configurations` de chaque
   CVE sont réduites à la liste de ses `cpeMatch` vulnérables (`vendor`, `product`, `version`,
   bornes `versionStart/End Including/Excluding`), au plus 500 entrées, dans `cves.affected`
   (JSON, migration `e5b8c1d4a907`). `NULL` = configuration inconnue (jamais lue).
2. **Verdict par couple (actif, CVE)** — `illwatch/modules/correlation/versions.py` :
   - `vulnerable` : produit reconnu et version dans une plage → évènement ;
   - `hors_plage` : produit reconnu, version hors de toutes ses plages → **pas d'évènement** ;
   - `autre_produit` : la CVE a des plages, aucune ne vise ce produit (la description le cite
     seulement) → **pas d'évènement** ;
   - `conditionnel` (ajout du 14/10) : version dans la plage, mais la NVD ne la déclare
     vulnérable que sur certaines plateformes (configuration ET, ex. CVE-2022-0543 : Redis
     **dans les paquets Debian 9 à 11**) ou avec une version « - » (faille d'un paquet de
     distribution) → évènement, plateformes requises affichées ;
   - `inconnu` (plages non lues) et `version_non_declaree` → évènement, le verdict étant
     affiché pour que l'analyste vérifie.
   Le doute reste donc du côté de l'alerte : on ne masque que ce qui est démontré hors d'atteinte.
3. **Comparaison de versions tolérante** : suffixes de distribution retirés (`+kali-amd64`,
   `~deb12u1`, `-1ubuntu2`), puis découpage en segments numériques et alphabétiques
   (`10.5p1` → 10, 5, p, 1). Le nom du produit est normalisé (minuscules, espaces → `_`) et
   rapproché par préfixe (`linux` ↔ `linux_kernel`).
4. **Rattrapage** : `illwatch cves refresh-affected` relit la NVD pour les CVE déjà en base
   (une requête `hasKev`, puis une requête par CVE P0/P1 avec exploit sans plages) ; sans clé
   NVD, compter 6 s par CVE.
5. **Mesure** : le jeu figé passe à 18 cas (8 attendus) avec trois pièges de version (noyau
   hors plage, Shellshock sur un autre produit) et un cas vulnérable dans la plage.

## Conséquences

- (+) Les faux positifs observés sur Kali disparaissent sans réglage manuel.
- (+) Le détail de l'évènement dit **pourquoi** la version est jugée vulnérable ou non vérifiée.
- (−) Un actif sans version déclarée garde le comportement d'ADR-020 (bruyant) : la version
  devient de fait obligatoire pour une corrélation fiable.
- (−) Les CPE de la NVD sont parfois incomplets ou tardifs ; une CVE sans configuration reste
  au verdict `inconnu`.
