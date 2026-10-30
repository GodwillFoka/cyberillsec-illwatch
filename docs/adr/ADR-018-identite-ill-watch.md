# ADR-018, Identité ILLWATCH : le brand book v2 fait autorité sur l'interface

- **Statut :** **accepté le 11/10/2026** (décision de Godwill FOKA : appliquer le brand book à l'interface)
- **Date :** 2026-10-11
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-016 (interface web, système de design), `docs/DESIGN_SYSTEM.md`

> Le brand book proposait de consigner cette décision dans une « ADR-017 » ; ce numéro était déjà
> pris par M8 (détection et corrélation). Elle devient l'ADR-018.

## Contexte

Le système de design v7 « Veille de nuit » (11/10/2026) avait été dessiné sans charte de marque :
logo en forme d'œil, polices IBM Plex, accent violet, nom écrit « ILLWATCH ». Le même jour, le
**brand book ILLWATCH v2** (kit « Design System », fichiers SVG, jetons, voix) a été remis. Deux
identités en parallèle ne sont pas tenables : l'interface, la documentation et les supports
commerciaux doivent dire la même chose.

## Décision

1. **Le brand book fait autorité** pour le nom, le logo, la palette, la typographie, les icônes,
   le mouvement et la voix. `docs/DESIGN_SYSTEM.md` (v8) n'en est que la déclinaison pour
   l'interface ; en cas d'écart, le brand book l'emporte.
2. **Nom** : « ILLWATCH », endossement « PAR CYBERILL », dans tous les textes (interface,
   documentation, messages, titres d'API et de CLI). Les **identifiants techniques ne changent
   pas** : paquet `illwatch`, commande `illwatch`, variables `ILLWATCH_*`, volumes, en-tête
   `User-Agent: ILLWATCH/…` (déjà connu des sources). Les rapports et entrées datés passés ne sont
   pas réécrits.
3. **Logo** : les fichiers SVG du kit sont versionnés dans `docs/assets/` ; le composant `Logo`
   reprend exactement la géométrie de `illwatch-mark.svg` ; le logotype n'est jamais recomposé
   avec une police (fichier vectorisé à l'écran de connexion).
4. **Jetons Nuit** du brand book dans `tokens.css` : `signal` remplace `indigo-light` ; rayons
   6/8/12 ; bordures 1 px sans ombre ; cibles ≥ 40 px. **Inter** et **JetBrains Mono**
   remplacent IBM Plex (dépendances réinstallées par le workflow « Verrouillage npm »).
5. **Voix** de l'état du direct et des boutons reprise mot pour mot du brand book.

## Options écartées

- **Garder la v7 et adapter le brand book** : le kit est la référence commerciale ; l'interface
  doit s'y conformer, pas l'inverse.
- **Renommer aussi les identifiants techniques** : migration des variables, volumes et
  déploiements pour un gain nul côté utilisateur ; le brand book l'exclut explicitement.

## Conséquences

- Positives : une seule identité ; contrastes du brand book (AA à AAA) ; logos et favicon
  cohérents entre application, documentation et dépôt.
- Négatives : deuxième refonte visuelle le même jour (captures de référence à régénérer) ;
  écart assumé entre le nom affiché (« ILLWATCH ») et les identifiants (`illwatch`) ; le site de
  documentation charge Inter et JetBrains Mono depuis Google Fonts (thème Material).

## Suivi

- Décisions ouvertes du brand book, à trancher par CYBERILL : accent Signal, endossement
  « PAR CYBERILL », lecture de « ill », Lucide comme jeu d'icônes.
- **Recherche d'antériorité de marque (INPI, EUIPO)** avant tout dépôt ou communication publique.
- Supports commerciaux (pitch, dossier) et profils sociaux à mettre à jour hors dépôt.
