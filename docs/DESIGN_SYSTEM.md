# ILLWATCH — Système de design (v8 « Identité ILLWATCH »)

v6 adoptée le 08/10/2026 (ADR-016) ; v7 « Veille de nuit » le 11/10/2026 ; **v8 le 11/10/2026** :
application du **brand book ILLWATCH v2** (ADR-018), qui fait autorité pour la marque, la
palette, la typographie et la voix. Ce document en est la déclinaison pour l'interface.
Référence vivante : `frontend/src/styles/tokens.css` (jetons) et `base.css` (composants).

> La v7 avait choisi IBM Plex, un accent violet et un logo en forme d'œil. Le brand book les
> remplace : Inter et JetBrains Mono, accent **Signal**, symbole **écu-radar**.

**Idée directrice.** ILLWATCH est un poste de veille : des analystes y passent des heures, souvent
de nuit. Le thème **Nuit** est celui de l'application ; la couleur ne sert qu'à informer. Quatre
couleurs ont un sens fixe, partout :

- **indigo** (maison CYBERILL) : où vous êtes, ce qui est sélectionné — toujours avec du blanc dessus ;
- **Signal** : la veille — liens, anneau de focus, courbes des graphiques, rayon du radar ;
- **orange** : l'action principale (une par vue), le point de menace du symbole, le repère de
  sélection de 3 px ;
- **échelle P0–P3** : la gravité, et rien d'autre.

La confiance d'un IOC (ADR-017) n'utilise pas l'échelle de gravité : jauge Signal à 5 crans.

## Marque

- **Ponctuation du site** : pas de tiret long (« — ») dans un texte visible (décision du
  24/10/2026) ; virgule, deux-points ou point dans une phrase, « | » dans un titre de page.
  La construction du site échoue si une page en contient.
- **Nom** : « ILLWATCH », en un seul mot et en capitales (décision du 23/10/2026) ; jamais
  « ILL Watch », IllWatch ou Ill Watch dans un texte ; le dessin du logo (ILL + Watch) reste
  inchangé pour l'instant. Endossement :
  « PAR CYBERILL ». Les identifiants techniques (`illwatch`, `ILLWATCH_*`, en-tête
  `User-Agent: ILLWATCH/…`) ne changent pas.
- **Symbole** : écu indigo `#20155C`, contour et radar Signal `#22D3EE`, point de menace orange
  `#E6681B`. Composant `components/Logo.tsx` = géométrie exacte de `docs/assets/illwatch-mark.svg`.
- **Logotype** : « ILL » 800 + « Watch » 500 en Inter Display, **vectorisé** : on utilise les
  fichiers du kit, on ne le recompose jamais avec une police.
- **Fichiers** (`docs/assets/`) : `illwatch-logo-dark|light.svg`, `illwatch-logo-endorsed-dark|light.svg`,
  `illwatch-logo-mono-white|ink.svg`, `illwatch-mark.svg`, `illwatch-mark-light.svg`,
  `illwatch-mark-mono-white|ink.svg`, `favicon.svg` (aussi `frontend/public/favicon.svg`),
  `illwatch-app-icon.svg`, `illwatch-avatar.svg`.
- **Signature** : « Voir la menace avant qu'elle ne vous voie. » (écran de connexion).
- **Motif radar** : arcs Signal à faible opacité, jamais sous du texte ; à la connexion seulement,
  un seul balayage de 1,2 s au chargement, jamais en boucle.

## Couleurs — thème Nuit (application)

| Jeton | Valeur | Usage | Contraste |
|---|---|---|---|
| `bg` | `#0A0E1A` | fond de page | |
| `nav` | `#0D1220` | menu latéral, barre supérieure | |
| `panel` | `#121A2B` | cartes, panneaux, tableaux | |
| `panel-head` | `#0F1626` | en-têtes de tableau, champs | |
| `line` | `#222C42` | bordures 1 px (décoratif) | |
| `text` | `#ECEFF5` | texte principal | 15,1:1 sur `panel` |
| `muted` | `#A3ACBF` | secondaire, libellés, métadonnées | 7,6:1 |
| `indigo` / `on-indigo` | `#20155C` / `#FFFFFF` | actif, sélection | 15,9:1 |
| `signal` | `#22D3EE` | liens, focus, courbes | 9,6:1 |
| `orange` / `on-orange` | `#E6681B` / `#1B0D04` | action principale | 5,8:1 |
| `new-fg` | `#D9D2FF` | badge « Nouvelle » sur indigo | 11,0:1 |
| `critical` / `success` / `warning` | `#E5484D` / `#3FB27F` / `#F2B33D` | états (avec un mot) | |
| `ok-bg` / `ok-fg` | `#12301F` / `#8FE0B8` | « Clôturé / sain » | 9,2:1 |

Dérivés techniques (ne portent jamais de texte courant) : `panel-raise #18223A` (survol),
`grid #1A2336` (graphiques), `line-strong #34405A` (bordure de champ au survol), `faint #8089A0`
(texte désactivé, exemples de saisie : 5,2:1), marques pleines des graphiques `p0-mark` à `p3-mark`.

Le thème **Jour** du brand book (`bg #F5F6FA`, `signal #0E7490`, etc.) sert aux documents et au
site de documentation ; l'application reste en Nuit.

## Échelle de gravité (identique dans tous les modules)

| Niveau | Badge (fond / texte) | Contraste | Marque pleine | CVE | Alertes, incidents, IOC |
|---|---|---|---|---|---|
| P0 | `#3B1518` / `#FF9B9E` | 8,0:1 | `#E5484D` | correctif sous 24 h | Critique |
| P1 | `#3A2C0C` / `#F7CB70` | 8,9:1 | `#F2B33D` | correctif sous 7 j | Élevée |
| P2 | `#122848` / `#9BC2FF` | 8,1:1 | `#5B9BF5` | correctif sous 30 j | Moyenne |
| P3 | `#1E2535` / `#C6CDD9` | 9,6:1 | `#6E7A93` | maintenance | Faible |

Chaque badge porte son libellé, coloré selon la gravité ou l'état, **sans pastille** (décision du 23/10/2026) : le mot et sa couleur suffisent, et la gravité ne repose jamais sur la couleur seule puisque le libellé l'écrit.

## Typographie

**Inter** pour tout le texte, **JetBrains Mono** pour les données (IP, domaines, URL, empreintes,
identifiants CVE, horodatages). Échelle : titre de page 24/32 600 · titre de carte 16/24 600 ·
valeur d'indicateur 28/36 600 · texte 14/20 · tableau 13/20 · métadonnées 12/16 ·
**libellé 11/16 600 en capitales espacées de 0,08 em, couleur `muted`** (sections du menu,
intertitres) · donnée 13/20 mono. Chiffres tabulaires dans les tableaux et indicateurs.

Typographie française : espace insécable avant « : ; ? ! » et « % » (« 93 % »), espace fine
pour les milliers (`Intl.NumberFormat("fr-FR")`), virgule décimale.

## Espacements, formes, mouvement

Échelle 4, 8, 12, 16, 24, 32 px. Rayons : badge 6, bouton et champ 8, carte 12. Bordures 1 px,
**aucune ombre**. Cibles cliquables ≥ 40 px. Mouvement : surbrillance d'un élément nouveau
2,5 s (`rgba(34, 211, 238, 0.16)`), panneau 180 ms, balayage radar unique ≤ 1,2 s sur la page de
connexion. Tout est désactivé si `prefers-reduced-motion`. Focus clavier : contour Signal de
2 px, décalé de 2 px.

## Icônes

Lucide, 20 px, trait 1,5, `currentColor` en `muted` (texte au survol, blanc sur l'élément actif).
Pas d'emoji dans l'interface.

## Voix

Directe, factuelle, en français. Vocabulaire : « veille », « indicateur (IOC) », « CVE ».
États du direct : « Connecté · en direct » · « Direct en pause · 3 mises à jour en attente » ·
« Direct interrompu · nouvel essai, données relues chaque minute ». Boutons : « Mettre en
pause » / « Reprendre le direct ». Heure : « UTC · 08:02:17 ».

## Composants

- **Menu latéral** (240 px) : symbole 32 px, « ILLWATCH » 700 et « PAR CYBERILL » (10 px,
  capitales, 0,12 em, `muted`) ; sections en capitales ; liens de 40 px ; élément actif = fond
  indigo, texte et icône blancs, repère orange de 3 px à gauche ; compteurs en badge P1 (P0 pour
  les sources dégradées), seulement s'il y a quelque chose à traiter. Sous 900 px, le menu devient
  une barre d'onglets horizontale (repère orange en bas).
- **Barre supérieure** : état du direct (point vert, ambre ou rouge + texte de la voix, réduit au
  point sur téléphone avec texte pour lecteur d'écran), pause, heure, compte, déconnexion.
- **Tableau** : en-tête `panel-head`, lignes de 44 px ; sélection = fond indigo + repère orange ;
  nouvelle ligne = surbrillance Signal qui s'efface sans déplacer la lecture.
- **Panneau de détail** : identité et priorité · statut · éléments associés · historique ·
  actions (principale à droite) ; intertitres en libellés capitales.
- **Boutons** (40 px) : principal (orange, un par vue), secondaire (contour), discret (texte),
  danger (contour rouge, après confirmation), désactivé (pointillés + raison affichée).
- **Onglets** : actif souligné d'un repère orange de 3 px.
- **Graphiques** (ECharts) : barres empilées aux marques pleines de gravité, séries sans gravité
  en Signal, police Inter, infobulle en classes CSS (politique `style-src 'self'`).

## Navigation

Vue d'ensemble · Opérations SOC (Triage, Incidents) · Renseignement (Indicateurs, Sources CTI) ·
Vulnérabilités (CVE et priorités) · Détection (Chasse) · Administration (administrateurs, en bas).

## Décisions ouvertes du brand book

Accent Signal, endossement « PAR CYBERILL », lecture de « ill », recherche d'antériorité de
marque (INPI, EUIPO) avant tout dépôt, choix de Lucide : à valider par CYBERILL (voir ADR-018).

## Vérification

Chaque modification de l'interface passe par le workflow « Préproduction » : la pile de
production tourne derrière Caddy, chaque écran est capturé (grand écran et téléphone) et publié
sur la branche `captures`. Une erreur d'écran, de console, une violation CSP ou un débordement
de mise en page fait échouer la CI.
