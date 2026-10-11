# ILLWATCH — Système de design (v7 « Veille de nuit »)

v6 adoptée le 08/10/2026 (ADR-016) ; **v7 le 11/10/2026** : nouveau logo, IBM Plex, icônes de
navigation, palette recalibrée, graphiques en couleurs pleines. Référence vivante :
`frontend/src/styles/tokens.css` (jetons) et `base.css` (composants).

**Idée directrice.** ILLWATCH est un poste de veille : des analystes y passent des heures, souvent
de nuit. Les surfaces sont un bleu nuit calme plutôt qu'un noir pur ; la couleur ne sert qu'à
informer. Trois couleurs ont un sens fixe, partout :

- **violet « veille »** : où vous êtes, ce qui est sélectionné, ce qui a le focus ;
- **orange « signal »** : l'action principale (une par vue) et le repère de sélection ;
- **échelle P0–P3** : la gravité, et rien d'autre.

La confiance d'un IOC (ADR-017) n'utilise pas l'échelle de gravité : jauge violette à 5 crans.

## Marque

Logo : un œil dont l'iris est un balayage radar orange (`components/Logo.tsx`, favicon identique).
Mot-symbole « ILLWATCH » en IBM Plex Sans 700, approche 0,08 em, avec « par CYBERILLSEC » dessous.
L'écran de connexion est le seul endroit où la marque prend de la place : cercles de portée et un
seul tour de balayage au chargement (supprimé si l'utilisateur réduit les animations).

## Couleurs

| Jeton | Valeur | Usage | Contraste |
|---|---|---|---|
| `bg` (encre) | `#0A0F1C` | fond de page | |
| `nav` | `#0C1222` | rail, barre supérieure | |
| `panel` (ardoise) | `#111A2C` | cartes, panneaux | |
| `panel-head` | `#0E1627` | en-têtes de tableau, champs | |
| `panel-raise` | `#172238` | survol | |
| `line` | `#1F2A42` | traits | |
| `grid` | `#18223A` | grille des graphiques | |
| `text` (givre) | `#E6EBF5` | texte principal | 14,5:1 |
| `muted` | `#97A3BA` | texte secondaire | 6,8:1 |
| `faint` | `#6E7A93` | désactivé, exemples de saisie uniquement | 4,0:1 |
| `indigo` | `#2A1F78` | élément actif, ligne sélectionnée, filtre actif | blanc 13,4:1 |
| `indigo-light` (veille) | `#8E80FF` | liens, focus, jauge de confiance | 5,5:1 |
| `orange` (signal) | `#F27A2E` | action principale, repère ; texte `#1A0B02` | 7,0:1 |
| `critical` / `success` / `warning` | `#E5484D` / `#3FB27F` / `#F2B33D` | états | |

## Échelle de gravité (identique dans tous les modules)

| Niveau | Badge (fond / texte) | Marque pleine (graphiques) | CVE | Alertes, incidents, IOC |
|---|---|---|---|---|
| P0 | `#3A1418` / `#FF8A8D` | `#E5484D` | patch sous 24 h | Critique |
| P1 | `#382909` / `#F5C35A` | `#E9A23B` | patch sous 7 j | Élevée |
| P2 | `#10264A` / `#8DB8FF` | `#4C8DF0` | patch sous 30 j | Moyenne |
| P3 | `#1C2436` / `#B8C2D4` | `#66728A` | maintenance | Faible |

Les quatre teintes se distinguent aussi par la luminosité (lisibles en vision des couleurs
réduite) ; chaque badge porte en plus son libellé et une pastille.

## Typographie

IBM Plex Sans (interface) : page 24/32 600 · titre de carte 16/24 600 · section 15/22 600 ·
texte 14/20 · tableau 13/20 · métadonnées 12/16. Chiffres tabulaires dans les tableaux et
indicateurs. **IBM Plex Mono uniquement pour les observables** : IP, domaines, URL, empreintes,
identifiants CVE, horodatages. Jamais de majuscules espacées pour les libellés : les titres de
section sont en casse normale.

## Espacements, formes, mouvement

Échelle 4, 8, 12, 16, 24, 32 px ; marges de page 32 (16 sur téléphone). Rayons : cartes 10,
boutons et champs 6, badges 4 — l'arrondi suit la hiérarchie. Aucune ombre décorative.
Mouvement autorisé : surbrillance brève d'un élément nouveau (2,5 s), survols 120 ms, balayage
du logo à la connexion. Tout est désactivé si `prefers-reduced-motion`.

## Composants

- **Rail de navigation** : icône (lucide, trait 1,75) + libellé ; sections en casse normale ;
  écran actif = fond indigo, icône veille, repère orange à gauche ; compteurs seulement s'il y a
  quelque chose à traiter (P1 pour les alertes et incidents, P0 pour les sources dégradées).
  Sous 900 px, le rail devient une barre d'onglets horizontale.
- **Barre supérieure** : pastille d'état du direct (toujours visible), pause, heure UTC/locale,
  compte (initiales, rôle), déconnexion.
- **Tableau** : en-tête `panel-head`, lignes de 44 px ; sélection = fond indigo + repère orange ;
  nouvelle ligne = surbrillance qui s'efface sans déplacer la lecture.
- **Panneau de détail** : identité et priorité · statut · éléments associés · historique ·
  actions (principale à droite).
- **Boutons** : principal (orange), secondaire (contour), discret (texte), danger (rouge, après
  confirmation), désactivé (pointillés + raison affichée).
- **Avis** : bordure gauche colorée (succès, erreur), texte qui dit quoi faire.
- **Graphiques** (ECharts) : barres empilées aux marques pleines, seul le haut de pile arrondi,
  légende à gauche, grille discrète, infobulle en classes CSS (politique `style-src 'self'`).

## Navigation

Vue d'ensemble · Opérations SOC (Triage, Incidents) · Renseignement (Indicateurs, Sources CTI) ·
Vulnérabilités (CVE et priorités) · Détection (Chasse) · Administration (administrateurs, en bas).
Heures en UTC par défaut, bascule vers l'heure locale dans la barre supérieure.

## Vérification

Chaque modification de l'interface passe par le workflow « Préproduction » : la pile de
production tourne derrière Caddy, chaque écran est capturé (grand écran et téléphone) et publié
sur la branche `captures`. Une erreur d'écran, de console ou une violation CSP fait échouer la CI.
