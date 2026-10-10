# ILLWATCH — Système de design (v6)

Adopté le 08/10/2026 (ADR-016). Référence visuelle : canevas « ILLWATCH — Maquette v6 (système de
design) ». Principes : clarté opérationnelle, densité maîtrisée, cohérence, sobriété. La couleur et le
mouvement transmettent une information ; ils ne décorent jamais.

## Couleurs

| Jeton | Valeur | Usage |
|---|---|---|
| `bg` | `#0A0E1A` | fond de page |
| `panel` | `#121A2B` | cartes, panneaux |
| `panel-head` | `#0F1626` | en-têtes de tableau, champs |
| `line` | `#222C42` | bordures |
| `nav` | `#0D1220` | menu latéral, barre supérieure |
| `text` | `#ECEFF5` | texte principal |
| `muted` | `#A3ACBF` | texte secondaire (contraste ≈ 7:1 sur `panel`) |
| `indigo` | `#20155C` | identité CYBERILLSEC : page active, ligne sélectionnée, filtre actif |
| `indigo-light` | `#9D8CFF` | liens, focus clavier, courbes |
| `orange` | `#E6681B` | action principale (une par vue), repère de sélection ; texte `#1B0D04` dessus |
| `critical` | `#E5484D` | P0 / critique uniquement |
| `success` | `#3FB27F` | état sain uniquement |
| `warning` | `#F2B33D` | direct en pause ou en reconnexion (pastille de la barre supérieure) |
| `grid` | `#1A2236` | lignes de grille des graphiques (plus discrètes que `line`) |

## Échelle de priorité (identique dans tous les modules)

| Badge | Fond / texte | CVE | Alertes, incidents, IOC |
|---|---|---|---|
| P0 | `#3B1518` / `#FF9B9E` | patch sous 24 h | Critique |
| P1 | `#3A2C0C` / `#F7CB70` | patch sous 7 j | Élevée |
| P2 | `#122848` / `#9BC2FF` | patch sous 30 j | Moyenne |
| P3 | `#1E2535` / `#C6CDD9` | maintenance | Faible |

États : Nouvelle (indigo), Acquittée (P3), En analyse (P2), Confinement (P1), Clôturé / sain (succès).

## Typographie

Inter : page 24/32 (600) · carte 16/24 (600) · texte 14/20 · tableau 13/20 · métadonnées 12/16 ·
libellé de section 11/16 majuscules espacées. JetBrains Mono : IP, domaines, URL, empreintes, CVE,
horodatages.

## Espacements et formes

Échelle 4, 8, 12, 16, 24, 32 px. Marge interne des cartes 16 ; entre cartes 16 ; entre sections 24 ;
marges de page 32. Rayons : cartes 12, boutons 8, badges 6. Cibles cliquables ≥ 40 px.

## Composants

- **Carte indicateur** : libellé court, valeur dominante, contexte en une ligne ; hauteur identique sur
  une rangée.
- **Tableau** : en-tête `panel-head`, lignes de 44 px ; sélection = fond indigo + repère orange à
  gauche ; nouvelle ligne = surbrillance qui s'efface en 2,5 s sans déplacer la ligne lue.
- **Panneau de détail** : 1 identifiant et priorité, 2 statut et essentiel, 3 éléments associés,
  4 historique, 5 actions (principale à droite). Consultation rapide dans le panneau ; investigation
  approfondie sur une page dédiée.
- **Boutons** : principal (orange), secondaire (contour), discret (texte), désactivé (pointillés + raison
  affichée).

## Mouvement

Autorisé : surbrillance brève d'un nouvel élément, ouverture de panneau en 180 ms, compteur qui change
de teinte une fois. Proscrit : pulsations permanentes, halos, éléments qui défilent pendant la lecture.
Toujours visibles : état de la connexion, heure de mise à jour, bouton « Mettre en pause ».

## Navigation

Vue d'ensemble · Opérations SOC (Triage, Incidents) · Renseignement (Indicateurs, Sources CTI) ·
Vulnérabilités (CVE et priorités) · Chasse (Recherches et règles) · Administration (séparée en bas).
Heures affichées en UTC par défaut, bascule vers l'heure locale dans la barre supérieure.
