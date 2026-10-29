# ADR-028 : Inventaire d'actifs en fichier (import et export Excel ou CSV)

- **Statut :** **accepté le 30/10/2026** (demande de Godwill FOKA : déclarer l'inventaire dans
  un fichier Excel puis l'importer depuis l'application)
- **Date :** 2026-10-30
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-020 (corrélation et inventaire), ADR-016 (interface web), ADR-011
  (journal d'audit), `illwatch/modules/correlation/inventory_file.py`, `/api/v1/assets/import`,
  `/api/v1/assets/export`, `/api/v1/assets/template`, écran Inventaire, `illwatch assets`

## Contexte

La corrélation (ADR-020) ne produit rien sans inventaire. Jusqu'ici, l'écran Inventaire ne
permettait de déclarer les actifs qu'un par un ; l'import en masse n'existait qu'en ligne de
commande, avec un CSV au séparateur `;` imposé, en UTF-8 uniquement, sans aperçu, et qui
effaçait les notes des actifs mis à jour. Or un inventaire vit le plus souvent dans un tableur
tenu par l'équipe informatique : c'est là qu'il faut aller le chercher.

## Décision

1. **Un seul analyseur** (`inventory_file.py`) pour l'écran, l'API et la ligne de commande.
2. **Formats** : Excel `.xlsx` et CSV (séparateur `;`, `,` ou tabulation détecté sur l'en-tête,
   UTF-8 avec ou sans BOM, ou Windows-1252). En-têtes insensibles à la casse et aux accents,
   synonymes anglais acceptés ; criticité en clair (« Critique », « Élevée »…) ou par code.
3. **Aperçu puis import, tout ou rien** : `POST /assets/import` sans `apply` renvoie chaque ligne
   avec l'action prévue (création, mise à jour) ou le motif du refus ; avec `apply=true`, rien
   n'est écrit si une seule ligne est refusée.
4. **Identité par le nom** : un actif présent est mis à jour ; une colonne absente du fichier
   conserve la valeur existante.
5. **Modèle Excel** téléchargeable (`/assets/template`, `illwatch assets template`) : en-têtes,
   colonnes au format texte, listes de choix (criticité, en service), onglet « Mode d'emploi ».
6. **Export réimportable** (`/assets/export`, `illwatch assets export`), consigné au journal
   d'audit (`data.export`) : l'inventaire décrit la surface exposée de l'organisation.
7. **Droits** : import et export pour ADMIN et ANALYST ; modèle pour tout utilisateur connecté.

## Justification

- Le tableur est l'outil que les équipes utilisent déjà : l'import supprime la double saisie.
- L'aperçu et le « tout ou rien » évitent un inventaire à moitié importé, plus difficile à
  corriger qu'un fichier refusé avec la liste précise des lignes à reprendre.
- `openpyxl` est la bibliothèque de référence pour lire et écrire le format Excel en Python pur.
  Écartés : un lecteur XML maison (fragile, plus de code à sécuriser) ; le CSV seul (oblige
  l'utilisateur à convertir, et Excel abîme les versions comme « 7.10 » à l'ouverture d'un CSV).

## Conséquences

- **Positives** : déclaration d'un parc complet en quelques minutes ; mêmes règles de
  validation que la saisie à l'écran ; export, modification dans Excel puis réimport.
- **Négatives** :
  - une dépendance de plus (`openpyxl`, et `et-xmlfile`), à suivre dans les analyses de
    dépendances ;
  - un fichier Excel est une archive : sa lecture est protégée par des plafonds (2 Mo, 5 000
    lignes, 40 Mo décompressés, 500 membres) qui refusent un classeur légitime hors normes ;
  - l'identité par le nom suppose des noms stables : renommer un actif dans le fichier crée un
    nouvel actif au lieu de modifier l'ancien.

## Suivi

- Import depuis un outil de gestion de parc (GLPI, CMDB) par connecteur, si le besoin apparaît.
- Formats ODS (LibreOffice) si des utilisateurs le demandent.
