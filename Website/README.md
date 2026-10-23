# Site de présentation ILL Watch

Site public qui **présente** ILL Watch (la documentation explique, l'application sert).
Décision : [ADR-027](../docs/adr/ADR-027-site-de-presentation.md) ·
feuille de route : [ROADMAP.md](ROADMAP.md).

- **Cinq langues** : français, anglais, allemand, espagnol, chinois simplifié.
- **Langue choisie selon le pays** à la première visite de `/` : choix mémorisé → pays du
  visiteur (IP, par l'API) → langue du navigateur → langue de l'instance → anglais ; le
  navigateur départage les pays bilingues. Le sélecteur de langue l'emporte toujours.
- **Aucune dépendance** : Node ≥ 20 suffit. Aucune police, aucun script, aucune image tiers.

## Construire et prévisualiser

```bash
node Website/build.mjs                         # → Website/dist/
node --test Website/tests/*.test.mjs           # simulateur et choix de la langue
python3 -m http.server 8080 -d Website/dist    # http://127.0.0.1:8080/
```

La construction échoue si une traduction manque, si une page contient du style ou du script en
ligne (CSP), charge une ressource tierce, a un lien interne cassé, affiche `NaN`/`undefined`,
ou si l'accueil dépasse 500 Ko.

| Variable | Rôle | Défaut |
|---|---|---|
| `ILLWATCH_SITE_URL` | adresse publique (canonique, `hreflang`, plan du site) | `https://illwatch.example` |
| `ILLWATCH_SITE_BASE` | sous-chemin si le site n'est pas à la racine | `/` |
| `ILLWATCH_SITE_GEO_ENDPOINT` | adresse relayée vers `GET /api/v1/locale` (ex. `/langue`, voir `deploy/`) | vide : fuseau horaire |
| `ILLWATCH_SITE_COUNTRY` | pays de l'instance (ISO alpha-2), donne la langue par défaut | vide |
| `ILLWATCH_SITE_DEFAULT_LANG` | langue par défaut explicite (`fr`, `en`, `de`, `es`, `zh`) | vide : anglais |

## Organisation

```
Website/
├── build.mjs              générateur et contrôles
├── src/
│   ├── config.mjs         langues, liens, budget
│   ├── i18n/<langue>.json une clé par texte ; fr.json fait référence
│   ├── data/facts.json    chiffres constatés, datés et sourcés
│   ├── templates.mjs      gabarits HTML
│   ├── assets/site.css    jetons du brand book (ADR-018)
│   ├── assets/js/         lang.js (détection), score.js (formule du moteur), simulateur, visite
│   └── static/img/        captures de la CI (branche captures), en WebP
├── tests/                 node --test ; score-vectors.json partagé avec tests/test_site_score_parity.py
├── scripts/captures.py    captures et contrôles navigateur (workflow « Site web »)
└── deploy/                exemple Caddy pour le VPS
```

Les logos viennent de `docs/assets/` (source unique, ADR-018), copiés à la construction.

## Ajouter une langue

1. Copier `src/i18n/en.json` en `src/i18n/<code>.json` et traduire chaque valeur.
2. Ajouter la langue dans `LANGS` (`src/config.mjs`) et dans `SUPPORTED` (`src/assets/js/lang.js`),
   avec ses fuseaux horaires dans `TZ_LANG`.
3. `node Website/build.mjs` : toute clé manquante est signalée.

## Changer un chiffre

Modifier `src/data/facts.json` **avec sa date et sa source** (rapport, CI). Le site n'affiche
que des valeurs constatées (ADR-027, décision 8).

## Mettre à jour les captures

Les images de `src/static/img/screens/` sont les captures de la branche `captures` (workflow
« Préproduction »), recadrées à 1440 × 1130 et converties en WebP (1440 et 720 px de large).
