# ADR-027 — Site de présentation international (`Website/`)

- **Statut :** **accepté le 22/10/2026** (décisions de Godwill FOKA : portée mondiale, cinq
  langues, langue du navigateur puis pays, dossier `Website`, dépôt GitHub par PR)
- **Date :** 2026-10-22
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-013 (Caddy), ADR-016 (interface web), ADR-018 (identité ILL Watch v2),
  ADR-019 (DB-IP Lite), feuille de route `Website/ROADMAP.md`

## Contexte

ILL Watch a une documentation (MkDocs, GitHub Pages) et une interface d'analyste, mais rien qui
**présente** la solution à quelqu'un qui ne la connaît pas : RSSI, responsable de SOC, CERT
national, décideur public ou privé, contributeur open source. La cible est **internationale** :
le site doit parler la langue du visiteur dès la première page et être hébergé à terme avec la
solution, sur le même serveur.

## Décision

1. **Un site de présentation distinct** de la documentation et de l'application, dans le
   dossier **`Website/`** du dépôt. Il convainc ; la documentation explique ; l'application sert.
2. **Cinq langues au lancement : français, anglais, allemand, espagnol, chinois simplifié.**
   Une page = un dictionnaire par langue (`Website/src/i18n/<code>.json`) ; une clé absente fait
   échouer la construction (aucune page à moitié traduite). Ajouter une langue = ajouter un
   fichier et une ligne dans `Website/src/config.mjs`. L'arabe (droite à gauche) n'est pas
   exclu : la mise en page utilise des propriétés logiques CSS pour le permettre.
3. **Choix automatique de la langue à la première visite**, dans cet ordre :
   1. choix déjà fait par le visiteur (mémorisé dans son navigateur) ;
   2. **langue du navigateur** (`Accept-Language` côté serveur, `navigator.languages` côté
      navigateur) — elle reflète la personne, pas le réseau (Suisse, Belgique, Canada,
      expatriés, VPN) ;
   3. **pays du visiteur** — côté serveur par l'adresse IP, avec la base DB-IP Lite déjà
      importée pour l'enrichissement (ADR-019), **sans service tiers ni conservation de
      l'adresse** ; tant que le site est statique, le fuseau horaire du navigateur sert de
      signal de pays équivalent ;
   4. anglais par défaut.
   Le sélecteur de langue est visible sur chaque page ; un choix manuel l'emporte toujours. Les
   URL portent la langue (`/fr/`, `/en/`…), avec `hreflang` et `x-default` pour les moteurs de
   recherche : la détection ne redirige que l'adresse racine `/`.
4. **Générateur statique sans dépendance** (`Website/build.mjs`, Node ≥ 20 seul). Pas de
   framework : rien à mettre à jour, aucune alerte `npm audit`, construction vérifiable depuis
   n'importe quel poste, pages légères (cible < 500 Ko pour l'accueil) et **CSP stricte**
   (`script-src 'self'`, aucun script en ligne). L'interactivité est en JavaScript natif,
   chargé seulement par les pages qui en ont besoin. Si le site grandit (blog, recherche), une
   migration vers Astro reste possible sans changer les dictionnaires ni les gabarits CSS.
5. **Identité** : jetons et fichiers du brand book (ADR-018), thème Nuit, symbole écu-radar.
6. **Interactivité utile, jamais décorative** : simulateur de priorité CVE qui applique la
   **formule réelle** du moteur (ADR-001, plancher KEV de l'ADR-014) — un test Python vérifie
   que le simulateur et `illwatch.modules.cve_tracker.scoring` donnent les mêmes résultats sur
   un jeu de cas partagé ; visite guidée des écrans ; chiffres constatés.
7. **Le site n'appelle jamais l'API en direct.** Les chiffres viennent d'un fichier
   (`Website/src/data/facts.json`) daté et sourcé ; plus tard, un fichier agrégé généré chaque
   jour (comptages seulement, aucune valeur d'indicateur).
8. **Ne publier que ce qui est constaté** : chaque chiffre porte sa date et son contexte ;
   tant que M7 n'est pas clos, le site parle de préproduction.
9. **Hébergement** : construction et contrôles en CI (workflow « Site web ») ; publication sur
   le VPS derrière Caddy à côté de l'application, avec la détection de langue côté serveur.
   GitHub Pages sert déjà la documentation à la racine du projet : le choix d'une publication
   intermédiaire du site (sous-chemin ou domaine dédié) est tranché au lot S6.
10. **Vie privée** : aucun cookie, aucun traceur, aucune police ni script chargés depuis un
    tiers ; mentions légales (Impressum) et déclaration de protection des données obligatoires
    avant la mise en ligne publique.

## Conséquences

- Positif : site rapide partout dans le monde, sans surface d'attaque côté dépendances,
  cohérent avec l'application ; chaque chiffre est vérifiable.
- Négatif : un générateur maison à maintenir (≈ 300 lignes) ; la traduction de cinq langues
  demande une relecture humaine par des locuteurs natifs avant la mise en ligne.
- Ouvert : nom de domaine (non choisi au 22/10), publication intermédiaire, relecteurs des
  traductions.
