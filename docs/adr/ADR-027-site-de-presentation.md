# ADR-027 — Site de présentation international (`Website/`)

- **Statut :** **accepté le 22/10/2026** (décisions de Godwill FOKA : portée mondiale, cinq
  langues, langue du navigateur puis pays, dossier `Website`, dépôt GitHub par PR)
- **Date :** 2026-10-22
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-013 (Caddy), ADR-016 (interface web), ADR-018 (identité ILLWATCH v2),
  ADR-019 (DB-IP Lite), feuille de route `Website/ROADMAP.md`

## Contexte

ILLWATCH a une documentation (MkDocs, GitHub Pages) et une interface d'analyste, mais rien qui
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
3. **Choix automatique de la langue selon le pays** (révisé le 23/10/2026 à la demande de
   CYBERILL : « la langue s'adapte en fonction du pays »), dans cet ordre, **le même pour le
   site et pour l'application** :
   1. choix déjà fait par le visiteur (mémorisé dans son navigateur) — toujours prioritaire ;
   2. **pays** : celui du visiteur, d'après son adresse IP publique et la base DB-IP Lite déjà
      importée (ADR-019), **sans service tiers** ; à défaut (adresse privée : réseau interne,
      VPN), celui où l'instance est installée (`INSTANCE_COUNTRY`). Dans un pays à plusieurs
      langues prises en charge (Suisse, Belgique, Luxembourg, Canada, Cameroun, Singapour,
      Porto Rico), la langue du navigateur départage ;
   3. **langue du navigateur** (`Accept-Language`) si le pays n'en donne aucune (Japon,
      Brésil…) ;
   4. **langue de l'instance** (`DEFAULT_LANGUAGE`), puis **anglais**.
   La décision est prise par `GET /api/v1/locale` (`illwatch/shared/i18n.py`). Le site
   statique, sans serveur, applique la même table pays → langues (copie vérifiée par test)
   avec le fuseau horaire du navigateur comme indice de pays.
   **Sécurité et vie privée** : l'adresse sert à une seule recherche locale en mémoire ; elle
   n'est ni renvoyée, ni journalisée, ni conservée ; la réponse ne contient que la langue.
   uvicorn n'accepte `X-Forwarded-For` que de Caddy (un en-tête forgé ne change pas le pays) ;
   `Accept-Language` est borné (512 caractères, 20 étiquettes) et validé ; les recherches
   simultanées sont plafonnées (au-delà, décision sans la base). Le sélecteur de langue est
   visible partout ; les URL du site portent la langue (`/fr/`, `/en/`…), avec `hreflang` et
   `x-default` : seule l'adresse racine `/` redirige.
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

11. **L'application elle-même est multilingue** (décision du 23/10/2026), dans les mêmes cinq
    langues et selon le même ordre de choix (choix mémorisé, puis `GET /api/v1/locale`, puis
    navigateur, puis anglais). Sélecteur sur l'écran de connexion et dans la barre supérieure.
    Les textes de chaque écran sont déclarés à côté de lui dans les cinq langues ; une
    traduction manquante est une erreur de compilation, pas un texte vide découvert en
    production. Les contenus écrits par le serveur ou par les analystes (incidents, règles,
    recommandations) ne sont pas traduits. La préproduction capture la vue d'ensemble et le
    triage dans chaque langue et échoue sur toute erreur de console.

12. **Textes écrits par le serveur dans la langue de l'instance** (décision du 23/10/2026 :
    « toute capture doit avoir un contenu au moins en anglais »). Titres de corrélation,
    règles et résultats de chasse, recommandations de réponse, messages de la chronologie et
    jeu de démonstration suivent `DEFAULT_LANGUAGE` : français si elle est absente ou `fr`
    (comportement inchangé), **anglais** pour toute autre langue, en attendant une traduction
    complète côté serveur (`illwatch/shared/server_text.py`). Un texte déjà enregistré n'est
    pas réécrit. La préproduction tourne en anglais (`DEFAULT_LANGUAGE=en`) : les captures
    principales — celles du site — sont entièrement en anglais, interface et données.

13. **Un site qui vend** (décision du 23/10/2026, sur le modèle de github.com/home et
    about.gitlab.com) : héros animé avec la capture et l'appel « Demander une démo », standards
    en défilement, fonctionnalités en onglets illustrées, chiffres constatés animés, solutions
    par équipe, obligations (NIS 2, DORA, RGPD, ISO 27001) sans promesse de certification,
    comparaison par catégories d'outils (aucun concurrent nommé), offres Communauté / Pilote /
    Accompagnement **sur demande** (aucun prix publié), FAQ. Pas de logo client ni de
    témoignage tant qu'il n'en existe pas de réels. Les animations respectent
    `prefers-reduced-motion` et le contenu reste entier sans JavaScript.

14. **Site complet et publication** (décision du 23/10/2026, réponses de Godwill FOKA) :
    - **GitLab seul** comme dépôt public : tous les liens du site (code, versions, sécurité,
      demande de démo) mènent à GitLab ; le projet GitLab doit être rendu public. La
      documentation et le site sont publiés par GitLab Pages (`<pages>/` et `<pages>/docs/`).
    - **Pages** Plateforme, Sécurité, Tarifs, À propos, Démonstration, Impressum,
      Datenschutz, dans les cinq langues ; l'Impressum est rempli depuis
      `Website/src/data/legal.json` et la construction publique (`ILLWATCH_SITE_PUBLIC=1`)
      échoue tant qu'il manque un champ obligatoire.
    - **Prix arbitraires et indicatifs** (Pilote dès 1 490 €, Accompagnement dès 290 €/mois — prix de lancement volontairement bas pour se faire un nom, demande du 23/10/2026),
      affichés comme « en phase d'évaluation » ; prix définitifs à fixer après les premiers
      pilotes (tâche à venir, `Website/ROADMAP.md`).
    - **Demande de démonstration traitée par l'application** : `POST /api/v1/demo-requests`
      public (débit limité par IP sans l'enregistrer, plafond quotidien, champ piège,
      consentement daté), suivi par les administrateurs (journal d'audit), purge à 12 mois.
      Caddy ne relaie vers l'API, sur le domaine du site, que cette route et `/langue`.
    - **Qualité** : chaque page contrôlée dans les cinq langues en grand écran et sur téléphone
      (débordement, console, CSP), accessibilité WCAG 2.2 AA par axe-core en CI.

## Conséquences

- Positif : site rapide partout dans le monde, sans surface d'attaque côté dépendances,
  cohérent avec l'application ; chaque chiffre est vérifiable.
- Négatif : un générateur maison à maintenir (≈ 300 lignes) ; la traduction de cinq langues
  demande une relecture humaine par des locuteurs natifs avant la mise en ligne.
- Ouvert : nom de domaine (non choisi au 22/10), publication intermédiaire, relecteurs des
  traductions.
