# ILL Watch — Feuille de route du site de présentation

**Version :** 22/10/2026 · **Décision :** [ADR-027](../docs/adr/ADR-027-site-de-presentation.md) ·
**Dossier :** `Website/`

Comme les jalons M1–M11 : chaque lot a ses livrables et un critère de sortie **constaté**, et
la CI fait foi.

## 1. Positionnement

Le site **présente et convainc** ; la documentation explique ; l'application sert. Comme
about.gitlab.com ou github.com, il s'adresse à quelqu'un qui découvre ILL Watch.

**Portée : internationale.** Le site vise toute organisation, partout dans le monde, qui doit
surveiller les menaces sans budget de plateforme commerciale ni infrastructure lourde.

| Public | Ce qu'il cherche | Ce que le site lui montre |
|---|---|---|
| RSSI, responsable de SOC | moins de bruit, des priorités défendables | score CVE décomposé, plancher KEV, corrélation par version |
| Analyste SOC | gagner du temps, un outil fiable | visite guidée des écrans, chasse, incidents |
| CERT / CSIRT national ou sectoriel | partage standardisé, souveraineté | STIX 2.1, serveur TAXII 2.1, auto-hébergement |
| Administrations, PME, ETI, collectivités | conformité (NIS 2, DORA…), coût | open source MIT, < 256 Mo de mémoire, un seul serveur |
| Contributeur open source | un projet sérieux | CI publique, tests, ADR, feuille de route |

Trois messages : **quoi** (plateforme CTI open source auto-hébergeable), **pour qui** (toute
équipe de sécurité, quelle que soit sa taille ou son pays), **pourquoi y croire** (code public,
CI verte, validation hebdomadaire sur données réelles, chiffres datés).

## 2. Choix technique

| Besoin | Choix | Raison |
|---|---|---|
| Génération | `Website/build.mjs`, **Node seul, aucune dépendance** | rien à mettre à jour, construction vérifiable partout, CSP stricte |
| Interactivité | JavaScript natif en modules, chargé par page | léger, aucun framework côté visiteur |
| Style | jetons du brand book (ADR-018) copiés dans `src/assets/site.css` | même identité que l'application |
| Langues | FR, EN, DE, ES, ZH ; dictionnaires JSON ; clé manquante = échec | aucune page à moitié traduite |
| Chiffres | `src/data/facts.json`, daté et sourcé | jamais d'appel à l'API en direct |
| Hébergement | CI → VPS derrière Caddy, à côté de l'application | « hébergé avec la solution » |

Si le site grandit (blog, recherche plein texte), migration possible vers Astro en gardant
dictionnaires et CSS.

## 3. Arborescence

1. **Accueil** — promesse, capture de l'interface, chiffres constatés, modules, simulateur CVE,
   preuves de confiance, appel à l'action.
2. **Plateforme** — une page par module : flux de menaces · moteur CVE · détection et
   corrélation · incidents et opérations SOC · chasse · renseignement (ATT&CK, campagnes,
   STIX/TAXII) · observabilité.
3. **Cas d'usage** — SOC d'entreprise, CERT national ou sectoriel, finance, télécoms, secteur
   public, PME et ETI, enseignement et recherche.
4. **Démo** — visite guidée interactive des écrans.
5. **Sécurité et confiance** — open source, analyses constatées (image, SAST, secrets),
   auto-hébergement, données qui restent chez le client.
6. **Feuille de route** — jalons M1 → M11 et suite, état réel.
7. **Documentation** → site MkDocs.
8. **À propos** — CYBERILL, porteur du projet.
9. **Actualités** — tirées du CHANGELOG et des releases.
10. **Contact / demande de démo**.
11. **Mentions légales (Impressum) et protection des données** — obligatoires (éditeur en
    Allemagne).

## 4. Interactivité

- **Simulateur de priorité CVE** : formule réelle (ADR-001, ADR-014), parité vérifiée par un
  test Python.
- **Visite guidée** : captures de la CI avec points cliquables.
- **Chiffres** : constatés et datés, puis un fichier agrégé quotidien (comptages seulement).
- **Explorateur ATT&CK** miniature, **exemple TAXII/STIX** copiable, **schéma d'architecture**.
- Sélecteur de langue, respect de `prefers-reduced-motion`, fonctionnement sans JavaScript en
  mode dégradé.

## 5. Langues et détection

| Ordre | Signal | Où | Pourquoi |
|---|---|---|---|
| 1 | choix déjà fait | navigateur (`localStorage`) | le visiteur a toujours le dernier mot |
| 2 | langue du navigateur | `Accept-Language` (serveur) / `navigator.languages` | reflète la personne, pas le réseau |
| 3 | pays | IP via DB-IP Lite locale (serveur) ; fuseau horaire tant que le site est statique | aucun service tiers, adresse jamais conservée |
| 4 | anglais | — | langue par défaut internationale |

Pays → langue : France, Belgique, Suisse romande, Luxembourg, Canada (Québec), Afrique
francophone → FR ; Allemagne, Autriche, Suisse alémanique, Liechtenstein → DE ; Espagne,
Amérique latine, Guinée équatoriale → ES ; Chine, Taïwan, Hong Kong, Macao → ZH ; reste → EN.

Seule l'adresse racine `/` redirige ; chaque page a son URL (`/de/`, `/zh/`…), `hreflang` et
`x-default`. Les traductions sont relues par des locuteurs natifs avant la mise en ligne.

## 6. Lots

| Lot | Contenu | Critère de sortie |
|---|---|---|
| **S0 Cadrage** ✅ | publics, messages, arborescence, ADR-027 | ADR accepté — **22/10** |
| **S1 Fondations** 🟡 | `Website/`, générateur, 5 langues, détection, jetons, accueil, simulateur, CI « Site web » | construction et contrôles verts en CI, captures de l'accueil dans les 5 langues |
| **S2 Contenu** | pages Plateforme, Cas d'usage, Sécurité, Feuille de route, À propos, légal | toutes les pages dans les 5 langues, aucune clé manquante, relecture native |
| **S3 Interactivité** | visite guidée, explorateur ATT&CK, exemple TAXII, schéma animé, chiffres quotidiens | chaque module testé (`node --test`), dégradé sans JavaScript |
| **S4 Contact** | demande de démo traitée par l'application (point d'entrée dédié, limité en débit), consentement, mesure d'audience sans cookie | demande reçue de bout en bout, aucune donnée inutile conservée |
| **S5 Qualité** | WCAG 2.2 AA, performance, référencement multilingue, en-têtes de sécurité | Lighthouse ≥ 95, accueil < 500 Ko, 0 violation CSP, 0 lien mort |
| **S6 Mise en ligne** | domaine, Caddy (site + application), détection serveur par IP | site servi sur le VPS, SSL Labs ≥ A, redirection constatée depuis 5 pays |

## 7. Points de vigilance

- **Ne promettre que ce qui est constaté** : « 100 % détectés, 0 % de faux positifs » vaut sur
  le jeu figé de M8 ; sur données réelles le bilan est différent. Tant que M7 n'est pas clos :
  « préproduction », pas « prêt pour la production ».
- **Traductions** : générées avec assistance, à faire relire par un locuteur natif par langue
  (priorité : chinois et espagnol).
- **Conformité internationale** : RGPD (éditeur en Allemagne, visiteurs européens), Impressum ;
  pas de cookie donc pas de bandeau ; adresse IP traitée en mémoire seulement pour la langue.
- **Maintenance** : captures, chiffres, actualités et feuille de route générés, jamais recopiés.
- **Nom de domaine** : à réserver tôt (conditionne S6 et la clôture de M7) ; vérifier
  l'antériorité de la marque (EUIPO, OMPI) avant tout dépôt (ADR-018).
- **Chine** : l'accès à des ressources hors de Chine peut être lent ou filtré ; le site n'en
  charge aucune (polices et scripts servis par le site lui-même).
