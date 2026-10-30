# ADR-031 : Transparence du renseignement (source, fraîcheur, confiance)

- **Statut :** **accepté le 30/10/2026** (revue d'amélioration de Godwill FOKA : renforcer la
  transparence du renseignement, priorité 3)
- **Date :** 2026-10-30
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-006 (provenance), ADR-017 (confiance), ADR-007 (moteur CVE), ADR-014
  (dépendance à EPSS), `illwatch/modules/threat_feeds/freshness.py`, `/api/v1/indicators`,
  `/api/v1/cves/freshness`, écrans Indicateurs et CVE et priorités

## Contexte

La confiance d'un IOC tient déjà compte de ses sources et de sa fraîcheur (ADR-017), et sa
fiche détaille chaque source. Mais dans la **liste**, l'analyste ne voyait qu'un nombre de
sources et un âge brut (« il y a 12 jours ») : rien ne disait si 12 jours, c'est beaucoup pour
ce type d'indicateur, ni qui l'avait rapporté. Côté vulnérabilités, une priorité calculée sur un
EPSS vieux d'une semaine s'affichait comme une priorité du jour ; seul `illwatch status`
signalait le retard.

Le risque est connu : une donnée ancienne ou peu fiable lue comme une menace actuelle et
confirmée, qui mène à bloquer un service légitime ou à mobiliser l'équipe pour rien.

## Décision

**Partout où un IOC ou une CVE s'affiche, sa source, sa fraîcheur et sa confiance sont visibles
sans ouvrir la fiche.**

1. **Fraîcheur d'un IOC**, rapportée à la demi-vie de son type (celle du score de confiance) :
   *récent* (moins d'une demi-vie), *vieillissant* (moins de trois), *ancien* (au-delà), ou
   *expiré*. Une adresse IP vue il y a 10 jours est vieillissante ; une empreinte vue il y a
   10 jours est récente.
2. **Sources dans la liste** : la plus fiable par son nom et sa cote, puis le nombre des autres ;
   toutes au survol. L'API renvoie jusqu'à trois sources (`sources_preview`), les plus fiables
   d'abord.
3. **Fraîcheur des catalogues** NVD, CISA KEV et FIRST EPSS (`GET /api/v1/cves/freshness`) :
   dernière synchronisation réussie, âge, et état *à jour*, *périmé* ou *jamais synchronisé*.
   L'écran CVE l'affiche en tête et avertit dès qu'un catalogue est périmé.

Seuils de péremption : 24 h pour NVD et KEV (le critère du jalon M3), 48 h pour EPSS (la règle
déjà appliquée par `illwatch status`).

## Justification

1. **Une seule définition de la fraîcheur.** Reprendre les demi-vies du score de confiance
   garantit que l'étiquette et le score racontent la même chose.
2. **Des mots plutôt qu'un chiffre.** « Vieillissant » se lit d'un coup d'œil ; l'âge exact et
   la demi-vie restent au survol et dans la fiche.
3. **La source la plus fiable en premier.** C'est elle qui pèse le plus dans la confiance ; la
   montrer d'abord évite qu'une source cotée E paraisse aussi solide qu'une source cotée A.
4. **Avertir sur la page, pas seulement en console.** L'analyste qui trie les CVE n'ouvre pas
   `illwatch status` ; c'est sur l'écran qu'il doit apprendre qu'EPSS est en retard.

## Conséquences

**Positives**

- Une donnée ancienne ou isolée se repère avant d'agir.
- Une panne de synchronisation des catalogues se voit sans attendre l'alerte de supervision.

**Négatives**

- Une requête de plus par page d'IOC (noms des sources), groupée pour toute la page.
- Les seuils de péremption des catalogues sont fixes ; une instance volontairement synchronisée
  moins souvent verra un avertissement permanent.
