# ADR-020 — Corrélation : inventaire d'actifs, trois règles, score justifié, mesure sur jeu figé

- **Statut :** **accepté le 13/10/2026** (décision de Godwill FOKA : « Fais toutes les choses à faire »)
- **Date :** 2026-10-13
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-017 (M8, incréments 3 et 4), ADR-001 (score des CVE), ADR-019 (enrichissement)

## Contexte

Jusqu'ici ILL Watch dit ce qui est dangereux **dans le monde** (CVE exploitées, IOC) ; il ne dit
pas ce qui est dangereux **pour l'organisation**. Le critère de sortie de M8 l'exige : « un
évènement corrélé produit une alerte priorisée », avec un taux de faux positifs mesuré.

## Décision

1. **Inventaire d'actifs déclaratif** (`assets`) : nom, produit tel qu'il apparaît dans les
   avis (« FortiOS »), éditeur, version (information), criticité (LOW → CRITICAL), adresses IP
   publiques, domaines. Saisi par les analystes (écran Inventaire, API, CLI, import CSV).
2. **Trois règles**, choisies pour leur valeur et leur faible bruit :
   - **CORR-01** : CVE du catalogue KEV dont la description cite le produit d'un actif ;
   - **CORR-02** : CVE P0/P1 avec exploit public (hors KEV), même correspondance ;
   - **CORR-03** : adresse ou domaine (sous-domaines compris) d'un actif présent dans un IOC
     actif dont la confiance (ADR-017) atteint le seuil, 40 par défaut.
3. **Score 0–100 justifié** : base de la règle (60, 45, 50) + criticité de l'actif (0, 5, 12,
   20) + signal (score de la CVE × 0,2, ou confiance de l'IOC × 0,3) ; même grille de priorité
   que les CVE (P0 ≥ 80, P1 ≥ 60, P2 ≥ 40). La décomposition est stockée avec l'évènement.
4. **Un évènement par règle et par couple (actif, CVE/IOC)** : une nouvelle passe met à jour
   l'évènement ; acquitté puis aggravé d'un cran de priorité, il est rouvert. Ouvrir l'incident
   l'acquitte et y rattache la CVE ou l'IOC.
5. **Exécution** : par le worker toutes les heures (`CORRELATION_INTERVAL_SECONDS`), ou à la
   demande (bouton « Corréler maintenant », `illwatch correlate run`). Événements temps réel
   `correlation.created` / `correlation.updated`.
6. **Mesure (incrément 4)** : jeu de données figé et versionné
   (`illwatch/modules/correlation/benchmark.json`, 15 cas dont 8 pièges), exécuté dans une base
   SQLite en mémoire par `illwatch correlate evaluate` et par la CI à chaque modification :
   100 % des cas attendus doivent être détectés, aucun faux positif toléré sur ce jeu.

## Options écartées

- **Correspondance par CPE** (NVD) : plus précise (versions), mais les CPE ne sont pas encore
  stockés et l'inventaire devrait être saisi en CPE, ce qu'aucun analyste ne fait de tête.
  Reportée : le nom de produit en mot entier, piégé et mesuré, suffit pour démarrer.
- **Moteur de règles générique** (Sigma, requêtes libres) : puissant mais impossible à mesurer
  et à expliquer simplement ; trois règles explicables d'abord.
- **Corrélation sur les journaux** (SIEM) : ILL Watch ne collecte pas de journaux ; c'est le
  rôle de la chasse (M6) sur des observables fournis.

## Conséquences

- Positives : chaque évènement dit pourquoi, point par point ; l'analyste voit d'abord ce qui
  touche **ses** actifs ; critère de sortie de M8 mesuré et vérifié en continu.
- Négatives : la version n'est pas comparée (une CVE corrigée dans la version déployée reste
  signalée) ; un produit mal nommé produit du bruit ou du silence ; le jeu figé est petit et
  écrit à la main — le taux de faux positifs **réel** reste à mesurer sur l'inventaire d'un
  pilote ; la recherche des domaines (`LIKE '%.domaine'`) parcourt la table des IOC à chaque
  passe (acceptable à l'heure, à indexer si l'inventaire grossit).

## Suivi

- Mesure sur données réelles avec l'inventaire du premier pilote (rapport daté dans `Rapport/`).
- CPE et comparaison de versions (M10, contextualisation).
- Notification des évènements P0 par le webhook des alertes.

## Suivi

- 13/10/2026 : sur données réelles, la correspondance par nom seul produit ≈ 80 % de faux
  positifs. La version déclarée est désormais comparée aux plages NVD : voir ADR-021.
