# ADR-019 — Enrichissement hors ligne des IP : base DB-IP Lite importée localement

- **Statut :** **accepté le 12/10/2026** (décision de Godwill FOKA : « Faisons cette étape »)
- **Date :** 2026-10-12
- **Décideurs :** Godwill FOKA
- **Concerne :** ADR-017 (M8, incrément 2), ADR-013 (requêtes sortantes)

## Contexte

L'incrément 2 de M8 doit dire, pour chaque IP, **dans quel pays** elle est routée et **quel
opérateur** (système autonome, AS) l'annonce : c'est ce que l'analyste cherche en premier
(hébergeur « bulletproof », VPS jetable, opérateur national). L'ADR-017 impose qu'aucune
requête sortante ne soit faite par IOC : interroger un service en ligne à chaque consultation
divulguerait les IOC enquêtés à un tiers et dépendrait de sa disponibilité.

## Décision

1. **Base DB-IP Lite** (pays et AS), au format CSV, **téléchargée une fois par mois** par
   `illwatch enrich update` et importée dans PostgreSQL (`ip_ranges`). La consultation d'un
   IOC lit cette table : aucune requête sortante.
2. Bornes stockées en **clés hexadécimales de 32 caractères** (IPv4 convertie en IPv6
   `::ffff:a.b.c.d`), collation binaire : une recherche indexée « dernière plage qui commence
   avant l'adresse » suffit, identique sous PostgreSQL et SQLite (tests).
3. Import **dans une seule transaction** : l'ancienne base reste en place si le fichier est
   refusé (vide, mauvais format, plus de 1 % de lignes invalides). Chaque import est journalisé
   (`enrichment.import`).
4. Le téléchargement reprend les garde-fous du collecteur : hôte fixe
   (`download.db-ip.com`), destination publique vérifiée, aucune redirection, 200 Mo au plus,
   fichier temporaire supprimé. Poste sans Internet : `illwatch enrich import FICHIER`.
5. **Attribution** exigée par la licence : « IP Geolocation by DB-IP » avec un lien vers
   db-ip.com, partout où le résultat est affiché (fiche d'un IOC, paramètres, CLI).
6. Une adresse non routable (privée, réservée, documentation) est signalée comme telle : ce que
   la base en dit n'a pas de valeur de renseignement.

## Options écartées

- **MaxMind GeoLite2** : compte et clé de licence obligatoires, contrat d'utilisation plus
  restrictif (pas de redistribution, suppression des données sous 30 jours) ; plus de friction
  pour un même résultat.
- **Service en ligne par IOC** (ipinfo, RIPEstat…) : fuite des IOC enquêtés, quotas,
  dépendance réseau ; contraire à l'ADR-017.
- **Format MMDB** : plus compact, mais exige une dépendance Python supplémentaire et un
  fichier hors de la base (sauvegarde, droits) ; le CSV importé reste dans PostgreSQL, sauvegardé
  avec le reste.
- **Âge des domaines** (WHOIS/RDAP) : une requête sortante par domaine ; reporté.

## Conséquences

- Positives : pays et AS de chaque IP sans requête sortante ; base sauvegardée et restaurée
  avec PostgreSQL ; licence CC BY 4.0 compatible avec un usage commercial (attribution).
- Négatives : environ 1,2 million de plages (mesuré sur Kali le 12/10 : 710 834 pays et 477 362 AS, fichiers de 4,3 et 6,7 Mo) ; précision
  « Lite » (pays et AS, pas de ville) ; données vieilles d'un mois au plus si la mise à jour
  mensuelle est oubliée — la date d'import est affichée dans Administration → Paramètres.

## Suivi

- Mise à jour mensuelle automatique par le worker (option), à décider après un mois d'usage.
- Incrément 3 : utiliser pays et AS dans les règles de corrélation et la chasse.
