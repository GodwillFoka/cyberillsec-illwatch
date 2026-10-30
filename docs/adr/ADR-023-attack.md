# ADR-023, M10, incrément 1 : contexte MITRE ATT&CK des détections

- **Statut :** **accepté le 14/10/2026** (décision de Godwill FOKA : « fais ce que tu peux faire »)
- **Date :** 2026-10-14
- **Décideurs :** Godwill FOKA
- **Concerne :** ROADMAP M10, ADR-009 (chasse), ADR-020 (corrélation), ADR-022 (incidents)

## Contexte

Critère de sortie de M10 : « une alerte affiche sa technique ATT&CK et, si connu, l'acteur
associé ». ILLWATCH détecte (chasse, corrélation) sans dire **comment** l'adversaire opère
ni **qui** il est.

## Décision

1. **Référentiel importé, jamais appelé en ligne** : `illwatch attack import` lit le bundle STIX
   2.1 d'ATT&CK Enterprise publié par MITRE (dépôt `mitre-attack/attack-stix-data`, ou
   `--file` hors ligne) et le range dans `attack_techniques`, `attack_actors` (groupes,
   logiciels malveillants, outils) et `attack_uses`. Objets révoqués ou dépréciés écartés ;
   chaque import remplace le précédent. Mention « ATT&CK® © The MITRE Corporation, reproduit
   avec son autorisation » partout où le contenu est affiché.
2. **Technique par règle**, versionnée avec les règles (`modules/attack/catalog.py`) :
   RULE-01 → T1090.003 (proxy multi-sauts, Tor), RULE-02 → T1568 (résolution dynamique),
   RULE-03 → T1568.002 (DGA), RULE-04 → T1486 (chiffrement pour impact), RULE-05, CORR-01,
   CORR-02 → T1190 (exploitation d'une application exposée). **Pas d'attribution forcée** :
   RULE-06 (« IOC déjà connu ») et CORR-03 (« notre adresse dans un IOC ») ne disent pas
   comment l'adversaire opère et ne déclarent aucune technique.
3. **Acteur « si connu »** : proposé seulement quand son nom ou un alias figure **en toutes
   lettres** dans le renseignement attaché (description de l'IOC par sa source, détail de la
   règle, titre de l'incident). Groupes et logiciels malveillants seulement (les outils
   génériques « Net », « Ping », « Tor » ne désignent personne) ; 4 caractères au moins, mot
   entier ; liste de mots courants exclus (« Royal », « Play », « Hive »…). L'acteur est montré
   avec ses techniques connues dans ATT&CK.
4. **Affichage** : chaque correspondance de chasse, chaque évènement corrélé et chaque incident
   porte son contexte (`attack`), dans l'API et à l'écran ; `GET /attack/status`,
   `GET /attack/techniques/{id}` ; démonstration : extrait réel minimal (2 acteurs, 10
   techniques) remplacé par l'import complet.

## Conséquences

- (+) Le critère de sortie est vérifiable : test `tests/test_attack.py`, captures.
- (+) Aucune dépendance réseau à l'exécution ; l'attribution reste explicable (« cité : … »).
- (−) L'attribution par le nom manque les campagnes non nommées par la source ; c'est voulu
  (pas d'acteur deviné). Un rapprochement par infrastructure viendra avec le modèle
  campagne → infrastructure (incrément 2).
- Reste pour M10 : modèle acteur → campagne → infrastructure, export STIX 2.1 et serveur TAXII
  sortant (incréments 2 et 3). Migration `d4a8f2c6e019`.
