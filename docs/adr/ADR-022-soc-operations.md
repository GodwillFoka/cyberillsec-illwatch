# ADR-022 — M9 SOC Operations : niveaux L1/L2/L3, faux positifs, réponse, pilotage

- **Statut :** **accepté le 14/10/2026** (décision de Godwill FOKA : « fais le M9-SOC »)
- **Date :** 2026-10-14
- **Décideurs :** Godwill FOKA
- **Concerne :** ROADMAP M9, PLAN_DIRECTEUR tâche 3.6, ADR-008 (incidents), ADR-009 (chasse),
  ADR-020/021 (corrélation)

## Contexte

M9 doit « outiller le travail des analystes L1/L2/L3 », avec ce critère de sortie : **un
incident traverse L1 → L2 → L3 sans quitter ILL Watch, MTTR mesuré**. Jusqu'ici, un incident
n'avait pas de niveau, un faux positif ne pouvait qu'être acquitté (et revenait), la chasse
était séparée de l'investigation et aucun délai n'était mesuré.

## Décision

1. **Niveau SOC de l'incident** (`incidents.tier`, L1 à l'ouverture). L'**escalade** monte
   d'un niveau (ou vers un niveau visé), **motif obligatoire**, consignée dans la chronologie
   immuable (`ESCALATED`) ; elle ne redescend jamais. Rôles : L1 qualifie, L2 investigue, L3
   traite (réponse avancée, ingénierie de détection). Les comptes n'ont pas de niveau : tout
   analyste peut agir à tout niveau, la traçabilité suffit à ce stade.
2. **Faux positifs et liste d'exclusion** (tâche 3.6). Une valeur exclue (type et valeur
   normalisée, motif, auteur, incident d'origine, expiration facultative) cesse d'être un IOC
   **actif** : `is_active_clause` l'écarte, donc elle n'est plus comptée, chassée ni corrélée.
   L'IOC reste en base avec sa provenance ; une nouvelle observation ne lève pas l'exclusion ;
   seul un administrateur la retire. Un **évènement corrélé** qualifié de faux positif est clos
   et **jamais rouvert** par le moteur ; pour CORR-03, l'IOC en cause est exclu.
3. **Investigation L2 depuis l'incident** : la chasse part des IOC associés (plus les
   observables relevés), avec l'inventaire pour RULE-05 ; la session est rattachée à l'incident
   et résumée dans la chronologie (`HUNT_RUN`). L'enrichissement (pays, AS) reste à la demande
   dans la fiche de l'IOC.
4. **L3 : règles versionnées** : chaque règle de chasse porte une version et un historique ;
   chaque session enregistre les versions appliquées (`hunting_sessions.rule_versions`). RULE-03
   v2 (calibration Tranco) et RULE-06 v3 (plages CIDR, exclusions) en sont les premiers usages.
5. **Recommandations de réponse** déduites du contenu de l'incident (types d'IOC, CVE KEV avec
   échéance CISA ou à exploit, rançongiciel) et de sa phase NIST, phase en cours d'abord.
   ILL Watch **recommande, n'exécute rien** : l'analyste déclare ensuite l'action menée.
6. **Pilotage** (`GET /dashboard/soc?days=7|30`, écran Pilotage, `illwatch soc metrics`) :
   - **MTTA** : ouverture → premier geste d'un analyste (assignation, statut, escalade, action,
     chasse) ; **MTTR** : ouverture → clôture ;
   - **délais cibles** par sévérité (prise en charge / résolution) : critique 1 h / 24 h,
     élevée 4 h / 72 h, moyenne 24 h / 7 j, faible 72 h / 30 j ; part dans le délai et liste
     des incidents ouverts en dépassement ;
   - incidents en cours par niveau, escalades de la période, charge par analyste (noms visibles
     des seuls administrateurs), ouverts et clos par jour, faux positifs écartés.

## Conséquences

- (+) Le critère de sortie est vérifiable par un test de bout en bout
  (`tests/test_soc.py::test_parcours_l1_l2_l3_de_bout_en_bout`) et par le scénario
  d'acceptation (`scripts/scenario_soc.py`, étapes M9).
- (+) Les faux positifs ne reviennent plus : la qualité des alertes s'améliore à l'usage.
- (−) `is_active_clause` porte un `NOT EXISTS` sur `exclusions` : coût négligeable tant que la
  liste reste courte (index unique sur type et valeur) ; à mesurer sur Kali (528 000 IOC).
- (−) Les délais cibles sont des valeurs par défaut raisonnables, pas un contrat : ils
  deviendront paramétrables quand un pilote en fixera d'autres.
- Migration `c9f1a3e5b742` (descente refusée si la chronologie contient des évènements M9 :
  la chronologie est immuable).
