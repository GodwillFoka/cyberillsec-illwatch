---
hide:
  - navigation
  - toc
---

<div class="iw-hero" markdown>

<div class="iw-hero-text" markdown>

<span class="iw-kicker">Cyber Threat Intelligence · open source · hébergé en Europe</span>

# La veille sur les menaces, enfin lisible et actionnable

ILLWATCH collecte le renseignement public sur les menaces, écarte le bruit, dit quelles
vulnérabilités corriger en premier et relie chaque alerte à **vos** actifs. Votre équipe garde
les décisions ; la plateforme fait le travail répétitif.

[:material-rocket-launch: Installer ILLWATCH](GUIDE_INSTALLATION.md){ .md-button .md-button--primary }
[:material-book-open-variant: Découvrir les fonctionnalités](MANUEL_FONCTIONNEL.md){ .md-button }
[:material-file-pdf-box: Documents PDF](#documents-de-reference){ .md-button }

</div>

<div class="iw-hero-logo" markdown>
![ILLWATCH](assets/illwatch-logo-light.svg#only-light)
![ILLWATCH](assets/illwatch-logo-dark.svg#only-dark)
</div>

</div>

<div class="iw-stats" markdown>
<div><strong>528 453</strong><span>IOC collectés sur le poste de travail</span></div>
<div><strong>26 416</strong><span>CVE suivies, notées de 0 à 100</span></div>
<div><strong>93 %</strong><span>du bruit écarté : 6,7 % des CVE à traiter</span></div>
<div><strong>&lt; 256 Mo</strong><span>de mémoire pour toute la plateforme</span></div>
<div><strong>0 €</strong><span>licence MIT, auto-hébergé</span></div>
</div>

<p class="iw-note">Chiffres mesurés sur données réelles, poste de travail Kali, 07 et 08/10/2026.</p>

## Ce que fait ILLWATCH

<div class="grid cards" markdown>

-   :material-radar:{ .lg .middle } **Collecter**

    ---

    Neuf sources publiques ou gratuites (NVD, CISA KEV, FIRST EPSS, AlienVault OTX, abuse.ch,
    IPsum, C2IntelFeeds, flux TAXII 2.1), collectées en continu, normalisées et dédoublonnées
    avec leur provenance.

-   :material-sort-numeric-descending:{ .lg .middle } **Prioriser**

    ---

    Chaque CVE reçoit un score de 0 à 100 fondé sur l'exploitation réelle et une priorité de
    P0 à P3. Une faille déjà exploitée n'est jamais sous P1.

-   :material-link-variant:{ .lg .middle } **Corréler**

    ---

    Votre inventaire, déclaré en quelques minutes depuis un fichier Excel, est confronté aux
    CVE et aux IOC, version comprise. Seul ce qui vous concerne remonte.

-   :material-shield-alert:{ .lg .middle } **Répondre**

    ---

    Triage L1, L2, L3, incidents au cycle NIST SP 800-61 avec chronologie immuable, chasse sur
    vos journaux, contexte MITRE ATT&CK et campagnes.

-   :material-share-variant:{ .lg .middle } **Partager**

    ---

    Export STIX 2.1 et serveur TAXII 2.1 en lecture seule pour votre SIEM, OpenCTI ou MISP ;
    exports CSV et JSON protégés.

-   :material-chart-box:{ .lg .middle } **Piloter et prouver**

    ---

    Écran Pilotage (MTTA, MTTR, délais cibles), métriques Prometheus et Grafana, journal
    d'audit en ajout seul pour NIS 2 et DORA.

</div>

![De la source à la décision](assets/schemas/pipeline.svg)

## Par où commencer

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Je veux l'installer**

    ---

    Installation de A à Z sur un poste ou un serveur, sources, comptes, premier remplissage,
    sauvegardes et mises à jour.

    [:octicons-arrow-right-24: Guide d'installation et d'exploitation](GUIDE_INSTALLATION.md)

-   :material-microsoft-excel:{ .lg .middle } **Je veux déclarer mon parc**

    ---

    Téléchargez le modèle Excel depuis l'écran Inventaire, remplissez une ligne par actif,
    analysez puis importez.

    [:octicons-arrow-right-24: Déclarer votre inventaire](GUIDE_INSTALLATION.md#5-declarer-votre-inventaire-methode-excel)

-   :material-account-group:{ .lg .middle } **Je veux savoir qui fait quoi**

    ---

    Les acteurs (administrateur, analystes L1 à L3, lecteur, partenaire TAXII, worker), leurs
    droits et chaque fonctionnalité expliquée.

    [:octicons-arrow-right-24: Manuel fonctionnel](MANUEL_FONCTIONNEL.md)

-   :material-clipboard-check:{ .lg .middle } **Je veux les exigences**

    ---

    La spécification opposable : exigences fonctionnelles et non fonctionnelles, leur statut
    réel, l'architecture et les critères d'acceptation.

    [:octicons-arrow-right-24: Cahier des charges v2.0](CAHIER_DES_CHARGES.md)

-   :material-compass:{ .lg .middle } **Je veux la stratégie**

    ---

    Le problème, les cibles, la proposition de valeur, la concurrence, le modèle et la
    trajectoire jusqu'en 2035.

    [:octicons-arrow-right-24: Vision produit v2.0](PRODUCT_VISION.md)

-   :material-code-braces:{ .lg .middle } **Je veux contribuer**

    ---

    Organisation du code, standards, première tâche, et les 28 décisions d'architecture avec
    leurs coûts assumés.

    [:octicons-arrow-right-24: Prise en main](ONBOARDING.md) · [Architecture](ARCHITECTURE.md)

</div>

## Où en est le projet

![Jalons M1 à M11](assets/schemas/jalons.svg)

| Étape | État au 30/10/2026 |
|---|---|
| **M1 à M6** : fondation, flux, CVE, incidents, tableau de bord, chasse | :material-check-circle:{ .iw-ok } constatés sur données réelles, release `v0.1.1` |
| **M8** : détection et corrélation | :material-check-circle:{ .iw-ok } clos le 14/10 (100 % détectés sur le jeu figé) |
| **M9 et M10** : opérations SOC, contexte ATT&CK, partage STIX et TAXII | :material-progress-check:{ .iw-wip } livrés, constatés en CI, à rejouer sur le poste |
| **M7 et M11** : durcissement de production, observabilité | :material-server-network:{ .iw-wait } livrés, attendent le serveur européen et 7 jours de préproduction |
| **v0.2.0** « Production Candidate » | :material-flag-outline:{ .iw-wait } après M7 et M11 |

[:material-map-marker-path: Feuille de route](ROADMAP.md){ .md-button }
[:material-file-document-multiple: Rapports et bilans](rapport/index.md){ .md-button }

## Un aperçu de l'application

<div class="iw-shots" markdown>

<figure markdown>
![Vue d'ensemble](assets/captures/01-vue-ensemble-fr.webp)
<figcaption>Vue d'ensemble : ce qui demande votre attention maintenant.</figcaption>
</figure>

<figure markdown>
![Triage des alertes](assets/captures/02-triage-fr.webp)
<figcaption>Triage : alertes priorisées et score décomposé.</figcaption>
</figure>

<figure markdown>
![Import de l'inventaire](assets/captures/11c-inventaire-apercu-fr.webp)
<figcaption>Inventaire : aperçu d'un import Excel avant validation.</figcaption>
</figure>

<figure markdown>
![Corrélations](assets/captures/10-correlations-fr.webp)
<figcaption>Corrélations : le renseignement rapporté à vos actifs.</figcaption>
</figure>

</div>

<p class="iw-note">Captures prises sur la préproduction locale avec le jeu de démonstration (données fictives).</p>

## Documents de référence

Tous les documents v2.0 du 30/10/2026 existent en ligne sur ce site et en PDF mis en page.

<div class="grid cards" markdown>

-   :material-file-pdf-box:{ .lg .middle } **Guide d'installation et d'exploitation**

    ---

    Installation, inventaire par Excel, travail quotidien en double méthode (application et
    ligne de commande), administration, serveur, dépannage.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Guide_installation_exploitation_v2.pdf) ·
    [Lire en ligne](GUIDE_INSTALLATION.md)

-   :material-file-pdf-box:{ .lg .middle } **Manuel fonctionnel**

    ---

    Acteurs et matrice des droits, chaque fonctionnalité en quatre temps, parcours types,
    glossaire.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Manuel_fonctionnel_v2.pdf) ·
    [Lire en ligne](MANUEL_FONCTIONNEL.md)

-   :material-file-pdf-box:{ .lg .middle } **Cahier des charges v2.0**

    ---

    Exigences RF-01 à RF-57 avec leur statut, exigences non fonctionnelles mesurées, modèle de
    données, interfaces, risques.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Cahier_des_charges_v2.pdf) ·
    [Lire en ligne](CAHIER_DES_CHARGES.md)

-   :material-file-pdf-box:{ .lg .middle } **Vision produit v2.0**

    ---

    Problème, cibles, valeur, marché et concurrence, modèle open source, trajectoire et vision
    2035.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Vision_produit_v2.pdf) ·
    [Lire en ligne](PRODUCT_VISION.md)

-   :material-file-pdf-box:{ .lg .middle } **Feuille de route v2.0**

    ---

    Jalons M1 à M11 avec leurs preuves, ce qui reste à faire dans l'ordre, calendrier et
    suite après la v0.2.0.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Feuille_de_route_v2.pdf) ·
    [Lire en ligne](ROADMAP.md)

-   :material-archive:{ .lg .middle } **Documents fondateurs (archive)**

    ---

    Cahier des charges v1.0.0 et vision produit v1.0 de juillet 2026, sous le nom d'origine
    SENTRY, conservés tels quels.

    [:octicons-download-16: Cahier des charges v1.0](pdf/SENTRY_Cahier_des_Charges.pdf) ·
    [Vision v1.0](pdf/CYBERILL-SENTRY-PRODUCT-VISION_3.pdf)

</div>

## Documentation technique

| Document | Pour qui | Contenu |
|---|---|---|
| [Architecture](ARCHITECTURE.md) | développeurs | couches, flux de données, décisions structurantes, sécurité |
| [Exploitation](OPERATIONS.md) | opérateurs | sondes, journaux, audit, sauvegarde, TLS, mise à jour, référence des commandes |
| [Environnements](ENVIRONNEMENTS.md) | opérateurs | développement, préproduction, production, passage en production |
| [Prise en main](ONBOARDING.md) | contributeurs | poste de développement, standards, première tâche |
| [Décisions d'architecture](adr/README.md) | tous | 28 décisions tracées avec leur contexte et leurs conséquences |
| [Changelog](changelog.md) | tous | évolutions par version |

!!! info "Hiérarchie des sources"
    En cas de contradiction entre deux documents, l'ordre de préséance est : un **ADR** accepté,
    qui tranche explicitement le point ; puis le **cahier des charges**, seul document approuvé
    pour le développement ; puis la **vision produit** ; enfin les PDF d'origine, conservés pour
    archive. Un écart constaté et non tranché fait l'objet d'un ADR, jamais d'une décision
    silencieuse dans le code.

<p class="iw-note">Code : <a href="https://gitlab.com/GodwillFoka/cyberillsec-illwatch">GitLab (référence)</a> ·
<a href="https://github.com/GodwillFoka/cyberillsec-illwatch">GitHub (miroir)</a> · image
<code>ghcr.io/godwillfoka/cyberillsec-illwatch</code>. ILLWATCH s'appelait SENTRY jusqu'au 08/10/2026.</p>
