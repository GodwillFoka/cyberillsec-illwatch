---
hide:
  - navigation
  - toc
---

<div class="iw-hero" markdown>

<div class="iw-hero-text" markdown>

<span class="iw-kicker">Cyber Threat Intelligence · open source · installé sur vos serveurs</span>

# Savoir chaque matin ce qui menace vraiment votre système d'information

Chaque jour, des centaines de failles et des milliers d'indicateurs de menace sont publiés.
Personne ne peut tout lire. ILLWATCH le fait à votre place : il rassemble ces informations,
écarte ce qui ne vous concerne pas, vous dit quoi corriger en premier et vous aide à traiter
les incidents jusqu'au bout. Les décisions restent les vôtres.

[:material-rocket-launch: Installer ILLWATCH](GUIDE_INSTALLATION.md){ .md-button .md-button--primary }
[:material-book-open-variant: Voir ce qu'il sait faire](MANUEL_FONCTIONNEL.md){ .md-button }
[:material-file-pdf-box: Documents PDF](#documents-de-reference){ .md-button }

</div>

<div class="iw-hero-logo" markdown>
![ILLWATCH](assets/illwatch-logo-light.svg#only-light)
![ILLWATCH](assets/illwatch-logo-dark.svg#only-dark)
</div>

</div>

<div class="iw-stats" markdown>
<div><strong>528 453</strong><span>indicateurs de menace collectés</span></div>
<div><strong>26 416</strong><span>failles suivies et notées de 0 à 100</span></div>
<div><strong>93 %</strong><span>de bruit en moins : seules 6,7 % des failles demandent une action</span></div>
<div><strong>&lt; 256 Mo</strong><span>de mémoire pour faire tourner l'application</span></div>
<div><strong>0 €</strong><span>de licence : code ouvert (MIT), installé chez vous</span></div>
</div>

<p class="iw-note">Chiffres mesurés sur des données réelles, sur notre poste de test Kali Linux, les 7 et 8 octobre 2026.</p>

## Ce que fait ILLWATCH

<div class="grid cards" markdown>

-   :material-radar:{ .lg .middle } **Il collecte**

    ---

    Il interroge en continu neuf sources publiques ou gratuites : la base de failles du NIST,
    le catalogue des failles exploitées de la CISA, les probabilités d'exploitation EPSS,
    AlienVault OTX, abuse.ch, IPsum, C2IntelFeeds et des flux TAXII 2.1. Chaque information
    garde la trace de sa source.

-   :material-sort-numeric-descending:{ .lg .middle } **Il trie**

    ---

    Chaque faille reçoit une note de 0 à 100 et une priorité de P0 (à corriger sous 24 heures)
    à P3. La note tient compte de ce qui se passe réellement : une faille déjà exploitée par
    des attaquants ne descend jamais sous P1.

-   :material-link-variant:{ .lg .middle } **Il relie la menace à vos équipements**

    ---

    Vous décrivez votre parc dans un simple fichier Excel. ILLWATCH le compare aux failles et
    aux indicateurs, version par version, et ne vous signale que ce qui vous touche.

-   :material-shield-alert:{ .lg .middle } **Il organise la réponse**

    ---

    Une file de tri pour vos analystes, des incidents suivis étape par étape selon la méthode
    du NIST, un historique que personne ne peut modifier, la recherche de traces dans vos
    journaux et le contexte des attaquants (MITRE ATT&CK).

-   :material-share-variant:{ .lg .middle } **Il partage**

    ---

    Il met ses indicateurs à disposition de vos autres outils (SIEM, OpenCTI, MISP) dans les
    formats standards STIX 2.1 et TAXII 2.1, et les exporte en CSV ou JSON.

-   :material-chart-box:{ .lg .middle } **Il mesure et il prouve**

    ---

    Délais de prise en charge et de résolution, tableaux de bord Grafana, et un journal
    d'audit où chaque action reste inscrite : de quoi rendre des comptes au titre de NIS 2 ou
    de DORA.

</div>

![De la source à la décision](assets/schemas/pipeline.svg)

## Par où commencer

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Je veux l'installer**

    ---

    Le guide vous accompagne pas à pas, d'un poste ou d'un serveur vierge jusqu'à une
    plateforme qui collecte, avec les sauvegardes et les mises à jour.

    [:octicons-arrow-right-24: Guide d'installation et d'exploitation](GUIDE_INSTALLATION.md)

-   :material-microsoft-excel:{ .lg .middle } **Je veux décrire mon parc**

    ---

    Téléchargez le modèle Excel depuis l'écran Inventaire, remplissez une ligne par
    équipement, vérifiez l'aperçu, puis importez.

    [:octicons-arrow-right-24: Déclarer votre inventaire](GUIDE_INSTALLATION.md#5-declarer-votre-inventaire-methode-excel)

-   :material-account-group:{ .lg .middle } **Je veux savoir qui fait quoi**

    ---

    Qui peut faire quoi (administrateur, analystes, lecteurs, partenaires), et comment chaque
    fonctionnalité se comporte, avec des exemples concrets.

    [:octicons-arrow-right-24: Manuel fonctionnel](MANUEL_FONCTIONNEL.md)

-   :material-clipboard-check:{ .lg .middle } **Je veux les exigences**

    ---

    Ce que la plateforme doit faire, ce qu'elle fait déjà, ce qui reste à faire, et comment
    on le vérifie.

    [:octicons-arrow-right-24: Cahier des charges](CAHIER_DES_CHARGES.md)

-   :material-compass:{ .lg .middle } **Je veux comprendre le projet**

    ---

    Pourquoi ILLWATCH existe, pour qui, ce qui le distingue des autres outils et où il va
    d'ici 2035.

    [:octicons-arrow-right-24: Vision produit](PRODUCT_VISION.md)

-   :material-code-braces:{ .lg .middle } **Je veux contribuer**

    ---

    Comment le code est organisé, comment préparer votre poste, et les 28 décisions
    d'architecture qui expliquent les choix faits jusqu'ici.

    [:octicons-arrow-right-24: Prise en main](ONBOARDING.md) · [Architecture](ARCHITECTURE.md)

</div>

## Où en est le projet

![Jalons M1 à M11](assets/schemas/jalons.svg)

Le projet avance par jalons. Un jalon n'est considéré comme terminé que lorsque son résultat a
été vérifié sur des données réelles, pas simplement quand le code est écrit.

| Étape | Où nous en sommes au 30/10/2026 |
|---|---|
| **M1 à M6** : socle, flux de menaces, failles, incidents, tableau de bord, chasse | :material-check-circle:{ .iw-ok } vérifiés sur données réelles, version `v0.1.1` publiée |
| **M8** : détection et corrélation | :material-check-circle:{ .iw-ok } terminé le 14/10 : 100 % des cas attendus détectés sur le jeu de test |
| **M9 et M10** : opérations SOC, contexte des attaquants, partage STIX et TAXII | :material-progress-check:{ .iw-wip } livrés et vérifiés en intégration continue, à rejouer sur le poste de test |
| **M7 et M11** : durcissement pour la production, supervision | :material-server-network:{ .iw-wait } livrés ; il manque le serveur européen et sept jours de préproduction |
| **v0.2.0**, première version candidate à la production | :material-flag-outline:{ .iw-wait } dès que M7 et M11 seront clos |

[:material-map-marker-path: Feuille de route](ROADMAP.md){ .md-button }
[:material-file-document-multiple: Rapports et bilans](rapport/index.md){ .md-button }

## À quoi ressemble l'application

<div class="iw-shots" markdown>

<figure markdown>
![Vue d'ensemble](assets/captures/01-vue-ensemble-fr.webp)
<figcaption>La vue d'ensemble : ce qui demande votre attention maintenant.</figcaption>
</figure>

<figure markdown>
![Triage des alertes](assets/captures/02-triage-fr.webp)
<figcaption>Le triage : les alertes rangées par priorité, avec le détail de chaque note.</figcaption>
</figure>

<figure markdown>
![Import de l'inventaire](assets/captures/11c-inventaire-apercu-fr.webp)
<figcaption>L'inventaire : l'aperçu d'un fichier Excel avant de l'importer.</figcaption>
</figure>

<figure markdown>
![Corrélations](assets/captures/10-correlations-fr.webp)
<figcaption>Les corrélations : la menace rapportée à vos propres équipements.</figcaption>
</figure>

</div>

<p class="iw-note">Captures réalisées sur notre environnement de préproduction, avec des données de démonstration fictives.</p>

## Documents de référence

Chaque document existe en deux versions : à lire en ligne sur ce site, ou à télécharger en PDF
mis en page.

<div class="grid cards" markdown>

-   :material-file-pdf-box:{ .lg .middle } **Guide d'installation et d'exploitation**

    ---

    Installer ILLWATCH, décrire votre parc avec Excel, l'utiliser au quotidien depuis
    l'application ou la ligne de commande, l'administrer et le dépanner.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Guide_installation_exploitation_v2.pdf) ·
    [Lire en ligne](GUIDE_INSTALLATION.md)

-   :material-file-pdf-box:{ .lg .middle } **Manuel fonctionnel**

    ---

    Les personnes et les systèmes qui interviennent, leurs droits, chaque fonctionnalité
    expliquée simplement, des journées types et un glossaire.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Manuel_fonctionnel_v2.pdf) ·
    [Lire en ligne](MANUEL_FONCTIONNEL.md)

-   :material-file-pdf-box:{ .lg .middle } **Cahier des charges**

    ---

    Toutes les exigences, numérotées de RF-01 à RF-57, avec leur état réel, les exigences de
    performance et de sécurité mesurées, le modèle de données et les risques.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Cahier_des_charges_v2.pdf) ·
    [Lire en ligne](CAHIER_DES_CHARGES.md)

-   :material-file-pdf-box:{ .lg .middle } **Vision produit**

    ---

    Le problème que nous voulons résoudre, pour qui, notre place face aux autres outils, notre
    modèle open source et le cap jusqu'en 2035.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Vision_produit_v2.pdf) ·
    [Lire en ligne](PRODUCT_VISION.md)

-   :material-file-pdf-box:{ .lg .middle } **Feuille de route**

    ---

    Les onze jalons avec leurs preuves, ce qu'il reste à faire et dans quel ordre, le
    calendrier et la suite après la version 0.2.0.

    [:octicons-download-16: PDF](pdf/ILLWATCH_Feuille_de_route_v2.pdf) ·
    [Lire en ligne](ROADMAP.md)

-   :material-archive:{ .lg .middle } **Documents fondateurs (archives)**

    ---

    Le cahier des charges et la vision de juillet 2026, écrits quand le projet s'appelait
    encore SENTRY. Nous les gardons tels quels, pour l'histoire du projet.

    [:octicons-download-16: Cahier des charges v1.0](pdf/SENTRY_Cahier_des_Charges.pdf) ·
    [Vision v1.0](pdf/CYBERILL-SENTRY-PRODUCT-VISION_3.pdf)

</div>

## Documentation technique

| Document | Pour qui | Ce que vous y trouverez |
|---|---|---|
| [Architecture](ARCHITECTURE.md) | développeurs | comment le code est découpé, comment circulent les données, les grands choix et la sécurité |
| [Exploitation](OPERATIONS.md) | administrateurs | surveiller, sauvegarder, sécuriser, mettre à jour, et toutes les commandes utiles |
| [Environnements](ENVIRONNEMENTS.md) | administrateurs | développement, préproduction, production, et comment passer de l'un à l'autre |
| [Prise en main](ONBOARDING.md) | contributeurs | préparer votre poste, les règles du code, votre première contribution |
| [Décisions d'architecture](adr/README.md) | tout le monde | les 28 décisions importantes, avec leur contexte et leurs conséquences |
| [Journal des versions](changelog.md) | tout le monde | ce qui a changé, version après version |

!!! info "Si deux documents se contredisent"
    Une **décision d'architecture** (ADR) acceptée l'emporte, car elle tranche explicitement
    la question. Vient ensuite le **cahier des charges**, qui fait foi pour le développement,
    puis la **vision produit**. Les PDF d'origine ne sont gardés que pour mémoire. Quand nous
    découvrons un écart, nous le tranchons dans une nouvelle décision écrite, jamais en
    silence dans le code.

<p class="iw-note">Code source : <a href="https://gitlab.com/GodwillFoka/cyberillsec-illwatch">GitLab (dépôt de référence)</a> ·
<a href="https://github.com/GodwillFoka/cyberillsec-illwatch">GitHub (miroir)</a> · image Docker
<code>ghcr.io/godwillfoka/cyberillsec-illwatch</code>. Le projet s'appelait SENTRY jusqu'au 8 octobre 2026.</p>
