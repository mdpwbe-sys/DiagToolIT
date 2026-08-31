# 🛠️ DiagToolIT — Suite de Diagnostic IT L3, Scanner CVE & Cartographie 3D FOSS

<div align="center">

[![Release](https://img.shields.io/badge/release-v0.2.0--alpha-38bdf8.svg?style=for-the-badge)](https://github.com/mdpwbe-sys/DiagToolIT/releases)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg?style=for-the-badge&logo=powershell)](https://microsoft.com/powershell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![Three.js](https://img.shields.io/badge/Visuals-Three.js%20WebGL-black.svg?style=for-the-badge&logo=three.js)](https://threejs.org/)
[![i18n](https://img.shields.io/badge/i18n-4%20Languages%20(FR%20NL%20EN%20DE)-emerald.svg?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-emerald.svg?style=for-the-badge)](LICENSE)

**Suite d'ingénierie système autonome, d'audit prédictif, de remédiation automatisée et de gestion logicielle pour les techniciens support Niveau 3, administrateurs système et prestataires MSP.**

[🚀 Démarrage Rapide](#-démarrage-rapide) •
[📋 Les 18 Menus & Modules](#-les-18-menus--modules-détaillés) •
[🌐 Moteur Multilingue (4 Langues)](#-moteur-multilingue-4-langues) •
[⚡ Protocole 1-Clic `diagit://`](#-protocole-windows-1-clic-diagit) •
[🏛️ Services nationaux & eID](#-services-nationaux-eid--logiciels-métiers) •
[📊 Score de Santé Prédictif](#-score-de-santé-prédictif) •
[📦 Exports locaux](#-exports-locaux--remise-client) •
[⚙️ CLI & Automatisation](#-options-en-ligne-de-commande-cli)

</div>

---

## 🌟 Présentation Générale

**DiagToolIT** est une console d'ingénierie système conçue pour automatiser l'intégralité du cycle de diagnostic matériel, réseau, applicatif, sécuritaire et prédictif des postes clients sous **Windows 10, Windows 11 et Windows Server**.

Développé selon le **Référentiel Méthodologique IT Niveau 3 (Observer ➔ Tester ➔ Corriger ➔ Valider ➔ Expliquer)**, DiagToolIT fournit un cockpit cybernétique interactif ultra-rapide généré localement en HTML5/Three.js avec zéro dépendance externe.

### 💎 Points Forts & Différenciateurs Majeurs :
* **⚡ 100% Autonome & Zéro Dépendance Distante au Rendu** : Exécution native en PowerShell 5.1/7+ sans agent résiduel ni compte cloud. Three.js r128 est vérifié puis intégré au rapport HTML ; le navigateur ne télécharge aucune bibliothèque au démarrage.
* **🌐 Moteur d'Internationalisation Réactif (4 Langues)** : Bascule instantanée entre 🇫🇷 Français, 🇳🇱 Nederlands (Belgique/Pays-Bas), 🇬🇧 English et 🇩🇪 Deutsch.
* **⚡ Protocole URL Windows 1-Clic (`diagit://run?lang=XX`)** : Relancez l'analyse dans la langue choisie depuis le navigateur (Opera, Chrome, Edge, Firefox) avec élévation automatique Administrateur.
* **🛡️ Scanner de Vulnérabilités CVE (CVSS $\ge$ 7.0)** : Détection proactive des failles critiques sur les logiciels installés avec commandes de patch Winget en 1 clic.
* **📈 Score de Santé Prédictif & Historique Glissant** : Calcul mathématique pondéré sur 5 piliers sectoriels et rétention FIFO des 120 derniers diagnostics en base JSON locale.
* **🏛️ Services nationaux, eID & logiciels métiers** : Catalogue par pays (Belgique, France, UK/US, Allemagne, Espagne, Italie, Portugal), services publics vérifiés et inventaire local de certificats séparé.
* **🌌 Applications libres 3D (Three.js WebGL)** : Cartographie 3D de 90+ alternatives libres avec shaders cosmiques (Trou Noir gravitationnel & Soleil à plasma) et générateur de scripts Winget.
* **📦 Exports locaux, sans télémétrie sortante** : Génération dans le navigateur de fichiers JSON compatibles RMM, d'un inventaire CSV et d'une impression PDF A4, sans webhook ni envoi automatique.

### 🔒 Confidentialité et réseau fermé

DiagToolIT n'intègre aucun tracker, service analytique, compte cloud ou envoi automatique de rapport. Le rapport HTML généré embarque son moteur Three.js et n'effectue aucune requête HTTP automatique. Les liens web et commandes Winget ne s'activent qu'à l'initiative de l'utilisateur.

Le diagnostic PowerShell effectue volontairement des sondes ICMP limitées (trois échantillons par cible vers les passerelles locales, Cloudflare, Google, Quad9 et Microsoft 365) dès l'entrée dans l'étape Réseau. Le même instantané alimente ensuite les contrôles DHCP/IP, LAN/WAN/DNS et la matrice affichée dans le rapport : min/moyenne/max, gigue et pertes restent cohérents. Ces sondes ne transmettent ni inventaire ni contenu du rapport. Le bouton optionnel **Test de débit Internet** lance explicitement une mesure de 20 secondes à quatre flux vers l'edge Cloudflare, après échauffement et avec un plafond de sécurité d'environ 2,5 Go (aucun appel au chargement). Les données reçues restent dans des tampons mémoire libérés après le test : aucun fichier de téléchargement n'est créé. Les résultats peuvent être traités par Cloudflare selon sa politique du service. `Update-CveDatabase.ps1` contacte l'API OSV uniquement lorsqu'il est lancé explicitement.

---

## ⚡ Démarrage Rapide

### 1. En 1-Clic via le Lanceur Batch
Double-cliquez sur :
```text
📁 Lancer Diagnostic IT UAA3.bat
```
*Après le choix de la langue, le lanceur enregistre automatiquement (ou actualise) les raccourcis système `diagit://` et `diagit-cve://` nécessaires au dashboard, puis déclenche l'élévation Administrateur (UAC), audite l'ensemble du système en ~35 secondes et ouvre instantanément le rapport interactif.*

### 2. En Ligne de Commande PowerShell
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Diag-IT-UAA3-V3.ps1
```

### 3. Mode Silencieux / Export Personnalisé
```powershell
.\Diag-IT-UAA3-V3.ps1 -NoElevate -OutputPath "C:\Rapports\DiagIT"
```

---

## 📋 Les 18 Menus & Modules Détaillés

Le tableau de bord est organisé en une grille cybernétique stricte de **18 menus et boutons d'action** :

| # | Onglet / Bouton | Description & Capacités Techniques |
| :-: | :--- | :--- |
| **1** | **📊 Bilan & Pannes** | Centralise et priorise les alertes actives.<br>Chaque carte décrit constat, correction et contexte technique.<br>Les filtres isolent Réseau, matériel, système, sécurité ou logiciel. |
| **2** | **📈 Santé & Tendances** | Calcule un score prédictif sur cinq piliers d'audit.<br>Expose les pondérations qui expliquent le score.<br>Compare l'exécution aux 120 diagnostics locaux conservés en FIFO. |
| **3** | **🔴 Vulnérabilités CVE** | Détecte les logiciels concernés par les CVE à sévérité élevée.<br>Affiche score, description et version locale observée.<br>Propose une mise à jour Winget ou une actualisation explicite de la base. |
| **4** | **🌐 Audit Réseau & RDP** | Audite carte, passerelle, DNS, RDP, SMB, MTU et Winsock.<br>La matrice conserve min/moyenne/max, gigue et pertes par cible.<br>Le test de débit volontaire mesure réception et envoi sans écrire de fichier. |
| **5** | **💾 Analyses Disques** | Recense les volumes, l'espace libre et les dossiers volumineux.<br>Présente santé SMART, usure, température, heures et erreurs disponibles.<br>Calcule les caches temporaires et fournit une purge explicitement déclenchée. |
| **6** | **🚀 Démarrage & Startup** | Évalue Fast Startup, hibernation, alimentation et throttling CPU.<br>Liste les programmes au démarrage avec emplacement et heuristique de risque.<br>Les actions restent explicites, relisibles et copiables. |
| **7** | **Services nationaux, eID & logiciels métiers** | Catalogue adaptatif piloté par une liste blanche (BE, FR, UK/US, DE, ES, IT, PT).<br>Chaque pays propose 20 services publics HTTPS, contrôlés contre des domaines institutionnels, plus un guide d'identité numérique/certificats officiel.<br>Les références éditeur et l'inventaire local Windows restent séparés : aucun certificat détecté ne vaut agrément. |
| **8** | **⚡ Benchmarks CPU, GPU & RAM** | Mesure le CPU après échauffement, sur cinq passes et via une médiane stable.<br>Estime GPU et RAM, avec contrôle indirect XMP/EXPO.<br>Le stress-test GPU optionnel Three.js dure 10 s et restitue FPS, 1 % low, timer GPU et débit géométrique. |
| **9** | **👤 Sécurité & Anomalies** | Inventorie administrateurs locaux, comptes Windows et âge des mots de passe.<br>Repère les processus depuis `%TEMP%` ou `Public` et les ports TCP à l'écoute.<br>Les résultats guident une vérification humaine sans bloquer ni supprimer automatiquement. |
| **10** | **🌐 Applications libres 3D** | Visualise plus de 90 outils libres dans 18 thématiques professionnelles.<br>Chaque tiroir relie alternative propriétaire, description, site officiel et commande Winget.<br>Le rendu Three.js est fourni localement, sans dépendance CDN. |
| **11** | **📋 Tous les Tests (26)** | Présente chaque sonde Niveau 3 avec son statut et ses métriques brutes.<br>Conserve le contexte et l'horodatage de l'exécution.<br>Les filtres permettent une revue ciblée sans masquer les alertes actives. |
| **12** | **📦 Profils Winget** | Regroupe les outils par profil métier : développement, administration, création, sécurité ou études.<br>Chaque profil compose des commandes Winget à relire puis copier.<br>Aucune installation n'est déclenchée automatiquement. |
| **13** | **⌨️ Raccourcis Pro** | Rassemble MMC, services, disques, registre et autres consoles Windows.<br>Les cartes compactes proposent une ouverture ou une copie contrôlée.<br>PowerToys est documenté avec liens officiels et commande Winget. |
| **14** | **📦 Export local & Client** | Produit localement un JSON RMM/ITSM, un inventaire CSV et un résumé client.<br>Les données restent sur le poste jusqu'à une transmission volontaire.<br>Les formats facilitent archivage, support et suivi d'intervention. |
| **15** | **📖 Documentation & Guide** | Décrit les 18 modules, leur collecte et leurs limites.<br>Inclut une boîte à outils PowerShell pour la maintenance courante.<br>Renvoie au README, à l'architecture et aux règles de sécurité. |
| **16** | **⚡ RELANCER DIAG (.BAT)** | Relance via `diagit://run?lang=XX` avec FR, NL, EN ou DE.<br>Le protocole applique une liste blanche et n'accepte aucun argument arbitraire.<br>Le nouveau rapport conserve la langue active. |
| **17** | **🌀 LOGS / ARCHIVE** | Affiche la chronologie locale de `DiagIT\history_db.json`.<br>Chaque exécution conserve date, machine, score, alertes, espace disque et CVE.<br>La rétention garde au plus 120 diagnostics en FIFO. |
| **18** | **🖨️ IMPRIMER** | Prépare un bilan exécutif, l'onglet actif ou le rapport complet.<br>Le mode synthétique cible la décision ; le complet conserve les détails techniques.<br>L'impression réutilise le rapport local sans publication en ligne. |

---

## 🌐 Moteur Multilingue (4 Langues)

DiagToolIT intègre un sélecteur déroulant cybernétique dans l'en-tête permettant une **traduction instantanée sans rechargement de page** :

1. 🇫🇷 **Français (FR)** : Référentiel complet en français (Belgique, France, Suisse, International).
2. 🇳🇱 **Nederlands (NL)** : Traduction complète pour le marché belge flamand et les Pays-Bas.
3. 🇬🇧 **English (EN)** : Terminologie technique internationale pour équipes DevOps et SysAdmins.
4. 🇩🇪 **Deutsch (DE)** : Support officiel pour la communauté germanophone de Belgique et la zone DACH.

---

## ⚡ Protocoles Windows 1-Clic (`diagit://` et `diagit-cve://`)

Le lanceur `Lancer Diagnostic IT UAA3.bat` exécute automatiquement cette étape après le choix de la langue. Pour l'activer manuellement ou la réparer, exécutez :

```powershell
.\Register-DiagProtocol.ps1
```

Ce script enregistre deux protocoles locaux dans le profil Windows courant :

* **Clés de registre** : `HKCU:\Software\Classes\diagit` et `HKCU:\Software\Classes\diagit-cve` (profil de l'utilisateur courant uniquement).
* **`diagit://run?lang=XX`** : relance le moteur de diagnostic local dans une langue strictement validée (FR/NL/EN/DE).
* **`diagit-cve://update`** : lance uniquement `Update-CveDatabase.ps1 -Interactive` après confirmation dans le rapport.
* **Sécurité** : les commandes enregistrées utilisent des chemins locaux fixes et n'acceptent aucun argument provenant de l'URL.

---

## 🏛️ Services nationaux, eID & logiciels métiers

L'onglet **Services nationaux, eID & logiciels métiers** possède un sélecteur national strictement limité à `BE`, `FR`, `UK/US`, `DE`, `ES`, `IT` et `PT`. Il sépare explicitement les solutions commerciales des services publics : une référence éditeur n'est jamais présentée comme un agrément gouvernemental.

Pour chaque pays, la première zone fournit exactement **20 liens HTTPS** vers des services institutionnels, organisés par usage. Les URL sont filtrées au rendu par une liste blanche de domaines gouvernementaux ou publics propre au pays sélectionné ; un lien hors liste n’est pas affiché. La fiche adjacente explique le mécanisme d’identité/certificats national (eID/CSAM, FranceConnect, GOV.UK One Login, BundID, Cl@ve, SPID/CIE ou Autenticação.gov) sans prétendre vérifier sa validité sur le poste.

* **🇧🇪 Belgique — portails officiels** : Belgium e-ID Middleware, CSAM (identité, mandats et accès), MyMinfin, Intervat, Biztax et e-Deposit/Centrale des bilans (BNB).
* **🇧🇪 Belgique — références métier** : Winbooks, Sage BOB 50/100, Isabel 6 Multi-Banking, Silverfin, Accon, SuperFisc et Octopus ; la fiche affiche le lien de l'éditeur et le statut détecté sur le poste.
* **🇫🇷 France** : impots.gouv.fr et Net-entreprises (portails officiels), complétés par Sage 50 France et Cegid (références éditeur).
* **🇬🇧 / 🇺🇸 International** : HMRC Online Services et Companies House (portails officiels), complétés par Xero UK et Sage Accounting UK.
* **🇩🇪 Allemagne** : ELSTER (portail officiel), DATEV et Lexware (références métier).
* **🇪🇸 Espagne** : Agencia Tributaria et SII/IVA (portails officiels), complétés par Sage 50 España et Holded.
* **🇮🇹 Italie** : Agenzia delle Entrate et Fatture e Corrispettivi (portails officiels), complétés par TeamSystem et Zucchetti.
* **🇵🇹 Portugal** : Portal das Finanças et e-Fatura (portails officiels), complétés par PRIMAVERA et PHC CS.

Les services officiels couvrent notamment MyMinfin et CSAM en Belgique, Service-Public/FranceConnect en France, GOV.UK/USA.gov, BundID/ELSTER, Cl@ve/Agencia Tributaria, SPID/Agenzia delle Entrate et Autenticação.gov/Portal das Finanças. La détection locale (installé/non installé, version) reste indépendante de ces fiches publiques.

### 🔐 Surveillance des Certificats Numériques :
* Détection automatique des certificats stockés dans `Cert:\CurrentUser\My` et `Cert:\LocalMachine\My`.
* Calcul automatique du compte à rebours d'expiration et alertes proactives pour les certificats arrivant à échéance à $\le 30\text{ jours}$ ou $\le 7\text{ jours}$.
* Cette télémétrie est un inventaire local : elle ne valide ni une eID, ni un certificat de signature, ni l'accès à un portail national.

---

## 📊 Score de Santé Prédictif

L'indice global de santé est calculé selon un algorithme mathématique strict combinant les résultats des tests et les pénalités de sécurité :

$$\text{Health Score} = \left[ \frac{\text{OK} \times 1.0 + \text{WARN} \times 0.5}{\text{Total des Tests}} \right] \times 100 - (\text{CVE} \times 5)$$

### 🏛️ Les 5 Piliers d'Audit Évalués :
1. **🛡️ Sécurité & Intégrité** : TPM 2.0, SecureBoot, BitLocker, UAC, Certificats eID, Fautes CVE critiques.
2. **⚡ Performance & Énergie** : Horloge CPU réelle vs nominale, Thermal Throttling, Plan d'alimentation actif.
3. **💾 Stockage & Disques** : Fiabilité SMART, Espace libre partition système `C:`, Caches temporaires $> 2\text{ Go}$.
4. **🌐 Connectivité & Réseau** : Connectivité Passerelle, Latence DNS, Fichier Hosts sain, Ports d'écoute non exposés `0.0.0.0`.
5. **🖥️ Stabilité Système & OS** : Spouleur d'impression, Analyse des Crash Dumps BSOD, Processus suspects au démarrage.

---

## 📦 Exports locaux & Remise client

DiagToolIT prépare localement des fichiers que l'utilisateur peut ensuite remettre à un client ou importer lui-même dans sa chaîne MSP/ITSM :
* **JSON compatible RMM** : Fichier JSON complet et normalisé, téléchargé localement, prêt pour une importation manuelle dans Datto RMM, NinjaOne, N-central, ConnectWise Automate, Microsoft Intune ou GLPI.
* **Inventaire CSV** : Export tabulaire complet de tous les indicateurs matériels, logiciels, réseau et sécurité.
* **Impression Pro A4 (PDF)** : Mise en page vectorielle haute fidélité optimisée pour impression ou enregistrement PDF direct.

Ces actions créent uniquement des fichiers sur le poste à la demande de l'utilisateur. Le produit n'envoie aucun rapport vers un webhook, un serveur RMM ou un service cloud.

---

## ⚙️ Options en Ligne de Commande (CLI)

```powershell
# Exécution standard avec auto-élévation
.\Diag-IT-UAA3-V3.ps1

# Exécution en mode lecture seule (sans demande d'élévation UAC)
.\Diag-IT-UAA3-V3.ps1 -NoElevate

# Spécifier un dossier de sortie personnalisé pour le rapport HTML
.\Diag-IT-UAA3-V3.ps1 -OutputPath "C:\Rapports\DiagIT"

# Exécution automatisée sans historique, ouverture du navigateur ni pause finale
.\Diag-IT-UAA3-V3.ps1 -NoElevate -NoHistory -NoOpen -NonInteractive -OutputPath "$env:TEMP\DiagToolIT"

# Mettre à jour la base locale de vulnérabilités CVE
.\Update-CveDatabase.ps1

# Activer une fois les boutons locaux du rapport (diagnostic + mise à jour CVE)
.\Register-DiagProtocol.ps1

# Installer la tâche planifiée de mise à jour CVE automatique (hebdomadaire)
.\Update-CveDatabase.ps1 -InstallScheduler

# Tester spécifiquement les alertes d'expiration des certificats eID
.\Test-EidCertAlert.ps1
```

---

## 📂 Architecture du Projet

```
DiagToolIT/
├── .github/
│   ├── workflows/ci.yml         # CI Validation syntaxe PowerShell & AST
│   └── ISSUE_TEMPLATE/          # Templates de bugs et suggestions
├── Lancer Diagnostic IT UAA3.bat # Lanceur rapide avec auto-élévation UAC
├── Run-DiagElevated.bat         # Wrapper fail-safe pour protocole diagit://
├── Diag-IT-UAA3-V3.ps1          # Moteur principal de diagnostic & génération de rapport
├── Diag-IT-UAA3-V3-FULL.ps1     # Point d'entrée de compatibilité vers le moteur principal
├── Update-CveDatabase.ps1       # Synchroniseur de flux CVE & tâche planifiée
├── Test-EidCertAlert.ps1        # Module d'audit dédié certificats eID
├── Register-DiagProtocol.ps1    # Script d'enregistrement du protocole diagit://
├── tests/                       # Contrats Pester et rapport HTML synthétique
├── modules_config.json          # Configuration des seuils, whitelists et modules
├── Diag-ConfigLoader.ps1        # Chargeur strict de modules_config.json (repli sûr, erreur explicite)
├── vendor/three/                # Three.js r128 local, licence MIT et empreinte SHA-256
├── ARCHITECTURE.md              # Spécifications d'architecture technique L3
├── CONTRIBUTING.md              # Guide de contribution
├── SECURITY.md                  # Politique de sécurité et signalement de vulnérabilités
├── CHANGELOG.md                 # Historique des versions
└── LICENSE                      # Licence MIT
```

Les rapports produits sont des artefacts locaux potentiellement sensibles. Ne les ajoutez pas à Git; utilisez `tests/New-SyntheticReport.ps1` pour les tests d'interface et les démonstrations reproductibles.

### 🔧 Correctifs récents (v0.2.0-alpha)
* **Chargement `modules_config.json`** : Le moteur lit désormais sa configuration via `Diag-ConfigLoader.ps1` (repli sûr sur les valeurs par défaut en cas d'absence/invalidité, aucune erreur silencieuse). Voir `ARCHITECTURE.md` § Module 11.
* **Extraction passerelle IPv4** : Correction du bug affichant « Passerelle : 1 » (`Test-NetConnection -ComputerName 1`). L'adresse complète est désormais extraite via `@(...)` dans le scope du moteur, gérant zéro / une / plusieurs passerelles. Voir `ARCHITECTURE.md` § 2.1.

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Consultez le fichier [`LICENSE`](LICENSE) pour plus d'informations.
