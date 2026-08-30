# 🛠️ DiagToolIT — Suite de Diagnostic IT L3, Scanner CVE & Cartographie 3D FOSS

<div align="center">

[![Release](https://img.shields.io/badge/release-v0.1.0--alpha-38bdf8.svg?style=for-the-badge)](https://github.com/mdpwbe-sys/DiagToolIT/releases)
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
[🏛️ Logiciels Métiers & eID](#-logiciels-métiers-étatiques--certificats-eid) •
[📊 Score de Santé Prédictif](#-score-de-santé-prédictif) •
[🔗 Intégrations RMM & Export](#-intégrations-rmm--export-client) •
[⚙️ CLI & Automatisation](#-options-en-ligne-de-commande-cli)

</div>

---

## 🌟 Présentation Générale

**DiagToolIT** est une console d'ingénierie système conçue pour automatiser l'intégralité du cycle de diagnostic matériel, réseau, applicatif, sécuritaire et prédictif des postes clients sous **Windows 10, Windows 11 et Windows Server**.

Développé selon le **Référentiel Méthodologique IT Niveau 3 (Observer ➔ Tester ➔ Corriger ➔ Valider ➔ Expliquer)**, DiagToolIT fournit un cockpit cybernétique interactif ultra-rapide généré localement en HTML5/Three.js avec zéro dépendance externe.

### 💎 Points Forts & Différenciateurs Majeurs :
* **⚡ 100% Autonome & Zéro Dépendance** : Exécution native en PowerShell 5.1/7+ sans agent résiduel, sans compte cloud obligatoire et 100% fonctionnel hors-ligne.
* **🌐 Moteur d'Internationalisation Réactif (4 Langues)** : Bascule instantanée entre 🇫🇷 Français, 🇳🇱 Nederlands (Belgique/Pays-Bas), 🇬🇧 English et 🇩🇪 Deutsch.
* **⚡ Protocole URL Windows 1-Clic (`diagit://run`)** : Relancez l'analyse directement depuis le navigateur (Opera, Chrome, Edge, Firefox) avec élévation automatique Administrateur.
* **🛡️ Scanner de Vulnérabilités CVE (CVSS $\ge$ 7.0)** : Détection proactive des failles critiques sur les logiciels installés avec commandes de patch Winget en 1 clic.
* **📈 Score de Santé Prédictif & Historique Glissant** : Calcul mathématique pondéré sur 5 piliers sectoriels et rétention FIFO des 30 derniers diagnostics en base JSON locale.
* **🏛️ Écosystème Métier & Certificats eID Adaptatifs** : Détection des suites logicielles par pays (Belgique, France, UK/US, Allemagne, Espagne, Italie, Portugal) et audit complet des certificats d'authentification/signature eID.
* **🌌 Univers 3D FOSS Interactif (Three.js WebGL)** : Cartographie 3D de 90+ alternatives libres avec shaders cosmiques (Trou Noir gravitationnel & Soleil à plasma) et générateur de scripts Winget.
* **🔗 Intégrations RMM & Télémétrie IT** : Export JSON conforme Datto, NinjaOne, N-central, ConnectWise, inventaire CSV et impression PDF A4 pro.

---

## ⚡ Démarrage Rapide

### 1. En 1-Clic via le Lanceur Batch
Double-cliquez sur :
```text
📁 Lancer Diagnostic IT UAA3.bat
```
*Le script déclenche l'élévation Administrateur (UAC), audite l'ensemble du système en ~35 secondes et ouvre instantanément le rapport interactif.*

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
| **1** | **📊 Bilan & Pannes** | Synthèse des anomalies détectées, fiches de résolution interactives, commandes PowerShell correctives copiables en 1 clic, filtres instantanés (Réseau, Hardware, Système, Sécurité, Logiciel). |
| **2** | **📈 Santé & Tendances** | Score global sur 100, jauge radar des 5 piliers d'intégrité, graphique d'évolution historique des 30 dernières exécutions et recommandations de maintenance préventive. |
| **3** | **🔴 Vulnérabilités CVE** | Scanner de vulnérabilités logicielles (CVSS $\ge$ 7.0), affichage des CVE actives avec descriptions détaillées, boutons de mise à jour Winget 1-clic et synchroniseur de base CVE. |
| **4** | **🌐 Audit Réseau & RDP** | Sélecteur dynamique de carte réseau (.NET), ping en direct passerelle/DNS/Internet, statut RDP (Port 3389, NLA), partages SMB actifs, MTU, configuration DNS et Winsock. |
| **5** | **💾 Analyse Disque** | Télémétrie SMART SSD/NVMe (taux d'usure, température, heures de vol, erreurs), arborescence TreeSize des dossiers volumineux, calcul des caches temporaires et purge 1-clic. |
| **6** | **🚀 Démarrage & Startup** | Analyse de l'impact au démarrage (Fast Startup, hibernation), détection du Thermal Throttling CPU, audit du plan d'alimentation, tableau interactif des programmes au démarrage avec filtrage heuristique. |
| **7** | **🇧🇪 Logiciels Métiers & eID** | Catalogue adaptatif selon le pays sélectionné (BE, FR, UK/US, DE, ES, IT, PT), statut installé/non installé avec fiches descriptives, magasin de certificats eID avec jours restants. |
| **8** | **⚡ Benchmarks & SMART** | Benchmark synthétique Single-Core CPU en temps réel (millions d'opérations/s), positionnement parmi les gammes matérielles réelles et spécifications d'horloge. |
| **9** | **👤 Sécurité & Anomalies** | Audit des membres du groupe Administrateurs locaux, inventaire des comptes utilisateurs Windows, âge des mots de passe, détection des processus suspects exécutés depuis `%TEMP%` ou `Public`, cartographie des ports d'écoute TCP. |
| **10** | **🌐 Arbre 3D FOSS** | Visualiseur WebGL Three.js immersif de 90+ outils Open Source classés en 18 thématiques professionnelles, tiroirs d'applications, alternatives propriétaires et générateur de packs Winget. |
| **11** | **📋 Tous les Tests (26)** | Journal exhaustif des 26 sondes de contrôle Niveau 3 avec statut détaillé (OK, Avertissement, Panne), métriques brutes et horodatages. |
| **12** | **📦 Profils Winget** | 12 profils de déploiement logiciel par métier (Développeur Web, SysAdmin/DevOps, Bureautique Pro, Multimédia/Graphisme, Cybersécurité, Étudiant IT, etc.). |
| **13** | **⌨️ Raccourcis Pro** | Console de lancement rapide des utilitaires Windows d'administration (MMC, Gestionnaire de disques, Services, Éditeur de registre, God Mode, Moniteur de ressources). |
| **14** | **🔗 Export RMM & Client** | Génération de payloads télémétriques JSON standardisés pour plateformes RMM/ITSM, export d'inventaire complet au format CSV et résumé pour remise client. |
| **15** | **📖 Documentation & Guide** | Guide technique complet, référentiel méthodologique L3, cheat-sheet des commandes PowerShell de maintenance et architecture interne de la suite. |
| **16** | **⚡ RELANCER DIAG (.BAT)** | Déclencheur 1-clic du protocole URL `diagit://run` pour réexécuter le diagnostic en arrière-plan sans quitter la page ni fermer l'onglet du navigateur. |
| **17** | **🔄 ACTUALISER** | Rafraîchissement instantané des données de la vue sans réinitialiser vos filtres. |
| **18** | **🖨️ IMPRIMER** | Modal d'impression professionnelle avec choix entre le Bilan Exécutif Synthétique (1 page), l'Onglet Actif ou le Rapport Technique Intégral. |

---

## 🌐 Moteur Multilingue (4 Langues)

DiagToolIT intègre un sélecteur déroulant cybernétique dans l'en-tête permettant une **traduction instantanée sans rechargement de page** :

1. 🇫🇷 **Français (FR)** : Référentiel complet en français (Belgique, France, Suisse, International).
2. 🇳🇱 **Nederlands (NL)** : Traduction complète pour le marché belge flamand et les Pays-Bas.
3. 🇬🇧 **English (EN)** : Terminologie technique internationale pour équipes DevOps et SysAdmins.
4. 🇩🇪 **Deutsch (DE)** : Support officiel pour la communauté germanophone de Belgique et la zone DACH.

---

## ⚡ Protocole Windows 1-Clic (`diagit://`)

Pour permettre le lancement du diagnostic directement depuis n'importe quel navigateur (Opera, Chrome, Edge, Firefox, Brave) sans blocage de sécurité ni permission de presse-papiers, DiagToolIT enregistre automatiquement un protocole URL personnalisé dans le registre Windows de l'utilisateur :

* **Clé de registre** : `HKCU:\Software\Classes\diagit`
* **Exécution** : `Run-DiagElevated.bat`
* **Mécanisme Web** : Déclenchement via un lien DOM invisible non bloquant, garantissant la stabilité totale de l'onglet actif.

---

## 🏛️ Logiciels Métiers, Étatiques & Certificats eID

L'onglet **Logiciels Belgique & Métiers** s'adapte dynamiquement à la langue et au pays sélectionné :

* **🇧🇪 Belgique** : Belgium e-ID Middleware (v5.1+), Winbooks Classic/Web, Sage BOB 50/100, Isabel 6 Multi-Banking, Silverfin Connector, Accon Bilans BNB, SuperFisc, Octopus Accountancy.
* **🇫🇷 France** : FranceConnect / eIDAS Agent, Cegid Expert/Quadra, Sage 100cloud, EBP Comptabilité, Chorus Pro, DGFIP Télé-déclarations.
* **🇬🇧 / 🇺🇸 International** : Gov.uk Verify, Intuit QuickBooks, Xero Cloud, Sage Business Cloud, Stripe Gateway, Companies House API.
* **🇩🇪 Allemagne** : AusweisApp2 (eID Bund), DATEV Unternehmen Online, SAP Business One, Lexware Buchhaltung, ELSTER Steuer.
* **🇪🇸 Espagne** : DNIe / FNMT Autenticación, Facturae Portal, ContaPlus, A3software, Sede Electrónica AEAT.
* **🇮🇹 Italie** : CIE Middleware / SPID, FatturaPA SDI, Zucchetti Omnia, TeamSystem, Entratel / Desktop Telematico.
* **🇵🇹 Portugal** : Autenticação.gov (Cartão de Cidadão), Primavera BSS, PHC Software, Portal das Finanças (AT SAF-T).

### 🔐 Surveillance des Certificats Numériques :
* Détection automatique des certificats stockés dans `Cert:\CurrentUser\My` et `Cert:\LocalMachine\My`.
* Surveillance des autorités officielles (*Citizen CA, BOSA, Fedict, eID National*).
* Calcul automatique du compte à rebours d'expiration et alertes proactives pour les certificats arrivant à échéance à $\le 30\text{ jours}$ ou $\le 7\text{ jours}$.

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

## 🔗 Intégrations RMM & Export Client

DiagToolIT s'intègre directement dans votre chaîne d'outils MSP et ITSM :
* **JSON RMM Télémétrie** : Fichier JSON complet et normalisé prêt pour ingestion dans les agents RMM (Datto RMM, NinjaOne, N-central, ConnectWise Automate, Microsoft Intune, GLPI).
* **Inventaire CSV** : Export tabulaire complet de tous les indicateurs matériels, logiciels, réseau et sécurité.
* **Impression Pro A4 (PDF)** : Mise en page vectorielle haute fidélité optimisée pour impression ou enregistrement PDF direct.

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
├── ARCHITECTURE.md              # Spécifications d'architecture technique L3
├── CONTRIBUTING.md              # Guide de contribution
├── SECURITY.md                  # Politique de sécurité et signalement de vulnérabilités
├── CHANGELOG.md                 # Historique des versions
└── LICENSE                      # Licence MIT
```

Les rapports produits sont des artefacts locaux potentiellement sensibles. Ne les ajoutez pas à Git; utilisez `tests/New-SyntheticReport.ps1` pour les tests d'interface et les démonstrations reproductibles.

### 🔧 Correctifs récents (v0.1.1-alpha)
* **Chargement `modules_config.json`** : Le moteur lit désormais sa configuration via `Diag-ConfigLoader.ps1` (repli sûr sur les valeurs par défaut en cas d'absence/invalidité, aucune erreur silencieuse). Voir `ARCHITECTURE.md` § Module 11.
* **Extraction passerelle IPv4** : Correction du bug affichant « Passerelle : 1 » (`Test-NetConnection -ComputerName 1`). L'adresse complète est désormais extraite via `@(...)` dans le scope du moteur, gérant zéro / une / plusieurs passerelles. Voir `ARCHITECTURE.md` § 2.1.

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Consultez le fichier [`LICENSE`](LICENSE) pour plus d'informations.
