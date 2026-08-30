# Journal des Modifications (Changelog)

Toutes les modifications notables apportées au projet **DiagToolIT** sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et ce projet adhère à [Semantic Versioning](https://semver.org/).

---

## [0.1.1-alpha] - 2026-08-30

### ✨ Ajouts
* **Chargement de `modules_config.json` (chantier 1)** : Le moteur `Diag-IT-UAA3-V3.ps1` charge désormais sa configuration depuis `modules_config.json` (via `Diag-ConfigLoader.ps1`) avec lecture stricte `ConvertFrom-Json`, validation des sections requises et **repli sûr** sur les valeurs historiques en cas d'absence/invalidité (aucune erreur silencieuse).
* **Tests Pester de configuration** : `tests/ConfigLoader.Tests.ps1` valide le chargement valide, le comportement avec fichier absent/invalide et le repli par défaut.

### 🐛 Corrections
* **Bug d'extraction de la passerelle IPv4** : `Test-NetConnection -ComputerName 1` / affichage « Passerelle : 1 » corrigé. L'extraction utilise désormais `@(...)` dans le scope du moteur, évitant l'unrolling PowerShell qui tronquait l'adresse au premier caractère. Gère correctement zéro, une ou plusieurs passerelles.
* **Tests Pester de régression passerelle** : `tests/GatewayExtraction.Tests.ps1` couvre les trois cas (aucune / une / plusieurs passerelles).

### 🔧 Interne
* Aucun changement de périmètre fonctionnel ni de format du rapport HTML. Paramètres CLI, compatibilité PowerShell 5.1 et comportement par défaut conservés.

---

## [0.1.0-alpha] - 2026-08-29

### 🌟 Ajouts Majeurs
* **Moteur d'Audit L3 Autonome** : 26 tests système, sécurité, matériel, réseau, spouleur et intégrité.
* **Cockpit Visuel 3D FOSS (Three.js)** : Arbre technologique de 90+ alternatives libres réparties en 18 domaines avec recherche interactive.
* **Score de Santé Prédictif & Trajectoire 3D** : Formule transparente avec décomposition en 5 piliers sectoriels et infobulles détaillées au survol.
* **Scanner de Vulnérabilités CVE** : Détection des applications vulnérables (CVSS $\ge$ 7.0) avec flux de mise à jour `Update-CveDatabase.ps1`.
* **Audit Réseau Avancé & Sockets** : Sélecteur multi-cartes, partages SMB, sessions RDP et cartographie des ports d'écoute TCP.
* **Module Métiers Belgique & Certificats eID** : Détection des suites logicielles belges et alertes d'expiration des certificats numériques.
* **Détecteur d'Anomalies Startup** : Scoring heuristique avec whitelist stricte anti-faux-positifs.
* **Exports Polyvalents** : JSON RMM conforme SIEM, inventaire CSV et feuille d'impression PDF A4 épurée.
* **Documentation & Guides** : Spécifications architecturales (`ARCHITECTURE.md`), guide PDF et suite de lanceurs batch.
