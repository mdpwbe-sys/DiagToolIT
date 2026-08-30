# 📚 ARCHITECTURE TECHNIQUE — DIAG-IT-UAA3 SUITE ENTERPRISE

Ce document détaille l'architecture modulaire, les schémas de données, les mécanismes de sécurité et la chaîne de traitement de la suite de diagnostic et d'audit IT **Diag-IT-UAA3**.

---

## 🏛️ 1. Vue d'Ensemble de l'Architecture

La solution fonctionne selon un modèle **monolithique autonome à zéro dépendance binaire** :
- **Moteur d'Audit & Collecte (PowerShell 5.1 / 7+)** : Sonde directement les API Windows, WMI/CIM, Event Logs, Windows Filtering Platform (WFP), Crypto API et registres sans requérir d'agent tiers.
- **Base Locale d'Historique (JSON FIFO)** : Enregistrement rotatif structuré dans `$env:LOCALAPPDATA\DiagIT\history_db.json` (30 runs max).
- **Rendu Visuel & Cockpit Interactif (HTML5 / Three.js)** : Génère un fichier HTML autonome intégrant la scène 3D GPU (Trou Noir Gargantua & Boule de Feu Solaire), la Matrice FOSS 3D, les graphiques temporels et les outils d'export.

```mermaid
graph TD
    subgraph PowerShell Host
        A[Diag-IT-UAA3.ps1] --> B[Collecte Système & WMI]
        A --> C[Audit Réseau & RDP Event Logs]
        A --> D[Crypto API & eID Belgium Store]
        A --> E[Moteur CVE Offline / CVSS 7.0+]
        A --> F[Scoring Heuristique Anomalies]
        A --> G[Benchmark Synthétique Safe]
    end
    subgraph Data & Storage
        B --> H[history_db.json - 30 Runs FIFO]
        E --> I[cveMatchesJson]
        C --> J[networkAuditJson]
        D --> K[belgianAppsJson & Certs]
    end
    subgraph Frontend HUD
        H --> L[Rapport_Diagnostic_UAA3.html]
        I --> L
        J --> L
        K --> L
        L --> M[Three.js Engine 3D]
        L --> N[Export RMM / CSV / JSON]
        L --> O[Impression PDF Pro A4]
    end
```

---

## 📦 2. Description Détaillée des 10 Modules

### Module 1 : Health Check & Historique Temporel
* **Schéma de données** : Enregistre `Timestamp`, `DateLabel`, `HealthScore` (0-100), `FreeDiskGB`, `OkCount`, `WarnCount`, `ErrCount`, `CveCount`, `CpuScore`.
* **Algorithme de rotation** : Conserve glissant les 30 derniers scans pour un poids de fichier < 50 Ko.
* **Score Prédictif** : Détecte les anomalies chroniques et évalue la probabilité de panne dans les 90 jours.

### Module 2 : Scanner de Vulnérabilités Logicielles (CVE)
* **Base offline embarquée** : Cible les logiciels à fort déploiement (Chrome, Firefox, Edge, WinRAR, 7-Zip, PuTTY, VLC, Git, Node.js, Python).
* **Seuil de criticité** : CVSS $\ge$ 7.0 (Haute & Critique) pour concentrer l'action sur les risques exploitables.

### Module 3 : Audit Réseau Avancé & RDP
* **Partages SMB** : Détection des partages locaux hors partages administratifs cachés (`ADMIN$`, `C$`).
* **Matrice de Latence** : Test ICMP/TCP vers la passerelle par défaut, Cloudflare (1.1.1.1), Google (8.8.8.8) et Microsoft 365.
* **Sécurité RDP** : Extraction des connexions distantes réussies (`Event ID 4624 Type 10`) et tentatives d'intrusion (`Event ID 4625`).

### Module 4 : Analyse Disque Intelligente & TreeMap
* **Mesure des zones volumineuses** : `%TEMP%`, `C:\Windows\Temp`, `SoftwareDistribution\Download`, `CrashDumps`.
* **Nettoyage 1-Clic** : Commande PowerShell préconfigurée pour récupérer immédiatement plusieurs gigaoctets.

### Module 5 : Détection Logiciels Métiers Belgique & Crypto API
* **Écosystème ciblé** : Winbooks, Sage (BOB 50, BOB 100), Ciel Compta, Belgium eID Middleware, Isabel 6, Silverfin, Accon, SuperFisc, Octopus.
* **Magasin de Certificats Windows** : Scanne `Cert:\CurrentUser\My` et `Cert:\LocalMachine\My` pour identifier les certificats d'authentification et de signature avec alerte d'expiration sous 30 jours.

### Module 6 : RMM Export & Intégrations
* **Formats supportés** : JSON universel (SIEM/Datto/ConnectWise), CSV d'inventaire technique.
* **Conditions d'alerte** : Déclenchement de tickets d'intervention automatisés en cas d'erreurs critiques.

### Module 7 : Benchmark Réel Non-Invasif
* **Calcul Mathématique Mono-Thread (< 1.5s)** : Calcul de 12 000 nombres premiers pour étalonner la puissance réelle du processeur sans générer d'échauffement thermique.
* **Télémétrie SMART** : Extraction de l'usure résiduelle (`Wear %`), des heures d'activité (`PowerOnHours`) et des erreurs de lecture.

### Module 8 : Audit Sécurité Utilisateurs & Persistance
* **Comptes locaux** : Statut d'activation, politique d'expiration de mot de passe et date de dernière session.
* **Privilèges** : Liste nominative des membres du groupe `Administrateurs`.

### Module 9 : Export Multiformat & Portail Client
* **Feuille de style `@media print` A4** : Structure le rapport pour une impression PDF immédiate et soignée destinée au client final.

### Module 10 : Détection d'Anomalies Heuristiques & Whitelist
* **Modèle de Scoring Heuristique** :
  * Emplacement non approuvé (`%TEMP%`, `Public`) : `+4 pts`
  * Absence de signature numérique valide : `+3 pts`
  * Exécution à la racine du lecteur : `+3 pts`
  * *Alerte active uniquement si Score Total $\ge$ 6*.
* **Whitelist intégrée** : Exclusion automatique des installateurs et outils certifiés (`msiexec`, `vcredist`, `dotnet`, `powershell`, `node`, `code`, `winget`, `update`).

---

## 🔒 3. Sécurité & Droits d'Exécution
* **Élévation UAC** : Redémarrage automatique avec invite d'élévation UAC si le script n'est pas exécuté en Administrateur.
* **Intégrité des Données** : Aucune donnée télémétrique n'est transmise vers des serveurs tiers ; tous les calculs sont strictement locaux au poste.
