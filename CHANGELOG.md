# Journal des Modifications (Changelog)

Toutes les modifications notables apportées au projet **DiagToolIT** sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et ce projet adhère à [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.2.0-alpha] - 2026-08-31

### ✨ Ajouts
* **Analyses disques étendues** : affichage de tous les volumes locaux (fixes et amovibles) et déplacement de la télémétrie SMART détaillée dans l'onglet dédié.
* **Benchmark matériel équilibré** : indices CPU, GPU et RAM, contrôle indirect XMP/EXPO et score global des trois piliers pour repérer les goulots d'étranglement.
* **Mesure CPU stabilisée** : échauffement préalable, cinq passes chronométrées et médiane affichée comme indice unique sur 100.
* **Stress-test GPU visuel optionnel** : réacteur holographique Three.js déterministe en 256×256, profils adaptatifs, PBR instancié, particules shader, post-traitement, vues de diagnostic, médiane FPS, 1 % low, GPU timer et débit géométrique. Le test reste borné à 10 secondes et libère ses ressources WebGL.
* **Test de débit Internet explicite et stabilisé** : mesure de 20 secondes via l'edge Cloudflare (10 s réception + 10 s envoi), quatre flux parallèles, plafond de sécurité d'environ 2,5 Go et statistiques médiane/P10/P90/pic/stabilité. Les échantillons sont horodatés en mémoire puis rejoués avec un délai fixe d'une seconde pendant la mesure grâce à un projectile Three.js déterministe, un resampling stable sur l'axe de progression, un ressort critique et une interpolation fluide à 60 FPS. Le redimensionnement de l'échelle est amorti et le buffer de dessin n'est pas conservé pour éviter les blocages GPU ; une traînée bleue et deux filaments électriques cyan suivent désormais la même polyligne que la sparkline, avec une chaîne amortie qui conserve une légère fuite dans les virages, dans un pool borné. Une légende et des axes Mbps/secondes restent visibles, avec les deux vitesses en haut à gauche. Aucun fichier n'est créé ; les tampons mémoire, requêtes et ressources WebGL sont libérés à la fin.
* **Matrice de latence détaillée** : trois échantillons ICMP par cible pour la passerelle, Cloudflare, Google, Quad9 et Microsoft 365, avec min/moyenne/max, gigue, pertes, réponses, filtres et tris.
* **Instantané réseau anticipé** : les pings des passerelles et des cibles DNS/cloud sont désormais collectés à l'entrée de l'étape Réseau, puis réutilisés par les contrôles DHCP/LAN/DNS et la matrice du rapport pour refléter immédiatement le même état réseau.

### 🎨 Interface, ergonomie & documentation
* **KPI apaisés et cohérents** : les cinq cartes de synthèse centrent désormais leur contenu ; la barre colorée rigide est remplacée par un liseré néon diffus dont l'intensité augmente légèrement au survol.
* **Commandes colorées par intention** : les 18 boutons du dashboard reprennent le même liseré néon discret, avec un accent cohérent par fonction (cyan, vert, mauve, ambre ou rose) qui s'intensifie au survol et à l'état actif.
* **Arbre FOSS plus confortable** : les titres et descriptions de cartes Open Source utilisent un blanc bleuté et un vert adouci, moins agressifs sur le fond sombre, sans réduire la lisibilité.
* **Palette de lecture assagie** : les badges, étiquettes, textes correctifs et cadres de résolution utilisent des teintes mates et des bordures moins saturées ; les scènes et graphiques conservent leurs couleurs de signalisation utiles.
* **Guide dashboard complet** : les 18 modules sont décrits dans le rapport et le README par trois à quatre lignes concrètes : rôle, données collectées, actions et limites locales.

## [0.1.1-alpha] - 2026-08-30

### ✨ Ajouts
* **Mode réseau fermé** : Three.js r128 est désormais fourni dans `vendor/three/`, vérifié par SHA-256 puis injecté directement dans le rapport HTML. Le rendu ne dépend plus de cdnjs et n'effectue aucune requête web automatique.
* **Mise à jour CVE explicite** : l'onglet CVE propose un bouton multilingue avec confirmation qui lance `Update-CveDatabase.ps1` via le protocole local dédié `diagit-cve://`, sans requête HTTP directe depuis le rapport.
* **Protocole CVE durci** : `Register-DiagProtocol.ps1` enregistre une commande locale fixe, sans `%1`, argument URL ni exécution dynamique.
* **Chargement de `modules_config.json` (chantier 1)** : Le moteur `Diag-IT-UAA3-V3.ps1` charge désormais sa configuration depuis `modules_config.json` (via `Diag-ConfigLoader.ps1`) avec lecture stricte `ConvertFrom-Json`, validation des sections requises et **repli sûr** sur les valeurs historiques en cas d'absence/invalidité (aucune erreur silencieuse).
* **Tests Pester de configuration** : `tests/ConfigLoader.Tests.ps1` valide le chargement valide, le comportement avec fichier absent/invalide et le repli par défaut.

### 🐛 Corrections
* **Scores de santé et historique** : le pilier Sécurité reste désormais aligné sur le calcul serveur (plus de faux 100 % lorsque SecureBoot/UAC sont dégradés), le score global conserve la moyenne exacte des cinq piliers et la rétention FIFO locale passe de 30 à 120 diagnostics sans supprimer les archives existantes.
* **Affichage DNS des cartes réseau** : correction de l'extraction .NET des serveurs DNS IPv4 ; les adresses configurées ne sont plus remplacées à tort par « Aucun serveur DNS ».
* **Faux positif antivirus** : l'état Microsoft Defender repose désormais sur `Get-MpComputerStatus`, tandis que les providers tiers sont validés via `productState`; un provider présent mais inactif déclenche une alerte visible dans le journal et le centre de résolution.
* **Courbes du débit réseau** : correction du repère vertical Three.js (les débits élevés remontent bien vers le haut), réinitialisation propre entre réception/envoi et interpolation des traces/projection pour éviter les retours arrière et les à-coups.
* **Langue de bout en bout** : les messages console FR/NL/EN/DE sont centralisés, la langue est conservée lors de l'élévation UAC et le protocole `diagit://run?lang=XX` relaie uniquement les quatre valeurs autorisées jusqu'au nouveau rapport.
* **Crash du lanceur Windows** : `Lancer Diagnostic IT UAA3.bat` ne tente plus une seconde élévation UAC fragile. Le moteur PowerShell reste l'unique responsable de l'élévation, le choix de langue est conservé et toute erreur réelle reste visible avant fermeture.
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
* **Exports Polyvalents** : JSON compatible RMM/SIEM généré localement, inventaire CSV et feuille d'impression PDF A4 épurée, sans transmission automatique.
* **Documentation & Guides** : Spécifications architecturales (`ARCHITECTURE.md`), guide PDF et suite de lanceurs batch.
