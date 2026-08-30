# Guide de Contribution à DiagToolIT

Merci de votre intérêt pour **DiagToolIT** ! Ce document détaille les bonnes pratiques pour contribuer au projet.

---

## 📜 Principes Directeurs
1. **Zéro Dépendance Externe Lourde** : Les scripts PowerShell doivent pouvoir s'exécuter sur un Windows 10/11 vierge avec PowerShell 5.1+.
2. **Robustesse & Gestion d'Erreurs** : Tout appel WMI/CIM ou système doit être encapsulé dans un `try { ... } catch { ... }` avec `-ErrorAction SilentlyContinue` afin de ne jamais interrompre le diagnostic global.
3. **Encodage & AST** : Tous les scripts `.ps1` doivent impérativement être enregistrés en **UTF-8 avec BOM (`utf-8-sig`)** pour préserver la compatibilité des commentaires et caractères accentués sur les consoles PowerShell 5.1.
4. **Rapport Autonome** : Le fichier HTML généré doit rester 100% autonome et visualisable hors-ligne sans connexion Internet.

---

## 🛠️ Processus de Développement

1. **Forkez** le dépôt et créez une branche dédiée :
   ```bash
   git checkout -b feature/amelioration-nom
   ```
2. **Apportez vos modifications** et testez la syntaxe :
   ```powershell
   # Vérification de l'arbre syntaxique (AST)
   [System.Management.Automation.Language.Parser]::ParseInput((Get-Content .\Diag-IT-UAA3-V3.ps1 -Raw), [ref]$null, [ref]$null)
   ```
3. **Validez les tests unitaires et le rendu du rapport HTML**.
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester -Script .\tests\RuntimeContract.Tests.ps1"

   $report = Join-Path $env:TEMP 'diagtoolit-synthetic-report.html'
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\New-SyntheticReport.ps1 -OutputPath $report -Lang EN
   node .\tests\browser-smoke.cjs $report
   ```
   Le smoke test navigateur requiert le package Node `playwright`. Le rapport utilisé est entièrement synthétique et ne doit contenir aucune donnée du poste.
4. **Commitez vos changements** avec un message clair suivant la convention [Conventional Commits](https://www.conventionalcommits.org/) :
   ```bash
   git commit -m "feat(network): ajout du contrôle de MTU et détection jumbo frames"
   ```
5. **Ouvrez une Pull Request** sur la branche `main`.

---

## 📋 Conventions de Code PowerShell
* Utilisez `Get-CimInstance` de préférence à `Get-WmiObject` (obsolète dans PowerShell 7+).
* Nommez les variables en CamelCase (`$networkAdapters`, `$healthScore`).
* Échappez systématiquement les sorties injectées dans le HTML via une fonction helper `Escape-Html`.
