# Politique de Sécurité — DiagToolIT

La sécurité et la fiabilité des systèmes audités sont une priorité absolue pour DiagToolIT.

---

## 🛡️ Versions Prises en Charge

| Version | Prise en Charge |
| :--- | :---: |
| `v0.1.x-alpha` | ✅ Oui (Version active) |
| `< v0.1.0` | ❌ Non |

---

## 🚨 Signalement d'une Vulnérabilité

Si vous découvrez une vulnérabilité de sécurité ou un comportement anormal pouvant impacter la sécurité d'un poste client :

1. **Ne créez pas d'issue publique sur GitHub.**
2. Envoyez un rapport détaillé via un [Advisory GitHub Privé](https://github.com/mdpwbe-sys/DiagToolIT/security/advisories/new).
3. Veuillez inclure :
   - Description précise de la vulnérabilité.
   - Étapes pour reproduire le problème.
   - Version du système d'exploitation Windows et version de PowerShell testées.
   - Impact potentiel estimé.

## 🔐 Données des rapports

Les rapports HTML peuvent contenir le nom du poste, les comptes locaux, les adresses réseau, les partages, les logiciels, les disques et des métadonnées de certificats. Ils doivent rester hors de Git, des issues publiques et des pièces jointes non chiffrées.

Pour les tests et les captures d'écran, générez exclusivement un rapport fictif avec `tests/New-SyntheticReport.ps1`. Si un rapport réel a déjà été publié dans l'historique Git, sa suppression exige une réécriture coordonnée de toutes les branches et de tous les clones; l'ajout au `.gitignore` ne retire pas les commits existants.

---

## ⏱️ Délai de Réponse
* **Prise en compte** : Sous 48 heures ouvrées.
* **Correctif / Patch** : Déployé sous forme de hotfix selon la sévérité CVSS.
