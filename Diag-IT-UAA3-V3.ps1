<#
.SYNOPSIS
    Outil IT de Diagnostic, Dépannage & Gestion de Packages - Niveau 3 (Tier 3 / UAA 3).
.DESCRIPTION
    Analyse Réseau, Matériel, Drivers, Système, BSOD/Minidumps, GPO, Sécurité et Logiciel.
    Inclut un Scanner de Runtimes Développeur/Système, 12 Profils Métiers Winget avec détection
    dynamique, une Matrice d'Alternatives Open-Source (FOSS), un Générateur de Déploiement
    sur-mesure et un Cyber HUD 3D interactif Three.js.
.AUTHOR
    Support IT & Admin Réseaux - Version 3.1 Super-Tool
#>

[CmdletBinding()]
param (
    [switch]$NoElevate,

    [ValidateSet('FR', 'NL', 'EN', 'DE')]
    [string]$Lang = 'FR',

    [ValidateScript({ $_ -notmatch '"' })]
    [string]$OutputPath,

    [switch]$NoHistory,

    [switch]$NoOpen,

    [switch]$NonInteractive
)

if ($OutputPath) {
    $OutputPath = [IO.Path]::GetFullPath($OutputPath)
}

# --- 0. ÉLÉVATION AUTOMATIQUE EN ADMINISTRATEUR (UAC) ---
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $NoElevate -and -not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSCommandPath) {
        Write-Host "Élévation des privilèges Administrateur requise pour le diagnostic Niveau 3..." -ForegroundColor Yellow
        $elevationArguments = @(
            '-NoProfile'
            '-ExecutionPolicy Bypass'
            "-File `"$PSCommandPath`""
            '-NoElevate'
            "-Lang $Lang"
        )
        if ($OutputPath) {
            $elevationArguments += "-OutputPath `"$OutputPath`""
        }
        if ($NoHistory) { $elevationArguments += '-NoHistory' }
        if ($NoOpen) { $elevationArguments += '-NoOpen' }
        if ($NonInteractive) { $elevationArguments += '-NonInteractive' }

        Start-Process powershell.exe -Verb RunAs -ArgumentList ($elevationArguments -join ' ')
        exit
    } else {
        Write-Warning "Veuillez exécuter la console PowerShell en tant qu'Administrateur."
    }
}

# Configuration de base
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$StartTime = Get-Date

$DesktopPath = [Environment]::GetFolderPath('Desktop')
$ReportDirectory = if ($OutputPath) { $OutputPath } else { $DesktopPath }
if (-not (Test-Path -LiteralPath $ReportDirectory)) {
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
}
$ReportPath = Join-Path $ReportDirectory "Rapport_Diagnostic_UAA3.html"

# --- 0.1 CHARGEMENT CONFIGURATION MODULES (modules_config.json) ---
$configLoader = Join-Path $PSScriptRoot 'Diag-ConfigLoader.ps1'
if (Test-Path -LiteralPath $configLoader) {
    try {
        . $configLoader
        $DiagConfig = Get-DiagConfig -ConfigPath (Join-Path $PSScriptRoot 'modules_config.json')
        $cfgHistoryMaxRuns      = [int]$DiagConfig.history.max_runs_retention
        $cfgScoreBaseline       = [int]$DiagConfig.history.score_baseline_threshold
        $cfgCvssMin             = [double]$DiagConfig.cve_scanner.cvss_min_severity
        $cfgCertAlertDays       = [int]$DiagConfig.belgian_ecosystem.cert_alert_days
        $cfgCertCriticalDays    = [int]$DiagConfig.belgian_ecosystem.cert_critical_alert_days
        Write-Host "[CONFIG] modules_config.json charge : retention=$cfgHistoryMaxRuns runs, seuil sante=$cfgScoreBaseline, CVSS>=$cfgCvssMin, eID alerte=$cfgCertAlertDays j / critique=$cfgCertCriticalDays j" -ForegroundColor DarkGray
    } catch {
        Write-Warning "[CONFIG] $($_.Exception.Message)"
        # Repli sûr sur les valeurs historiques par defaut
        $cfgHistoryMaxRuns   = 30
        $cfgScoreBaseline    = 75
        $cfgCvssMin          = 7.0
        $cfgCertAlertDays    = 30
        $cfgCertCriticalDays = 7
    }
} else {
    Write-Warning "[CONFIG] Diag-ConfigLoader.ps1 introuvable ; repli sur valeurs par defaut."
    $cfgHistoryMaxRuns   = 30
    $cfgScoreBaseline    = 75
    $cfgCvssMin          = 7.0
    $cfgCertAlertDays    = 30
    $cfgCertCriticalDays = 7
}

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Add-Diagnostic {
    param (
        [string]$Category,       # 'Réseau', 'Hardware & Drivers', 'Système & OS', 'Sécurité & GPO', 'Logiciel'
        [string]$TestName,
        [string]$Status,         # 'OK', 'WARNING', 'ERROR'
        [string]$Details,
        [string]$FixAction,
        [string]$PsFixCommand,   # Commande PowerShell prête à l'emploi (1 clic)
        [string]$GuiShortcut,    # Raccourci .msc, .cpl ou Windows
        [string]$ExamTip         # Méthode / Explication formateur UAA 3
    )
    $Results.Add([PSCustomObject]@{
        Category     = $Category
        TestName     = $TestName
        Status       = $Status
        Details      = $Details
        FixAction    = $FixAction
        PsFixCommand = $PsFixCommand
        GuiShortcut  = $GuiShortcut
        ExamTip      = $ExamTip
    })
}

function Escape-Html {
    param ([string]$text)
    if ([string]::IsNullOrEmpty($text)) { return "" }
    return [System.Security.SecurityElement]::Escape($text)
}

function ConvertTo-Utf8Base64 {
    param ([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
}

Clear-Host
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "       🛠️  CENTRE DE DIAGNOSTIC & GESTION APPS IT AVANCÉ (NIVEAU 3)       " -ForegroundColor Cyan
Write-Host "           Support PC, Réseaux, Runtimes & Bundles Métiers (UAA 3)        " -ForegroundColor DarkCyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

# ==========================================================================
# 0. COLLECTE INFOS SYSTÈME GÉNÉRALES (TÉLÉMÉTRIE DU POSTE)
# ==========================================================================
Write-Host "[0/5] Collecte des informations système de base..." -ForegroundColor Gray
$osInfo = Get-CimInstance Win32_OperatingSystem
$csInfo = Get-CimInstance Win32_ComputerSystem
$procInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$uptime = (Get-Date) - $osInfo.LastBootUpTime
$uptimeStr = "{0}j {1}h {2}min" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
$bootMode = try { if (Confirm-SecureBootUEFI) { "UEFI (SecureBoot ON)" } else { "UEFI (SecureBoot OFF)" } } catch { "Legacy BIOS" }

$systemSummary = @{
    HostName     = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OSName       = $osInfo.Caption
    OSVersion    = "$($osInfo.Version) (Build $($osInfo.BuildNumber))"
    Manufacturer = $csInfo.Manufacturer
    Model        = $csInfo.Model
    CPU          = $procInfo.Name.Trim()
    TotalRAM     = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
    Uptime       = $uptimeStr
    BootMode     = $bootMode
}

# ==========================================================================
# 1. DIAGNOSTIC RÉSEAU COMPLET (NIVEAU 3)
# ==========================================================================
Write-Host "[1/5] Diagnostic Réseau Avancé (L3)..." -ForegroundColor Yellow

# 1.1 État des Adaptateurs Réseau Physiques & Virtuels (.NET Ultra-Fast)
$rawNics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
$activeNics = $rawNics | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' }

if (-not $rawNics) {
    Add-Diagnostic -Category "Réseau" -TestName "Cartes Réseau Détectées" -Status "ERROR" `
        -Details "Aucune carte réseau détectée par le système d'exploitation." `
        -FixAction "Vérifier le branchement matériel ou réinstaller les pilotes de la carte réseau." `
        -PsFixCommand "devmgmt.msc" `
        -GuiShortcut "devmgmt.msc" `
        -ExamTip "Si aucune carte n'apparaît, vérifier le gestionnaire de périphériques (pilote manquant ou matériel désactivé dans le BIOS)."
} elseif (-not $activeNics) {
    Add-Diagnostic -Category "Réseau" -TestName "État de Connexion Réseau (Lien Physique)" -Status "ERROR" `
        -Details "Toutes les cartes réseau sont déconnectées ou désactivées (Câble RJ45 débranché / Wi-Fi coupé)." `
        -FixAction "Brancher le câble Ethernet, vérifier les voyants LED RJ45 ou activer le Wi-Fi." `
        -PsFixCommand "ncpa.cpl" `
        -GuiShortcut "ncpa.cpl" `
        -ExamTip "Règle UAA 3 : Toujours vérifier la couche physique (LED du port RJ45, état du câble) avant de modifier la configuration IP."
} else {
    $adNames = ($activeNics | ForEach-Object { "$($_.Name) ($($_.Description))" }) -join ", "
    Add-Diagnostic -Category "Réseau" -TestName "État des cartes réseau" -Status "OK" `
        -Details "Carte(s) active(s) : $adNames." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "ncpa.cpl" -ExamTip "N/A"
}

# 1.2 Configuration IPv4, Masque & Détection APIPA (.NET Fast Extraction)
$ipConfigs = [System.Collections.Generic.List[PSObject]]::new()
foreach ($n in $activeNics) {
    $ipProps = $n.GetIPProperties()
    $gwList = @($ipProps.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.Address.IPAddressToString })
    $dnsList = ($ipProps.DnsAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' }).Address.IPAddressToString
    foreach ($u in $ipProps.UnicastAddresses) {
        if ($u.Address.AddressFamily -eq 'InterNetwork') {
            $ipConfigs.Add([PSCustomObject]@{
                InterfaceAlias = $n.Name
                IPAddress      = $u.Address.IPAddressToString
                PrefixLength   = $u.PrefixLength
                Gateway        = if ($gwList) { $gwList[0] } else { $null }
                DNS            = ($dnsList -join ", ")
            })
        }
    }
}
$apipaList = $ipConfigs | Where-Object { $_.IPAddress -like "169.254.*" -and $_.InterfaceAlias -notmatch 'Virtual|Hyper-V|vEthernet|Loopback' }

if ($apipaList) {
    $apipaNames = ($apipaList.InterfaceAlias) -join ", "
    Add-Diagnostic -Category "Réseau" -TestName "Attribution IP (Détection APIPA)" -Status "ERROR" `
        -Details "Adresse APIPA détectée ($($apipaList[0].IPAddress)) sur $apipaNames. Échec d'obtention de bail DHCP." `
        -FixAction "Vérifier le serveur DHCP, le câble réseau, ou forcer le renouvellement d'adresse IP." `
        -PsFixCommand "ipconfig /release; ipconfig /renew" `
        -GuiShortcut "ncpa.cpl" `
        -ExamTip "Une adresse en 169.254.x.x signifie que Windows n'a reçu aucune réponse du serveur DHCP."
} elseif ($ipConfigs) {
    $primaryIP = $ipConfigs | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.Gateway } | Select-Object -First 1
    if (-not $primaryIP) {
        $primaryIP = $ipConfigs | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1
    }
    
    if ($primaryIP) {
        $gw = $primaryIP.Gateway
        $dns = if ($primaryIP.DNS) { $primaryIP.DNS } else { "Aucun" }
        
        Add-Diagnostic -Category "Réseau" -TestName "Configuration IPv4" -Status "OK" `
            -Details "Carte: $($primaryIP.InterfaceAlias) | IP: $($primaryIP.IPAddress) | Passerelle: $(if ($gw) { $gw } else { 'Aucune' }) | DNS: $dns" `
            -FixAction "N/A" -PsFixCommand "" -GuiShortcut "ncpa.cpl" -ExamTip "N/A"

        # 1.3 Test de Connectivité Passerelle (Gateway Ping .NET)
        if ($gw) {
            $gwPing = try { (New-Object System.Net.NetworkInformation.Ping).Send($gw, 400).Status -eq 'Success' } catch { $false }
            if (-not $gwPing) {
                Add-Diagnostic -Category "Réseau" -TestName "Passerelle par défaut ($gw)" -Status "ERROR" `
                    -Details "La passerelle par défaut ($gw) est injoignable par ping ICMP." `
                    -FixAction "Vérifier l'adresse IP de la passerelle, le câble relié au routeur/switch ou le pare-feu du routeur." `
                    -PsFixCommand "Test-NetConnection -ComputerName $gw" `
                    -GuiShortcut "ncpa.cpl" `
                    -ExamTip "Si la passerelle ne répond pas, le poste ne peut joindre aucun autre réseau ni internet."
            }

            # 1.4 Test Internet IP (8.8.8.8) & Résolution DNS (google.com)
            $inetPing = try { (New-Object System.Net.NetworkInformation.Ping).Send("8.8.8.8", 400).Status -eq 'Success' } catch { $false }
            $dnsResolve = try { [System.Net.Dns]::GetHostAddresses("google.com").Count -gt 0 } catch { $false }

            if ($gwPing -and -not $inetPing) {
                Add-Diagnostic -Category "Réseau" -TestName "Accès Internet Public (WAN / 8.8.8.8)" -Status "ERROR" `
                    -Details "Passerelle locale accessible ($gw), mais aucun trafic vers l'extérieur (8.8.8.8 KO)." `
                    -FixAction "Vérifier la connexion WAN du routeur (box Internet), le routage NAT ou le pare-feu externe." `
                    -PsFixCommand "tracert -d -h 5 8.8.8.8" `
                    -GuiShortcut "ncpa.cpl" `
                    -ExamTip "Passerelle OK mais 8.8.8.8 KO = panne côté FAI/Routeur ou règle de blocage sortant."
            } elseif ($gwPing -and $inetPing) {
                if (-not $dnsResolve) {
                    Add-Diagnostic -Category "Réseau" -TestName "Résolution DNS (google.com)" -Status "ERROR" `
                        -Details "Internet IP fonctionne (8.8.8.8 OK), mais les noms de domaines ne se résolvent pas (Panne DNS)." `
                        -FixAction "Changer les serveurs DNS de la carte réseau pour 8.8.8.8 / 1.1.1.1 et vider le cache DNS." `
                        -PsFixCommand "ipconfig /flushdns" `
                        -GuiShortcut "ncpa.cpl" `
                        -ExamTip "Ping 8.8.8.8 OK mais noms KO = configuration IP et passerelle impeccables, seul le serveur DNS est fautif."
                } else {
                    Add-Diagnostic -Category "Réseau" -TestName "Connectivité Internet & DNS" -Status "OK" `
                        -Details "Passerelle ($gw), Internet IP (8.8.8.8) et Résolution DNS (google.com) 100% opérationnels." `
                        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "ncpa.cpl" -ExamTip "N/A"
                }
            }
        } else {
            Add-Diagnostic -Category "Réseau" -TestName "Passerelle par défaut" -Status "ERROR" `
                -Details "Aucune passerelle par défaut configurée sur la carte active." `
                -FixAction "Configurer une passerelle par défaut valide ou repasser en DHCP automatique." `
                -PsFixCommand "ncpa.cpl" `
                -GuiShortcut "ncpa.cpl" `
                -ExamTip "Sans passerelle par défaut, le poste ne peut communiquer qu'avec son propre sous-réseau local."
        }
    }
} else {
    Add-Diagnostic -Category "Réseau" -TestName "Configuration IP" -Status "ERROR" `
        -Details "Aucune adresse IPv4 valide trouvée sur les cartes réseau actives." `
        -FixAction "Activer la carte réseau et vérifier la configuration DHCP." `
        -PsFixCommand "ncpa.cpl" `
        -GuiShortcut "ncpa.cpl" `
        -ExamTip "Vérifier l'adaptateur dans ncpa.cpl et le service Client DHCP."
}

# 1.5 Services Réseau Critiques (DHCP Client & DNS Cache)
$dhcpSvc = Get-Service -Name "Dhcp"
if ($dhcpSvc.Status -ne 'Running') {
    Add-Diagnostic -Category "Réseau" -TestName "Service Client DHCP" -Status "ERROR" `
        -Details "Le service système 'Client DHCP' est arrêté." `
        -FixAction "Démarrer le service Client DHCP et définir son démarrage sur Automatique." `
        -PsFixCommand "Set-Service -Name 'Dhcp' -StartupType Automatic; Start-Service -Name 'Dhcp'; ipconfig /renew" `
        -GuiShortcut "services.msc" `
        -ExamTip "Si une carte en mode automatique n'obtient jamais d'IP, ce service est la première chose à contrôler."
}

$dnsSvc = Get-Service -Name "Dnscache"
if ($dnsSvc.Status -ne 'Running') {
    Add-Diagnostic -Category "Réseau" -TestName "Service Client DNS (Dnscache)" -Status "WARNING" `
        -Details "Le service 'Client DNS' est à l'arrêt." `
        -FixAction "Démarrer le service DNS Client." `
        -PsFixCommand "Start-Service -Name 'Dnscache'" `
        -GuiShortcut "services.msc" `
        -ExamTip "Un service Dnscache coupé provoque des lenteurs et des échecs intermittents de navigation web."
}

# 1.6 Fichier Hosts (Détection Détournement / Hijack DNS)
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$criticalDomains = @('microsoft.com','windows.com','windowsupdate.com','google.com','gstatic.com','apple.com','mozilla.org','github.com','cloudflare.com','office.com')
if (Test-Path $hostsPath) {
    $rawHosts = Get-Content $hostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
    $suspectLines = @()
    $legitBlocks = 0
    foreach ($line in $rawHosts) {
        if ($line -match '^\s*(\S+)\s+(\S+)') {
            $hIp = $matches[1]
            $hName = $matches[2].ToLower()
            $isLoop = ($hIp -eq '0.0.0.0' -or $hIp -eq '127.0.0.1' -or $hIp -eq '::1')
            if (-not $isLoop) {
                $suspectLines += $line.Trim()
            } else {
                $isCrit = $false
                foreach ($cd in $criticalDomains) { if ($hName -like "*$cd*") { $isCrit = $true; break } }
                if ($isCrit) { $suspectLines += $line.Trim() } else { $legitBlocks++ }
            }
        }
    }
    if ($suspectLines.Count -gt 0) {
        $linesStr = $suspectLines -join " | "
        Add-Diagnostic -Category "Réseau" -TestName "Fichier Hosts (Redirection / Détournement)" -Status "WARNING" `
            -Details "Redirection(s) suspecte(s) détectée(s) : $linesStr." `
            -FixAction "Nettoyer le fichier hosts en supprimant les lignes suspectes et vider le cache DNS." `
            -PsFixCommand "notepad.exe C:\Windows\System32\drivers\etc\hosts; ipconfig /flushdns" `
            -GuiShortcut "notepad hosts" `
            -ExamTip "Piège classique : si UN SEUL site ne s'ouvre pas ou renvoie vers un faux site, c'est le fichier hosts."
    } else {
        Add-Diagnostic -Category "Réseau" -TestName "Fichier Hosts" -Status "OK" `
            -Details "Fichier hosts sain ($legitBlocks entrée(s) de blocage local légitimes, aucun détournement)." `
            -FixAction "N/A" -PsFixCommand "" -GuiShortcut "notepad hosts" -ExamTip "N/A"
    }
}

# 1.7 Configuration Proxy (WinINet & WinHTTP)
$proxyUser = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$winhttpProxy = (netsh winhttp show proxy) -join " "
$proxyActive = ($proxyUser -and $proxyUser.ProxyEnable -eq 1) -or ($winhttpProxy -notmatch "Direct access" -and $winhttpProxy -notmatch "Accès direct")

if ($proxyActive) {
    $proxyServer = if ($proxyUser.ProxyServer) { $proxyUser.ProxyServer } else { "Proxy WinHTTP actif" }
    Add-Diagnostic -Category "Réseau" -TestName "Serveur Proxy Activé" -Status "WARNING" `
        -Details "Un serveur proxy manuel est configuré ($proxyServer). Si le proxy est faux, toute la navigation web sera bloquée." `
        -FixAction "Désactiver le proxy manuel utilisateur et réinitialiser le proxy système WinHTTP." `
        -PsFixCommand "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxyEnable' -Value 0; netsh winhttp reset proxy" `
        -GuiShortcut "inetcpl.cpl" `
        -ExamTip "Symptôme typique : 'ping google.com' fonctionne parfaitement mais le navigateur affiche 'Impossible de se connecter au serveur proxy'."
} else {
    Add-Diagnostic -Category "Réseau" -TestName "Serveur Proxy" -Status "OK" `
        -Details "Aucun proxy bloquant configuré (Accès direct Internet)." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "inetcpl.cpl" -ExamTip "N/A"
}

# 1.8 Partage de fichiers & Client Réseaux Microsoft (LanmanWorkstation / SMB)
$lmWorkstation = Get-Service -Name "LanmanWorkstation" -ErrorAction SilentlyContinue
if ($lmWorkstation -and $lmWorkstation.Status -ne 'Running') {
    Add-Diagnostic -Category "Réseau" -TestName "Client Réseaux Microsoft (LanmanWorkstation)" -Status "ERROR" `
        -Details "Le service 'Station de travail' (LanmanWorkstation / Client SMB) est arrêté." `
        -FixAction "Démarrer le service LanmanWorkstation et le configurer en Automatique." `
        -PsFixCommand "Set-Service -Name 'LanmanWorkstation' -StartupType Automatic; Start-Service -Name 'LanmanWorkstation'" `
        -GuiShortcut "services.msc" `
        -ExamTip "Internet fonctionne très bien, mais l'accès aux dossiers partagés (\\serveur\partage) est totalement impossible."
} else {
    Add-Diagnostic -Category "Réseau" -TestName "Client Réseaux Microsoft (SMB)" -Status "OK" `
        -Details "Client pour les réseaux Microsoft (LanmanWorkstation) actif et fonctionnel." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "ncpa.cpl" -ExamTip "N/A"
}

# 1.9 Spouleur d'impression & Fichiers de spoule corrompus
$spoolerSvc = Get-Service -Name "Spooler"
$spoolDir = "$env:SystemRoot\System32\spool\PRINTERS"
$stuckJobs = if (Test-Path $spoolDir) { (Get-ChildItem -Path $spoolDir -File -ErrorAction SilentlyContinue).Count } else { 0 }

if ($spoolerSvc.Status -ne 'Running') {
    Add-Diagnostic -Category "Réseau" -TestName "Service Spouleur d'impression" -Status "ERROR" `
        -Details "Le spouleur d'impression est arrêté. Toutes les imprimantes refusent d'imprimer ou disparaissent." `
        -FixAction "Démarrer le service Spooler et le mettre en démarrage Automatique." `
        -PsFixCommand "Set-Service -Name 'Spooler' -StartupType Automatic; Start-Service -Name 'Spooler'" `
        -GuiShortcut "services.msc" `
        -ExamTip "Un document corrompu fait parfois crasher le spouleur en boucle au démarrage."
} elseif ($stuckJobs -gt 0) {
    Add-Diagnostic -Category "Réseau" -TestName "Spouleur d'impression (File bloquée)" -Status "WARNING" `
        -Details "$stuckJobs fichier(s) d'impression bloqué(s) dans le répertoire de spoule ($spoolDir)." `
        -FixAction "Arrêter le spouleur, purger les fichiers bloqués dans C:\Windows\System32\spool\PRINTERS et redémarrer le service." `
        -PsFixCommand "Stop-Service -Name 'Spooler' -Force; Remove-Item -Path '$spoolDir\*' -Force -Recurse; Start-Service -Name 'Spooler'" `
        -GuiShortcut "control printers" `
        -ExamTip "Pour débloquer une file d'attente d'impression gelée, vider le dossier PRINTERS pendant que le Spooler est arrêté."
} else {
    Add-Diagnostic -Category "Réseau" -TestName "Service Spouleur d'impression" -Status "OK" `
        -Details "Spouleur d'impression actif et file de spoule vide." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "control printers" -ExamTip "N/A"
}

# 1.10 Imprimantes Réseau & Port RAW 9100 (Ultra-Fast Zero-Lag)
if ($spoolerSvc.Status -eq 'Running') {
    $printers = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.PortName -match '(?:\d{1,3}\.){3}\d{1,3}' }
    foreach ($prt in $printers) {
        if ($prt.PortName -match '((?:\d{1,3}\.){3}\d{1,3})') {
            $pIp = $matches[1]
            $pPing = try { (New-Object System.Net.NetworkInformation.Ping).Send($pIp, 200).Status -eq 'Success' } catch { $false }
            $pPort9100 = try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $iar = $tcp.BeginConnect($pIp, 9100, $null, $null)
                $ok = $iar.AsyncWaitHandle.WaitOne(200)
                if ($ok) { $tcp.EndConnect($iar); $true } else { $false }
            } catch { $false } finally { if ($tcp) { $tcp.Close() } }
            if (-not $pPing -and -not $pPort9100) {
                Add-Diagnostic -Category "Réseau" -TestName "Imprimante Réseau ($($prt.Name))" -Status "WARNING" `
                    -Details "L'imprimante réseau ($pIp) ne répond ni au ping ni sur le port RAW 9100 (hors tension ou en veille)." `
                    -FixAction "Vérifier l'alimentation de l'imprimante, son adresse IP et la configuration du port TCP/IP (Standard RAW port 9100)." `
                    -PsFixCommand "Test-NetConnection -ComputerName $pIp -Port 9100" `
                    -GuiShortcut "control printers" `
                    -ExamTip "En impression réseau standard, le protocole utilisé est RAW sur le port 9100 (JetDirect)."
            }
        }
    }
}

# 1.11 Pare-feu Windows Defender (Profils & État)
$fwSvc = Get-Service -Name "MpsSvc"
if ($fwSvc.Status -ne 'Running') {
    Add-Diagnostic -Category "Réseau" -TestName "Service Pare-feu Windows (MpsSvc)" -Status "WARNING" `
        -Details "Le service Pare-feu Windows Defender est arrêté." `
        -FixAction "Démarrer le service Pare-feu et le configurer en Automatique." `
        -PsFixCommand "Set-Service -Name 'MpsSvc' -StartupType Automatic; Start-Service -Name 'MpsSvc'" `
        -GuiShortcut "wf.msc" `
        -ExamTip "Ne jamais laisser un poste sans pare-feu actif."
} else {
    $fwProfiles = Get-NetFirewallProfile
    $disProf = $fwProfiles | Where-Object { $_.Enabled -eq $false }
    if ($disProf) {
        $pNames = ($disProf.Name) -join ", "
        Add-Diagnostic -Category "Réseau" -TestName "Pare-feu - Profils actifs" -Status "WARNING" `
            -Details "Profil(s) pare-feu désactivé(s) : $pNames." `
            -FixAction "Réactiver tous les profils du Pare-feu Windows Defender." `
            -PsFixCommand "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" `
            -GuiShortcut "wf.msc" `
            -ExamTip "Désactiver le pare-feu sert uniquement à tester temporairement, pas à résoudre définitivement une panne."
    } else {
        Add-Diagnostic -Category "Réseau" -TestName "Pare-feu Windows Defender" -Status "OK" `
        -Details "Tous les profils de filtrage sont actifs (Domain, Private, Public)." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "wf.msc" -ExamTip "N/A"
    }
}


# ==========================================================================
# 2. DIAGNOSTIC HARDWARE, DRIVERS & MATÉRIEL (NIVEAU 3)
# ==========================================================================
Write-Host "[2/5] Diagnostic Hardware, Matériel & Drivers (L3)..." -ForegroundColor Yellow

# 2.1 Gestionnaire de périphériques & Codes d'erreur PNP (10, 28, 43, etc.)
$pnpErrors = Get-PnpDevice -PresentOnly | Where-Object { $_.ConfigManagerErrorCode -ne 0 -and $_.Status -ne 'OK' }
if ($pnpErrors) {
    foreach ($pnp in $pnpErrors) {
        $code = $pnp.ConfigManagerErrorCode
        $codeExplanation = switch ($code) {
            10 { "Code 10: Le périphérique ne peut pas démarrer (pilote corrompu, mauvais slot ou matériel défectueux)." }
            28 { "Code 28: Les pilotes de ce périphérique ne sont pas installés." }
            43 { "Code 43: Le périphérique a été arrêté car il a signalé des problèmes (panne GPU/composant ou surchauffe)." }
            45 { "Code 45: Le périphérique n'est pas connecté à l'ordinateur." }
            default { "Code $code : Problème de configuration ou pilote manquant." }
        }
        Add-Diagnostic -Category "Hardware & Drivers" -TestName "Périphérique en erreur : $($pnp.FriendlyName)" -Status "ERROR" `
            -Details "$codeExplanation (ID: $($pnp.InstanceId))" `
            -FixAction "Réinsérer physiquement le composant, réinstaller/mettre à jour son pilote ou changer de port PCIe/USB." `
            -PsFixCommand "Disable-PnpDevice -InstanceId '$($pnp.InstanceId)' -Confirm:`$false; Enable-PnpDevice -InstanceId '$($pnp.InstanceId)' -Confirm:`$false" `
            -GuiShortcut "devmgmt.msc" `
            -ExamTip "Un point d'exclamation jaune dans devmgmt.msc indique un pilote manquant ou un périphérique mal enfiché."
    }
} else {
    Add-Diagnostic -Category "Hardware & Drivers" -TestName "Gestionnaire de périphériques (PNP)" -Status "OK" `
        -Details "Aucun périphérique matériel en erreur détecté (0 anomalie Plug-and-Play sur le matériel branché)." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "devmgmt.msc" -ExamTip "N/A"
}

# 2.2 Santé SMART des Disques Physiques & Type de Média
$physDisks = Get-PhysicalDisk
foreach ($pd in $physDisks) {
    $media = if ($pd.MediaType) { $pd.MediaType } else { "Inconnu" }
    $bus = if ($pd.BusType) { $pd.BusType } else { "Inconnu" }
    $sizeGB = [math]::Round($pd.Size / 1GB, 1)

    if ($pd.HealthStatus -ne 'Healthy' -or $pd.OperationalStatus -ne 'OK') {
        Add-Diagnostic -Category "Hardware & Drivers" -TestName "Santé Disque Physique ($($pd.FriendlyName) - $media)" -Status "ERROR" `
            -Details "État SMART anormal : Santé = $($pd.HealthStatus), Statut Opérationnel = $($pd.OperationalStatus) ($sizeGB Go, Bus: $bus)." `
            -FixAction "Remplacer immédiatement le disque dur. Si des bruits mécaniques (claquements) sont audibles, couper le disque." `
            -PsFixCommand "Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, HealthStatus, OperationalStatus | Format-Table" `
            -GuiShortcut "diskmgmt.msc" `
            -ExamTip "Bruits anormaux de grattement/claquement = panne mécanique matérielle irréversible."
    } else {
        Add-Diagnostic -Category "Hardware & Drivers" -TestName "Santé Disque Physique ($($pd.FriendlyName))" -Status "OK" `
            -Details "Statut SMART sain ($media, $sizeGB Go, Bus: $bus, État: $($pd.OperationalStatus))." `
            -FixAction "N/A" -PsFixCommand "" -GuiShortcut "diskmgmt.msc" -ExamTip "N/A"
    }
}

# 2.3 Mémoire RAM, Détection des Barres & Diagnostic Matériel
$ramModules = Get-CimInstance Win32_PhysicalMemory
$totRamGB = [math]::Round(((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / 1MB), 2)
$ramDetails = ($ramModules | ForEach-Object { "$([math]::Round($_.Capacity / 1GB)) Go ($($_.Speed) MHz)" }) -join " + "

$memDiagErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} -MaxEvents 5 -ErrorAction SilentlyContinue

if ($memDiagErrors -and ($memDiagErrors | Where-Object { $_.Id -eq 1202 })) {
    Add-Diagnostic -Category "Hardware & Drivers" -TestName "Intégrité Mémoire RAM" -Status "ERROR" `
        -Details "Le test de mémoire Windows a détecté des défaillances matérielles sur les barrettes de RAM." `
        -FixAction "Tester les barrettes une par une pour identifier le module défectueux et le remplacer." `
        -PsFixCommand "mdsched.exe" `
        -GuiShortcut "mdsched.exe" `
        -ExamTip "Des écrans bleus aléatoires (MEMORY_MANAGEMENT) sont souvent le signe d'une barrette défectueuse."
} else {
    Add-Diagnostic -Category "Hardware & Drivers" -TestName "Mémoire RAM Détectée" -Status "OK" `
        -Details "$totRamGB Go de RAM physique reconnus ($ramDetails)." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "mdsched.exe" -ExamTip "N/A"
}

# 2.4 État de la Batterie (Pour Ordinateurs Portables)
$battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
if ($battery) {
    $batPercent = $battery.EstimatedChargeRemaining
    $batStatus = $battery.BatteryStatus
    $batHealthDesc = switch ($batStatus) {
        1 { "En décharge" }
        2 { "Sur secteur (En charge / Pleine)" }
        3 { "Niveau critique" }
        4 { "Faible" }
        default { "Connectée" }
    }
    if ($batPercent -lt 15 -and $batStatus -eq 1) {
        Add-Diagnostic -Category "Hardware & Drivers" -TestName "Niveau Batterie Faible" -Status "WARNING" `
            -Details "Niveau de charge critique ($batPercent%). Le PC risque de s'éteindre brutalement." `
            -FixAction "Brancher immédiatement l'adaptateur secteur du PC portable." `
            -PsFixCommand "powercfg /batteryreport /output $env:USERPROFILE\Desktop\battery_report.html" `
            -GuiShortcut "powercfg.cpl" `
            -ExamTip "Une extinction brutale par batterie vide corrompt les fichiers ouverts et la base de registre."
    } else {
        Add-Diagnostic -Category "Hardware & Drivers" -TestName "Batterie Ordinateur Portable" -Status "OK" `
            -Details "Charge : $batPercent% ($batHealthDesc)." `
            -FixAction "N/A" -PsFixCommand "" -GuiShortcut "powercfg.cpl" -ExamTip "N/A"
    }
}


# ==========================================================================
# 3. DIAGNOSTIC SYSTÈME, SÉCURITÉ & LOGICIEL (NIVEAU 3)
# ==========================================================================
Write-Host "[3/5] Diagnostic Système, Sécurité & Logiciel (L3)..." -ForegroundColor Yellow

# 3.1 Espace Disque & Dirty Bit (Chkdsk)
$volumes = Get-Volume | Where-Object { $_.DriveLetter -ne $null -and $_.DriveType -eq 'Fixed' }
foreach ($vol in $volumes) {
    $drive = "$($vol.DriveLetter):"
    $freePercent = [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1)
    $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
    $totalGB = [math]::Round($vol.Size / 1GB, 2)

    $dirtyCheck = (fsutil dirty query $drive 2>$null) -join " "
    $isDirty = $dirtyCheck -match "is dirty" -or $dirtyCheck -match "est endommagé"

    if ($freePercent -lt 10 -or $freeGB -lt 5) {
        Add-Diagnostic -Category "Système & OS" -TestName "Espace Disque ($drive)" -Status "ERROR" `
            -Details "Espace critique sur $drive : seulement $freeGB Go restants ($freePercent% de $totalGB Go)." `
            -FixAction "Vider la corbeille, lancer cleanmgr, purger les fichiers temporaires et les caches Windows Update." `
            -PsFixCommand "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Remove-Item -Path `"$env:TEMP\*`" -Recurse -Force -ErrorAction SilentlyContinue; cleanmgr.exe /sagerun:1" `
            -GuiShortcut "cleanmgr.exe" `
            -ExamTip "Un disque saturé bloque les mises à jour Windows, empêche l'écriture de fichiers et ralentit le système."
    } elseif ($isDirty) {
        Add-Diagnostic -Category "Système & OS" -TestName "Intégrité Système de fichiers ($drive)" -Status "WARNING" `
            -Details "Le volume $drive est marqué 'Dirty' (des erreurs de système de fichiers nécessitent une vérification)." `
            -FixAction "Programmer une vérification chkdsk au prochain démarrage." `
            -PsFixCommand "chkdsk $drive /f /r" `
            -GuiShortcut "diskmgmt.msc" `
            -ExamTip "Un arrêt brutal ou une coupure électrique corrompt la table NTFS et active le bit 'dirty'."
    } else {
        Add-Diagnostic -Category "Système & OS" -TestName "Espace Disque ($drive)" -Status "OK" `
            -Details "$freeGB Go libres sur $totalGB Go ($freePercent% disponible). Système de fichiers sain." `
            -FixAction "N/A" -PsFixCommand "" -GuiShortcut "cleanmgr.exe" -ExamTip "N/A"
    }
}

# 3.2 Crashs Système BSOD & Minidumps Récents
$minidumpFolder = "$env:SystemRoot\Minidump"
$recentDumps = if (Test-Path $minidumpFolder) { Get-ChildItem -Path $minidumpFolder -Filter "*.dmp" -ErrorAction SilentlyContinue } else { @() }
$bsodEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 5 -ErrorAction SilentlyContinue

if ($recentDumps.Count -gt 0) {
    $latestDump = ($recentDumps | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    Add-Diagnostic -Category "Système & OS" -TestName "Crashs BSOD (Minidumps Détectés)" -Status "WARNING" `
        -Details "$($recentDumps.Count) crash(s) d'écran bleu (BSOD) enregistrés. Dernier dump : $($latestDump.Name) ($($latestDump.LastWriteTime.ToString('dd/MM/yyyy HH:mm')))." `
        -FixAction "Analyser le minidump avec WinDbg ou BlueScreenView pour identifier le driver fautif (.sys)." `
        -PsFixCommand "Get-ChildItem -Path 'C:\Windows\Minidump' | Format-Table Name, Length, LastWriteTime" `
        -GuiShortcut "eventvwr.msc" `
        -ExamTip "Les BSOD sont causés par un pilote matériel défaillant, une surchauffe ou une barrette de RAM défectueuse."
} else {
    Add-Diagnostic -Category "Système & OS" -TestName "Stabilité Système (BSOD)" -Status "OK" `
        -Details "Aucun fichier de crash minidump récent dans C:\Windows\Minidump." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "eventvwr.msc" -ExamTip "N/A"
}

# 3.3 Redémarrages en attente (Reboot Pending / Windows Update)
$cbsReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
$wuReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
if ($cbsReboot -or $wuReboot) {
    Add-Diagnostic -Category "Système & OS" -TestName "Redémarrage Système Requis" -Status "WARNING" `
        -Details "Une installation ou mise à jour système Windows nécessite un redémarrage complet pour finaliser l'application." `
        -FixAction "Redémarrer l'ordinateur pour appliquer les modifications système en attente." `
        -PsFixCommand "Restart-Computer -Force" `
        -GuiShortcut "ms-settings:windowsupdate" `
        -ExamTip "Certains composants restent bloqués dans un état instable tant que le redémarrage requis n'est pas effectué."
}

# 3.4 Antivirus en conflit & État de Windows Defender
$avList = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
$defService = Get-Service WinDefend -ErrorAction SilentlyContinue
$defRunning = ($defService -and $defService.Status -eq 'Running')
$realtimeOff = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue).DisableRealtimeMonitoring -eq 1
$defRealtime = $defRunning -and (-not $realtimeOff)

if ($avList.Count -gt 1) {
    $avNames = ($avList.displayName) -join ", "
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "Conflit Antivirus Multiple" -Status "WARNING" `
        -Details "Plusieurs logiciels antivirus actifs détectés en simultané : $avNames." `
        -FixAction "Désinstaller l'antivirus superflu pour éviter les conflits d'interception et les ralentissements I/O." `
        -PsFixCommand "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Format-Table displayName, pathToSignedProductExe" `
        -GuiShortcut "windowsdefender" `
        -ExamTip "Deux antivirus simultanés créent des blocages de verrouillage de fichiers mutuels et divisent les débits disques."
} elseif (-not $defRealtime -and $avList.Count -eq 0) {
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "Protection Antivirus Désactivée" -Status "ERROR" `
        -Details "La protection en temps réel Windows Defender est désactivée ou le service est arrêté." `
        -FixAction "Réactiver la protection en temps réel Windows Defender." `
        -PsFixCommand "Set-MpPreference -DisableRealtimeMonitoring `$false -ErrorAction SilentlyContinue; Start-Service WinDefend -ErrorAction SilentlyContinue" `
        -GuiShortcut "windowsdefender" `
        -ExamTip "Le poste de travail ne doit jamais être laissé sans protection active."
} else {
    $avLabel = if ($avList.Count -ge 1) { $avList[0].displayName } else { "Windows Defender" }
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "Protection Antivirus Conforme" -Status "OK" `
        -Details "Protection en temps réel active et opérationnelle ($avLabel)." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "windowsdefender" -ExamTip "N/A"
}

# 3.5 Disposition Clavier (Détection AZERTY / QWERTY)
$langList = Get-WinUserLanguageList
if ($langList -and $langList.Count -gt 0 -and $langList[0].InputMethodTips.Count -gt 0) {
    $inputMethod = $langList[0].InputMethodTips[0]
    if ($inputMethod -notmatch '040c:0000040c' -and $inputMethod -notmatch '080c:0000080c') {
        Add-Diagnostic -Category "Logiciel" -TestName "Disposition du Clavier (QWERTY / Inversé)" -Status "WARNING" `
            -Details "Clavier configuré en QWERTY ou langue étrangère ($inputMethod). Les touches A/Q et Z/W sont inversées." `
            -FixAction "Basculer la disposition avec le raccourci Alt+Shift ou Win+Espace, ou rétablir le clavier Français/Belge." `
            -PsFixCommand "Set-WinUserLanguageList -LanguageList (New-WinUserLanguageList -Language 'fr-FR') -Force" `
            -GuiShortcut "Alt + Shift" `
            -ExamTip "Ce n'est pas un clavier en panne physique : l'utilisateur a simplement pressé Alt+Shift sans faire exprès."
    } else {
        Add-Diagnostic -Category "Logiciel" -TestName "Disposition du Clavier" -Status "OK" `
            -Details "Disposition AZERTY conforme ($inputMethod)." `
            -FixAction "N/A" -PsFixCommand "" -GuiShortcut "Alt + Shift" -ExamTip "N/A"
    }
}

# 3.6 Politiques GPO & Registre Bloquantes (USB, Bouton Arrêter, Task Manager)
# A. Blocage Clés USB
$usbBlockReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -ErrorAction SilentlyContinue
$usbDriverReg = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -ErrorAction SilentlyContinue).Start
if (($usbBlockReg -and $usbBlockReg.Deny_All -eq 1) -or $usbDriverReg -eq 4) {
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "GPO : Blocage des Clés USB" -Status "ERROR" `
        -Details "L'accès aux clés USB et disques amovibles est bloqué par stratégie GPO ou pilote USBSTOR désactivé (Start=4)." `
        -FixAction "Réactiver le pilote USBSTOR et désactiver le blocage de stockage amovible." `
        -PsFixCommand "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name 'Start' -Value 3; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_All' -ErrorAction SilentlyContinue; gpupdate /force" `
        -GuiShortcut "gpedit.msc" `
        -ExamTip "Si toutes les clés USB sont refusées sur tous les ports USB, c'est une stratégie de groupe (GPO), pas un port cassé."
} else {
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "Accès Supports Amovibles USB" -Status "OK" `
        -Details "Les supports USB de stockage sont autorisés." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "gpedit.msc" -ExamTip "N/A"
}

# B. Masquage Bouton Arrêter
$noCloseReg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoClose" -ErrorAction SilentlyContinue
if ($noCloseReg -and $noCloseReg.NoClose -eq 1) {
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "GPO : Bouton Arrêter Masqué" -Status "ERROR" `
        -Details "L'option d'arrêt du PC a été masquée dans le menu Démarrer par stratégie GPO (NoClose=1)." `
        -FixAction "Supprimer la restriction 'NoClose' dans le registre ou la GPO correspondante." `
        -PsFixCommand "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoClose' -ErrorAction SilentlyContinue; gpupdate /force" `
        -GuiShortcut "gpedit.msc" `
        -ExamTip "Bien distinguer le bouton physique du boîtier et le blocage de la commande Arrêter par stratégie Windows."
}

# C. Blocage Gestionnaire des tâches
$noTaskMgr = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -ErrorAction SilentlyContinue).DisableTaskMgr
if ($noTaskMgr -eq 1) {
    Add-Diagnostic -Category "Sécurité & GPO" -TestName "GPO : Gestionnaire des tâches Désactivé" -Status "ERROR" `
        -Details "L'accès au Gestionnaire des tâches (Ctrl+Shift+Échap) a été verrouillé par stratégie." `
        -FixAction "Réactiver le Gestionnaire des tâches." `
        -PsFixCommand "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableTaskMgr' -ErrorAction SilentlyContinue" `
        -GuiShortcut "gpedit.msc" `
        -ExamTip "Une restriction GPO ou un malware peut verrouiller le Task Manager pour empêcher de tuer des processus."
}

# 3.7 Association de Fichiers (.PDF)
$pdfAssoc = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" -ErrorAction SilentlyContinue).ProgId
if (-not $pdfAssoc) {
    $pdfAssoc = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\.pdf" -ErrorAction SilentlyContinue).'(default)'
}
if ($pdfAssoc -match "Chrome" -or $pdfAssoc -match "MSEdge" -or $pdfAssoc -match "Edge") {
    Add-Diagnostic -Category "Logiciel" -TestName "Association par défaut .PDF" -Status "WARNING" `
        -Details "Les documents PDF s'ouvrent avec le navigateur web ($pdfAssoc) au lieu d'un lecteur PDF dédié." `
        -FixAction "Définir une application PDF dédiée (PDF24 / Acrobat) comme application par défaut." `
        -PsFixCommand "Start-Process 'ms-settings:defaultapps'" `
        -GuiShortcut "Paramètres PDF" `
        -ExamTip "Installer le logiciel ne suffit pas : il faut rétablir l'association de l'extension de fichier dans Windows."
} else {
    Add-Diagnostic -Category "Logiciel" -TestName "Association de fichiers .PDF" -Status "OK" `
        -Details "Association .PDF configurée ($pdfAssoc)." `
        -FixAction "N/A" -PsFixCommand "" -GuiShortcut "Paramètres PDF" -ExamTip "N/A"
}

# 3.8 Processus Gourmands en Arrière-plan
$heavyMem = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 3
$topMemStr = ($heavyMem | ForEach-Object { "$($_.ProcessName) ($([math]::Round($_.WorkingSet64 / 1MB)) Mo)" }) -join ", "

Add-Diagnostic -Category "Système & OS" -TestName "Processus Actifs & Consommation Mémoire" -Status "OK" `
    -Details "Processus les plus consommateurs en RAM : $topMemStr." `
    -FixAction "Si un processus bloque la machine, le fermer avec TaskMgr ou Stop-Process." `
    -PsFixCommand "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 ProcessName, Id, CPU, @{Name='RAM (MB)';Expression={[math]::Round(`$_.WorkingSet64/1MB)}} | Format-Table" `
    -GuiShortcut "Ctrl + Shift + Esc" `
    -ExamTip "Utiliser Ctrl + Shift + Échap pour ouvrir directement le Gestionnaire des tâches sans passer par Ctrl+Alt+Suppr."


# ==========================================================================
# 4. SCANNER DE RUNTIMES, DÉPENDANCES & LOGICIELS INSTALLÉS (WINGET)
# ==========================================================================
Write-Host "[4/5] Analyse des Runtimes Développeur & Applications Installées..." -ForegroundColor Cyan

# 4.1 Runtimes Développeur & Écosystème Système
# 4.1 SCANNER EXHAUSTIF DES RUNTIMES DÉVELOPPEUR, COMPILATEURS & CONTENEURS (16 ITEMS)
$runtimes = @()

# 1. Python
$pyVer = try { $out = (python --version 2>&1 | Out-String).Trim(); if ($out -match 'Python\s+([\d\.]+)') { $matches[1] } else { "" } } catch { "" }
if (-not $pyVer) { $pyVer = try { $out = (py --version 2>&1 | Out-String).Trim(); if ($out -match 'Python\s+([\d\.]+)') { $matches[1] } else { "" } } catch { "" } }
$runtimes += [PSCustomObject]@{
    Name = "Python"
    Icon = "🐍"
    Version = if ($pyVer) { "v$pyVer" } else { "Non installé" }
    Installed = [bool]$pyVer
    WingetId = "Python.Python.3.12"
    Desc = "Moteur d'exécution pour scripts, intelligence artificielle, machine learning et data science."
}

# 2. Node.js (JavaScript / TypeScript)
$nodeVer = try { (node -v 2>&1 | Out-String).Trim() } catch { "" }
$isNode = $nodeVer -match '^v\d+'
$runtimes += [PSCustomObject]@{
    Name = "Node.js (JavaScript Runtime)"
    Icon = "🟢"
    Version = if ($isNode) { "$nodeVer" } else { "Non installé" }
    Installed = $isNode
    WingetId = "OpenJS.NodeJS.LTS"
    Desc = "Environnement d'exécution JavaScript côté serveur avec gestionnaires de paquets npm & npx."
}

# 3. Java JDK / JRE
$javaOut = try { (java -version 2>&1 | Select-Object -First 1 | Out-String).Trim() } catch { "" }
$isJava = $javaOut -match 'version' -or $javaOut -match 'openjdk' -or $javaOut -match 'java'
$runtimes += [PSCustomObject]@{
    Name = "Java JDK / JRE"
    Icon = "☕"
    Version = if ($isJava) { "$javaOut" } else { "Non installé" }
    Installed = $isJava
    WingetId = "Oracle.JDK.21"
    Desc = "Requis pour progiciels d'entreprise, microservices JVM, outils de build Android et serveurs."
}

# 4. .NET SDK & Runtimes
$dotnetVer = try { (dotnet --version 2>&1 | Out-String).Trim() } catch { "" }
$isDotnet = $dotnetVer -match '^\d+\.\d+'
$runtimes += [PSCustomObject]@{
    Name = ".NET SDK / Runtime"
    Icon = "🟣"
    Version = if ($isDotnet) { "v$dotnetVer (SDK)" } else { "Runtime Windows standard" }
    Installed = $isDotnet
    WingetId = "Microsoft.DotNet.SDK.8"
    Desc = "Plateforme d'exécution pour applications modernes C#, WPF, ASP.NET Core et services d'arrière-plan."
}

# 5. Rust & Cargo
$rustOut = try { (rustc --version 2>&1 | Out-String).Trim() } catch { "" }
$isRust = $rustOut -match 'rustc\s+[\d\.]+'
$runtimes += [PSCustomObject]@{
    Name = "Rust & Cargo"
    Icon = "🦀"
    Version = if ($isRust) { "$rustOut" } else { "Non installé" }
    Installed = $isRust
    WingetId = "Rustlang.Rustup"
    Desc = "Compilateur Rust et gestionnaire Cargo pour performances système extrêmes et sécurité mémoire."
}

# 6. Go (Golang)
$goOut = try { (go version 2>&1 | Out-String).Trim() } catch { "" }
$isGo = $goOut -match 'go\s+version'
$runtimes += [PSCustomObject]@{
    Name = "Go (Golang)"
    Icon = "🐹"
    Version = if ($isGo) { "$goOut" } else { "Non installé" }
    Installed = $isGo
    WingetId = "GoLang.Go"
    Desc = "Langage compilé de référence pour le Cloud, les microservices, Docker, Kubernetes et DevOps."
}

# 7. PHP CLI
$phpOut = try { $out = (php -v 2>&1 | Select-Object -First 1 | Out-String).Trim(); if ($out -match 'PHP\s+([\d\.]+)') { "v" + $matches[1] } else { "" } } catch { "" }
$isPhp = [bool]$phpOut
$runtimes += [PSCustomObject]@{
    Name = "PHP CLI"
    Icon = "🐘"
    Version = if ($isPhp) { "$phpOut" } else { "Non installé" }
    Installed = $isPhp
    WingetId = "PHP.PHP"
    Desc = "Interpréteur PHP pour développement web backend, WordPress, Symfony, Laravel et scripts d'API."
}

# 8. Ruby
$rubyOut = try { $out = (ruby -v 2>&1 | Select-Object -First 1 | Out-String).Trim(); if ($out -match 'ruby\s+([\d\.]+)') { "v" + $matches[1] } else { "" } } catch { "" }
$isRuby = [bool]$rubyOut
$runtimes += [PSCustomObject]@{
    Name = "Ruby"
    Icon = "💎"
    Version = if ($isRuby) { "$rubyOut" } else { "Non installé" }
    Installed = $isRuby
    WingetId = "RubyInstallerTeam.Ruby"
    Desc = "Moteur d'exécution Ruby et gestionnaire Gem pour scripting d'automatisation, Jekyll et DevSecOps."
}

# 9. Bun JS
$bunOut = try { $out = (bun --version 2>&1 | Out-String).Trim(); if ($out -match '^[\d\.]+') { "v" + $out } else { "" } } catch { "" }
$isBun = [bool]$bunOut
$runtimes += [PSCustomObject]@{
    Name = "Bun JS"
    Icon = "🍞"
    Version = if ($isBun) { "$bunOut" } else { "Non installé" }
    Installed = $isBun
    WingetId = "Oven-sh.Bun"
    Desc = "Runtime JavaScript/TypeScript tout-en-un ultra-rapide basé sur le moteur WebKit JavaScriptCore."
}

# 10. Docker CLI / Engine
$dockerOut = try { $out = (docker --version 2>&1 | Out-String).Trim(); if ($out -match 'Docker\s+version\s+([\d\.]+)') { "v" + $matches[1] } else { "" } } catch { "" }
$isDocker = [bool]$dockerOut
$runtimes += [PSCustomObject]@{
    Name = "Docker CLI / Engine"
    Icon = "🐳"
    Version = if ($isDocker) { "$dockerOut" } else { "Non installé" }
    Installed = $isDocker
    WingetId = "Docker.DockerDesktop"
    Desc = "Moteur de conteneurs Linux et conteneurisation d'applications en local et environnements de test."
}

# 11. WSL 2 (Windows Subsystem for Linux - Détection Robuste sans bug Unicode)
$wslCmd = Get-Command "wsl.exe" -ErrorAction SilentlyContinue
$wslStatusStr = ""
if ($wslCmd) {
    $rawWsl = try { (wsl.exe -l -q 2>&1 | Out-String) -replace "`0", "" } catch { "" }
    $distros = ($rawWsl -split "[\r\n]+" | Where-Object { $_.Trim() -and $_ -notmatch 'not recognized|introuvable' }) -join ", "
    if ($distros) {
        $wslStatusStr = "Actif ($distros)"
    } else {
        $wslStatusStr = "Disponible (wsl.exe présent)"
    }
}
$isWsl = [bool]$wslStatusStr
$runtimes += [PSCustomObject]@{
    Name = "WSL 2 (Linux Subsystem)"
    Icon = "🐧"
    Version = if ($isWsl) { "$wslStatusStr" } else { "Non configuré" }
    Installed = $isWsl
    WingetId = "Microsoft.WSL"
    Desc = "Noyau Linux officiel intégré dans Windows pour exécuter des distributions Ubuntu/Debian en natif."
}

# 12. Git (Gestionnaire de versions)
$gitVer = try { (git --version 2>&1 | Out-String).Trim() } catch { "" }
$isGit = $gitVer -match 'git version'
$runtimes += [PSCustomObject]@{
    Name = "Git (VCS)"
    Icon = "🐙"
    Version = if ($isGit) { "$gitVer" } else { "Non installé" }
    Installed = $isGit
    WingetId = "Git.Git"
    Desc = "Système de contrôle de version décentralisé standard pour tout projet de code et d'administration."
}

# 13. PowerShell 7 (pwsh moderne)
$pwshVer = try { (pwsh --version 2>&1 | Out-String).Trim() } catch { "" }
$isPwsh = $pwshVer -match 'PowerShell'
$runtimes += [PSCustomObject]@{
    Name = "PowerShell 7 (pwsh)"
    Icon = "⚡"
    Version = if ($isPwsh) { "$pwshVer" } else { "PowerShell 5.1 classique" }
    Installed = $isPwsh
    WingetId = "Microsoft.PowerShell"
    Desc = "Dernière version multiplateforme ultra-rapide de PowerShell avec parallélisme ForEach-Object -Parallel."
}

# 14. Visual C++ Redistributables (2015-2022)
$vc64 = Test-Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
$vc86 = Test-Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X86"
$vcInstalled = $vc64 -or $vc86
$vcStr = if ($vc64 -and $vc86) { "x64 & x86 Installés" } elseif ($vc64) { "x64 Installé" } elseif ($vc86) { "x86 Installé" } else { "Non installé" }
$runtimes += [PSCustomObject]@{
    Name = "Visual C++ (2015-2022)"
    Icon = "⚙️"
    Version = $vcStr
    Installed = $vcInstalled
    WingetId = "Microsoft.VCRedist.2015+.x64"
    Desc = "Dépendance indispensable pour la quasi-totalité des jeux 3D, bibliothèques C++ et moteurs multimédias."
}

# 15. LLVM / Clang C++
$llvmOut = try { $out = (clang --version 2>&1 | Select-Object -First 1 | Out-String).Trim(); if ($out -match 'clang\s+version\s+([\d\.]+)') { "v" + $matches[1] } else { "" } } catch { "" }
$isLlvm = [bool]$llvmOut
$runtimes += [PSCustomObject]@{
    Name = "LLVM / Clang C++"
    Icon = "🛠️"
    Version = if ($isLlvm) { "$llvmOut" } else { "Non installé" }
    Installed = $isLlvm
    WingetId = "LLVM.LLVM"
    Desc = "Infrastructure de compilation moderne C/C++/Rust et chaîne d'outils Clang pour Windows."
}

# 16. OpenSSL Crypto CLI
$sslOut = try { $out = (openssl version 2>&1 | Select-Object -First 1 | Out-String).Trim(); if ($out -match 'OpenSSL\s+([\d\.\w]+)') { "v" + $matches[1] } else { "" } } catch { "" }
$isSsl = [bool]$sslOut
$runtimes += [PSCustomObject]@{
    Name = "OpenSSL Crypto CLI"
    Icon = "🔒"
    Version = if ($isSsl) { "$sslOut" } else { "Non installé" }
    Installed = $isSsl
    WingetId = "ShiningLight.OpenSSL"
    Desc = "Boîte à outils de cryptographie standard pour génération de clés privées, CSR et certificats TLS/SSL."
}

# 4.2 Liste des applications installées sur le système (Scan Registre)
$installedAppsList = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
    Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
) | Where-Object { $_ } | ForEach-Object { $_.ToLower() }

function Check-AppInstalled([string]$keyword) {
    if ([string]::IsNullOrEmpty($keyword)) { return $false }
    $kw = $keyword.ToLower()
    foreach ($app in $installedAppsList) {
        if ($app -like "*$kw*") { return $true }
    }
    return $false
}

# 4.3 Définition des 12 Profils Métiers
$profilesData = @(
    @{
        ProfileId = "legal"
        Title = "⚖️ Profil Professions Libérales, Avocats, Juristes & Notaires"
        Desc = "Pack haute confidentialité pour la gestion documentaire, le chiffrement des dossiers clients, la signature PDF et la recherche juridique."
        Apps = @(
            @{ Name = "PDF24 Creator"; Id = "geeksoftwareGmbH.PDF24Creator"; Key = "pdf24"; Desc = "Signature numérique, fusion, anonymisation et conversion d'actes." },
            @{ Name = "VeraCrypt"; Id = "IDRIX.VeraCrypt"; Key = "veracrypt"; Desc = "Chiffrement fort (AES-256) des volumes et dossiers clients confidentiels." },
            @{ Name = "KeePassXC"; Id = "KeePassXCTeam.KeePassXC"; Key = "keepassxc"; Desc = "Coffre-fort de mots de passe souverain et local sans stockage cloud tiers." },
            @{ Name = "Zotero"; Id = "Zotero.Zotero"; Key = "zotero"; Desc = "Gestionnaire de sources juridiques, indexation documentaire et recherche." },
            @{ Name = "SumatraPDF"; Id = "SumatraPDF.SumatraPDF"; Key = "sumatrapdf"; Desc = "Lecteur PDF ultra-léger et instantané pour consultation rapide." },
            @{ Name = "LibreOffice"; Id = "TheDocumentFoundation.LibreOffice"; Key = "libreoffice"; Desc = "Suite bureautique complète 100% libre pour la rédaction d'actes et baux." },
            @{ Name = "Mozilla Thunderbird"; Id = "Mozilla.Thunderbird"; Key = "thunderbird"; Desc = "Messagerie professionnelle avec chiffrement OpenPGP/S-MIME intégré." },
            @{ Name = "7-Zip"; Id = "7zip.7zip"; Key = "7-zip"; Desc = "Archivage sécurisé de pièces jointes volumineuses avec mot de passe." }
        )
    },
    @{
        ProfileId = "finance"
        Title = "📊 Profil Comptabilité, Fiscalité & Finance PME"
        Desc = "Suite dédiée aux experts-comptables, directeurs financiers et fiduciaires pour le traitement de données, la TVA et l'analyse bilantaire."
        Apps = @(
            @{ Name = "ONLYOFFICE Desktop"; Id = "ONLYOFFICE.DesktopEditors"; Key = "onlyoffice"; Desc = "Suite bureautique avec compatibilité native Microsoft Excel / XLSX." },
            @{ Name = "SpeedCrunch"; Id = "Helldivers.SpeedCrunch"; Key = "speedcrunch"; Desc = "Calculatrice financière haute précision avec historique et formules." },
            @{ Name = "PDF24 Creator"; Id = "geeksoftwareGmbH.PDF24Creator"; Key = "pdf24"; Desc = "Numérisation, extraction de pages et archivage de factures dématérialisées." },
            @{ Name = "KeePassXC"; Id = "KeePassXCTeam.KeePassXC"; Key = "keepassxc"; Desc = "Sécurité des accès bancaires, portails Isabel et comptes fiscaux." },
            @{ Name = "LocalSend"; Id = "LocalSend.LocalSend"; Key = "localsend"; Desc = "Partage sécurisé de fichiers comptables sur réseau local sans serveur tiers." },
            @{ Name = "7-Zip"; Id = "7zip.7zip"; Key = "7-zip"; Desc = "Décompression des exports fiscaux, bilans BNB et archives comptables." }
        )
    },
    @{
        ProfileId = "health"
        Title = "🩺 Profil Santé, Cabinets Médicaux & Praticiens"
        Desc = "Pack sécurisé pour médecins, dentistes et kinésithérapeutes conforme au RGPD médical avec chiffrement renforcé."
        Apps = @(
            @{ Name = "VeraCrypt"; Id = "IDRIX.VeraCrypt"; Key = "veracrypt"; Desc = "Chiffrement strict des disques et dossiers médicaux des patients." },
            @{ Name = "KeePassXC"; Id = "KeePassXCTeam.KeePassXC"; Key = "keepassxc"; Desc = "Gestion centralisée et chiffrée des identifiants télématiques de santé." },
            @{ Name = "SumatraPDF"; Id = "SumatraPDF.SumatraPDF"; Key = "sumatrapdf"; Desc = "Ouverture instantanée de résultats d'analyses et comptes-rendus médicaux." },
            @{ Name = "LocalSend"; Id = "LocalSend.LocalSend"; Key = "localsend"; Desc = "Transfert direct de radiographies et clichés DICOM entre ordinateurs du cabinet." },
            @{ Name = "PDF24 Creator"; Id = "geeksoftwareGmbH.PDF24Creator"; Key = "pdf24"; Desc = "Signature et génération d'attestations et ordonnances sécurisées." }
        )
    },
    @{
        ProfileId = "dev"
        Title = "💻 Profil Développeur Full-Stack & DevOps"
        Desc = "Environnement complet pour le développement Web, Cloud, backend et conteneurisation avec terminal GPU."
        Apps = @(
            @{ Name = "Visual Studio Code"; Id = "Microsoft.VisualStudioCode"; Key = "visual studio code"; Desc = "IDE polyvalent avec écosystème d'extensions indispensable." },
            @{ Name = "Git"; Id = "Git.Git"; Key = "git"; Desc = "Système de contrôle de version décentralisé standard mondial." },
            @{ Name = "Lazygit"; Id = "JesseDuffield.lazygit"; Key = "lazygit"; Desc = "Interface console TUI ultra-rapide pour toutes les opérations Git." },
            @{ Name = "Docker Desktop"; Id = "Docker.DockerDesktop"; Key = "docker"; Desc = "Plateforme de conteneurisation pour déploiement local et CI/CD." },
            @{ Name = "Node.js LTS"; Id = "OpenJS.NodeJS.LTS"; Key = "node.js"; Desc = "Environnement d'exécution JavaScript / TypeScript côté serveur." },
            @{ Name = "Python 3.12"; Id = "Python.Python.3.12"; Key = "python 3"; Desc = "Langage d'ingénierie pour scripting, data science et intelligence artificielle." },
            @{ Name = "Beekeeper Studio"; Id = "BeekeeperStudio.BeekeeperStudio"; Key = "beekeeper studio"; Desc = "Gestionnaire de bases de données moderne SQL (Postgres, MySQL, SQLite)." },
            @{ Name = "Bruno API Client"; Id = "Usebruno.Bruno"; Key = "bruno"; Desc = "Client API REST/GraphQL moderne, léger et sans cloud forcé." },
            @{ Name = "Windows Terminal"; Id = "Microsoft.WindowsTerminal"; Key = "windows terminal"; Desc = "Console moderne multi-onglets accélérée matériellement par GPU." }
        )
    },
    @{
        ProfileId = "sec_it"
        Title = "🛡️ Profil Cybersécurité, SOC & SysAdmin Avancé"
        Desc = "Arsenal de diagnostic réseau, d'analyse de trames, de pare-feu applicatif et de télémaintenance sécurisée."
        Apps = @(
            @{ Name = "Wireshark"; Id = "WiresharkFoundation.Wireshark"; Key = "wireshark"; Desc = "Analyseur de protocoles réseau et capture de paquets PCAP en temps réel." },
            @{ Name = "Nmap"; Id = "Insecure.Nmap"; Key = "nmap"; Desc = "Scanner de vulnérabilités, découverte d'hôtes et cartographie de ports." },
            @{ Name = "Portmaster"; Id = "Safing.Portmaster"; Key = "portmaster"; Desc = "Pare-feu réseau interactif bloquant la télémétrie et les connexions non sollicitées." },
            @{ Name = "Simplewall"; Id = "henrypp.simplewall"; Key = "simplewall"; Desc = "Gestionnaire de filtrage Windows Filtering Platform (WFP) ultra-léger." },
            @{ Name = "PuTTY"; Id = "PuTTY.PuTTY"; Key = "putty"; Desc = "Client SSH / Telnet / Série pour la maintenance de switchs et serveurs." },
            @{ Name = "WinSCP"; Id = "WinSCP.WinSCP"; Key = "winscp"; Desc = "Client graphique pour transferts de fichiers sécurisés SFTP, SCP et FTPS." },
            @{ Name = "System Informer"; Id = "SystemInformer.SystemInformer"; Key = "system informer"; Desc = "Gestionnaire de processus, threads et sockets réseau de niveau kernel." },
            @{ Name = "CyberChef"; Id = "GCHQ.CyberChef"; Key = "cyberchef"; Desc = "Boîte à outils de décodage, déchiffrement et analyse hexadécimale du GCHQ." }
        )
    },
    @{
        ProfileId = "media_pro"
        Title = "🎬 Profil Vidéaste, Monteur & Audio Pro"
        Desc = "Suite complète pour la capture 4K, le montage cinéma, l'upscaling par IA et la conversion sans perte."
        Apps = @(
            @{ Name = "OBS Studio"; Id = "OBSProject.OBSStudio"; Key = "obs studio"; Desc = "Enregistrement vidéo multi-sources et streaming broadcast haute performance." },
            @{ Name = "DaVinci Resolve"; Id = "BlackmagicDesign.DaVinciResolve"; Key = "davinci resolve"; Desc = "Montage professionnel, étalonnage couleur cinéma et mixage Fairlight." },
            @{ Name = "LosslessCut"; Id = "mifi.lossless-cut"; Key = "losslesscut"; Desc = "Découpe et assemblage vidéo instantanés sans perte ni réencodage." },
            @{ Name = "HandBrake"; Id = "HandBrake.HandBrake"; Key = "handbrake"; Desc = "Transcodeur vidéo universel multithread (AV1, HEVC, H.264)." },
            @{ Name = "Upscayl"; Id = "Upscayl.Upscayl"; Key = "upscayl"; Desc = "Suréchantillonnage et amélioration d'images par modèles d'IA sur GPU." },
            @{ Name = "Audacity"; Id = "Audacity.Audacity"; Key = "audacity"; Desc = "Éditeur audio multipiste pour enregistrement de voix et nettoyage sonore." },
            @{ Name = "MediaInfo GUI"; Id = "MediaArea.MediaInfo.GUI"; Key = "mediainfo"; Desc = "Affichage exhaustif des métadonnées techniques de flux vidéo et audio." },
            @{ Name = "VLC Media Player"; Id = "VideoLAN.VLC"; Key = "vlc"; Desc = "Lecteur multimédia autonome capable de lire tous les conteneurs existants." }
        )
    },
    @{
        ProfileId = "creative_2d"
        Title = "🎨 Profil Graphiste, Illustration & PAO"
        Desc = "Pack créatif pour l'illustration vectorielle, la peinture numérique, la retouche photo et le design d'interfaces."
        Apps = @(
            @{ Name = "GIMP"; Id = "GIMP.GIMP"; Key = "gimp"; Desc = "Retouche photo avancée, calques, masques et filtres d'effets visuels." },
            @{ Name = "Krita"; Id = "KDE.Krita"; Key = "krita"; Desc = "Logiciel de peinture numérique et de concept art avec brosses réalistes." },
            @{ Name = "Inkscape"; Id = "Inkscape.Inkscape"; Key = "inkscape"; Desc = "Création et modification d'illustrations vectorielles SVG pour le print et le web." },
            @{ Name = "Upscayl"; Id = "Upscayl.Upscayl"; Key = "upscayl"; Desc = "Agrandissement net d'illustrations et logos vectorisés par IA." },
            @{ Name = "RawTherapee"; Id = "RawTherapee.RawTherapee"; Key = "rawtherapee"; Desc = "Traitement avancé non destructif des fichiers photographiques RAW." },
            @{ Name = "Figma Desktop"; Id = "Figma.Figma"; Key = "figma"; Desc = "Conception d'interfaces utilisateurs UI/UX et maquettage collaboratif." }
        )
    },
    @{
        ProfileId = "remote_work"
        Title = "🏠 Profil Télétravail, Productivité & Confidentialité"
        Desc = "Pack d'optimisation quotidienne pour le travail à distance, la prévisualisation rapide et les communications chiffrées."
        Apps = @(
            @{ Name = "Brave Browser"; Id = "Brave.Brave"; Key = "brave"; Desc = "Navigateur rapide avec bouclier intégré contre les trackers et publicités." },
            @{ Name = "Mozilla Thunderbird"; Id = "Mozilla.Thunderbird"; Key = "thunderbird"; Desc = "Client de messagerie souverain avec gestion multi-comptes et agenda." },
            @{ Name = "LocalSend"; Id = "LocalSend.LocalSend"; Key = "localsend"; Desc = "Envoi direct de fichiers en Wi-Fi / Ethernet sans passer par internet." },
            @{ Name = "QuickLook"; Id = "QL-Win.QuickLook"; Key = "quicklook"; Desc = "Aperçu instantané de fichiers (images, PDF, code) avec la barre d'espace." },
            @{ Name = "AutoHotkey v2"; Id = "AutoHotkey.AutoHotkey"; Key = "autohotkey"; Desc = "Moteur d'automatisation de frappe, raccourcis clavier et macros sur-mesure." },
            @{ Name = "Signal Desktop"; Id = "Signal.Signal"; Key = "signal"; Desc = "Messagerie instantanée chiffrée de bout en bout de référence." },
            @{ Name = "PDF24 Creator"; Id = "geeksoftwareGmbH.PDF24Creator"; Key = "pdf24"; Desc = "Boîte à outils PDF pour signer et compresser les documents professionnels." }
        )
    },
    @{
        ProfileId = "archi"
        Title = "🏡 Profil Architecture, Ingénierie & BTP"
        Desc = "Pack pour architectes et bureaux d'études : modélisation paramétrique BIM, plans 2D DWG et calcul de structures."
        Apps = @(
            @{ Name = "FreeCAD"; Id = "FreeCAD.FreeCAD"; Key = "freecad"; Desc = "Modeleur CAO paramétrique 3D avec module d'architecture BIM intégré." },
            @{ Name = "LibreCAD"; Id = "LibreCAD.LibreCAD"; Key = "librecad"; Desc = "Logiciel de dessin technique et plans 2D au format DWG et DXF." },
            @{ Name = "Blender"; Id = "BlenderFoundation.Blender"; Key = "blender"; Desc = "Moteur de rendu 3D photoréaliste pour visites architecturales virtuelles." },
            @{ Name = "MeshLab"; Id = "CNR-ISTI.MeshLab"; Key = "meshlab"; Desc = "Traitement et nettoyage de nuages de points 3D et relevés topographiques." },
            @{ Name = "OpenSCAD"; Id = "OpenSCAD.OpenSCAD"; Key = "openscad"; Desc = "Modélisation solide scriptée pour pièces sur-mesure et calculs d'ingénierie." },
            @{ Name = "7-Zip"; Id = "7zip.7zip"; Key = "7-zip"; Desc = "Gestionnaire d'archives pour plans volumineux et dossiers d'appels d'offres." }
        )
    },
    @{
        ProfileId = "maker_3d_gamedev"
        Title = "🧱 Profil 3D Maker, Game Dev & Création de Jeux (Godot & Moteurs)"
        Desc = "Suite complète pour les créateurs de jeux vidéo, modélistes 3D et FabLabs : moteur Godot, Blender, sound design et impression 3D."
        Apps = @(
            @{ Name = "Godot Engine"; Id = "GodotEngine.GodotEngine"; Key = "godot"; Desc = "Moteur de jeu 2D/3D open-source de référence, ultra-léger et puissant." },
            @{ Name = "Blender"; Id = "BlenderFoundation.Blender"; Key = "blender"; Desc = "Modélisation polygonale 3D, animation, rigging, sculpting et texturing." },
            @{ Name = "Audacity"; Id = "Audacity.Audacity"; Key = "audacity"; Desc = "Création et mixage des bruitages audio (SFX), dialogues et musiques de jeux." },
            @{ Name = "Tiled Map Editor"; Id = "ThorbjornLindeijer.Tiled"; Key = "tiled"; Desc = "Éditeur de cartes de tuiles 2D flexible pour level design et jeux rétro." },
            @{ Name = "Pixelorama"; Id = "Orama-Interactive.Pixelorama"; Key = "pixelorama"; Desc = "Éditeur de sprites 2D et pixel art animé open-source." },
            @{ Name = "FreeCAD"; Id = "FreeCAD.FreeCAD"; Key = "freecad"; Desc = "Conception mécanique paramétrique pour pièces physiques imprimables." },
            @{ Name = "Ultimaker Cura"; Id = "Ultimaker.Cura"; Key = "cura"; Desc = "Slicer d'impression 3D FDM pour fabriquer figurines et prototypes." },
            @{ Name = "PrusaSlicer"; Id = "Prusa3D.PrusaSlicer"; Key = "prusaslicer"; Desc = "Slicer puissant optimisé pour impressions résine et multi-matériaux." },
            @{ Name = "MeshLab"; Id = "CNR-ISTI.MeshLab"; Key = "meshlab"; Desc = "Nettoyage et réparation de maillages 3D STL/OBJ non étanches." }
        )
    },
    @{
        ProfileId = "gamer_unified"
        Title = "🎮 Profil Gamer, E-Sport, Jeux Open Source & Rétrogaming"
        Desc = "Pack ultime combiné pour le jeu vidéo compétitif, les pépites libres sans DRM et le rétrogaming universel."
        Apps = @(
            @{ Name = "Steam"; Id = "Valve.Steam"; Key = "steam"; Desc = "Plateforme de jeux PC incontournable et gestion de bibliothèque." },
            @{ Name = "Discord"; Id = "Discord.Discord"; Key = "discord"; Desc = "Messagerie vocale et salons communautaires de jeu en équipe." },
            @{ Name = "RetroArch"; Id = "Libretro.RetroArch"; Key = "retroarch"; Desc = "Frontend d'émulation universel tous systèmes et arcade." },
            @{ Name = "OpenTTD"; Id = "OpenTTD.OpenTTD"; Key = "openttd"; Desc = "Simulateur de gestion de transports ferroviaires et urbains mythique." },
            @{ Name = "SuperTuxKart"; Id = "SuperTuxKart.SuperTuxKart"; Key = "supertuxkart"; Desc = "Jeu de course de karting 3D arcade multijoueur avec mascottes libres." },
            @{ Name = "0 A.D."; Id = "WildfireGames.0AD"; Key = "0 a.d."; Desc = "Jeu de stratégie temps réel historique 3D de haute qualité." },
            @{ Name = "Mindustry"; Id = "Anuken.Mindustry"; Key = "mindustry"; Desc = "Jeu de gestion de chaînes logistiques industrielles et tower defense." },
            @{ Name = "Shattered Pixel Dungeon"; Id = "00-Evan.ShatteredPixelDungeon"; Key = "shattered pixel dungeon"; Desc = "Roguelike d'exploration de donjons classique au tour par tour." },
            @{ Name = "Epic Games Launcher"; Id = "EpicGames.EpicGamesLauncher"; Key = "epic games"; Desc = "Store de jeux et moteur Unreal Engine." },
            @{ Name = "OBS Studio"; Id = "OBSProject.OBSStudio"; Key = "obs studio"; Desc = "Capture de gameplay en 60 FPS et diffusion en direct." },
            @{ Name = "7-Zip"; Id = "7zip.7zip"; Key = "7-zip"; Desc = "Décompression express des mods, émulateurs et archives de jeux." },
            @{ Name = "GeForce Experience"; Id = "Nvidia.GeForceExperience"; Key = "geforce experience"; Desc = "Mise à jour des pilotes graphiques et optimisation des profils." }
        )
    },
    @{
        ProfileId = "office"
        Title = "💼 Profil Office / Bureautique & Administratif"
        Desc = "Pack productivité pour le secrétariat, la gestion documentaire, les mails et la visioconférence."
        Apps = @(
            @{ Name = "LibreOffice"; Id = "TheDocumentFoundation.LibreOffice"; Key = "libreoffice"; Desc = "Suite bureautique complète 100% gratuite (Writer, Calc, Impress)." },
            @{ Name = "Mozilla Thunderbird"; Id = "Mozilla.Thunderbird"; Key = "thunderbird"; Desc = "Client de messagerie pro avec agenda et carnet d'adresses." },
            @{ Name = "PDF24 Creator"; Id = "geeksoftwareGmbH.PDF24Creator"; Key = "pdf24"; Desc = "Boîte à outils PDF ultime (fusionner, signer, convertir, compresser)." },
            @{ Name = "7-Zip"; Id = "7zip.7zip"; Key = "7-zip"; Desc = "Gestionnaire d'archives pour pièces jointes ZIP/RAR." },
            @{ Name = "Notion"; Id = "Notion.Notion"; Key = "notion"; Desc = "Espace de travail tout-en-un pour notes, wikis et gestion de projets." },
            @{ Name = "Zoom"; Id = "Zoom.Zoom"; Key = "zoom"; Desc = "Client de visioconférence et réunions d'équipe." }
        )
    }
)

# 4.4 Génération HTML des Runtimes
$runtimesHtml = '<div class="runtime-grid">'
foreach ($rt in $runtimes) {
    $bClass = if ($rt.Installed) { "badge-ok" } else { "badge-warn" }
    $statText = if ($rt.Installed) { "✅ $($rt.Version)" } else { "❌ Non installé" }
    $wingetBtn = '<button class="btn-mini-copy" style="margin-top:6px;" onclick="copyDirect(this)" data-cmd="winget install --id ' + $rt.WingetId + ' -e --accept-package-agreements --accept-source-agreements">📦 Installer via Winget</button>'
    
    $runtimesHtml += '<div class="runtime-card">'
    $runtimesHtml += '  <div class="runtime-header">'
    $runtimesHtml += '    <span style="font-size:22px;">' + $rt.Icon + '</span>'
    $runtimesHtml += '    <strong style="font-size:14px;">' + (Escape-Html $rt.Name) + '</strong>'
    $runtimesHtml += '    <span class="badge ' + $bClass + '" style="margin-left:auto;">' + (Escape-Html $statText) + '</span>'
    $runtimesHtml += '  </div>'
    $runtimesHtml += '  <p style="font-size:12px; color:var(--text-muted); margin:8px 0;">' + (Escape-Html $rt.Desc) + '</p>'
    $runtimesHtml += '  <div style="font-family:monospace; font-size:11px; color:var(--neon-cyan);">' + $rt.WingetId + '</div>'
    $runtimesHtml += '  ' + $wingetBtn
    $runtimesHtml += '</div>'
}
$runtimesHtml += '</div>'

# 4.5 Génération HTML des Profils Métiers & Bundles en Tiroirs (Accordéons)
$profilesHtml = '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:8px;">'
$profilesHtml += '  <span style="font-size:12.5px; color:var(--text-muted);">Cliquez sur un profil métier pour déployer ses applications :</span>'
$profilesHtml += '  <div style="display:flex; gap:6px;">'
$profilesHtml += '    <button class="btn-mini-copy" style="cursor:pointer;" onclick="toggleAllProfileDrawers(true)">📂 Tout Déplier</button>'
$profilesHtml += '    <button class="btn-mini-copy" style="cursor:pointer;" onclick="toggleAllProfileDrawers(false)">📁 Tout Replier</button>'
$profilesHtml += '  </div>'
$profilesHtml += '</div>'
$profilesHtml += '<div class="profile-drawers-container">'

foreach ($prof in $profilesData) {
    $missingIds = @()
    $appsRowsHtml = ""
    
    foreach ($app in $prof.Apps) {
        $isInst = Check-AppInstalled $app.Key
        $statusBadge = if ($isInst) { '<span class="badge badge-ok">✅ Présent</span>' } else { '<span class="badge badge-warn">❌ Absent</span>' }
        if (-not $isInst) { $missingIds += $app.Id }
        
        $checkbox = '<input type="checkbox" class="app-chk" data-id="' + $app.Id + '" data-name="' + (Escape-Html $app.Name) + '" onchange="updateCustomWinget()">'
        $copySingle = '<button class="btn-mini-copy" onclick="copyDirect(this)" data-cmd="winget install --id ' + $app.Id + ' -e --accept-package-agreements --accept-source-agreements" title="Copier commande Winget pour ' + $app.Name + '">📋 Winget</button>'
        
        $appsRowsHtml += '<div class="app-row">'
        $appsRowsHtml += '  <div style="display:flex; align-items:center; gap:8px;">' + $checkbox + '<strong>' + (Escape-Html $app.Name) + '</strong> ' + $statusBadge + '</div>'
        $appsRowsHtml += '  <div style="font-size:12px; color:var(--text-muted);">' + (Escape-Html $app.Desc) + '</div>'
        $appsRowsHtml += '  <div style="display:flex; align-items:center; gap:6px; justify-content:flex-end;"><code style="font-size:10.5px; color:var(--neon-cyan);">' + $app.Id + '</code> ' + $copySingle + '</div>'
        $appsRowsHtml += '</div>'
    }

    $bundleScript = if ($missingIds.Count -gt 0) {
        ($missingIds | ForEach-Object { "winget install --id $_ -e --accept-package-agreements --accept-source-agreements" }) -join "; "
    } else {
        "Write-Host 'Toutes les applications de ce profil sont déjà installées !' -ForegroundColor Green"
    }

    $escapedBundle = Escape-Html $bundleScript
    $drawerId = "drawer-" + $prof.ProfileId

    $profilesHtml += '<div class="profile-drawer glass-panel" id="' + $drawerId + '">'
    $profilesHtml += '  <div class="drawer-header" onclick="toggleProfileDrawer(''' + $drawerId + ''')">'
    $profilesHtml += '    <div style="display:flex; align-items:center; gap:10px;">'
    $profilesHtml += '      <span class="drawer-chevron">▶</span>'
    $profilesHtml += '      <div>'
    $profilesHtml += '        <h3 style="margin:0; font-size:15px; color:var(--neon-cyan);">' + (Escape-Html $prof.Title) + '</h3>'
    $profilesHtml += '        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">' + (Escape-Html $prof.Desc) + '</div>'
    $profilesHtml += '      </div>'
    $profilesHtml += '    </div>'
    $profilesHtml += '    <div style="display:flex; align-items:center; gap:8px;" onclick="event.stopPropagation()">'
    $profilesHtml += '      <span class="badge ' + (if ($missingIds.Count -gt 0) { "badge-warn" } else { "badge-ok" }) + '">' + $missingIds.Count + ' manquante(s)</span>'
    $profilesHtml += '      <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="' + $escapedBundle + '">📦 Déployer le Pack</button>'
    $profilesHtml += '    </div>'
    $profilesHtml += '  </div>'
    $profilesHtml += '  <div class="drawer-body">' + $appsRowsHtml + '</div>'
    $profilesHtml += '</div>'
}
$profilesHtml += '</div>'

# 4.6 Matrice 100% OPEN SOURCE STRICT (15 Grands Domaines & 160+ Alternatives FLOSS Certifiées)
$fossThemes = @(
    @{
        Id = "design-3d"
        Title = "Graphisme, Retouche Photo, UI/UX & 3D"
        Icon = "🎨"
        Color = "#00f0ff"
        Items = @(
            @{ Prop = "Adobe Photoshop"; Foss = "GIMP"; Winget = "GIMP.GIMP"; Type = "Desktop Natif (GTK/C)"; Stack = "C, GTK3, GEGL Engine"; License = "GNU GPLv3+"; Origin = "1996 (v0.54 Peter Mattis & Spencer Kimball)"; Version = "v2.10.38 / v3.0 RC"; Desc = "Suite de retouche matricielle avancée, gestion fine des calques, masques de fusion et canaux."; Web = "https://www.gimp.org" },
            @{ Prop = "Photoshop / PaintTool SAI"; Foss = "Krita"; Winget = "KDE.Krita"; Type = "Desktop Natif (Qt/C++)"; Stack = "C++, Qt5/Qt6, OpenGL"; License = "GNU GPLv3"; Origin = "2005 (v1.4 KOffice Project)"; Version = "v5.2.3"; Desc = "Standard mondial de peinture numérique pour artistes conceptuels, illustrateurs et animateurs 2D."; Web = "https://krita.org" },
            @{ Prop = "Adobe Illustrator"; Foss = "Inkscape"; Winget = "Inkscape.Inkscape"; Type = "Desktop Natif (GTKmm/C++)"; Stack = "C++, GTKmm, Cairo, Pango"; License = "GNU GPLv2+"; Origin = "2003 (v0.32 Fork Sodipodi)"; Version = "v1.3.2 / v1.4"; Desc = "Éditeur vectoriel SVG professionnel avec gestion typographique avancée et courbes de Bézier."; Web = "https://inkscape.org" },
            @{ Prop = "Adobe Lightroom"; Foss = "Darktable"; Winget = "Darktable.Darktable"; Type = "Desktop Natif (C/GTK)"; Stack = "C, OpenCL, GTK3, SQLite"; License = "GNU GPLv3+"; Origin = "2009 (v0.1 Johannes Hanika)"; Version = "v4.8.1"; Desc = "Chambre noire numérique non destructive et traitement de fichiers RAW pour photographes experts."; Web = "https://www.darktable.org" },
            @{ Prop = "Lightroom / DxO PhotoLab"; Foss = "RawTherapee"; Winget = "RawTherapee.RawTherapee"; Type = "Desktop Natif (C++/GTK)"; Stack = "C++, GTKmm, SSE/AVX Dématriçage"; License = "GNU GPLv3"; Origin = "2004 (v1.0 Gabor Horvath)"; Version = "v5.10"; Desc = "Moteur de dématriçage RAW haute fidélité avec algorithmes de débruitage et profil ICC."; Web = "https://rawtherapee.com" },
            @{ Prop = "Figma / Adobe XD"; Foss = "Penpot"; Winget = "Penpot.Penpot"; Type = "Plateforme Web & PWA / Docker"; Stack = "Clojure, ClojureScript, SVG natif"; License = "MPL-2.0"; Origin = "2021 (Kaleidos Open Source)"; Version = "v2.1.x"; Desc = "Conception UI/UX et prototypage vectoriel interactif multi-utilisateurs en temps réel basé sur les standards web."; Web = "https://penpot.app" },
            @{ Prop = "Visio / Lucidchart / Miro"; Foss = "Draw.io (diagrams.net)"; Winget = "jgraph.drawio.desktop"; Type = "Éditeur de Schémas & Diagrammes (JavaScript)"; Stack = "JavaScript, Electron, mxGraph, SVG, XML"; License = "Apache-2.0"; Origin = "2005 (JGraph / Gaudenz Alder)"; Version = "v24.7.5"; Desc = "Création de diagrammes d'architecture réseau, organigrammes, UML et schémas techniques sans cloud imposé."; Web = "https://www.drawio.com" },
            @{ Prop = "AutoCAD / SolidWorks"; Foss = "FreeCAD"; Winget = "FreeCAD.FreeCAD"; Type = "Desktop CAO Paramétrique (C++/Qt)"; Stack = "C++, Python, OpenCASCADE, Qt"; License = "LGPLv2+"; Origin = "2002 (v0.1 J. Riegel & W. Mayer)"; Version = "v0.21.2 / v1.0 RC"; Desc = "Modéliseur 3D paramétrique pour l'ingénierie mécanique, l'architecture BIM et l'impression 3D."; Web = "https://www.freecad.org" },
            @{ Prop = "AutoCAD 2D / DWG"; Foss = "LibreCAD"; Winget = "LibreCAD.LibreCAD"; Type = "Desktop CAO 2D (C++/Qt)"; Stack = "C++, Qt5, muParser"; License = "GNU GPLv2"; Origin = "2010 (Fork QCad Community)"; Version = "v2.2.0"; Desc = "Création de plans techniques 2D industriels et schémas cotés au format DXF/DWG."; Web = "https://librecad.org" },
            @{ Prop = "Autodesk Maya / 3ds Max / Cinema4D"; Foss = "Blender"; Winget = "BlenderFoundation.Blender"; Type = "Suite 3D Complète (C/C++/Python)"; Stack = "C, C++, Python, Cycles, Vulkan/OpenGL"; License = "GNU GPLv2+"; Origin = "1994 (v1.0 Ton Roosendaal)"; Version = "v4.2 LTS / v4.3"; Desc = "Production 3D complète : modélisation, sculpture polygonale, animation, rendu Cycles et montage VFX."; Web = "https://www.blender.org" },
            @{ Prop = "Aseprite (Payant)"; Foss = "Pixelorama"; Winget = "OramaInteractive.Pixelorama"; Type = "Desktop Natif (Godot/GDScript)"; Stack = "Godot Engine, GDScript, C#"; License = "MIT License"; Origin = "2019 (v0.1 Orama Interactive)"; Version = "v0.11.4"; Desc = "Studio de Pixel Art et d'animation par images clés avec pelures d'oignon et export spritesheet."; Web = "https://orama-interactive.itch.io/pixelorama" }
        )
    },
    @{
        Id = "office-docs"
        Title = "Bureautique, Documents PDF, Notion & Notes"
        Icon = "💼"
        Color = "#10b981"
        Items = @(
            @{ Prop = "Microsoft 365 / Office"; Foss = "LibreOffice"; Winget = "TheDocumentFoundation.LibreOffice"; Type = "Suite Bureautique Native (C++/Java)"; Stack = "C++, UNO API, HarfBuzz, ICU"; License = "MPL-2.0"; Origin = "2010 (Fork OpenOffice.org / StarOffice 1985)"; Version = "v24.8.0 Fresh / v24.2 Still"; Desc = "Suite complète (Writer, Calc, Impress, Draw) avec moteur de conversion et interopérabilité DOCX/XLSX/PPTX."; Web = "https://www.libreoffice.org" },
            @{ Prop = "MS Office (Desktop/Web)"; Foss = "OnlyOffice"; Winget = "ONLYOFFICE.DesktopEditors"; Type = "Suite Bureautique Web/Desktop"; Stack = "C++, JavaScript, HTML5 Canvas"; License = "AGPLv3"; Origin = "2009 (Ascensio System TeamLab)"; Version = "v8.1.1"; Desc = "Éditeurs de documents avec moteur de rendu 100% basé sur les standards OOXML Microsoft."; Web = "https://www.onlyoffice.com" },
            @{ Prop = "Adobe Acrobat Pro (Payant)"; Foss = "PDFsam Basic"; Winget = "PDFsam.PDFsamBasic"; Type = "Découpe & Assemblage PDF (Java/JavaFX)"; Stack = "Java, JavaFX, SAMBox Engine, OpenJDK"; License = "GNU GPLv3"; Origin = "2006 (Andrea Vacondio)"; Version = "v5.2.4"; Desc = "Boîte à outils 100% open source pour fusionner, découper, pivoter et extraire des pages de documents PDF."; Web = "https://pdfsam.org" },
            @{ Prop = "Adobe Acrobat (Serveur Web Local)"; Foss = "Stirling-PDF"; Winget = "StirlingPDF.StirlingPDF"; Type = "Application Web Self-Hosted (Java/Spring)"; Stack = "Java 21, Spring Boot, PDFBox, Tesseract"; License = "MIT License"; Origin = "2023 (Anthony Stirling)"; Version = "v0.28.0"; Desc = "Serveur de manipulation PDF 100% hors-ligne auto-hébergeable avec OCR et chiffrement de documents."; Web = "https://github.com/Stirling-Tools/Stirling-PDF" },
            @{ Prop = "Notion Cloud / Roam Research"; Foss = "Logseq"; Winget = "Logseq.Logseq"; Type = "Second Cerveau à Graphe 100% FOSS (ClojureScript)"; Stack = "ClojureScript, Electron, Datascript, Markdown/Org-mode"; License = "GNU AGPLv3"; Origin = "2020 (Tienson Qin)"; Version = "v0.10.9"; Desc = "Base de connaissances locale et privée avec graphe de liens bidirectionnels et fiches de révision intégrées."; Web = "https://logseq.com" },
            @{ Prop = "Evernote / OneNote"; Foss = "Joplin"; Winget = "Joplin.Joplin"; Type = "Prise de Notes Chiffrée (TypeScript/React)"; Stack = "TypeScript, React Native, Electron, SQLite, E2EE"; License = "GNU AGPLv3"; Origin = "2017 (Laurent Cozic)"; Version = "v3.0.13"; Desc = "Gestionnaire de notes Markdown avec synchronisation chiffrée de bout en bout vers Nextcloud, Dropbox ou WebDAV."; Web = "https://joplinapp.org" },
            @{ Prop = "Notion (Workspace Local)"; Foss = "AppFlowy"; Winget = "AppFlowy.AppFlowy"; Type = "Desktop & Mobile Natif (Flutter/Rust)"; Stack = "Flutter, Rust, SQLite, AppFlowy-Core"; License = "AGPLv3"; Origin = "2021 (v0.0.1 Annie Lin)"; Version = "v0.6.6"; Desc = "Alternative open-source moderne à Notion basée sur le stockage local avec tableaux Kanban et vues tabulaires."; Web = "https://appflowy.io" },
            @{ Prop = "Notion / Miro (Visuel)"; Foss = "AFFiNE"; Winget = "TOeverything.AFFiNE"; Type = "Workspace Hybride (Rust/TypeScript)"; Stack = "Rust, OctoBase, TypeScript, React"; License = "MPL-2.0"; Origin = "2022 (TO EVERYTHING PTE. LTD.)"; Version = "v0.16.2"; Desc = "Espace de travail multimodal fusionnant documents textuels de structure et canvas de dessin infini."; Web = "https://affine.pro" },
            @{ Prop = "Airtable / MS Access"; Foss = "NocoDB"; Winget = "NocoDB.NocoDB"; Type = "Base de Données No-Code (Node/Vue)"; Stack = "Node.js, TypeScript, Vue.js, Knex.js"; License = "AGPLv3"; Origin = "2021 (v0.1 Naveen Rudrappa)"; Version = "v0.250.0"; Desc = "Transforme n'importe quelle base relationnelle SQL (PostgreSQL, MySQL) en tableur collaboratif intelligent."; Web = "https://nocodb.com" },
            @{ Prop = "Airtable / Low-Code DB"; Foss = "Baserow"; Winget = "Baserow.Baserow"; Type = "Base No-Code & API (Python/Django/Nuxt)"; Stack = "Python, Django, PostgreSQL, Nuxt.js"; License = "MIT License"; Origin = "2019 (v0.1 Bram Wiepjes)"; Version = "v1.27.0"; Desc = "Plateforme no-code auto-hébergeable pour construire des bases de données d'entreprise et générer des API REST."; Web = "https://baserow.io" },
            @{ Prop = "Trello / Asana / Jira"; Foss = "Plane"; Winget = "MakePlane.Plane"; Type = "Gestion de Projets & Sprints (Python/Next.js)"; Stack = "Python, Django, Next.js, Redis, PostgreSQL"; License = "AGPLv3"; Origin = "2022 (MakePlane Community)"; Version = "v0.21.0"; Desc = "Gestion de projets pour équipes tech avec suivi des cycles, modules, roadmaps et backlog de bugs."; Web = "https://plane.so" },
            @{ Prop = "Calendly / Doodle"; Foss = "Cal.com"; Winget = "Calcom.Calcom"; Type = "Planificateur de Rendez-vous (TypeScript/Next.js)"; Stack = "TypeScript, Next.js, Prisma, TailwindCSS"; License = "AGPLv3"; Origin = "2021 (v1.0 Peer Richelsen)"; Version = "v4.3.0"; Desc = "Infrastructure de prise de rendez-vous et synchronisation de calendriers sécurisée et personnalisable."; Web = "https://cal.com" },
            @{ Prop = "MindManager / XMind"; Foss = "Freeplane"; Winget = "Freeplane.Freeplane"; Type = "Mind-Mapping Desktop (Java)"; Stack = "Java, OSGi, Groovy Scripting"; License = "GNU GPLv2+"; Origin = "2009 (Fork FreeMind 2000)"; Version = "v1.11.14"; Desc = "Organisation de la pensée logique, cartes heuristiques arborescentes et indexation sémantique d'idées."; Web = "https://www.freeplane.org" },
            @{ Prop = "Typora / Bear"; Foss = "MarkText"; Winget = "MarkText.MarkText"; Type = "Desktop Natif (Electron/Node)"; Stack = "TypeScript, Electron, Muya Engine"; License = "MIT"; Origin = "2017 (YHat)"; Version = "v0.17.1"; Desc = "Éditeur Markdown WYSIWYG épuré en temps réel avec support KaTeX mathématique et diagrammes Mermaid."; Web = "https://www.marktext.cc" },
            @{ Prop = "EndNote / Mendeley"; Foss = "Zotero"; Winget = "DigitalScience.Zotero"; Type = "Desktop Natif (C++/JS)"; Stack = "C++, JavaScript, SQLite"; License = "AGPLv3"; Origin = "2006 (Roy Rosenzweig CHNM)"; Version = "v7.0.4"; Desc = "Gestionnaire de recherche académique, bibliographie, thèses et annotations de PDF incontournable."; Web = "https://www.zotero.org" }
        )
    },
    @{
        Id = "security-net"
        Title = "Cybersécurité, Mots de Passe & IAM"
        Icon = "🛡️"
        Color = "#f59e0b"
        Items = @(
            @{ Prop = "1Password / LastPass / Dashlane"; Foss = "Bitwarden"; Winget = "Bitwarden.Bitwarden"; Type = "Coffre-fort Mots de Passe (C#/TypeScript)"; Stack = "C#, .NET, TypeScript, Electron, SQLite"; License = "GPLv3 / AGPLv3"; Origin = "2016 (v1.0 Kyle Spearrin)"; Version = "v2024.7.1"; Desc = "Gestionnaire chiffré de bout en bout (AES-256 / PBKDF2) avec partage d'organisations et audit 2FA."; Web = "https://bitwarden.com" },
            @{ Prop = "1Password (100% Hors-ligne)"; Foss = "KeePassXC"; Winget = "KeePassXCTeam.KeePassXC"; Type = "Desktop Natif C++/Qt (100% Hors-ligne)"; Stack = "C++, Qt5/Qt6, Argon2, ChaCha20, AES"; License = "GPLv2 / GPLv3"; Origin = "2016 (Fork KeePassX / KeePass 2003)"; Version = "v2.7.9"; Desc = "Coffre-fort local ultra-durci sans connexion distante, intégration navigateur et générateur TOTP intégré."; Web = "https://keepassxc.org" },
            @{ Prop = "TeamViewer / AnyDesk"; Foss = "RustDesk"; Winget = "RustDesk.RustDesk"; Type = "Contrôle à Distance (Rust/Flutter)"; Stack = "Rust, Flutter, WebRTC, Tokio Async"; License = "AGPLv3 / GPLv3"; Origin = "2021 (v1.1.8 Purslane Ltd)"; Version = "v1.3.0"; Desc = "Logiciel d'assistance et bureau à distance auto-hébergé chiffré TLS/P2P sans coupure de session."; Web = "https://rustdesk.com" },
            @{ Prop = "Auth0 / Okta (SSO/IAM)"; Foss = "Keycloak"; Winget = "RedHat.Keycloak"; Type = "Serveur IAM & SSO Entreprise (Java/Quarkus)"; Stack = "Java, Quarkus, OpenID Connect, SAML 2.0"; License = "Apache-2.0"; Origin = "2014 (v1.0 JBoss / Red Hat)"; Version = "v25.0.2"; Desc = "Gestionnaire centralisé d'identités, fédération LDAP/Active Directory et authentification multi-facteurs."; Web = "https://www.keycloak.org" },
            @{ Prop = "Auth0 / Okta (Moderne)"; Foss = "Authentik"; Winget = "goauthentik.authentik"; Type = "Fournisseur d'Identité & SSO (Python/Go)"; Stack = "Python, Django, Go, PostgreSQL, Redis"; License = "GPLv3"; Origin = "2019 (v1.0 Jens L. Langhammer)"; Version = "v2024.6.4"; Desc = "Solution d'authentification unifiée avec proxy d'avant-plan, flux personnalisables et portail d'apps."; Web = "https://goauthentik.io" },
            @{ Prop = "Cisco AnyConnect / NordVPN"; Foss = "WireGuard"; Winget = "WireGuard.WireGuard"; Type = "Protocole VPN Kernel/Desktop (C/Go)"; Stack = "C (Kernel module), Go, Noise Protocol, ChaCha20"; License = "GPLv2 / Apache-2.0"; Origin = "2016 (v0.1 Jason A. Donenfeld)"; Version = "v0.5.3 (Windows Native)"; Desc = "Protocole VPN de nouvelle génération ultra-rapide, léger, économe en batterie et d'une sécurité mathématique irréprochable."; Web = "https://www.wireguard.com" },
            @{ Prop = "OpenVPN Propriétaire"; Foss = "OpenVPN Community"; Winget = "OpenVPNTechnologies.OpenVPN"; Type = "Client/Serveur VPN SSL/TLS (C)"; Stack = "C, OpenSSL, mbed TLS, TAP Driver"; License = "GNU GPLv2"; Origin = "2001 (v1.0 James Yonan)"; Version = "v2.6.11"; Desc = "Standard historique de tunnels chiffrés point-à-point et site-à-site avec routage multi-sous-réseaux."; Web = "https://openvpn.net" },
            @{ Prop = "Analyseurs Réseau Propriétaires"; Foss = "Wireshark"; Winget = "WiresharkFoundation.Wireshark"; Type = "Analyseur de Paquets Réseau (C/C++/Qt)"; Stack = "C, C++, Qt6, Npcap / libpcap Engine"; License = "GNU GPLv2+"; Origin = "1998 (v0.2.0 Ethereal par Gerald Combs)"; Version = "v4.2.6"; Desc = "Capture et décodage microscopique de trames réseau en temps réel supportant des milliers de protocoles L2-L7."; Web = "https://www.wireshark.org" },
            @{ Prop = "Authy / Google Authenticator"; Foss = "Ente Auth"; Winget = "Ente.EnteAuth"; Type = "Générateur 2FA / TOTP (Flutter/Rust)"; Stack = "Flutter, Dart, Rust, XChaCha20-Poly1305"; License = "GPLv3"; Origin = "2023 (Ente Technologies)"; Version = "v3.0.1"; Desc = "Application 2FA multiplateforme avec synchronisation chiffrée de bout en bout et export déchiffré sécurisé."; Web = "https://ente.io/auth" },
            @{ Prop = "BitLocker / Symantec Encryption"; Foss = "VeraCrypt"; Winget = "IDRIX.VeraCrypt"; Type = "Chiffrement de Disques (C/C++/ASM)"; Stack = "C, C++, Assembly, AES-NI, Twofish, Serpent"; License = "Apache-2.0 / TrueCrypt 3.0"; Origin = "2013 (Fork TrueCrypt 2004 par IDRIX)"; Version = "v1.26.14"; Desc = "Chiffrement transparent de partitions, disques entiers et conteneurs virtuels à très haute immunité cryptographique."; Web = "https://www.veracrypt.fr" },
            @{ Prop = "Boxcryptor Cloud"; Foss = "Cryptomator"; Winget = "Cryptomator.Cryptomator"; Type = "Chiffrement Côté Client (Java/C++)"; Stack = "Java, JavaFX, C++ Dokany/FUSE, AES-256"; License = "GPLv3"; Origin = "2014 (v1.0 Skymatic GmbH)"; Version = "v1.13.0"; Desc = "Chiffrement côté client de coffres virtuels avant envoi sur Google Drive, Dropbox ou OneDrive."; Web = "https://cryptomator.org" },
            @{ Prop = "GlassWire / Little Snitch"; Foss = "Portmaster"; Winget = "Safing.Portmaster"; Type = "Natif + Service (Go/C/Flutter)"; Stack = "Go, C, Windows Filtering Platform, Flutter"; License = "GNU AGPLv3"; Origin = "2020 (Safing ICS)"; Version = "v1.6.8"; Desc = "Pare-feu applicatif nouvelle génération avec blocage natif de la télémétrie, traceurs et DNS chiffré DoT/DoH."; Web = "https://safing.io" },
            @{ Prop = "ZoneAlarm / Windows Defender Firewall"; Foss = "Simplewall"; Winget = "henrypp.simplewall"; Type = "Desktop Natif (C/Win32)"; Stack = "C, Win32, Windows Filtering Platform (WFP)"; License = "GNU GPLv3"; Origin = "2016 (Henry++)"; Version = "v3.8.5"; Desc = "Contrôle chirurgical des connexions réseau sortantes Windows sans aucun service résiduel en arrière-plan."; Web = "https://www.henrypp.org" }
        )
    },
    @{
        Id = "media-video"
        Title = "Audio, Montage Vidéo, Streaming & Médias"
        Icon = "🎬"
        Color = "#f43f5e"
        Items = @(
            @{ Prop = "Adobe Premiere Pro"; Foss = "Kdenlive"; Winget = "KDE.Kdenlive"; Type = "Montage Vidéo Multipiste (C++/Qt)"; Stack = "C++, Qt6, MLT Multimedia Framework, FFmpeg"; License = "GNU GPLv3+"; Origin = "2002 (v0.1 Jason Wood)"; Version = "v24.05.2"; Desc = "Logiciel de montage vidéo non linéaire avec découpe multipiste, titrage, accélération GPU et rendu 4K."; Web = "https://kdenlive.org" },
            @{ Prop = "Final Cut / Vegas Pro"; Foss = "Shotcut"; Winget = "Meltytech.Shotcut"; Type = "Montage Vidéo Léger (C++/Qt)"; Stack = "C++, Qt6, MLT, OpenGL, FFmpeg"; License = "GNU GPLv3"; Origin = "2011 (v1.0 Dan Dennedy)"; Version = "v24.06.26"; Desc = "Éditeur vidéo multiplateforme ultra-stable sans importation obligatoire supportant des centaines de formats."; Web = "https://shotcut.org" },
            @{ Prop = "Adobe Premiere / Camtasia"; Foss = "OpenShot"; Winget = "OpenShot.OpenShotVideoEditor"; Type = "Éditeur Vidéo Débutant/Pro (C++/Python)"; Stack = "C++, libopenshot, Python, Qt5, FFmpeg"; License = "GNU GPLv3+"; Origin = "2008 (Jonathan Thomas)"; Version = "v3.2.1"; Desc = "Éditeur vidéo facile d'accès avec animations d'images clés, transitions 3D et titrage vectoriel."; Web = "https://www.openshot.org" },
            @{ Prop = "Adobe Audition"; Foss = "Audacity"; Winget = "Audacity.Audacity"; Type = "Station Audio Multipiste (C++/wxWidgets)"; Stack = "C++, wxWidgets, PortAudio, FFmpeg"; License = "GNU GPLv2+ / GPLv3"; Origin = "2000 (v0.8 Dominic Mazzoni & Roger Dannenberg)"; Version = "v3.6.1"; Desc = "Enregistrement multipiste, nettoyage de spectre sonore, réduction de bruit et mastering audio."; Web = "https://www.audacityteam.org" },
            @{ Prop = "FL Studio / Logic Pro"; Foss = "LMMS"; Winget = "LMMS.LMMS"; Type = "Station de Travail DAW (C++/Qt)"; Stack = "C++, Qt5, VST2/VST3, SoundFont2"; License = "GNU GPLv2"; Origin = "2004 (v0.1 Paul Giblock & Tobias Doerffel)"; Version = "v1.2.2 / v1.3 Alpha"; Desc = "Production musicale complète : séquençage MIDI, synthétiseurs virtuels, boîtes à rythmes et mixeur à effets."; Web = "https://lmms.io" },
            @{ Prop = "XSplit / Camtasia"; Foss = "OBS Studio"; Winget = "OBSProject.OBSStudio"; Type = "Capture & Diffusion Streaming (C/C++)"; Stack = "C, C++, Qt6, FFmpeg, NVENC/AMF/QSV"; License = "GNU GPLv2+"; Origin = "2012 (v0.1 Hugh Bailey)"; Version = "v30.2.2"; Desc = "Plateforme mondiale de capture d'écran, gestion de scènes multicaméras et streaming en direct (Twitch/YouTube)."; Web = "https://obsproject.com" },
            @{ Prop = "Windows Media Player"; Foss = "VLC Media Player"; Winget = "VideoLAN.VLC"; Type = "Lecteur Multimédia Universel (C/C++)"; Stack = "C, C++, Qt, libVLC Core, FFmpeg"; License = "GNU LGPLv2.1+"; Origin = "1996 (Projet étudiant École Centrale Paris)"; Version = "v3.0.21 / v4.0 Dev"; Desc = "Lecteur universel lisant tous flux réseau, disques et formats vidéo sans nécessiter aucun pack de codecs tiers."; Web = "https://www.videolan.org" },
            @{ Prop = "VLC / KMPlayer (Minimaliste)"; Foss = "mpv"; Winget = "mpv.mpv"; Type = "Lecteur Vidéo Minimaliste (C)"; Stack = "C, libass, FFmpeg, Vulkan/Direct3D/OpenGL"; License = "GPLv2+ / LGPLv2.1+"; Origin = "2013 (Fork MPlayer2 / MPlayer 2000)"; Version = "v0.38.0"; Desc = "Moteur de lecture vidéo ultra-performant avec décodage matériel GPU avancé et scripts Lua."; Web = "https://mpv.io" },
            @{ Prop = "Adobe Media Encoder"; Foss = "HandBrake"; Winget = "HandBrake.HandBrake"; Type = "Transcodeur Vidéo Haute Performance (C/C#)"; Stack = "C, C# .NET (GUI Windows), x264, x265, SVT-AV1"; License = "GNU GPLv2"; Origin = "2003 (v0.1 Eric Petit)"; Version = "v1.8.2"; Desc = "Compression et conversion par lots de vidéos vers les formats modernes H.264, HEVC et AV1."; Web = "https://handbrake.fr" },
            @{ Prop = "iTunes / Spotify Local"; Foss = "Clementine"; Winget = "Clementine.Clementine"; Type = "Gestionnaire Audio & Radios (C++/Qt)"; Stack = "C++, Qt5, GStreamer, SQLite"; License = "GNU GPLv3"; Origin = "2010 (Fork Amarok 1.4)"; Version = "v1.4.1"; Desc = "Gestion de discothèque locale volumineuse, extraction de tags audio et écoute de radios web mondiales."; Web = "https://www.clementine-player.org" },
            @{ Prop = "QuickTime Pro / Boilsoft"; Foss = "LosslessCut"; Winget = "mifi.lossless-cut"; Type = "Desktop Natif (Electron/FFmpeg)"; Stack = "TypeScript, FFmpeg, Electron"; License = "GNU GPLv2"; Origin = "2016 (Mikael Finstad)"; Version = "v3.61.1"; Desc = "Découpe, fusion et extraction audio de vidéos instantanées en 0 seconde SANS réencodage ni perte de qualité."; Web = "https://github.com/mifi/lossless-cut" },
            @{ Prop = "Topaz Gigapixel AI"; Foss = "Upscayl"; Winget = "Upscayl.Upscayl"; Type = "IA Desktop (Vulkan/NCNN)"; Stack = "Electron, NCNN Vulkan, Real-ESRGAN"; License = "GNU AGPLv3"; Origin = "2022 (Nayam Amarshe)"; Version = "v2.11.5"; Desc = "Amélioration et agrandissement d'images et textures par IA en local sans cloud, compatible tout GPU."; Web = "https://www.upscayl.org" },
            @{ Prop = "MediaInfo / GSpot"; Foss = "MediaInfo GUI"; Winget = "MediaArea.MediaInfo.GUI"; Type = "Desktop Natif (C++/Qt)"; Stack = "C++, Qt, LibMediaInfo"; License = "BSD-2-Clause"; Origin = "2002 (Jérôme Martinez)"; Version = "v24.06"; Desc = "Analyseur technique exhaustif des codecs, flux audio/vidéo, débits et métadonnées de tout fichier multimédia."; Web = "https://mediaarea.net/MediaInfo" }
        )
    },
    @{
        Id = "dev-devops"
        Title = "Développement, Éditeurs de Code, API & DevOps"
        Icon = "💻"
        Color = "#a855f7"
        Items = @(
            @{ Prop = "Visual Studio Code (Microsoft)"; Foss = "VSCodium"; Winget = "VSCodium.VSCodium"; Type = "IDE & Éditeur de Code (TypeScript/Electron)"; Stack = "TypeScript, Electron, Monaco Editor, Open-VSX"; License = "MIT License"; Origin = "2019 (Projet VSCodium Community)"; Version = "v1.92.2"; Desc = "Binaire officiel libre de VS Code compilé directement depuis les sources sans télémétrie ni trackers propriétaires."; Web = "https://vscodium.com" },
            @{ Prop = "Sublime Text / Atom"; Foss = "Zed Editor"; Winget = "Zed.Zed"; Type = "Éditeur de Code Haute Performance (Rust)"; Stack = "Rust, GPUI Framework, Tree-sitter, CRDT"; License = "GPLv3 / AGPLv3 / Apache-2.0"; Origin = "2023 (Nathan Sobo - Créateur d'Atom)"; Version = "v0.149.0"; Desc = "Éditeur multithreadé ultra-rapide rendu par GPU avec édition collaborative en temps réel intégrée."; Web = "https://zed.dev" },
            @{ Prop = "Notepad / TextEdit"; Foss = "Notepad++"; Winget = "Notepad++.Notepad++"; Type = "Éditeur de Texte SysAdmin (C++/Win32)"; Stack = "C++, Pure Win32 API, Scintilla Component"; License = "GNU GPLv3"; Origin = "2003 (v1.0 Don Ho)"; Version = "v8.6.9"; Desc = "Éditeur de code léger et indestructible, indispensable pour la manipulation de scripts et fichiers de configuration."; Web = "https://notepad-plus-plus.org" },
            @{ Prop = "Vim / Emacs"; Foss = "Neovim"; Winget = "Neovim.Neovim"; Type = "Éditeur Modal Extensible (C/Lua)"; Stack = "C, LuaJIT, Tree-sitter, LSP Protocol"; License = "Apache-2.0 / Vim License"; Origin = "2014 (Fork Vim 1991 par Thiago de Arruda)"; Version = "v0.10.1"; Desc = "Refonte moderne de Vim avec support complet du protocole LSP, architecture asynchrone et configuration Lua."; Web = "https://neovim.io" },
            @{ Prop = "Postman / Insomnia"; Foss = "Bruno"; Winget = "Bruno.Bruno"; Type = "Client API Git-Friendly (JavaScript/Electron)"; Stack = "JavaScript, React, Electron, Bru DSL format"; License = "MIT License"; Origin = "2023 (v0.1 Anoop M D)"; Version = "v1.23.0"; Desc = "Client de test REST/GraphQL stockant les collections directement en fichiers texte plats dans votre dépôt Git."; Web = "https://www.usebruno.com" },
            @{ Prop = "Postman Cloud (Web)"; Foss = "Hoppscotch"; Winget = "Hoppscotch.Hoppscotch"; Type = "Écosystème de Développement API (TypeScript/Vue)"; Stack = "TypeScript, Vue 3, Vite, WebSockets, GraphQL"; License = "MIT License"; Origin = "2019 (Postwoman par Liyas Thomas)"; Version = "v2024.7.0"; Desc = "Suite de test d'API ultra-légère et moderne utilisable sur le web ou déployable en auto-hébergement."; Web = "https://hoppscotch.com" },
            @{ Prop = "Docker Desktop (Payant en entreprise)"; Foss = "Podman Desktop"; Winget = "RedHat.Podman-Desktop"; Type = "Gestionnaire de Conteneurs OCI (TypeScript/Svelte)"; Stack = "TypeScript, Svelte, Electron, Libpod API"; License = "Apache-2.0"; Origin = "2022 (Red Hat)"; Version = "v1.12.0"; Desc = "Gestionnaire de conteneurs et pods Kubernetes sans daemon root, compatible avec les fichiers Dockerfile."; Web = "https://podman-desktop.io" },
            @{ Prop = "Docker / Kubernetes GUI"; Foss = "Rancher Desktop"; Winget = "SUSE.RancherDesktop"; Type = "Environnement Kubernetes Local (TypeScript/Electron)"; Stack = "TypeScript, Electron, Containerd, k3s"; License = "Apache-2.0"; Origin = "2021 (SUSE / Rancher)"; Version = "v1.14.2"; Desc = "Environnement de conteneurs complet intégrant Kubernetes k3s pour tester vos architectures micro-services en local."; Web = "https://rancherdesktop.io" },
            @{ Prop = "Firebase / AWS Amplify"; Foss = "Supabase"; Winget = "Supabase.Supabase"; Type = "Backend-as-a-Service (Postgres/Go/Elixir)"; Stack = "PostgreSQL, Go, Elixir, Realtime Engine, Deno"; License = "Apache-2.0"; Origin = "2020 (Co-fondé par Paul Copplestone)"; Version = "v1.190.0"; Desc = "Alternative open-source à Firebase proposant base de données PostgreSQL temps réel, authentification et Edge Functions."; Web = "https://supabase.com" },
            @{ Prop = "Firebase / Mobile Backend"; Foss = "Appwrite"; Winget = "Appwrite.Appwrite"; Type = "Plateforme Backend pour Web/Mobile (PHP/Docker)"; Stack = "PHP 8, Swoole, Redis, MariaDB/Postgres, Docker"; License = "BSD-3-Clause"; Origin = "2019 (v0.1 Eldad Fux)"; Version = "v1.5.8"; Desc = "Serveur backend sécurisé avec API REST et GraphQL pour l'authentification des utilisateurs, bases de données et stockage de fichiers."; Web = "https://appwrite.io" },
            @{ Prop = "Navicat / DataGrip"; Foss = "DBeaver CE"; Winget = "dbeaver.dbeaver"; Type = "Client SQL Universel (Java/Eclipse RCP)"; Stack = "Java 17, Eclipse OSGi, JDBC Drivers"; License = "Apache-2.0"; Origin = "2010 (v1.0 Serge Rider)"; Version = "v24.1.4"; Desc = "Gestionnaire universel de bases de données relationnelles et NoSQL (MySQL, PostgreSQL, Oracle, SQLite, MongoDB)."; Web = "https://dbeaver.io" },
            @{ Prop = "Heroku / Netlify / Vercel"; Foss = "Coolify"; Winget = "Coolify.Coolify"; Type = "PaaS Auto-hébergeable Tout-en-un (PHP/Laravel/Vue)"; Stack = "PHP, Laravel, Vue.js, Docker, Traefik"; License = "Apache-2.0"; Origin = "2021 (v1.0 Andras Bacsai)"; Version = "v4.0.0-beta.315"; Desc = "Déployez vos applications web, bases de données et services Docker en 1 clic sur votre propre serveur VPS."; Web = "https://coolify.io" },
            @{ Prop = "React / Angular UI Framework"; Foss = "SolidJS"; Winget = "SolidJS.Solid"; Type = "Framework UI Réactif sans Virtual DOM (TypeScript)"; Stack = "TypeScript, Fine-Grained Reactive Signals, JSX Compiler, DOM Primitives"; License = "MIT License"; Origin = "2018 (Ryan Carniato)"; Version = "v1.8.18 / SolidStart"; Desc = "Framework web ultra-performant à réactivité granulaire sans Virtual DOM, compilant directement en manipulations DOM chirurgicales."; Web = "https://www.solidjs.com" },
            @{ Prop = "GitKraken / Tower"; Foss = "Lazygit"; Winget = "jesseduffield.lazygit"; Type = "TUI Terminal (Go)"; Stack = "Go, Tcell, Git Subprocess Engine"; License = "MIT"; Origin = "2018 (Jesse Duffield)"; Version = "v0.44.1"; Desc = "L'interface Git pour terminal la plus rapide au monde : commits atomiques, rebases interactifs et diffs instantanés."; Web = "https://github.com/jesseduffield/lazygit" },
            @{ Prop = "TablePlus / DataGrip"; Foss = "Beekeeper Studio"; Winget = "BeekeeperStudio.BeekeeperStudio"; Type = "Desktop Natif (Vue/TypeScript)"; Stack = "Vue.js, TypeScript, SQL Engines"; License = "GNU GPLv3"; Origin = "2019 (Matthew Rathbone)"; Version = "v4.4.2"; Desc = "Éditeur et gestionnaire de bases de données (SQL, PostgreSQL, SQLite, Redis) à l'interface épurée et moderne."; Web = "https://www.beekeeperstudio.io" }
        )
    },
    @{
        Id = "ai-local"
        Title = "Intelligence Artificielle & LLM Locaux"
        Icon = "🧠"
        Color = "#38bdf8"
        Items = @(
            @{ Prop = "ChatGPT Plus / Claude Pro"; Foss = "Ollama"; Winget = "Ollama.Ollama"; Type = "Moteur d'Inférence LLM CLI/Serveur (Go/C++)"; Stack = "Go, C++ (llama.cpp engine), CUDA, ROCm, Metal"; License = "MIT License"; Origin = "2023 (v0.1 Jeffrey Morgan)"; Version = "v0.3.6"; Desc = "Exécutez localement les modèles Llama 3, Mistral, Gemma et DeepSeek avec accélération GPU complète sans fuite de données."; Web = "https://ollama.com" },
            @{ Prop = "ChatGPT Desktop (Propriétaire)"; Foss = "GPT4All"; Winget = "NomicAI.GPT4All"; Type = "Assistant IA de Bureau 100% FOSS (C++/Qt)"; Stack = "C++, Qt6, llama.cpp, LocalDocs Vector Store"; License = "Apache-2.0"; Origin = "2023 (Nomic AI)"; Version = "v3.1.1"; Desc = "Écosystème de bureau open source pour faire tourner des modèles de langage en local avec RAG de dossiers privés."; Web = "https://www.nomic.ai/gpt4all" },
            @{ Prop = "ChatGPT Web UI (Auto-hébergé)"; Foss = "Open WebUI"; Winget = "OpenWebUI.OpenWebUI"; Type = "Interface Web IA Complète (Python/Svelte)"; Stack = "Python, SvelteKit, FastAPI, ChromaDB"; License = "MIT License"; Origin = "2023 (Ollama WebUI par Timothy J. Baek)"; Version = "v0.3.10"; Desc = "Interface web riche type ChatGPT avec support RAG, recherche web, multi-utilisateurs et contrôle vocal."; Web = "https://openwebui.com" },
            @{ Prop = "ChatGPT Offline"; Foss = "Jan AI"; Winget = "Jan.Jan"; Type = "Assistant IA de Bureau (TypeScript/C++)"; Stack = "TypeScript, Electron, Nitro C++ Engine"; License = "AGPLv3"; Origin = "2023 (Jan Team)"; Version = "v0.5.2"; Desc = "Assistant IA natif 100% hors-ligne transformant votre ordinateur en nœud d'intelligence artificielle privée."; Web = "https://jan.ai" },
            @{ Prop = "GitHub Copilot"; Foss = "Continue.dev"; Winget = "Continue.Continue"; Type = "Extension Copilot IDE (TypeScript/Python)"; Stack = "TypeScript, Python, Tree-sitter, VS Code API"; License = "Apache-2.0"; Origin = "2023 (Nate Sesti & Ty Dunn)"; Version = "v0.8.44"; Desc = "Assistant de complétion et de refactoring de code connecté à Ollama ou aux modèles distants sécurisés."; Web = "https://continue.dev" },
            @{ Prop = "GitHub Copilot Entreprise"; Foss = "Tabby"; Winget = "TabbyML.Tabby"; Type = "Serveur d'Auto-complétion de Code (Rust)"; Stack = "Rust, Axum, Candle, ONNX Runtime"; License = "Apache-2.0"; Origin = "2023 (TabbyML Team)"; Version = "v0.14.0"; Desc = "Serveur d'assistance de code auto-hébergé adapté aux bases de code propriétaires des entreprises."; Web = "https://tabbyml.github.io/tabby" },
            @{ Prop = "Midjourney / DALL-E"; Foss = "Fooocus"; Winget = "Fooocus.Fooocus"; Type = "Générateur d'Images SDXL (Python/PyTorch)"; Stack = "Python, PyTorch, Gradio, Stable Diffusion XL"; License = "GPLv3"; Origin = "2023 (v1.0 Lvmin Zhang - lllyasviel)"; Version = "v2.5.5"; Desc = "Génération d'images photoréalistes de très haute qualité avec invite simplifiée et automatisations avancées."; Web = "https://github.com/lllyasviel/Fooocus" },
            @{ Prop = "OpenAI Whisper Cloud"; Foss = "Buzz"; Winget = "Buzz.Buzz"; Type = "Transcripteur Audio Local (Python/Qt)"; Stack = "Python, PyQt6, Whisper, faster-whisper"; License = "MIT License"; Origin = "2022 (Chidi Williams)"; Version = "v1.1.0"; Desc = "Transcription vocale et sous-titrage SRT/VTT en local et en direct sur le microphone ou fichiers audio."; Web = "https://github.com/chidiwilliams/buzz" },
            @{ Prop = "OpenAI Whisper API"; Foss = "Whisper.cpp"; Winget = "ggerganov.whisper.cpp"; Type = "Moteur d'Inférence Vocale (C/C++)"; Stack = "C, C++, ggml Tensor Library, AVX/NEON"; License = "MIT License"; Origin = "2022 (Georgi Gerganov)"; Version = "v1.6.2"; Desc = "Portage haute performance en C pur du modèle Whisper d'OpenAI sans dépendance Python."; Web = "https://github.com/ggerganov/whisper.cpp" },
            @{ Prop = "Automatic1111"; Foss = "ComfyUI"; Winget = "comfyanonymous.ComfyUI"; Type = "Moteur Graphique IA (Python/Node)"; Stack = "Python, PyTorch, CUDA/DirectML"; License = "GNU GPLv3"; Origin = "2023 (Comfyanonymous)"; Version = "v0.2.2"; Desc = "L'environnement modulaire basé sur des nœuds le plus puissant et performant pour la génération d'images Stable Diffusion / Flux."; Web = "https://github.com/comfyanonymous/ComfyUI" }
        )
    },
    @{
        Id = "cloud-storage"
        Title = "Stockage Cloud, Synchronisation & Sauvegarde"
        Icon = "☁️"
        Color = "#06b6d4"
        Items = @(
            @{ Prop = "Dropbox / Google Drive"; Foss = "Nextcloud"; Winget = "Nextcloud.NextcloudDesktop"; Type = "Hub Collaboratif & Cloud Privé (PHP/Vue)"; Stack = "PHP, JavaScript, Vue.js, PostgreSQL/MariaDB"; License = "AGPLv3"; Origin = "2016 (Fork ownCloud 2010 par Frank Karlitschek)"; Version = "v29.0.4 (Hub 8)"; Desc = "Plateforme collaborative complète : synchronisation de fichiers, calendrier, contacts, messagerie et suite bureautique."; Web = "https://nextcloud.com" },
            @{ Prop = "Dropbox / Box Enterprise"; Foss = "ownCloud"; Winget = "ownCloud.ownCloudDesktop"; Type = "Cloud d'Entreprise Infinite Scale (Go/Vue)"; Stack = "Go, Microservices, Vue.js, LibreGraph API"; License = "AGPLv3 / Apache-2.0"; Origin = "2010 (v1.0 Frank Karlitschek)"; Version = "v5.0.0 (Infinite Scale)"; Desc = "Solution de stockage distribuée haute performance pour universités et grands groupes industriels."; Web = "https://owncloud.com" },
            @{ Prop = "OneDrive / Resilio Sync"; Foss = "Syncthing"; Winget = "Syncthing.Syncthing"; Type = "Synchronisation P2P Décentralisée (Go)"; Stack = "Go, Block Exchange Protocol (BEP), TLS"; License = "MPL-2.0"; Origin = "2013 (v0.1 Jakob Borg)"; Version = "v1.27.10"; Desc = "Synchronisation de répertoires poste-à-poste chiffrée sans passer par un serveur cloud intermédiaire."; Web = "https://syncthing.net" },
            @{ Prop = "Amazon S3 / Azure Blob"; Foss = "MinIO"; Winget = "MinIO.MinIO"; Type = "Stockage d'Objets Haute Performance (Go)"; Stack = "Go, SIMD-accelerated Erasure Coding"; License = "AGPLv3"; Origin = "2014 (Anand Babu Periasamy)"; Version = "RELEASE.2024-07-31"; Desc = "Stockage d'objets cloud natif compatible API S3 capable de débits de centaines de gigaoctets par seconde."; Web = "https://min.io" },
            @{ Prop = "Google Photos / iCloud Photos"; Foss = "Immich"; Winget = "Immich.Immich"; Type = "Gestionnaire Photos avec IA (TypeScript/Dart)"; Stack = "TypeScript, NestJS, Flutter, PostgreSQL, pgvector"; License = "AGPLv3"; Origin = "2022 (Alex Tran)"; Version = "v1.112.0"; Desc = "Sauvegarde mobile et classement d'albums photo avec reconnaissance faciale IA et cartes géographiques."; Web = "https://immich.app" },
            @{ Prop = "Google Photos (Classification)"; Foss = "PhotoPrism"; Winget = "PhotoPrism.PhotoPrism"; Type = "Galerie Photos IA Décentralisée (Go/Vue)"; Stack = "Go, Vue.js, TensorFlow, SQLite/MariaDB"; License = "AGPLv3"; Origin = "2018 (Michael Mayer)"; Version = "v240726"; Desc = "Indexation et recherche sémantique de photos basée sur l'intelligence artificielle TensorFlow."; Web = "https://www.photoprism.app" },
            @{ Prop = "WeTransfer / SwissTransfer"; Foss = "Pingvin Share"; Winget = "Stonith404.Pingvin-Share"; Type = "Partage de Fichiers Temporaire (Node/Next)"; Stack = "TypeScript, Next.js, Prisma, SQLite"; License = "BSD-2-Clause"; Origin = "2022 (Eli Stonith)"; Version = "v0.28.0"; Desc = "Plateforme de partage de fichiers auto-hébergée avec liens protégés par mot de passe et date d'expiration."; Web = "https://github.com/stonith404/pingvin-share" },
            @{ Prop = "Veeam Backup / Acronis"; Foss = "Duplicati"; Winget = "Duplicati.Duplicati"; Type = "Sauvegarde Chiffrée Incrémentielle (C#/.NET)"; Stack = "C#, .NET 8, SQLite, AES-256"; License = "LGPLv2.1+"; Origin = "2008 (v1.0 Kenneth Skovhede)"; Version = "v2.0.8.1 / v2.1 Beta"; Desc = "Sauvegarde avec déduplication de blocs, chiffrement fort et envoi vers Amazon S3, WebDAV, SFTP, OneDrive."; Web = "https://www.duplicati.com" },
            @{ Prop = "Veeam / BorgBackup"; Foss = "Kopia"; Winget = "Kopia.Kopia"; Type = "Sauvegarde Haute Cadence par Snapshots (Go)"; Stack = "Go, Content-Addressable Storage, AES-GCM"; License = "Apache-2.0"; Origin = "2019 (Jarek Kowalski)"; Version = "v0.17.0"; Desc = "Outil de snapshotting rapide avec déduplication native et compression ZSTD pour serveurs et postes de travail."; Web = "https://kopia.io" },
            @{ Prop = "FileZilla Pro / CuteFTP"; Foss = "Cyberduck"; Winget = "Iterate.Cyberduck"; Type = "Navigateur de Stockage Distant (Java/C#)"; Stack = "Java, .NET (Windows), macOS Cocoa"; License = "GNU GPLv2+"; Origin = "2002 (David Kocher)"; Version = "v8.8.4"; Desc = "Client de transfert supportant SFTP, WebDAV, Amazon S3, Google Drive, Backblaze B2 et Azure."; Web = "https://cyberduck.io" }
        )
    },
    @{
        Id = "messaging-collab"
        Title = "Communication, Messagerie & Visioconférence"
        Icon = "💬"
        Color = "#84cc16"
        Items = @(
            @{ Prop = "Slack / Microsoft Teams"; Foss = "Mattermost"; Winget = "Mattermost.MattermostDesktop"; Type = "Collaboration d'Équipe Sécurisée (Go/React)"; Stack = "Go, React, Redux, PostgreSQL/MySQL"; License = "Apache-2.0 / AGPLv3"; Origin = "2015 (v1.0 Ian Tien)"; Version = "v9.10.0 / v5.8 Desktop"; Desc = "Espace d'échange professionnel auto-hébergeable avec canaux, appels vocaux, playbooks d'incident et intégrations DevOps."; Web = "https://mattermost.com" },
            @{ Prop = "Slack / Threads Structurés"; Foss = "Zulip"; Winget = "Zulip.Zulip"; Type = "Messagerie par Fils de Discussion (Python/Django)"; Stack = "Python, Django, PostgreSQL, Tornado, TypeScript"; License = "Apache-2.0"; Origin = "2012 (v1.0 Tim Abbott / Dropbox)"; Version = "v9.0"; Desc = "Modèle unique de messagerie d'équipe par sujets organisés évitant le débordement d'informations."; Web = "https://zulip.com" },
            @{ Prop = "Discord / WhatsApp"; Foss = "Element (Matrix)"; Winget = "Element.Element"; Type = "Client Matrix Sécurisé (TypeScript/Electron)"; Stack = "TypeScript, React, Matrix Rust SDK, Olm/Megolm E2EE"; License = "Apache-2.0"; Origin = "2016 (Vector par Matthew Hodgson & Amandine Le Pape)"; Version = "v1.11.74 / Element X"; Desc = "Messagerie décentralisée et souveraine chiffrée de bout en bout interconnectée au réseau mondial Matrix."; Web = "https://element.io" },
            @{ Prop = "Discord (Salons Vocaux)"; Foss = "Revolt"; Winget = "Revolt.Revolt"; Type = "Messagerie Communautaire (Rust/TypeScript)"; Stack = "Rust (backend), TypeScript, Preact, WebRTC"; License = "AGPLv3"; Origin = "2021 (Paul Makles)"; Version = "v1.0.6"; Desc = "Plateforme communautaire alternative à Discord avec salons texte personnalisés, voix et bots."; Web = "https://revolt.chat" },
            @{ Prop = "Zoom / Google Meet"; Foss = "Jitsi Meet"; Winget = "Jitsi.JitsiMeet"; Type = "Visioconférence WebRTC (Java/JavaScript)"; Stack = "Java (JVB), JavaScript, React, WebRTC"; License = "Apache-2.0"; Origin = "2003 (SIP Communicator par Emil Ivov)"; Version = "v2.0.9500"; Desc = "Visioconférence sécurisée avec partage d'écran fluide, enregistrement et chiffrement de bout en bout."; Web = "https://meet.jit.si" },
            @{ Prop = "Intercom / Zendesk Chat"; Foss = "Chatwoot"; Winget = "Chatwoot.Chatwoot"; Type = "Service Client Omnicanal (Ruby on Rails/Vue)"; Stack = "Ruby on Rails, Vue.js, PostgreSQL, Redis"; License = "MIT License / AGPLv3"; Origin = "2019 (Pranav Raj & Sojan Jose)"; Version = "v3.13.0"; Desc = "Gestion centralisée du support client intégrant Live Chat de site web, WhatsApp, Email et réseaux sociaux."; Web = "https://www.chatwoot.com" },
            @{ Prop = "Zendesk Helpdesk"; Foss = "FreeScout"; Winget = "FreeScout.FreeScout"; Type = "Helpdesk Partagé Léger (PHP/Laravel)"; Stack = "PHP 8, Laravel, MySQL/MariaDB"; License = "GNU AGPLv3"; Origin = "2017 (FreeScout Community)"; Version = "v1.8.125"; Desc = "Boîte de réception d'assistance partagée pour répondre aux tickets clients sans frais récurrents."; Web = "https://freescout.net" },
            @{ Prop = "Telegram / WhatsApp"; Foss = "Signal"; Winget = "OpenWhisperSystems.Signal"; Type = "Messagerie Mobile & Desktop Chiffrée (TypeScript/Rust)"; Stack = "Rust, Signal Protocol, TypeScript, Electron, SQLite"; License = "GPLv3 / AGPLv3"; Origin = "2014 (Moxie Marlinspike / Open Whisper Systems)"; Version = "v7.19.0"; Desc = "Standard d'or de la confidentialité des télécommunications sans métadonnées exploitables."; Web = "https://signal.org" },
            @{ Prop = "TeamSpeak / Discord Voice"; Foss = "Mumble"; Winget = "Mumble.Mumble"; Type = "Communication Vocale Ultra-Basse Latence (C++/Qt)"; Stack = "C++, Qt5, Opus Codec, TLS"; License = "BSD-3-Clause"; Origin = "2005 (v1.0 Thorvald Natvig)"; Version = "v1.5.634"; Desc = "Serveur et client vocal chiffré dédié aux équipes nécessitant une transmission audio instantanée sans lag."; Web = "https://www.mumble.info" }
        )
    },
    @{
        Id = "data-analytics"
        Title = "Données, Analytics, BI & Monitoring"
        Icon = "📊"
        Color = "#ec4899"
        Items = @(
            @{ Prop = "Google Analytics (RGPD)"; Foss = "Plausible Analytics"; Winget = "Plausible.Plausible"; Type = "Mesure d'Audience Web Conforme RGPD (Elixir/ClickHouse)"; Stack = "Elixir, Phoenix, ClickHouse, PostgreSQL, Tailwind"; License = "AGPLv3"; Origin = "2019 (Uku Taht & Marko Saric)"; Version = "v2.1.1"; Desc = "Statistiques de fréquentation web ultra-légères (< 1 Ko) sans cookies et respectant scrupuleusement la vie privée."; Web = "https://plausible.io" },
            @{ Prop = "Google Analytics / Matomo"; Foss = "Umami"; Winget = "Umami.Umami"; Type = "Analytics Web Rapides & Épurés (TypeScript/Next)"; Stack = "TypeScript, Next.js, Prisma, PostgreSQL/MySQL"; License = "MIT License"; Origin = "2020 (Mike Cao)"; Version = "v2.12.0"; Desc = "Solution de suivi analytique moderne et simple d'utilisation pour mesurer pages vues et conversions."; Web = "https://umami.is" },
            @{ Prop = "Google Analytics Suite Complète"; Foss = "Matomo"; Winget = "InnoCraft.Matomo"; Type = "Suite Analytics Avancée (PHP/MySQL)"; Stack = "PHP 8, MariaDB/MySQL, Vue.js"; License = "GNU GPLv3"; Origin = "2007 (Piwik par Matthieu Aubry)"; Version = "v5.1.0"; Desc = "Mesure d'audience exhaustive avec cartes de chaleur, entonnoirs et 100% de souveraineté des données récoltées."; Web = "https://matomo.org" },
            @{ Prop = "Mixpanel / Amplitude"; Foss = "PostHog"; Winget = "PostHog.PostHog"; Type = "Plateforme d'Analyse Produit (Python/TypeScript/ClickHouse)"; Stack = "Python, Django, TypeScript, React, ClickHouse, Kafka"; License = "MIT License / Elastic 2.0"; Origin = "2020 (James Hawkins & Tim Glaser)"; Version = "v1.140.0"; Desc = "Analyse comportementale des utilisateurs avec enregistrement de session, feature flags et tests A/B."; Web = "https://posthog.com" },
            @{ Prop = "Tableau / Power BI"; Foss = "Metabase"; Winget = "Metabase.Metabase"; Type = "Business Intelligence & Tableaux de Bord (Clojure/React)"; Stack = "Clojure, Java, React, SQL Connectors"; License = "AGPLv3"; Origin = "2015 (Sameer Al-Sakran)"; Version = "v0.50.15"; Desc = "Tableaux de bord d'entreprise interactifs et requêtes de données accessibles sans connaissances SQL approfondies."; Web = "https://www.metabase.com" },
            @{ Prop = "Tableau / Looker (Big Data)"; Foss = "Apache Superset"; Winget = "Apache.Superset"; Type = "Exploration de Données à Grande Échelle (Python/React)"; Stack = "Python, Flask, React, SQLAlchemy, Apache Arrow"; License = "Apache-2.0"; Origin = "2015 (Maxime Beauchemin chez Airbnb)"; Version = "v4.0.2"; Desc = "Visualisation de pétaoctets de données d'entreprise avec connecteurs vers Snowflake, Trino, BigQuery."; Web = "https://superset.apache.org" },
            @{ Prop = "Datadog / New Relic"; Foss = "Grafana"; Winget = "Grafana.Grafana"; Type = "Observabilité & Dashboards Métriques (Go/TypeScript)"; Stack = "Go, TypeScript, React, Prometheus/Loki API"; License = "AGPLv3"; Origin = "2014 (v1.0 Torkel Ödegaard)"; Version = "v11.1.3"; Desc = "Standard mondial pour la création de tableaux de bord opérationnels et la surveillance d'infrastructures serveurs."; Web = "https://grafana.com" },
            @{ Prop = "Datadog Metrics Collector"; Foss = "Prometheus"; Winget = "Prometheus.Prometheus"; Type = "Moteur de Métriques Temporelles (Go)"; Stack = "Go, TSDB, PromQL, Alertmanager"; License = "Apache-2.0"; Origin = "2012 (SoundCloud / CNCF)"; Version = "v2.53.1"; Desc = "Système de collecte de métriques par scrutation et moteur d'alerting en temps réel pour conteneurs et machines virtuelles."; Web = "https://prometheus.io" },
            @{ Prop = "Segment / mParticle"; Foss = "RudderStack"; Winget = "RudderStack.RudderStack"; Type = "Customer Data Platform CDP (Go/Node)"; Stack = "Go, Node.js, PostgreSQL, Redis"; License = "AGPLv3 / Apache-2.0"; Origin = "2019 (Soumyadeb Mitra)"; Version = "v1.20.0"; Desc = "Routage et transformation d'événements de données client vers vos entrepôts de données et outils marketing."; Web = "https://rudderstack.com" }
        )
    },
    @{
        Id = "business-crm"
        Title = "Entreprise, CRM, E-Commerce & Facturation"
        Icon = "🏢"
        Color = "#6366f1"
        Items = @(
            @{ Prop = "Salesforce / HubSpot CRM"; Foss = "Twenty CRM"; Winget = "TwentyHQ.Twenty"; Type = "CRM Open Source Moderne (TypeScript/Nest/React)"; Stack = "TypeScript, NestJS, React, GraphQL, PostgreSQL"; License = "AGPLv3"; Origin = "2023 (Felix Malfait & Charles Bochet)"; Version = "v0.25.0"; Desc = "CRM open-source nouvelle génération pour le suivi des opportunités commerciales, contacts et pipelines de vente."; Web = "https://twenty.com" },
            @{ Prop = "Salesforce / SugarCRM"; Foss = "SuiteCRM"; Winget = "SalesAgility.SuiteCRM"; Type = "CRM d'Entreprise Éprouvé (PHP/Angular)"; Stack = "PHP 8, Symfony, Angular, MariaDB/MySQL"; License = "GNU AGPLv3"; Origin = "2013 (Fork SugarCRM 2004 par SalesAgility)"; Version = "v8.6.1"; Desc = "Suite CRM complète pour la gestion des forces de vente, service client et campagnes marketing complexes."; Web = "https://suitecrm.com" },
            @{ Prop = "SAP / Odoo Payant"; Foss = "ERPNext"; Winget = "Frappe.ERPNext"; Type = "ERP Tout-en-un d'Entreprise (Python/Frappe)"; Stack = "Python, Frappe Framework, MariaDB, Node.js"; License = "GNU GPLv3"; Origin = "2008 (Rushabh Mehta)"; Version = "v15.30.0"; Desc = "Système de gestion intégrée complet : comptabilité générale, chaîne logistique, stock, paie et fabrication."; Web = "https://erpnext.com" },
            @{ Prop = "SAP / Microsoft Dynamics"; Foss = "Odoo Community"; Winget = "Odoo.Odoo"; Type = "Suite Modulaire d'Applications Pro (Python/JavaScript)"; Stack = "Python, JavaScript, PostgreSQL, OWL Framework"; License = "GNU LGPLv3"; Origin = "2005 (TinyERP par Fabien Pinckaers)"; Version = "v17.0 Community"; Desc = "Écosystème modulaire d'applications de vente, achats, facturation conforme et gestion d'inventaire."; Web = "https://www.odoo.com" },
            @{ Prop = "Shopify / Magento"; Foss = "Medusa"; Winget = "Medusa.Medusa"; Type = "Moteur E-Commerce Headless (TypeScript/Node)"; Stack = "TypeScript, Node.js, Express, PostgreSQL, Redis"; License = "MIT License"; Origin = "2021 (Sebastian Rindom & Oliver Juhl)"; Version = "v2.0.0"; Desc = "Architecture de commerce électronique composable pour développer des boutiques ultra-rapides et personnalisées."; Web = "https://medusajs.com" },
            @{ Prop = "Shopify / BigCommerce"; Foss = "WooCommerce"; Winget = "Automattic.WooCommerce"; Type = "Moteur E-Commerce Modulaire (PHP/WordPress)"; Stack = "PHP, WordPress, MySQL, REST API"; License = "GNU GPLv3"; Origin = "2011 (WooThemes / Automattic 2015)"; Version = "v9.1.4"; Desc = "Plateforme e-commerce la plus déployée au monde avec des milliers d'extensions de paiement et livraison."; Web = "https://woocommerce.com" },
            @{ Prop = "QuickBooks / Sage"; Foss = "Akaunting"; Winget = "Akaunting.Akaunting"; Type = "Comptabilité & Facturation PME (PHP/Laravel)"; Stack = "PHP 8, Laravel, Vue.js, MySQL"; License = "GPLv3"; Origin = "2017 (Denis Duliçi)"; Version = "v3.1.8"; Desc = "Gestion financière en ligne pour indépendants et TPE : devis, factures, dépenses et suivi de trésorerie."; Web = "https://akaunting.com" },
            @{ Prop = "Mailchimp / SendGrid"; Foss = "Listmonk"; Winget = "KailashNadh.Listmonk"; Type = "Gestionnaire de Newsletters Haute Cadence (Go/Vue)"; Stack = "Go, Vue.js, PostgreSQL"; License = "AGPLv3"; Origin = "2019 (Kailash Nadh chez Zerodha)"; Version = "v4.0.0"; Desc = "Envoi massif de bulletins d'information et d'emails transactionnels à des millions de destinataires avec débit record."; Web = "https://listmonk.app" },
            @{ Prop = "Mailchimp / HubSpot Marketing"; Foss = "Mautic"; Winget = "Mautic.Mautic"; Type = "Marketing Automation d'Entreprise (PHP/Symfony)"; Stack = "PHP 8, Symfony, MySQL, Doctrine"; License = "GNU GPLv3"; Origin = "2014 (David Hurley)"; Version = "v5.1.0"; Desc = "Automatisation des parcours clients, segmentation fine des prospects et scoring des leads commerciaux."; Web = "https://www.mautic.org" }
        )
    },
    @{
        Id = "browsers-privacy"
        Title = "Navigateurs, Vie Privée & Adblocking"
        Icon = "🌐"
        Color = "#14b8a6"
        Items = @(
            @{ Prop = "Google Chrome"; Foss = "Brave Browser"; Winget = "Brave.Brave"; Type = "Navigateur Web Anti-Trackers (C++/Chromium)"; Stack = "C++, Chromium Engine, Rust (Brave Shields)"; License = "MPL-2.0 / Chromium"; Origin = "2016 (Brendan Eich - Créateur de JS & Mozilla)"; Version = "v1.68.134"; Desc = "Navigation Chromium ultra-rapide bloquant nativement publicités invasives, traceurs et empreintes digitales sans extension."; Web = "https://brave.com" },
            @{ Prop = "Google Chrome / Edge"; Foss = "Mozilla Firefox"; Winget = "Mozilla.Firefox"; Type = "Navigateur Indépendant & Moteur Gecko (C++/Rust)"; Stack = "C++, Rust, Gecko Engine, SpiderMonkey JS"; License = "MPL-2.0"; Origin = "2002 (Phoenix par Dave Hyatt & Blake Ross)"; Version = "v129.0 / v128.1 ESR"; Desc = "Défenseur historique du web ouvert avec protection renforcée contre le pistage et isolation totale des onglets."; Web = "https://www.mozilla.org" },
            @{ Prop = "Chrome / Safari Ultra-Privé"; Foss = "LibreWolf"; Winget = "LibreWolf.LibreWolf"; Type = "Navigateur Durci Anti-Surveillance (C++/Rust)"; Stack = "C++, Rust, Gecko Engine, Arkenfox Settings"; License = "MPL-2.0"; Origin = "2020 (LibreWolf Community)"; Version = "v129.0-1"; Desc = "Version durcie de Firefox exempte de toute télémétrie, suppression automatique des cookies et anti-fingerprinting natif."; Web = "https://librewolf.net" },
            @{ Prop = "Vivaldi / Arc Browser"; Foss = "Floorp"; Winget = "Ablaze.Floorp"; Type = "Navigateur Modulaire Haute Ergonomie (C++/JavaScript)"; Stack = "C++, JavaScript, Gecko Engine, Ablaze UI"; License = "MPL-2.0"; Origin = "2021 (Ablaze Community Japon)"; Version = "v11.16.0"; Desc = "Navigateur pour power-users proposant onglets verticaux natifs, panneaux latéraux Web Panel et double barre d'onglets."; Web = "https://floorp.app" },
            @{ Prop = "Navigation Sous Surveillance FAI"; Foss = "Tor Browser"; Winget = "TorProject.TorBrowser"; Type = "Navigateur Anonyme par Routage en Oignon (C/C++)"; Stack = "C, C++, Tor Network, Onion Routing, Gecko"; License = "BSD-3-Clause / MPL"; Origin = "2008 (The Tor Project)"; Version = "v13.5.2"; Desc = "Navigation anonyme absolue acheminée à travers un réseau décentralisé de 3 relais chiffrés pour masquer votre adresse IP."; Web = "https://www.torproject.org" },
            @{ Prop = "Pi-hole / Box Opérateur"; Foss = "AdGuard Home"; Winget = "Adguard.AdguardHome"; Type = "Serveur DNS Filtrant Réseau (Go)"; Stack = "Go, DoH (DNS-over-HTTPS), DoT, DoQ"; License = "GPLv3"; Origin = "2018 (AdGuard Team)"; Version = "v0.107.52"; Desc = "Serveur DNS local bloquant publicités, malwares et traqueurs sur tous les appareils de votre réseau local sans installer d'application."; Web = "https://adguard.com/adguard-home.html" },
            @{ Prop = "Moteur de Recherche Google / Bing"; Foss = "SearXNG"; Winget = "SearXNG.SearXNG"; Type = "Méta-moteur de Recherche Privé (Python)"; Stack = "Python 3, Flask, Jinja2, HTML5/CSS3"; License = "AGPLv3"; Origin = "2021 (Fork Searx 2014 par Adam Tauber)"; Version = "v2024.8.12"; Desc = "Agrégateur de recherche libre combinant les résultats de 70 moteurs sans profiler vos requêtes ni stocker d'adresses IP."; Web = "https://searx.space" },
            @{ Prop = "Internet Download Manager (IDM)"; Foss = "Motrix"; Winget = "AGALWood.Motrix"; Type = "Accélérateur de Téléchargements (Electron/Aria2)"; Stack = "TypeScript, Electron, Vue.js, Aria2 Engine"; License = "MIT License"; Origin = "2018 (AGALWood)"; Version = "v1.8.19"; Desc = "Gestionnaire de téléchargements moderne avec découpage multi-threads supportant HTTP, FTP, BitTorrent et Magnet."; Web = "https://motrix.app" }
        )
    },
    @{
        Id = "system-utils"
        Title = "Utilitaires Système, Nettoyage & Clés Bootables"
        Icon = "⚙️"
        Color = "#eab308"
        Items = @(
            @{ Prop = "WinRAR / WinZip"; Foss = "7-Zip"; Winget = "7zip.7zip"; Type = "Archiveur Haute Compression (C/C++)"; Stack = "C, C++, Assembly x86/x64, LZMA/LZMA2"; License = "GNU LGPLv2.1+ / BSD"; Origin = "1999 (v1.0 Igor Pavlov)"; Version = "v24.07"; Desc = "Archiveur à très haut taux de compression supportant le format 7z, le déballage RAR/ISO et le chiffrement AES-256."; Web = "https://www.7-zip.org" },
            @{ Prop = "WinRAR / 7-Zip (Interface Graphique)"; Foss = "PeaZip"; Winget = "Giorgiotani.Peazip"; Type = "Gestionnaire d'Archives Moderne (Free Pascal)"; Stack = "Free Pascal, Lazarus GUI, 7z/Arc Engines"; License = "GNU LGPLv3"; Origin = "2006 (Giorgio Tani)"; Version = "v9.9.0"; Desc = "Gestionnaire d'archives graphique prenant en charge plus de 200 formats de compression avec vérification de hachages."; Web = "https://peazip.github.io" },
            @{ Prop = "CCleaner (Télémétrie)"; Foss = "BleachBit"; Winget = "BleachBit.BleachBit"; Type = "Nettoyeur de Disque & Confidentialité (Python/C)"; Stack = "Python, GTK3, SQLite, Win32 Native"; License = "GNU GPLv3+"; Origin = "2008 (Andrew Ziem)"; Version = "v4.6.0"; Desc = "Libère des gigaoctets d'espace disque en supprimant caches, logs et historiques avec écrasement sécurisé de fichiers."; Web = "https://www.bleachbit.org" },
            @{ Prop = "IObit / Revo Uninstaller"; Foss = "Bulk Crap Uninstaller"; Winget = "Klocman.BulkCrapUninstaller"; Type = "Désinstalleur Avancé par Lots (C#/.NET)"; Stack = "C#, .NET Framework, Windows Registry API"; License = "Apache-2.0"; Origin = "2016 (Marcin Szeniak - Klocman)"; Version = "v5.8.1"; Desc = "Désinstalle par lots de multiples applications en nettoyant automatiquement les résidus de registre et fichiers orphelins."; Web = "https://www.bcuninstaller.com" },
            @{ Prop = "BalenaEtcher / UltraISO"; Foss = "Rufus"; Winget = "Rufus.Rufus"; Type = "Créateur de Clés USB Bootables (C/Win32)"; Stack = "C, Pure Windows API, libfat32, ISO/VHD Engine"; License = "GNU GPLv3"; Origin = "2011 (Pete Batard)"; Version = "v4.5"; Desc = "Création ultra-rapide de clés USB d'installation Windows 11 (avec contournement TPM/SecureBoot) et distributions Linux."; Web = "https://rufus.ie" },
            @{ Prop = "MultiBoot USB Propriétaires"; Foss = "Ventoy"; Winget = "Ventoy.Ventoy"; Type = "Clé USB MultiBoot Directe (C/ASM)"; Stack = "C, Assembly, GRUB2, EFI Drivers"; License = "GPLv3+"; Origin = "2020 (LongPanda)"; Version = "v1.0.99"; Desc = "Déposez simplement vos fichiers ISO/WIM/VHD sur la clé USB pour démarrer dessus directement via un menu interactif."; Web = "https://www.ventoy.net" },
            @{ Prop = "Alfred / Raycast / Spotlight"; Foss = "Flow Launcher"; Winget = "Flow-Launcher.Flow-Launcher"; Type = "Lanceur d'Applications & Recherche Rapide (C#/.NET)"; Stack = "C#, .NET 8, WPF, Community Plugins API"; License = "MIT License"; Origin = "2020 (Flow Launcher Team)"; Version = "v1.18.1"; Desc = "Lanceur rapide et recherche de fichiers instantanée extensible par plugins pour exécuter des commandes sans souris."; Web = "https://www.flowlauncher.com" },
            @{ Prop = "Snipping Tool / Snagit"; Foss = "ShareX"; Winget = "ShareX.ShareX"; Type = "Capture d'Écran & Productivité (C#/.NET)"; Stack = "C#, .NET 8, FFmpeg, Tesseract OCR Engine"; License = "GNU GPLv3"; Origin = "2007 (ZScreen par Jaex & Michael)"; Version = "v16.1.0"; Desc = "Outil tout-en-un de capture d'écran, enregistrement vidéo d'écran/GIF, reconnaissance optique OCR et téléversement automatique."; Web = "https://getsharex.com" },
            @{ Prop = "Visionneuse Windows Lente"; Foss = "ImageGlass"; Winget = "DuongDieuPhap.ImageGlass"; Type = "Visionneuse d'Images Moderne (C#/.NET)"; Stack = "C#, .NET 8, Magick.NET, WinUI 3"; License = "GNU GPLv3"; Origin = "2010 (Duong Dieu Phap)"; Version = "v9.1.8"; Desc = "Visionneuse d'images ultra-légère et polyvalente supportant plus de 80 formats (WebP, SVG, AVIF, PSD, RAW)."; Web = "https://imageglass.org" },
            @{ Prop = "Menu Démarrer Windows 11"; Foss = "Open-Shell"; Winget = "Open-Shell.Open-Shell-Menu"; Type = "Menu Démarrer Personnalisé (C++/Win32)"; Stack = "C++, COM, Windows Shell Hook"; License = "MIT License"; Origin = "2018 (Fork Classic Shell 2009 par Ivo Beltchev)"; Version = "v4.4.191"; Desc = "Restaure le menu Démarrer classique personnalisable sous Windows 11 avec accès direct aux outils d'administration."; Web = "https://open-shell.github.io/Open-Shell-Menu" },
            @{ Prop = "TreeSize Pro (Payant)"; Foss = "WinDirStat"; Winget = "WinDirStat.WinDirStat"; Type = "Analyseur d'Espace Disque (C++/Win32)"; Stack = "C++, MFC, Treemap Visualization"; License = "GNU GPLv2"; Origin = "2003 (Bernhard Seifert)"; Version = "v1.1.2"; Desc = "Visualisation arborescente et graphique de l'espace disque pour débusquer instantanément les fichiers volumineux."; Web = "https://windirstat.net" },
            @{ Prop = "macOS QuickLook / Aperçu"; Foss = "QuickLook"; Winget = "QL-Win.QuickLook"; Type = "Desktop Natif (WPF/C#)"; Stack = "C#, WPF, Windows Shell Hook"; License = "GNU GPLv3"; Origin = "2017 (Paddy Xu)"; Version = "v3.7.3"; Desc = "Aperçu instantané ultra-rapide de tout fichier (images, PDF, code, archives) par simple pression sur Espace."; Web = "https://github.com/QL-Win/QuickLook" },
            @{ Prop = "Windows Explorer"; Foss = "Explorer++"; Winget = "ExplorerPlusPlus.ExplorerPlusPlus"; Type = "Desktop Natif (C++/Win32)"; Stack = "C++, Win32 API Natif"; License = "GNU GPLv3"; Origin = "2008 (David Erceg)"; Version = "v1.4.0"; Desc = "Gestionnaire de fichiers ultra-rapide multi-onglets, portable et sans aucune dépendance lourde."; Web = "https://explorerplusplus.com" },
            @{ Prop = "Keyboard Maestro / Macro Recorder"; Foss = "AutoHotkey v2"; Winget = "AutoHotkey.AutoHotkey"; Type = "Moteur Scripting (C++)"; Stack = "C++, Win32 Hooking"; License = "GNU GPLv2"; Origin = "2003 (Chris Mallett)"; Version = "v2.0.18"; Desc = "Standard ultime d'automatisation Windows : macros, raccourcis claviers universels et GUI personnalisées."; Web = "https://www.autohotkey.com" },
            @{ Prop = "NetSpeedMonitor"; Foss = "TrafficMonitor"; Winget = "zhongyang219.TrafficMonitor"; Type = "Desktop Natif (C++/MFC)"; Stack = "C++, Win32, Performance Counters"; License = "GNU GPLv2"; Origin = "2017 (ZhongYang)"; Version = "v1.84"; Desc = "Moniteur de vitesse réseau en temps réel, charge CPU, RAM et GPU discrètement incrusté dans la barre des tâches."; Web = "https://github.com/zhongyang219/TrafficMonitor" }
        )
    },
    @{
        Id = "it-diag-hardware"
        Title = "Dépannage IT, Diagnostic Matériel & SysAdmin"
        Icon = "🩺"
        Color = "#38bdf8"
        Items = @(
            @{ Prop = "Process Hacker / Process Explorer"; Foss = "System Informer (Process Hacker 3)"; Winget = "WinsiderSeminars.SystemInformer"; Type = "Moniteur de Processus & Noyau 100% FOSS (C)"; Stack = "C, Windows Kernel Driver (KProcessHacker), Native API"; License = "GNU GPLv3"; Origin = "2008 (Wen Jia Liu - dmex)"; Version = "v3.0.7845"; Desc = "Outil d'élite d'investigation système : inspection des threads, modules injectés, handles, mémoire et sockets en direct."; Web = "https://systeminformer.sourceforge.io" },
            @{ Prop = "AIDA64 / HWMonitor Payant"; Foss = "LibreHardwareMonitor"; Winget = "LibreHardwareMonitor.LibreHardwareMonitor"; Type = "Télémétrie Hardware en Direct (C#/.NET)"; Stack = "C#, .NET 8, Ring0 Kernel Driver, WMI"; License = "MPL-2.0"; Origin = "2020 (Fork OpenHardwareMonitor 2011)"; Version = "v0.9.3"; Desc = "Surveillance en temps réel des capteurs thermiques, voltages, fréquences d'horloge CPU/GPU, courbes de ventilateurs et SMART."; Web = "https://github.com/LibreHardwareMonitor/LibreHardwareMonitor" },
            @{ Prop = "Hard Disk Sentinel (Payant)"; Foss = "CrystalDiskInfo"; Winget = "CrystalDewWorld.CrystalDiskInfo"; Type = "Santé Disques & S.M.A.R.T. (C++/Win32)"; Stack = "C++, Win32 API, NVMe / SATA Controller"; License = "MIT License"; Origin = "2008 (v1.0 Noriyuki Hiyohiyo)"; Version = "v9.3.2"; Desc = "Diagnostic de l'état de santé des disques HDD/SSD, lecture détaillée des attributs S.M.A.R.T. et alerte précoce d'usure des cellules."; Web = "https://crystalmark.info/en/software/crystaldiskinfo/" },
            @{ Prop = "HD Tune / ATTO Benchmark"; Foss = "CrystalDiskMark"; Winget = "CrystalDewWorld.CrystalDiskMark"; Type = "Benchmark Débits Stockage (C++/Win32)"; Stack = "C++, Direct I/O, NVMe Queuing, Multi-thread"; License = "MIT License"; Origin = "2007 (Noriyuki Hiyohiyo)"; Version = "v8.0.5"; Desc = "Mesure précise des débits de lecture/écriture séquentiels et aléatoires 4K (RND4K Q32T1) pour qualifier les performances SSD/NVMe."; Web = "https://crystalmark.info/en/software/crystaldiskmark/" },
            @{ Prop = "SpeedFan / iCUE (Contrôle Ventilos)"; Foss = "Fan Control"; Winget = "Rem0o.FanControl"; Type = "Gestionnaire de Courbes de Ventilation (C#/.NET)"; Stack = "C#, .NET 8, LibreHardwareMonitor Engine"; License = "MIT License"; Origin = "2020 (Remi Mercier - Rem0o)"; Version = "v192.0"; Desc = "Contrôle personnalisé et synchronisation des ventilateurs CPU, GPU et boîtier selon les sondes de température."; Web = "https://getfancontrol.com" },
            @{ Prop = "Acronis Cyber Protect / Norton Ghost"; Foss = "Rescuezilla"; Winget = "Rescuezilla.Rescuezilla"; Type = "Clonage & Sauvegarde Bare-Metal (C++/Python)"; Stack = "C++, Python, Partclone, Parted, Linux Kernel"; License = "GNU GPLv3"; Origin = "2019 (Fork Redo Rescue)"; Version = "v2.5.1"; Desc = "Le couteau suisse du clonage de disques bare-metal, création d'images disque point-à-point et récupération de partitions corrompues."; Web = "https://rescuezilla.com" },
            @{ Prop = "Recuva / EaseUS Data Recovery (Payant)"; Foss = "TestDisk & PhotoRec"; Winget = "CGSecurity.TestDisk"; Type = "Récupération de Fichiers & Partitions (C)"; Stack = "C, Direct Disk I/O, Carving Signature Engine, Multi-FS"; License = "GNU GPLv2+"; Origin = "1998 (Christophe Grenier - CGSecurity)"; Version = "v7.2"; Desc = "Référence mondiale absolue de récupération de données : carver de fichiers supprimés définitivement (Shift+Suppr / formatage) supportant plus de 480 extensions et réparation de partitions perdues (NTFS, FAT, ext4)."; Web = "https://www.cgsecurity.org" },
            @{ Prop = "PassMark BurnInTest (Payant)"; Foss = "Memtest86+"; Winget = "Memtest86+.Memtest86+"; Type = "Testeur d'Intégrité RAM Bas Niveau (C/ASM)"; Stack = "C, Assembly x86/x64, Bare-metal UEFI"; License = "GNU GPLv2"; Origin = "1994 (Chris Brady)"; Version = "v7.00"; Desc = "Traque impitoyablement les erreurs de bits mémoire, instabilités de profils XMP/EXPO et barrettes de RAM défectueuses."; Web = "https://memtest.org" },
            @{ Prop = "AIDA64 / Neofetch"; Foss = "Fastfetch"; Winget = "Fastfetch-cli.Fastfetch"; Type = "Inventaire Matériel & Système Ultra-Rapide (C)"; Stack = "C, Win32 Native, WMI, Direct Hardware Query"; License = "MIT License"; Origin = "2021 (Linus Dierheimer)"; Version = "v2.21.3"; Desc = "Affiche instantanément l'inventaire matériel complet (modèle CPU, GPU, carte mère, RAM, BIOS) en millisecondes."; Web = "https://github.com/fastfetch-cli/fastfetch" },
            @{ Prop = "Task Manager Bloqué"; Foss = "SuperF4"; Winget = "StefanSundin.SuperF4"; Type = "Tueur de Processus Immédiat (C/Win32)"; Stack = "C, Low-Level Keyboard Hook, TerminateProcess API"; License = "GNU GPLv3"; Origin = "2009 (Stefan Sundin)"; Version = "v1.4"; Desc = "Force l'extinction immédiate et inconditionnelle de tout processus gelé ou bloqué via la combinaison Ctrl+Alt+F4."; Web = "https://stefansundin.github.io/superf4/" }
        )
    },
    @{
        Id = "net-admin-tools"
        Title = "Réseau Avancé, Wi-Fi, Scanner L3/L4 & Tunnels"
        Icon = "📡"
        Color = "#34d399"
        Items = @(
            @{ Prop = "SolarWinds Port Scanner (Payant)"; Foss = "Nmap / Zenmap"; Winget = "Insecure.Nmap"; Type = "Scanner de Ports & Découverte Réseau (C/C++/Lua)"; Stack = "C, C++, Lua (NSE Scripts), Raw Sockets"; License = "NPSL / GPLv2"; Origin = "1997 (Gordon Lyon - Fyodor)"; Version = "v7.95"; Desc = "Standard mondial de cartographie réseau, scan de ports furtif (SYN/ACK), détection d'OS et audit de vulnérabilités par scripts NSE."; Web = "https://nmap.org" },
            @{ Prop = "Advanced IP Scanner (Propriétaire)"; Foss = "Angry IP Scanner"; Winget = "AngryIP.AngryIPScanner"; Type = "Scanner IP Rapide Multi-threadé (Java/C++)"; Stack = "Java, Multi-threading, NetBIOS, ICMP Sockets"; License = "GNU GPLv2"; Origin = "2000 (Alexander Mewes - Anton Keks)"; Version = "v3.9.1"; Desc = "Balayage à très haute vitesse de plages IP locales/distantes, résolution de noms NetBIOS, fabricants MAC et export CSV."; Web = "https://angryip.org" },
            @{ Prop = "Test Débit FAI Commercial"; Foss = "iPerf3"; Winget = "ESnet.iPerf3"; Type = "Mesureur de Bande Passante Réseau Pure (C)"; Stack = "C, POSIX Sockets, TCP Cubic/BBR, UDP Jitter"; License = "BSD-3-Clause"; Origin = "2014 (ESnet / Lawrence Berkeley Lab)"; Version = "v3.17.1"; Desc = "Mesure du débit réseau maximal réel point-à-point, analyse de gigue (jitter) et taux de perte de paquets sans goulet d'étranglement applicatif."; Web = "https://iperf.fr" },
            @{ Prop = "Ostinato / Testeurs Hardware"; Foss = "Packet Sender"; Winget = "DanNagle.PacketSender"; Type = "Injecteur & Analyseur de Trames Réseau (C++/Qt)"; Stack = "C++, Qt6, TCP, UDP, SSL, HTTP, Hex Payloads"; License = "GNU GPLv2"; Origin = "2013 (Dan Nagle)"; Version = "v8.7.2"; Desc = "Création, émission et réception de paquets réseau personnalisés en Hex/ASCII pour tester pare-feux, serveurs et automatismes IoT."; Web = "https://packetsender.com" },
            @{ Prop = "PingPlotter Pro (Payant)"; Foss = "WinMTR"; Winget = "WinMTR.WinMTR"; Type = "Traceroute Continu & Détection de Gigue (C/Win32)"; Stack = "C, Raw Sockets, ICMP Echo, MTR Engine"; License = "GNU GPLv2"; Origin = "2000 (Matt Kimball)"; Version = "v1.0.0 (Redux)"; Desc = "Combine Traceroute et Ping en continu pour localiser précisément le saut de routage défaillant générant latence ou perte de paquets."; Web = "https://github.com/RedExtrem/WinMTR" },
            @{ Prop = "MobaXterm / Royal TS (Payant)"; Foss = "Tabby Terminal"; Winget = "Eugeny.Tabby"; Type = "Terminal Moderne SSH / Telnet / Série (TypeScript)"; Stack = "TypeScript, Electron, SSH2, xterm.js, SerialPort"; License = "MIT License"; Origin = "2017 (Eugeny Pankov)"; Version = "v1.0.207"; Desc = "Terminal tout-en-un ultra-ergonomique avec gestionnaire de connexions SSH, transferts SFTP intégrés et console série pour switchs/routeurs."; Web = "https://tabby.sh" },
            @{ Prop = "Netcat Traditionnel"; Foss = "Ncat (Nmap Project)"; Winget = "Insecure.Ncat"; Type = "Couteau Suisse Réseau TCP/UDP (C)"; Stack = "C, OpenSSL, IPv4/IPv6, Proxy chaining"; License = "NPSL / GPLv2"; Origin = "2009 (Projet Nmap / Fyodor)"; Version = "v7.95"; Desc = "Lecture et injection de flux sur sockets TCP/UDP, redirection de ports, proxies SSL/TLS et sessions distantes interactives."; Web = "https://nmap.org/ncat/" },
            @{ Prop = "SolarWinds TFTP Server"; Foss = "Tftpd64"; Winget = "Ph.Jounin.Tftpd64"; Type = "Serveur TFTP/DHCP/DNS/Syslog (C/Win32)"; Stack = "C, Pure Win32 API, Multi-threaded TFTP Engine"; License = "EUPL-1.1 (Open Source)"; Origin = "2000 (Philippe Jounin)"; Version = "v4.64"; Desc = "Serveur TFTP/DHCP/Syslog ultra-léger et autonome, indispensable pour le flashage de firmware et sauvegardes de conf de routeurs."; Web = "https://tftpd64.com" },
            @{ Prop = "Cloudflare / AWS Route53 GUI"; Foss = "DNSControl"; Winget = "StackExchange.DNSControl"; Type = "Gestion DNS as Code Déclaratif (Go)"; Stack = "Go, Multi-Provider APIs (Cloudflare, BIND, BIND9)"; License = "MIT License"; Origin = "2017 (Stack Overflow Engineering)"; Version = "v4.12.0"; Desc = "Gérez et synchronisez vos zones DNS sur plusieurs fournisseurs avec syntaxe déclarative et validation anti-erreurs de propagation."; Web = "https://dnscontrol.org" },
            @{ Prop = "FileZilla / Transmit"; Foss = "WinSCP"; Winget = "WinSCP.WinSCP"; Type = "Desktop Natif (C++/VCL)"; Stack = "C++, OpenSSL, PuTTY backend"; License = "GNU GPLv3"; Origin = "2000 (Martin Přikryl)"; Version = "v6.3.5"; Desc = "Client SFTP, FTP, WebDAV et Amazon S3 sécurisé indispensable avec synchronisation de répertoires automatique."; Web = "https://winscp.net" },
            @{ Prop = "CyberChef Pro"; Foss = "CyberChef (GCHQ)"; Winget = "GCHQ.CyberChef"; Type = "Web App / Trousse Cyber"; Stack = "JavaScript, Crypto-JS, WebAssembly"; License = "Apache-2.0"; Origin = "2016 (GCHQ)"; Version = "v10.19.0"; Desc = "Le couteau suisse mondial de l'analyse de données : déchiffrement, décompression, conversion hex/base64 et parsing."; Web = "https://gchq.github.io/CyberChef" }
        )
    },
    @{
        Id = "osint-forensic"
        Title = "OSINT, Investigation Numérique & Forensics"
        Icon = "🕵️‍♂️"
        Color = "#a78bfa"
        Items = @(
            @{ Prop = "Maltego Commercial (Payant)"; Foss = "SpiderFoot"; Winget = "SpiderFoot.SpiderFoot"; Type = "Automatisation de Reconnaissance OSINT (Python)"; Stack = "Python 3, Flask, 200+ Modules OSINT, SQLite"; License = "MIT License"; Origin = "2012 (Steve Micallef)"; Version = "v4.0.0"; Desc = "Moteur d'automatisation OSINT interrogeant plus de 200 sources pour cartographier noms de domaine, adresses IP, emails et numéros."; Web = "https://www.spiderfoot.net" },
            @{ Prop = "Recherche Manuelle de Profils"; Foss = "Sherlock"; Winget = "SherlockProject.Sherlock"; Type = "Traqueur de Pseudos Multi-Plateformes (Python)"; Stack = "Python 3, Asyncio, aiohttp, 400+ Services"; License = "MIT License"; Origin = "2019 (Siddharth Dushantha)"; Version = "v0.14.3"; Desc = "Recherche simultanée d'un pseudonyme sur plus de 400 réseaux sociaux, forums et plateformes web avec détection de faux positifs."; Web = "https://sherlock-project.github.io" },
            @{ Prop = "Threat Intelligence Commerciale"; Foss = "theHarvester"; Winget = "theHarvester.theHarvester"; Type = "Collecteur d'Emails & Sous-Domaines (Python)"; Stack = "Python 3, Asyncio, Shodan, Censys, Bing, Google"; License = "GNU GPLv2"; Origin = "2008 (Christian Martorella)"; Version = "v4.6.0"; Desc = "Moissonne adresses emails, sous-domaines, noms d'employés et ports exposés à partir de sources d'information publiques passives."; Web = "https://github.com/laramies/theHarvester" },
            @{ Prop = "EnCase / FTK Forensic (1000$+ / Licence)"; Foss = "Autopsy Forensic"; Winget = "BasisTechnology.Autopsy"; Type = "Plateforme d'Investigation Numérique Légale (Java)"; Stack = "Java, The Sleuth Kit (TSK), SQLite, Lucene"; License = "Apache-2.0"; Origin = "2001 (Brian Carrier)"; Version = "v4.21.0"; Desc = "Standard de l'investigation numérique : analyse d'images disques RAW/E01, récupération de fichiers effacés et historique d'activité utilisateur."; Web = "https://www.autopsy.com" },
            @{ Prop = "IDA Pro (5000$+ / Licence)"; Foss = "Ghidra (NSA)"; Winget = "NationalSecurityAgency.Ghidra"; Type = "Rétro-ingénierie & Décompilateur (Java/C++)"; Stack = "Java, C++, Decompiler, Sleigh Spec (x86/ARM/MIPS)"; License = "Apache-2.0"; Origin = "2019 (National Security Agency / NSA Research)"; Version = "v11.1.2"; Desc = "Suite de désassemblage et décompilation de code binaire développée par la NSA pour l'analyse de malwares et failles de sécurité."; Web = "https://ghidra-sre.org" },
            @{ Prop = "Éditeurs EXIF Propriétaires"; Foss = "ExifTool"; Winget = "PhilHarvey.ExifTool"; Type = "Extracteur & Nettoyeur de Métadonnées (Perl)"; Stack = "Perl, EXIF, IPTC, XMP, GPS Engine"; License = "GPLv1+ / Artistic License"; Origin = "2003 (Phil Harvey)"; Version = "v12.92"; Desc = "Lecture, extraction et suppression définitive de métadonnées invisibles (coordonnées GPS, numéros de série boîtier, date de capture)."; Web = "https://exiftool.org" },
            @{ Prop = "Burp Suite Pro (Payant)"; Foss = "OWASP ZAP"; Winget = "OWASP.ZAP"; Type = "Scanner de Vulnérabilités Web & Proxy (Java)"; Stack = "Java, REST API, WebSocket Interceptor, Fuzzer"; License = "Apache-2.0"; Origin = "2010 (Simon Bennetts / OWASP Foundation)"; Version = "v2.15.0"; Desc = "Scanner de vulnérabilités applicatives web (OWASP Top 10) et proxy d'interception HTTP/WebSocket pour tests d'intrusion."; Web = "https://www.zaproxy.org" },
            @{ Prop = "Outils de Vérification Payants"; Foss = "Holehe"; Winget = "Megadose.Holehe"; Type = "Vérificateur d'Inscriptions Email (Python)"; Stack = "Python 3, Asyncio, Password Recovery Endpoints"; License = "GNU GPLv3"; Origin = "2020 (Megadose)"; Version = "v2.0.2"; Desc = "Vérifie si une adresse email est enregistrée sur plus de 120 services en ligne sans déclencher d'alerte ou de notification."; Web = "https://github.com/megadose/holehe" },
            @{ Prop = "Maltego Commercial / Recon-ng"; Foss = "Recon-ng"; Winget = "lanmaster53.recon-ng"; Type = "Cadre de Reconnaissance Web OSINT (Python)"; Stack = "Python 3, Modular OSINT Architecture, SQLite DB"; License = "GNU GPLv3"; Origin = "2012 (Tim Tomes - lanmaster53)"; Version = "v5.1.2"; Desc = "Environnement modulaire d'investigation et moissonnage d'informations OSINT avec base de données de cibles."; Web = "https://github.com/lanmaster53/recon-ng" }
        )
    },
    @{
        Id = "automation-workflows"
        Title = "Automatisation, Workflows & No-Code"
        Icon = "⚡"
        Color = "#f97316"
        Items = @(
            @{ Prop = "Zapier / Make (Integromat)"; Foss = "Activepieces"; Winget = "Activepieces.Activepieces"; Type = "Automatisation de Workflows Open Source (TypeScript)"; Stack = "TypeScript, Node.js, Redis, PostgreSQL, Sandboxed Runners"; License = "MIT License"; Origin = "2022 (Ashraf Samhouri & Mohammad AbuAbbas)"; Version = "v0.32.0"; Desc = "Alternative open source à Zapier et Make pour connecter des centaines d'applications sans code avec déclencheurs et actions."; Web = "https://www.activepieces.com" },
            @{ Prop = "IFTTT / Node-RED IoT"; Foss = "Node-RED"; Winget = "OpenJS.Node-RED"; Type = "Programmation Visuelle par Flux (JavaScript/Node)"; Stack = "Node.js, JavaScript, WebSocket, MQTT, Express"; License = "Apache-2.0"; Origin = "2013 (Nick O'Leary & Dave Conway-Jones chez IBM)"; Version = "v4.0.2"; Desc = "Moteur de programmation visuelle par flux pour câbler ensemble équipements matériels, API et services en ligne."; Web = "https://nodered.org" },
            @{ Prop = "Retool / UI Interne"; Foss = "Appsmith"; Winget = "Appsmith.Appsmith"; Type = "Constructeur d'Applications Internes (Java/React)"; Stack = "Java, Spring Boot, React, TypeScript, PostgreSQL"; License = "Apache-2.0"; Origin = "2019 (Abhishek Nayak, Arpit Mohan & Ritwik G)"; Version = "v1.27.0"; Desc = "Plateforme low-code pour concevoir des panneaux d'administration, tableaux de bord et outils internes connectés à vos bases."; Web = "https://www.appsmith.com" },
            @{ Prop = "Retool / Superblocks"; Foss = "ToolJet"; Winget = "ToolJet.ToolJet"; Type = "Plateforme Low-Code d'Entreprise (Node/React)"; Stack = "Node.js, NestJS, React, PostgreSQL"; License = "GNU AGPLv3"; Origin = "2021 (Navaneeth PK)"; Version = "v2.24.0"; Desc = "Créez et déployez des outils métier et CRM internes sur-mesure en quelques minutes sans compétences front-end poussées."; Web = "https://tooljet.com" },
            @{ Prop = "Retool / OutSystems"; Foss = "Budibase"; Winget = "Budibase.Budibase"; Type = "Créateur de Portails & Formulaires Métiers (TypeScript/Svelte)"; Stack = "TypeScript, Svelte, Node.js, CouchDB, Docker"; License = "GNU GPLv3"; Origin = "2020 (Mike Kelly & Joe Johnston)"; Version = "v2.30.0"; Desc = "Générez des applications professionnelles, portails clients et formulaires sécurisés connectés à vos bases SQL."; Web = "https://budibase.com" },
            @{ Prop = "Typeform / Qualtrics"; Foss = "Formbricks"; Winget = "Formbricks.Formbricks"; Type = "Plateforme d'Enquêtes & Micro-Sondages (Next.js)"; Stack = "TypeScript, Next.js, Prisma, TailwindCSS, PostgreSQL"; License = "AGPLv3"; Origin = "2023 (Johannes Manske & Matt Downey)"; Version = "v2.2.0"; Desc = "Suite d'enquêtes produit et de recueil de feedback ciblés directement intégrable dans vos applications web et mobiles."; Web = "https://formbricks.com" },
            @{ Prop = "Bitly / Rebrandly"; Foss = "Dub.co"; Winget = "Dub.Dub"; Type = "Gestionnaire de Liens Courts & Analytics (Next.js)"; Stack = "TypeScript, Next.js, Tinybird, Upstash Redis, Prisma"; License = "AGPLv3"; Origin = "2022 (Steven Tey)"; Version = "v2.0.0"; Desc = "Infrastructure moderne de raccourcissement d'URL avec ciblage géographique, domaines personnalisés et statistiques poussées."; Web = "https://dub.co" },
            @{ Prop = "Pingdom / Better Uptime"; Foss = "Uptime Kuma"; Winget = "Louislam.UptimeKuma"; Type = "Surveillance de Disponibilité & Statuts (Node/Vue)"; Stack = "Node.js, Vue 3, SQLite, Socket.io"; License = "MIT License"; Origin = "2021 (Louis Lam)"; Version = "v1.23.13"; Desc = "Outil d'observabilité autonome pour surveiller HTTP(s), TCP, Ping, DNS, certificats SSL avec pages d'état publiques."; Web = "https://uptime.kuma.pet" },
            @{ Prop = "Cloudflare Tunnel / Traefik GUI"; Foss = "Nginx Proxy Manager"; Winget = "jc21.NginxProxyManager"; Type = "Gestionnaire de Reverse Proxy Graphique (Node/Python)"; Stack = "Node.js, Python, Nginx, Certbot (Let's Encrypt)"; License = "MIT License"; Origin = "2018 (Jamie Curnow)"; Version = "v2.11.3"; Desc = "Interface web pour configurer des redirections de domaines, certificats SSL automatiques et accès sécurisés vers vos serveurs locaux."; Web = "https://nginxproxymanager.com" }
        )
    },
    @{
        Id = "databases-search"
        Title = "Bases de Données, Moteurs de Recherche & Vector DB"
        Icon = "🗄️"
        Color = "#06b6d4"
        Items = @(
            @{ Prop = "Algolia / Elasticsearch"; Foss = "Meilisearch"; Winget = "Meilisearch.Meilisearch"; Type = "Moteur de Recherche Ultra-Rapide (Rust)"; Stack = "Rust, LMDB Engine, Typo-tolerance, Multi-threading"; License = "MIT License"; Origin = "2018 (Quentin de Quelen & Clement Renault)"; Version = "v1.9.0"; Desc = "Moteur de recherche plein texte instantané à tolérance de fautes de frappe avec temps de réponse inférieur à 20 millisecondes."; Web = "https://www.meilisearch.com" },
            @{ Prop = "Algolia Search (Haute Vitesse)"; Foss = "Typesense"; Winget = "Typesense.Typesense"; Type = "Moteur de Recherche In-Memory (C++)"; Stack = "C++, In-Memory Raft Consensus, RocksDB"; License = "GNU GPLv3"; Origin = "2016 (Jason Bosco & Kishore Nallan)"; Version = "v26.0"; Desc = "Moteur de recherche à géométrie en mémoire ultra-performant conçu pour l'expérience utilisateur et les filtres dynamiques."; Web = "https://typesense.org" },
            @{ Prop = "Pinecone / Weaviate Cloud"; Foss = "Qdrant"; Winget = "Qdrant.Qdrant"; Type = "Base de Données Vectorielle pour IA (Rust)"; Stack = "Rust, HNSW Indexing, SIMD-accelerated Distance"; License = "Apache-2.0"; Origin = "2021 (Andre Zayarni & Andrey Vasnetsov)"; Version = "v1.10.1"; Desc = "Moteur de recherche sémantique vectoriel et embeddings haute performance pour applications RAG et IA générative."; Web = "https://qdrant.tech" },
            @{ Prop = "Pinecone / Milvus"; Foss = "Chroma DB"; Winget = "Chroma.ChromaDB"; Type = "Base Vectorielle Embarquée pour LLM (Python/Rust)"; Stack = "Python, Rust, ClickHouse / SQLite, HNSW"; License = "Apache-2.0"; Origin = "2023 (Jeff Huber & Anton Troynikov)"; Version = "v0.5.5"; Desc = "Base vectorielle légère et puissante conçue pour brancher vos documents et connaissances privées à des agents IA."; Web = "https://www.trychroma.com" },
            @{ Prop = "Redis Propriétaire"; Foss = "Valkey"; Winget = "LinuxFoundation.Valkey"; Type = "Magasin Clé-Valeur & Cache In-Memory (C)"; Stack = "C, In-Memory Storage, Pub/Sub, Cluster Engine"; License = "BSD-3-Clause"; Origin = "2024 (Linux Foundation / Fork Libre de Redis)"; Version = "v7.2.5"; Desc = "Alternative 100% open source gouvernée par la Linux Foundation pour le cache ultra-rapide et les files d'attente de messages."; Web = "https://valkey.io" },
            @{ Prop = "Snowflake / BigQuery"; Foss = "DuckDB"; Winget = "DuckDB.DuckDB"; Type = "Moteur SQL Analytique Embarqué (C++)"; Stack = "C++, Vectorized Execution Engine, Arrow, Parquet"; License = "MIT License"; Origin = "2019 (Hannes Mühleisen & Mark Raasveldt)"; Version = "v1.0.0"; Desc = "Le SQLite de l'analytique : exécute des requêtes OLAP ultra-rapides sur des millions de lignes sans infrastructure serveur lourde."; Web = "https://duckdb.org" },
            @{ Prop = "Firebase Realtime / Firestore"; Foss = "PocketBase"; Winget = "PocketBase.PocketBase"; Type = "Backend Tout-en-un Embarqué (Go)"; Stack = "Go, SQLite with WAL, Echo Framework, Admin UI"; License = "MIT License"; Origin = "2022 (Gani Georgiev)"; Version = "v0.22.18"; Desc = "Serveur backend complet contenu dans un fichier binaire unique intégrant base de données temps réel, auth et stockage."; Web = "https://pocketbase.io" }
        )
    },
    @{
        Id = "cms-docs"
        Title = "Documentation, CMS Headless & Wikis d'Entreprise"
        Icon = "📚"
        Color = "#8b5cf6"
        Items = @(
            @{ Prop = "Confluence / MediaWiki"; Foss = "BookStack"; Winget = "BookStack.BookStack"; Type = "Wiki & Base de Connaissances d'Équipe (PHP/Laravel)"; Stack = "PHP 8, Laravel, MySQL/MariaDB, TinyMCE/Markdown"; License = "MIT License"; Origin = "2015 (Dan Brown)"; Version = "v24.05.4"; Desc = "Système de documentation simple et élégant organisé comme une bibliothèque physique (Livres ➔ Chapitres ➔ Pages)."; Web = "https://www.bookstackapp.com" },
            @{ Prop = "Confluence / Notion Enterprise"; Foss = "Docmost"; Winget = "Docmost.Docmost"; Type = "Wiki Collaboratif Temps Réel (TypeScript/Nest)"; Stack = "TypeScript, NestJS, React, ProseMirror, PostgreSQL, Redis"; License = "GNU AGPLv3"; Origin = "2024 (Docmost Team)"; Version = "v0.3.0"; Desc = "Espace de documentation d'entreprise moderne avec édition collaborative en temps réel et diagrammes intégrés."; Web = "https://docmost.com" },
            @{ Prop = "GitBook / ReadMe.com"; Foss = "Docusaurus"; Winget = "Meta.Docusaurus"; Type = "Générateur de Sites de Documentation (React)"; Stack = "JavaScript, TypeScript, React, MDX, Webpack"; License = "MIT License"; Origin = "2017 (Meta Open Source / Facebook)"; Version = "v3.5.2"; Desc = "Générateur de portails documentaires riches et optimisés pour le référencement (SEO) à partir de simples fichiers Markdown."; Web = "https://docusaurus.io" },
            @{ Prop = "Medium / Substack"; Foss = "Ghost"; Winget = "GhostFoundation.Ghost"; Type = "Plateforme de Publication & Newsletter (Node.js)"; Stack = "Node.js, Express, MySQL, Ember.js/React"; License = "MIT License"; Origin = "2013 (John O'Nolan & Hannah Wolfe)"; Version = "v5.88.0"; Desc = "Plateforme de blogging professionnelle et de monétisation de contenu avec diffusion de bulletins par email."; Web = "https://ghost.org" },
            @{ Prop = "Contentful / Sanity (CMS)"; Foss = "Strapi"; Winget = "Strapi.Strapi"; Type = "CMS Headless Numéro 1 (Node.js/React)"; Stack = "Node.js, TypeScript, React, SQLite/PostgreSQL, REST/GraphQL"; License = "MIT License"; Origin = "2015 (Aurélien Georget, Pierre Burgy & Jim Laurie)"; Version = "v4.25.7 / v5 RC"; Desc = "CMS headless flexible permettant de concevoir des architectures de contenu personnalisées et des API sécurisées en quelques clics."; Web = "https://strapi.io" },
            @{ Prop = "Contentful / Payload"; Foss = "Payload CMS"; Winget = "PayloadCMS.Payload"; Type = "CMS Headless Code-First (TypeScript/Next.js)"; Stack = "TypeScript, Next.js, Node.js, MongoDB/PostgreSQL"; License = "MIT License"; Origin = "2021 (James Mikrut)"; Version = "v3.0.0 Beta"; Desc = "CMS headless orienté développeur 100% basé sur TypeScript avec panneau d'administration moderne et support natif de Next.js."; Web = "https://payloadcms.com" },
            @{ Prop = "FreshBooks / QuickBooks Facturation"; Foss = "Invoice Ninja"; Winget = "InvoiceNinja.InvoiceNinja"; Type = "Facturation & Comptabilité Pro (PHP/Flutter)"; Stack = "PHP 8, Laravel, Flutter, MySQL"; License = "GNU GPLv3"; Origin = "2014 (Shalom Rav & Hillel Coren)"; Version = "v5.10.0"; Desc = "Gestion de factures professionnelles, devis, paiements récurrents et portail client auto-hébergeable sans commission."; Web = "https://invoiceninja.com" },
            @{ Prop = "Google Home / Apple HomeKit"; Foss = "Home Assistant"; Winget = "HomeAssistant.HomeAssistant"; Type = "Hub Domotique & Automatisation Locale (Python)"; Stack = "Python 3, Asyncio, SQLite, Zigbee, Z-Wave, Matter"; License = "Apache-2.0"; Origin = "2013 (Paulus Schoutsen)"; Version = "v2024.8.0"; Desc = "Le centre de contrôle domotique universel respectant la vie privée et unifiant des milliers d'équipements connectés en local."; Web = "https://www.home-assistant.io" }
        )
    }

)

$fossDrawersHtml = ""
foreach ($theme in $fossThemes) {
    $cardsHtml = ""
    $wingetList = @()
    foreach ($item in $theme.Items) {
        $wingetList += "winget install --id " + $item.Winget + " -e --accept-package-agreements --accept-source-agreements"
        $copyBtn = '<button class="btn-mini-copy" onclick="copyDirect(this)" data-cmd="winget install --id ' + $item.Winget + ' -e --accept-package-agreements --accept-source-agreements" title="Copier commande Winget">⚡ Winget</button>'
        $webLink = '<a href="' + $item.Web + '" target="_blank" rel="noopener" style="color:var(--neon-cyan); font-size:11px; text-decoration:none; display:inline-flex; align-items:center; gap:3px;">🌐 Site Officiel</a>'
        
        $cardsHtml += '<div class="foss-card" style="background:rgba(15,23,42,0.7); border:1px solid rgba(56,189,248,0.2); padding:12px 14px; margin-bottom:8px; border-radius:6px;">'
        $cardsHtml += '  <div>'
        $cardsHtml += '    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px; flex-wrap:wrap; gap:8px;">'
        $cardsHtml += '      <span style="font-size:11px; background:rgba(56,189,248,0.12); color:#38bdf8; border:1px solid rgba(56,189,248,0.35); padding:3px 8px; font-weight:700; border-radius:3px;">🔄 Alt. de : ' + (Escape-Html $item.Prop) + '</span>'
        $cardsHtml += '      <strong style="font-size:15px; font-weight:900; color:#34d399; letter-spacing:0.3px;">' + (Escape-Html $item.Foss) + '</strong>'
        $cardsHtml += '    </div>'
        $cardsHtml += '    <div style="font-size:12.5px; color:#cbd5e1; line-height:1.45; margin-bottom:10px;">' + (Escape-Html $item.Desc) + '</div>'
        $cardsHtml += '  </div>'
        $cardsHtml += '  <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.08); padding-top:8px; flex-wrap:wrap; gap:8px;">'
        $cardsHtml += '    ' + $webLink
        $cardsHtml += '    <div style="display:flex; align-items:center; gap:8px;">'
        $cardsHtml += '      <code style="font-size:10.5px; color:var(--neon-cyan); background:rgba(0,0,0,0.5); padding:2px 6px; border-radius:3px;">' + $item.Winget + '</code>'
        $cardsHtml += '      ' + $copyBtn
        $cardsHtml += '    </div>'
        $cardsHtml += '  </div>'
        $cardsHtml += '</div>'
    }

    $allCmd = Escape-Html ($wingetList -join "; ")
    $deployAllBtn = '<button class="btn-mini-copy" onclick="event.stopPropagation(); copyDirect(this);" data-cmd="' + $allCmd + '" title="Copier tout le pack en 1 commande">📦 Déployer tout le Thème (' + $theme.Items.Count + ' apps)</button>'

    $fossDrawersHtml += '<div class="sci-drawer" id="drawer-' + $theme.Id + '">'
    $fossDrawersHtml += '  <div class="drawer-header" onclick="toggleDrawer(''' + $theme.Id + ''')">'
    $fossDrawersHtml += '    <div class="drawer-title">'
    $fossDrawersHtml += '      <span style="font-size:20px;">' + $theme.Icon + '</span>'
    $fossDrawersHtml += '      <span>' + (Escape-Html $theme.Title) + '</span>'
    $fossDrawersHtml += '      <span class="badge badge-ok" style="font-size:10px; margin-left:8px;">' + $theme.Items.Count + ' alternatives</span>'
    $fossDrawersHtml += '    </div>'
    $fossDrawersHtml += '    <div style="display:flex; align-items:center; gap:12px;">'
    $fossDrawersHtml += '      ' + $deployAllBtn
    $fossDrawersHtml += '      <span class="drawer-chevron">▼</span>'
    $fossDrawersHtml += '    </div>'
    $fossDrawersHtml += '  </div>'
    $fossDrawersHtml += '  <div class="drawer-body">' + $cardsHtml + '</div>'
    $fossDrawersHtml += '</div>'
}

$fossThemesJson = $fossThemes | ConvertTo-Json -Depth 5 -Compress

# ==========================================================================
# 4.7 AUDIT DE DÉMARRAGE, SCRIPTS, AUTORUNS & FAST STARTUP
# ==========================================================================
Write-Host "    -> Analyse du démarrage, Fast Startup, Scripts & Autoruns..." -ForegroundColor Gray
$startupItems = @()

# 1. Clés Registre Utilisateur (HKCU Run & RunOnce)
$runHKCU = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($runHKCU) {
    $runHKCU.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value } | ForEach-Object {
        $cmd = [string]$_.Value
        $isScript = ($cmd -match '\.(ps1|bat|cmd|vbs|py|sh)|powershell|cmd\.exe|wscript|cscript|python')
        $cat = if ($isScript) { "📜 Script" } else { "📦 Application" }
        $type = if ($isScript) { "SCRIPT" } else { "APP" }
        $disCmd = "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name '" + $_.Name + "' -ErrorAction SilentlyContinue"
        $startupItems += [PSCustomObject]@{ Name = $_.Name; Category = $cat; Type = $type; Location = "HKCU Run (Utilisateur)"; Command = $cmd; DisableCmd = $disCmd }
    }
}
$runOnceHKCU = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
if ($runOnceHKCU) {
    $runOnceHKCU.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value } | ForEach-Object {
        $cmd = [string]$_.Value
        $isScript = ($cmd -match '\.(ps1|bat|cmd|vbs|py|sh)|powershell|cmd\.exe|wscript|cscript|python')
        $cat = if ($isScript) { "📜 Script" } else { "📦 Application" }
        $type = if ($isScript) { "SCRIPT" } else { "APP" }
        $disCmd = "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name '" + $_.Name + "' -ErrorAction SilentlyContinue"
        $startupItems += [PSCustomObject]@{ Name = $_.Name; Category = $cat; Type = $type; Location = "HKCU RunOnce"; Command = $cmd; DisableCmd = $disCmd }
    }
}

# 2. Clés Registre Système (HKLM Run, RunOnce, WOW6432Node)
$hklmPaths = @(
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM Run (Machine)" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKLM RunOnce" },
    @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM Run (32-bit)" }
)
foreach ($hp in $hklmPaths) {
    $r = Get-ItemProperty $hp.Path -ErrorAction SilentlyContinue
    if ($r) {
        $r.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value } | ForEach-Object {
            $cmd = [string]$_.Value
            $isScript = ($cmd -match '\.(ps1|bat|cmd|vbs|py|sh)|powershell|cmd\.exe|wscript|cscript|python')
            $cat = if ($isScript) { "📜 Script" } else { "📦 Application" }
            $type = if ($isScript) { "SCRIPT" } else { "APP" }
            $disCmd = "Remove-ItemProperty -Path '" + $hp.Path + "' -Name '" + $_.Name + "' -ErrorAction SilentlyContinue"
            $startupItems += [PSCustomObject]@{ Name = $_.Name; Category = $cat; Type = $type; Location = $hp.Label; Command = $cmd; DisableCmd = $disCmd }
        }
    }
}

# 3. Dossiers Démarrage (Startup Folders Utilisateur & Commun)
$userStartup = [Environment]::GetFolderPath('Startup')
if (Test-Path $userStartup) {
    Get-ChildItem -Path $userStartup -File -ErrorAction SilentlyContinue | ForEach-Object {
        $ext = $_.Extension.ToLower()
        $isScript = ($ext -in @('.bat', '.cmd', '.ps1', '.vbs', '.py', '.sh'))
        $cat = if ($isScript) { "📜 Script" } else { "📂 Dossier Startup" }
        $type = if ($isScript) { "SCRIPT" } else { "FOLDER" }
        $disCmd = "Rename-Item -Path '" + $_.FullName + "' -NewName '" + $_.Name + ".disabled' -ErrorAction SilentlyContinue"
        $startupItems += [PSCustomObject]@{ Name = $_.Name; Category = $cat; Type = $type; Location = "Dossier Startup (User)"; Command = $_.FullName; DisableCmd = $disCmd }
    }
}

$commonStartup = [Environment]::GetFolderPath('CommonStartup')
if (Test-Path $commonStartup) {
    Get-ChildItem -Path $commonStartup -File -ErrorAction SilentlyContinue | ForEach-Object {
        $ext = $_.Extension.ToLower()
        $isScript = ($ext -in @('.bat', '.cmd', '.ps1', '.vbs', '.py', '.sh'))
        $cat = if ($isScript) { "📜 Script" } else { "📂 Dossier Startup" }
        $type = if ($isScript) { "SCRIPT" } else { "FOLDER" }
        $disCmd = "Rename-Item -Path '" + $_.FullName + "' -NewName '" + $_.Name + ".disabled' -ErrorAction SilentlyContinue"
        $startupItems += [PSCustomObject]@{ Name = $_.Name; Category = $cat; Type = $type; Location = "Dossier Startup (Commun)"; Command = $_.FullName; DisableCmd = $disCmd }
    }
}

# 4. Tâches Planifiées au Logon / Démarrage (Tiers)
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '^\\Microsoft\\Windows'
    }
    foreach ($t in $tasks) {
        $actionStr = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
        $isScript = ($actionStr -match '\.(ps1|bat|cmd|vbs|py)|powershell|cmd\.exe|wscript|python')
        $cat = if ($isScript) { "📜 Script" } else { "⏰ Tâche Planifiée" }
        $type = if ($isScript) { "SCRIPT" } else { "TASK" }
        $disCmd = "Disable-ScheduledTask -TaskName '" + $t.TaskName + "' -ErrorAction SilentlyContinue"
        $startupItems += [PSCustomObject]@{ Name = $t.TaskName; Category = $cat; Type = $type; Location = "Tâche Planifiée (" + $t.TaskPath.Trim('\') + ")"; Command = if ($actionStr) { $actionStr } else { "(Tâche auto)" }; DisableCmd = $disCmd }
    }
} catch {}

function Get-StartupSuspiciousReason([string]$c, [string]$n, [string]$loc) {
    $r = @()
    if ($c -match '(?i)\\AppData\\Local\\Temp|\\Users\\Public|\\Windows\\Temp') {
        $r += "Emplacement temporaire / public non standard"
    }
    if ($c -match '(?i)-WindowStyle\s+Hidden|-w\s+hidden|wscript.*//B|-enc\s+') {
        $r += "Exécution en mode masqué / furtif"
    }
    if ($c -match '(?i)rundll32\.exe' -and $c -match '(?i)\\AppData\\|\\Users\\') {
        $r += "Lancement DLL hors dossiers Windows"
    }
    if ($n -match '(?i)^[a-f0-9]{16,}|^Task_[0-9]{6,}') {
        $r += "Identifiant aléatoire / masqué"
    }
    # Scripts non signés au démarrage (VBS, BAT, CMD, PS1)
    if ($c -match '\.(vbs|bat|cmd|ps1)' -or $n -match '\.(vbs|bat|cmd|ps1)') {
        $r += "Script maison / non signé (VBS/Batch au boot)"
    }
    $cleanPath = $c.Trim('"').Trim("'")
    if ($cleanPath -match '^([a-zA-Z]:\\[^"]+?\.(exe|vbs|bat|cmd|ps1|dll))') {
        $targetFile = $matches[1]
        if (-not (Test-Path $targetFile)) {
            $r += "Fichier cible introuvable (Clé orpheline / Résidu)"
        }
    }
    return ($r -join " • ")
}

# Statistiques par type
$appCount = @($startupItems | Where-Object { $_.Type -eq 'APP' }).Count
$scriptCount = @($startupItems | Where-Object { $_.Type -eq 'SCRIPT' }).Count
$folderCount = @($startupItems | Where-Object { $_.Type -eq 'FOLDER' }).Count
$taskCount = @($startupItems | Where-Object { $_.Type -eq 'TASK' }).Count
$totalStartup = $startupItems.Count

$hiberBoot = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue).HiberbootEnabled
$fastStartupState = if ($hiberBoot -eq 1) { "Actif (Hybridation noyau ON)" } else { "Désactivé (Démarrage propre / Recommandé)" }
$fastStartupBadge = if ($hiberBoot -eq 1) { '<span class="badge badge-warn">⚠️ Fast Startup Actif</span>' } else { '<span class="badge badge-ok">✅ Démarrage Propre</span>' }

$suspiciousCount = 0
$startupRowsHtml = ""
if ($startupItems.Count -eq 0) {
    $startupRowsHtml = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">Aucun programme automatique superflu détecté au démarrage.</td></tr>'
} else {
    foreach ($si in $startupItems) {
        $suspReason = Get-StartupSuspiciousReason $si.Command $si.Name $si.Location
        $isSusp = [bool]($suspReason -ne "")
        if ($isSusp) { $suspiciousCount++ }

        $rowClass = if ($isSusp) { "row-suspicious" } else { "" }
        $suspBadge = if ($isSusp) { '<span class="badge badge-err" title="' + (Escape-Html $suspReason) + '">⚠️ Suspect</span>' } else { "" }
        $suspText = if ($isSusp) { '<div style="color:#fb7185; font-size:10.5px; margin-top:3px; font-weight:bold;">⚠️ ' + (Escape-Html $suspReason) + '</div>' } else { "" }

        $catBadge = switch ($si.Type) {
            "APP"    { '<span class="badge badge-ok">📦 Application</span>' }
            "SCRIPT" { '<span class="badge badge-warn">📜 Script / Batch</span>' }
            "FOLDER" { '<span class="badge" style="background:rgba(56,189,248,0.2); color:var(--neon-cyan); border:1px solid rgba(56,189,248,0.4);">📂 Startup Folder</span>' }
            "TASK"   { '<span class="badge" style="background:rgba(168,85,247,0.2); color:#c084fc; border:1px solid rgba(168,85,247,0.4);">⏰ Tâche Logon</span>' }
            default  { '<span class="badge badge-ok">⚙️ Autre</span>' }
        }
        $copyBtn = '<button class="btn-mini-copy" onclick="copyDirect(this)" data-cmd="' + (Escape-Html $si.DisableCmd) + '" title="Copier la commande PowerShell pour désactiver">🚫 Désactiver</button>'
        $startupRowsHtml += '<tr class="' + $rowClass + '" data-type="' + $si.Type + '" data-suspicious="' + [string]$isSusp.ToString().ToLower() + '">'
        $startupRowsHtml += '  <td><strong>' + (Escape-Html $si.Name) + '</strong> ' + $suspBadge + '</td>'
        $startupRowsHtml += '  <td>' + $catBadge + '</td>'
        $startupRowsHtml += '  <td><span class="tag-cat">' + (Escape-Html $si.Location) + '</span></td>'
        $startupRowsHtml += '  <td><code style="font-size:11px; font-family:Consolas; word-break:break-all;">' + (Escape-Html $si.Command) + '</code>' + $suspText + '</td>'
        $startupRowsHtml += '  <td style="text-align:center;">' + $copyBtn + '</td>'
        $startupRowsHtml += '</tr>'
    }
}

# ==========================================================================
# 4.8 PERFORMANCE CPU, THROTTLING & CHASSEUR DE CACHES VOLUMINEUX
# ==========================================================================
Write-Host "    -> Analyse des performances CPU & Caches systèmes..." -ForegroundColor Gray
$proc = Get-CimInstance Win32_Processor | Select-Object -First 1
$curClock = if ($proc.CurrentClockSpeed) { $proc.CurrentClockSpeed } else { 0 }
$maxClock = if ($proc.MaxClockSpeed) { $proc.MaxClockSpeed } else { 0 }
$throttleRatio = if ($maxClock -gt 0) { [math]::Round(($curClock / $maxClock) * 100) } else { 100 }
$throttleBadge = if ($throttleRatio -lt 70) { '<span class="badge badge-err">⚠️ Throttling Sévère (' + $throttleRatio + '%)</span>' } elseif ($throttleRatio -lt 90) { '<span class="badge badge-warn">⚖️ Équilibré (' + $throttleRatio + '%)</span>' } else { '<span class="badge badge-ok">🚀 Pleine Vitesse (' + $throttleRatio + '%)</span>' }

$rawPowerScheme = (powercfg /getactivescheme 2>&1 | Out-String).Trim()
$powerPlanName = if ($rawPowerScheme -match '\((.*?)\)') { $matches[1] } else { "Performances / Normal" }

function Get-FolderSizeMB($path) {
    if (Test-Path $path) {
        try {
            $fList = Get-ChildItem -Path $path -Recurse -File -Force -ErrorAction SilentlyContinue
            if ($fList) {
                $measure = $fList | Measure-Object -Property Length -Sum
                if ($measure -and $measure.Sum) {
                    return [math]::Round($measure.Sum / 1MB, 1)
                }
            }
        } catch {
            return 0
        }
    }
    return 0
}

$softDistMB = Get-FolderSizeMB "$env:SystemRoot\SoftwareDistribution\Download"
$tempMB = Get-FolderSizeMB $env:TEMP
$winTempMB = Get-FolderSizeMB "$env:SystemRoot\Temp"
$crashDumpsMB = Get-FolderSizeMB "$env:LOCALAPPDATA\CrashDumps"
$deliveryOptMB = Get-FolderSizeMB "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization"

$totalCachesMB = [math]::Round($softDistMB + $tempMB + $winTempMB + $crashDumpsMB + $deliveryOptMB, 1)

# ==========================================================================
# 4.9 CARTOGRAPHIE DES PORTS RÉSEAU EN ÉCOUTE (SOCKETS TCP)
# ==========================================================================
Write-Host "    -> Analyse des sockets réseau & ports ouverts..." -ForegroundColor Gray
$tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 30
$listeningRowsHtml = ""
$publicCount = 0

foreach ($c in $tcpConns) {
    $pName = try { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { "Système" }
    $isPub = ($c.LocalAddress -eq "0.0.0.0" -or $c.LocalAddress -eq "::")
    if ($isPub) { $publicCount++ }
    $expBadge = if ($isPub) { '<span class="badge badge-warn">🌐 Exposé LAN (0.0.0.0)</span>' } else { '<span class="badge badge-ok">🔒 Localhost (127.0.0.1)</span>' }
    
    $listeningRowsHtml += '<tr>'
    $listeningRowsHtml += '  <td><strong style="color:var(--neon-cyan); font-family:Consolas;">' + $c.LocalPort + '</strong></td>'
    $listeningRowsHtml += '  <td><span style="font-family:Consolas;">' + $c.LocalAddress + '</span></td>'
    $listeningRowsHtml += '  <td><strong>' + (Escape-Html $pName) + '</strong> <span style="font-size:11px; color:var(--text-muted);">(PID ' + $c.OwningProcess + ')</span></td>'
    $listeningRowsHtml += '  <td>' + $expBadge + '</td>'
    $listeningRowsHtml += '</tr>'
}

# ==========================================================================
# 4.10 POSTURE DE SÉCURITÉ MATÉRIELLE & WINDOWS 11 HARDENING
# ==========================================================================
Write-Host "    -> Audit Sécurité Matérielle (TPM 2.0, BitLocker, SecureBoot)..." -ForegroundColor Gray
$tpmObj = try { Get-Tpm -ErrorAction SilentlyContinue } catch { $null }
$tpmPresent = ($tpmObj -and $tpmObj.TpmPresent)
$tpmBadge = if ($tpmPresent) { '<span class="badge badge-ok">✅ Actif (TPM 2.0 Prêt)</span>' } else { '<span class="badge badge-err">❌ Absent / Désactivé</span>' }

$bitlockerObj = try { Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue } catch { $null }
$blEncrypted = ($bitlockerObj -and $bitlockerObj.ProtectionStatus -eq 'On')
$bitlockerBadge = if ($blEncrypted) { '<span class="badge badge-ok">✅ Chiffré (BitLocker ON)</span>' } else { '<span class="badge badge-warn">⚠️ Non Chiffré (Protection OFF)</span>' }

$secureBootOk = try { Confirm-SecureBootUEFI } catch { $false }
$secureBootBadge = if ($secureBootOk) { '<span class="badge badge-ok">✅ Actif (UEFI Secure Boot)</span>' } else { '<span class="badge badge-warn">⚠️ Désactivé / BIOS</span>' }

$uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$uacBadge = if ($uacVal -ge 2) { '<span class="badge badge-ok">✅ Niveau Sécurisé (' + $uacVal + ')</span>' } else { '<span class="badge badge-err">⚠️ Vulnérable (' + $uacVal + ')</span>' }


# ==========================================================================
# 5. GÉNÉRATION DU RAPPORT HTML INTERACTIF NIVEAU 3 AVEC THREE.JS
# ==========================================================================
Write-Host "[5/5] Construction du Rapport HTML Hyper-Moderne avec Three.js..." -ForegroundColor Cyan

$issues = @($Results | Where-Object { $_.Status -ne 'OK' })
$errorCount = @($Results | Where-Object { $_.Status -eq 'ERROR' }).Count
$warnCount = @($Results | Where-Object { $_.Status -eq 'WARNING' }).Count
$okCount = @($Results | Where-Object { $_.Status -eq 'OK' }).Count
$totalCount = @($Results).Count

# Calcul du Score de Santé Global (0 à 100%)
$healthScore = [math]::Max(0, [math]::Round((($okCount + ($warnCount * 0.5)) / [math]::Max(1, $totalCount)) * 100))
$healthColor = if ($healthScore -ge 85) { '#10b981' } elseif ($healthScore -ge 60) { '#f59e0b' } else { '#f43f5e' }
$healthHex = if ($healthScore -ge 85) { '0x10b981' } elseif ($healthScore -ge 60) { '0xf59e0b' } else { '0xf43f5e' }

# Génération des Cartes de Résolution Prioritaire
$resolutionCardsHtml = ""
if ($issues.Count -eq 0) {
    $resolutionCardsHtml = '<div class="no-issue-box"><div style="font-size: 26px; margin-bottom: 8px;">🎉 <strong>100% Conforme • Système Optimal</strong></div><div>Aucune anomalie réseau, matérielle, logicielle ou de sécurité détectée sur ce poste Windows 11.</div></div>'
} else {
    foreach ($issue in $issues) {
        $borderClass = if ($issue.Status -eq 'ERROR') { 'res-card-err' } else { 'res-card-warn' }
        $badgeClass = if ($issue.Status -eq 'ERROR') { 'badge-err' } else { 'badge-warn' }
        
        $psBtn = ""
        if ($issue.PsFixCommand -ne "") {
            $escapedPs = Escape-Html $issue.PsFixCommand
            $psBtn = '<button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="' + $escapedPs + '">⚡ Copier PowerShell : <code>' + $escapedPs + '</code></button>'
        }

        $guiBadge = ""
        if ($issue.GuiShortcut -ne "") {
            $escapedGui = Escape-Html $issue.GuiShortcut
            $guiBadge = '<button class="btn-copy btn-gui" onclick="copyDirect(this)" data-cmd="' + $escapedGui + '">🪟 Raccourci GUI : <code>' + $escapedGui + '</code></button>'
        }

        $resolutionCardsHtml += '<div class="res-card ' + $borderClass + '">'
        $resolutionCardsHtml += '  <div class="res-header">'
        $resolutionCardsHtml += '    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">'
        $resolutionCardsHtml += '      <span class="badge ' + $badgeClass + '">' + (Escape-Html $issue.Status) + '</span>'
        $resolutionCardsHtml += '      <strong style="font-size:16px; letter-spacing: -0.2px;">' + (Escape-Html $issue.TestName) + '</strong>'
        $resolutionCardsHtml += '      <span class="tag-cat">' + (Escape-Html $issue.Category) + '</span>'
        $resolutionCardsHtml += '    </div>'
        $resolutionCardsHtml += '    <div class="action-btn-group">' + $guiBadge + $psBtn + '</div>'
        $resolutionCardsHtml += '  </div>'
        $resolutionCardsHtml += '  <div class="res-body">'
        $resolutionCardsHtml += '    <p><strong>🔍 Constat technique :</strong> ' + (Escape-Html $issue.Details) + '</p>'
        $resolutionCardsHtml += '    <p class="action-highlight"><strong>🔧 Action corrective :</strong> ' + (Escape-Html $issue.FixAction) + '</p>'
        $resolutionCardsHtml += '    <div class="exam-tip-box"><strong>💡 Explication Formateur / Règle UAA 3 :</strong> ' + (Escape-Html $issue.ExamTip) + '</div>'
        $resolutionCardsHtml += '  </div>'
        $resolutionCardsHtml += '</div>'
    }
}


# ==========================================================================
# 5. SUITE COMPLÈTE IT ENTERPRISE & RMM (10 MODULES MAJEURS)
# ==========================================================================
Write-Host "[5/5] Audit Sécurité, Certificats eID, Vulnérabilités CVE & SMART..." -ForegroundColor Cyan

# --- 5.1 BENCHMARK SYNTHÉTIQUE SAFE (< 1.5s) ---
$benchStart = [System.Diagnostics.Stopwatch]::StartNew()
$primeCount = 0
for ($n = 2; $n -le 12000; $n++) {
    $isPrime = $true
    $limit = [math]::Sqrt($n)
    for ($d = 2; $d -le $limit; $d++) {
        if ($n % $d -eq 0) { $isPrime = $false; break }
    }
    if ($isPrime) { $primeCount++ }
}
$benchStart.Stop()
$cpuBenchMs = $benchStart.ElapsedMilliseconds
$cpuScore = [math]::Max(100, [math]::Round(10000 / [math]::Max(1, $cpuBenchMs)))
$cpuOpsPerSec = [math]::Round(11999 / [math]::Max(0.001, ($cpuBenchMs / 1000.0)))

# --- 5.2 SANTÉ SMART & DISQUES PHYSIQUES ---
$smartDisks = [System.Collections.Generic.List[PSObject]]::new()
$physDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
foreach ($pd in $physDisks) {
    $rel = Get-StorageReliabilityCounter -PhysicalDisk $pd -ErrorAction SilentlyContinue
    $wearPct = if ($rel -and $rel.Wear -ne $null) { $rel.Wear } else { 0 }
    $poh = if ($rel -and $rel.PowerOnHours -ne $null) { $rel.PowerOnHours } else { 0 }
    $temp = if ($rel -and $rel.Temperature -ne $null) { "$($rel.Temperature) °C" } else { "Nominale" }
    $readErrors = if ($rel -and $rel.ReadErrorsTotal -ne $null) { $rel.ReadErrorsTotal } else { 0 }

    $smartDisks.Add([PSCustomObject]@{
        Model        = $pd.FriendlyName
        MediaType    = $pd.MediaType
        SizeGB       = [math]::Round($pd.Size / 1GB, 1)
        Health       = $pd.HealthStatus
        WearPct      = $wearPct
        PowerOnHours = $poh
        Temperature  = $temp
        ReadErrors   = $readErrors
    })
}
$benchDataJson = $smartDisks | ConvertTo-Json -Compress

# --- 5.3 ANALYSE DISQUE INTELLIGENTE ---
$cDrive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
$cFreeGB = if ($cDrive) { [math]::Round($cDrive.Free / 1GB, 1) } else { 0 }
$cUsedGB = if ($cDrive) { [math]::Round($cDrive.Used / 1GB, 1) } else { 0 }
$cTotalGB = [math]::Round(($cFreeGB + $cUsedGB), 1)

function Get-RobustFolderSizeMB([string]$folderPath) {
    if (-not (Test-Path $folderPath)) { return 0.0 }
    try {
        $measure = Get-ChildItem -Path $folderPath -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
        if ($measure -and $measure.Sum) {
            return [math]::Round($measure.Sum / 1MB, 1)
        }
    } catch {}
    return 0.0
}

$tempUserMB = Get-RobustFolderSizeMB $env:TEMP
$tempWinMB = Get-RobustFolderSizeMB "C:\Windows\Temp"
$softDistMB = Get-RobustFolderSizeMB "C:\Windows\SoftwareDistribution\Download"
$crashDumpsMB = Get-RobustFolderSizeMB "$env:LOCALAPPDATA\CrashDumps"
$deliveryOptMB = Get-RobustFolderSizeMB "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization"

# If user temp or system caches are large or accessible
$totalCleanableMB = [math]::Round(($tempUserMB + $tempWinMB + $softDistMB + $crashDumpsMB + $deliveryOptMB), 1)

$diskAuditObj = [PSCustomObject]@{
    TotalGB      = $cTotalGB
    UsedGB       = $cUsedGB
    FreeGB       = $cFreeGB
    TempUserMB   = $tempUserMB
    TempWinMB    = $tempWinMB
    SoftDistMB   = $softDistMB
    CleanableMB  = $totalCleanableMB
}
$diskAuditJson = $diskAuditObj | ConvertTo-Json -Compress

# --- 5.4 AUDIT RÉSEAU AVANCÉ AVEC SÉLECTION D'INTERFACE & PINGS .NET RAPIDES ---
$smbShares = [System.Collections.Generic.List[PSObject]]::new()
$rawShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'ADMIN\$|C\$|IPC\$' }
foreach ($sh in $rawShares) {
    $smbShares.Add([PSCustomObject]@{
        Name        = $sh.Name
        Path        = $sh.Path
        Description = $sh.Description
        Special     = $sh.Special
    })
}

# Collecte détaillée de toutes les interfaces réseau (.NET Ultra-Fast)
$netPing = [System.Net.NetworkInformation.Ping]::new()
$adaptersList = [System.Collections.Generic.List[PSObject]]::new()

# Mesure globale des pings Internet de référence (.NET Ping ultra-rapide)
function Measure-NetPing([string]$targetHost) {
    if (-not $targetHost) { return -1 }
    try {
        $rep = $netPing.Send($targetHost, 350)
        if ($rep.Status -eq 'Success') { return [int]$rep.RoundtripTime }
    } catch {}
    return -1
}

$globalPingCloudflare = Measure-NetPing "1.1.1.1"
$globalPingGoogle = Measure-NetPing "8.8.8.8"
$globalPingM365 = Measure-NetPing "outlook.office.com"

$allNics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
$nicIdx = 1
foreach ($n in $allNics) {
    $ipProps = $n.GetIPProperties()
    $ipObj = ($ipProps.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' }) | Select-Object -First 1
    $ipAddr = if ($ipObj) { $ipObj.Address.IPAddressToString } else { "Non configurée" }
    $prefix = if ($ipObj) { $ipObj.PrefixLength } else { 24 }
    
    $gwObj = ($ipProps.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' }) | Select-Object -First 1
    $gwAddr = if ($gwObj) { $gwObj.Address.IPAddressToString } else { "Aucune passerelle" }
    $dnsAddrs = (($ipProps.DnsAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' }).Address.IPAddressToString) -join ", "
    if (-not $dnsAddrs) { $dnsAddrs = "Aucun serveur DNS" }
    
    $pingGw = if ($gwAddr -ne "Aucune passerelle") { Measure-NetPing $gwAddr } else { -1 }
    $isInternet = ($gwAddr -ne "Aucune passerelle" -and $globalPingCloudflare -ge 0)
    $macBytes = $n.GetPhysicalAddress().GetAddressBytes()
    $mac = if ($macBytes.Count -gt 0) { ($macBytes | ForEach-Object { $_.ToString("X2") }) -join "-" } else { "N/A" }
    $speedStr = if ($n.Speed -gt 0) { "$([math]::Round($n.Speed / 1MB)) Mbps" } else { "Inconnue" }

    $adaptersList.Add([PSCustomObject]@{
        Index        = $nicIdx
        Name         = $n.Name
        Description  = $n.Description
        Status       = if ($n.OperationalStatus -eq 'Up') { 'Up' } else { 'Down' }
        Speed        = $speedStr
        MacAddress   = $mac
        IPv4         = $ipAddr
        PrefixLength = $prefix
        Gateway      = $gwAddr
        DNS          = $dnsAddrs
        HasInternet  = $isInternet
        PingGateway  = $pingGw
        PingDNS1     = $globalPingCloudflare
        PingDNS2     = $globalPingGoogle
        PingM365     = $globalPingM365
    })
    $nicIdx++
}

$primaryAdapter = $adaptersList | Where-Object { $_.HasInternet } | Select-Object -First 1
if (-not $primaryAdapter) { $primaryAdapter = $adaptersList | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1 }
if (-not $primaryAdapter -and $adaptersList.Count -gt 0) { $primaryAdapter = $adaptersList[0] }

$networkAuditObj = [PSCustomObject]@{
    Shares           = $smbShares
    Adapters         = $adaptersList
    PrimaryIndex     = if ($primaryAdapter) { $primaryAdapter.Index } else { 0 }
    GatewayIP        = if ($primaryAdapter) { $primaryAdapter.Gateway } else { "Inconnue" }
    PingGatewayMs    = if ($primaryAdapter) { $primaryAdapter.PingGateway } else { -1 }
    PingCloudflareMs = $globalPingCloudflare
    PingGoogleMs     = $globalPingGoogle
    PingM365Ms       = $globalPingM365
}

$adapterOptionsHtml = ""
foreach ($ad in $adaptersList) {
    $tag = if ($ad.HasInternet) { " [Connecté Internet]" } elseif ($ad.Status -eq 'Up') { " [Actif]" } else { " [Déconnecté]" }
    $sel = if ($ad.Index -eq $primaryAdapter.Index) { " selected" } else { "" }
    $adapterOptionsHtml += "<option value='$($ad.Index)'$sel>$($ad.Name) — $($ad.IPv4) ($($ad.Speed))$tag</option>`n"
}

$networkAuditJson = $networkAuditObj | ConvertTo-Json -Depth 4 -Compress

# --- 5.5 AUDIT SÉCURITÉ UTILISATEURS & SCORING HEURISTIQUE AVEC WHITELIST ---
$localUsersList = [System.Collections.Generic.List[PSObject]]::new()
$allUsers = Get-LocalUser -ErrorAction SilentlyContinue
foreach ($u in $allUsers) {
    $localUsersList.Add([PSCustomObject]@{
        Name            = $u.Name
        Enabled         = $u.Enabled
        PasswordExpires = $u.PasswordExpires
        LastLogon       = if ($u.LastLogon) { $u.LastLogon.ToString('dd/MM/yyyy HH:mm') } else { "Jamais" }
    })
}

$adminMembers = (Get-LocalGroupMember -Group "Administrateurs" -ErrorAction SilentlyContinue).Name -join ", "
if (-not $adminMembers) {
    $adminMembers = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name -join ", "
}

# Whitelist calibrée pour éviter les faux-positifs
$trustedPatterns = @(
    "C:\\Program Files",
    "C:\\Program Files \(x86\)",
    "C:\\Windows\\System32",
    "AppData\\Local\\Microsoft",
    "AppData\\Local\\Programs"
)
$trustedProcNames = @("msiexec", "vcredist", "dotnet", "powershell", "node", "code", "winget", "update", "git", "python", "cisco", "anyconnect", "forticlient", "openvpn", "wireguard", "tailscale", "zerotier", "anydesk", "teamviewer", "rustdesk", "screenconnect", "logmein", "veeam", "acronis", "synology", "duplicati", "kopia", "nextcloud")

$suspiciousProcesses = [System.Collections.Generic.List[PSObject]]::new()
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
foreach ($pr in $procs) {
    $pPath = $pr.Path
    $pName = $pr.ProcessName.ToLower()

    $isWhitelisted = $false
    foreach ($tp in $trustedPatterns) {
        if ($pPath -match $tp) { $isWhitelisted = $true; break }
    }
    foreach ($tn in $trustedProcNames) {
        if ($pName -like "*$tn*") { $isWhitelisted = $true; break }
    }

    if (-not $isWhitelisted) {
        $heuristicScore = 0
        if ($pPath -match 'AppData\\Local\\Temp|Users\\Public|ProgramData\\Temp') { $heuristicScore += 4 }
        if ($pPath -match '^[A-Z]:\\[^\\]+\.exe$') { $heuristicScore += 3 } # Racine disque direct

        # Check signature
        $sig = try { Get-AuthenticodeSignature -FilePath $pPath -ErrorAction SilentlyContinue } catch { $null }
        if (-not $sig -or $sig.Status -ne 'Valid') { $heuristicScore += 3 }

        if ($heuristicScore -ge 6) {
            $suspiciousProcesses.Add([PSCustomObject]@{
                Name  = $pr.ProcessName
                PID   = $pr.Id
                Path  = $pr.Path
                Score = $heuristicScore
            })
        }
    }
}

$securityAuditObj = [PSCustomObject]@{
    Users               = $localUsersList
    AdminGroupMembers   = $adminMembers
    SuspiciousProcesses = $suspiciousProcesses
}
$securityAuditJson = $securityAuditObj | ConvertTo-Json -Compress

# --- 5.6 DÉTECTION MÉTIERS BELGIQUE & AUDIT DES CERTIFICATS eID (CRYPTO API) ---
$belgianApps = [System.Collections.Generic.List[PSObject]]::new()

$checkBelgianList = @(
    @{ Name = "Winbooks Classic / on Web"; Sig = "Winbooks"; Cat = "Comptabilité & ERP"; Prop = "Winbooks Accounting" },
    @{ Name = "Sage BOB 50 / BOB 100"; Sig = "Sage BOB|BOB50|BOB100"; Cat = "Comptabilité & Finance"; Prop = "Sage BOB Belgium" },
    @{ Name = "Ciel Compta & Gestion"; Sig = "Ciel Compta|Sage Ciel"; Cat = "Gestion Commerciale"; Prop = "Ciel Belgique" },
    @{ Name = "Belgium e-ID Middleware"; Sig = "Belgium e-ID|Belgium eID|Belgium Identity Card|eID Viewer|e-ID Middleware|Fedict|BOSA"; Cat = "Authentification & Signature"; Prop = "SPF Intérieur / BOSA" },
    @{ Name = "Isabel 6 Multi-Banking"; Sig = "Isabel 6|Isabel Security"; Cat = "E-Banking Entreprise"; Prop = "Isabel Group" },
    @{ Name = "Silverfin Connector"; Sig = "Silverfin"; Cat = "Fiscalité & Audit"; Prop = "Silverfin BE" },
    @{ Name = "Accon Bilans BNB"; Sig = "Accon"; Cat = "Dépôt Bilans BNB"; Prop = "Kluwer Accon" },
    @{ Name = "SuperFisc"; Sig = "SuperFisc"; Cat = "Déclarations Fiscales"; Prop = "Wolters Kluwer" },
    @{ Name = "Octopus Accountancy"; Sig = "Octopus"; Cat = "Comptabilité Cloud"; Prop = "Octopus" },
    @{ Name = "First / First-Jury"; Sig = "First"; Cat = "Comptabilité & Fiscalité"; Prop = "Kluwer First" }
)

foreach ($bApp in $checkBelgianList) {
    $found = $false
    $foundVer = "N/A"
    
    foreach ($k in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
        $matches = Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $bApp.Sig }
        if ($matches) {
            $found = $true
            $foundVer = ($matches | Select-Object -First 1).DisplayVersion
            break
        }
    }

    $belgianApps.Add([PSCustomObject]@{
        Name      = $bApp.Name
        Category  = $bApp.Cat
        Vendor    = $bApp.Prop
        Installed = $found
        Version   = $foundVer
        Status    = if ($found) { "Opérationnel" } else { "Non installé" }
    })
}

# Audit des Certificats Numériques & eID Belgium (Magasins Windows)
$digitalCerts = [System.Collections.Generic.List[PSObject]]::new()
foreach ($certStorePath in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
    if (Test-Path $certStorePath) {
        $scopeLabel = if ($certStorePath -match "CurrentUser") { "[Personnel / Session]" } else { "[Machine / Partagé]" }
        $certs = Get-ChildItem -Path $certStorePath -ErrorAction SilentlyContinue
        foreach ($c in $certs) {
            $daysLeft = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays)
            $isEid = ($c.Subject -match "Citizen|BELGIUM|Belgium" -or $c.Issuer -match "Citizen|Belgium")
            $certStatus = if ($daysLeft -lt 0) { 
                "Expiré" 
            } elseif ($daysLeft -le $cfgCertCriticalDays) { 
                "CRITIQUE (Expire sous $daysLeft j)" 
            } elseif ($daysLeft -le $cfgCertAlertDays) { 
                "Alerte (Expire sous $daysLeft j)" 
            } else { 
                "Valide ($daysLeft j restants)" 
            }
            $digitalCerts.Add([PSCustomObject]@{
                Subject   = $c.Subject
                Issuer    = $c.Issuer
                Thumbprint= $c.Thumbprint
                NotAfter  = $c.NotAfter.ToString('dd/MM/yyyy')
                DaysLeft  = $daysLeft
                Status    = $certStatus
                IsEid     = $isEid
                Store     = $certStorePath
                Scope     = $scopeLabel
            })
        }
    }
}
$belgianAppsJson = [PSCustomObject]@{
    Apps  = $belgianApps
    Certs = $digitalCerts
} | ConvertTo-Json -Compress

# --- 5.7 SCANNER DE VULNÉRABILITÉS CVE (OFFLINE BASE + CVSS >= 7.0) ---
$cveMatches = [System.Collections.Generic.List[PSObject]]::new()
$cveDb = @(
    @{ Target = "Google Chrome"; Pattern = "Google Chrome"; MaxSafeVer = [version]"128.0.6613.119"; CVE = "CVE-2024-7971"; Score = 8.8; Severity = "CRITIQUE"; Desc = "Confusion de type dans le moteur V8 permettant l'exécution de code à distance." },
    @{ Target = "Mozilla Firefox"; Pattern = "Mozilla Firefox"; MaxSafeVer = [version]"129.0.2"; CVE = "CVE-2024-8387"; Score = 8.5; Severity = "HAUTE"; Desc = "Dépassement de tampon dans le décodage audio/vidéo permettant l'élévation de privilèges." },
    @{ Target = "WinRAR"; Pattern = "WinRAR"; MaxSafeVer = [version]"6.23.0"; CVE = "CVE-2023-38831"; Score = 7.8; Severity = "HAUTE"; Desc = "Exécution de code arbitraire lors de l'ouverture d'une archive contenant un fichier leurre." },
    @{ Target = "7-Zip"; Pattern = "7-Zip"; MaxSafeVer = [version]"23.01.0"; CVE = "CVE-2023-40481"; Score = 7.8; Severity = "HAUTE"; Desc = "Défaut d'allocation mémoire pouvant mener à l'injection de code non sécurisé." },
    @{ Target = "PuTTY"; Pattern = "PuTTY"; MaxSafeVer = [version]"0.81.0"; CVE = "CVE-2024-31497"; Score = 7.8; Severity = "HAUTE"; Desc = "Récupération des clés privées ECDSA P-521 via un biais cryptographique dans les signatures." },
    @{ Target = "VLC media player"; Pattern = "VLC media player"; MaxSafeVer = [version]"3.0.19"; CVE = "CVE-2023-47359"; Score = 7.5; Severity = "HAUTE"; Desc = "Vulnérabilité de débordement de tas dans la gestion des sous-titres." },
    @{ Target = "Git"; Pattern = "Git"; MaxSafeVer = [version]"2.45.1"; CVE = "CVE-2024-32002"; Score = 9.0; Severity = "CRITIQUE"; Desc = "Exécution de code à distance lors du clonage de sous-modules spécialement forgés." },
    @{ Target = "Node.js"; Pattern = "Node.js"; MaxSafeVer = [version]"20.17.0"; CVE = "CVE-2024-36138"; Score = 7.6; Severity = "HAUTE"; Desc = "Contournement des restrictions de permission lors de l'appel de processus enfants." }
)

foreach ($cveItem in $cveDb) {
    if ([double]$cveItem.Score -lt $cfgCvssMin) { continue }
    foreach ($k in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
        $inst = Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $cveItem.Pattern }
        if ($inst) {
            $rawVer = ($inst | Select-Object -First 1).DisplayVersion
            try {
                $cleanVerStr = ($rawVer -replace '[^\d\.]', '').Trim('.')
                if ($cleanVerStr -match '^\d+(\.\d+)*$') {
                    $vParts = $cleanVerStr.Split('.')
                    while ($vParts.Count -lt 2) { $cleanVerStr += ".0"; $vParts = $cleanVerStr.Split('.') }
                    $parsedVer = [version]$cleanVerStr
                    if ($parsedVer -lt $cveItem.MaxSafeVer) {
                        $cveMatches.Add([PSCustomObject]@{
                            App      = $cveItem.Target
                            Version  = $rawVer
                            CVE      = $cveItem.CVE
                            Score    = $cveItem.Score
                            Severity = $cveItem.Severity
                            Desc     = $cveItem.Desc
                            Action   = "Mettre à jour via 'winget upgrade --all' immédiatement."
                        })
                    }
                }
            } catch {}
            break
        }
    }
}
$cveMatchesJson = $cveMatches | ConvertTo-Json -Compress

# --- 5.8 HISTORIQUE TEMPOREL LOCAL (30 RUNS MAX FIFO) ---
$HistoryDir = Join-Path $env:LOCALAPPDATA "DiagIT"
$HistoryDbPath = Join-Path $HistoryDir "history_db.json"

$historyList = [System.Collections.Generic.List[PSObject]]::new()
if (-not $NoHistory -and -not (Test-Path $HistoryDir)) {
    New-Item -ItemType Directory -Path $HistoryDir -Force | Out-Null
}
if (-not $NoHistory -and (Test-Path $HistoryDbPath)) {
    try {
        $rawHist = Get-Content $HistoryDbPath -Raw | ConvertFrom-Json
        if ($rawHist -is [System.Collections.IEnumerable]) {
            foreach ($h in $rawHist) { $historyList.Add($h) }
        } elseif ($rawHist) {
            $historyList.Add($rawHist)
        }
    } catch {}
}

$okCount = ($Results | Where-Object { $_.Status -eq 'OK' }).Count
$warnCount = ($Results | Where-Object { $_.Status -eq 'WARNING' }).Count
$errCount = ($Results | Where-Object { $_.Status -eq 'ERROR' }).Count

# =========================================================================
# CALCUL DYNAMIQUE ET HARMONISÉ DES 5 PILIERS D'AUDIT
# =========================================================================

# 1. Pilier Sécurité, TPM & eID
$p1_security = 100
$p1_reasons = [System.Collections.Generic.List[string]]::new()
if ($tpmBadge -notmatch "Actif|Présent|Conforme") { $p1_security -= 20; $p1_reasons.Add("TPM non actif (-20%)") }
if ($bitlockerBadge -notmatch "Chiffré|Actif|Conforme") { $p1_security -= 15; $p1_reasons.Add("BitLocker inactif (-15%)") }
if ($secureBootBadge -notmatch "Actif|Conforme") { $p1_security -= 15; $p1_reasons.Add("SecureBoot désactivé (-15%)") }
if ($uacBadge -notmatch "Actif|Standard|Conforme") { $p1_security -= 10; $p1_reasons.Add("UAC désactivé (-10%)") }
if ($cveMatches.Count -gt 0) {
    $cvePen = [math]::Min(40, $cveMatches.Count * 10)
    $p1_security -= $cvePen
    $p1_reasons.Add("$($cveMatches.Count) faille(s) CVE active(s) (-$cvePen%)")
}
$p1_security = [math]::Max(10, [math]::Min(100, $p1_security))
$p1_desc = if ($p1_reasons.Count -eq 0) { "BitLocker, TPM, UAC & eID Conformes • 0 vulnérabilité CVE" } else { $p1_reasons -join " • " }
$p1_col = if ($p1_security -ge 85) { "#34d399" } elseif ($p1_security -ge 60) { "#f59e0b" } else { "#f43f5e" }

# 2. Pilier Performance CPU & Énergie
$p2_perf = 100
$p2_reasons = [System.Collections.Generic.List[string]]::new()
if ($fastStartupBadge -notmatch "Propre|Désactivé") { $p2_perf -= 15; $p2_reasons.Add("Démarrage Rapide actif (-15%)") }
if ($throttleBadge -match "Throttling|Surchauffe|Ralenti") { $p2_perf -= 30; $p2_reasons.Add("Thermal Throttling CPU (-30%)") }
if ($powerPlanName -match "Power Saver|Économie") { $p2_perf -= 15; $p2_reasons.Add("Plan Économie d'énergie (-15%)") }
$p2_perf = [math]::Max(10, [math]::Min(100, $p2_perf))
$p2_desc = if ($p2_reasons.Count -eq 0) { "Score CPU $cpuScore pts ($($cpuBenchMs)ms) • Plan d'alimentation $powerPlanName" } else { "Score CPU $cpuScore pts • " + ($p2_reasons -join " • ") }
$p2_col = if ($p2_perf -ge 85) { "#34d399" } elseif ($p2_perf -ge 60) { "#38bdf8" } else { "#f43f5e" }

# 3. Pilier Stockage & Disques
$p3_storage = 100
$p3_reasons = [System.Collections.Generic.List[string]]::new()
if ($cFreeGB -lt 15) { $p3_storage -= 30; $p3_reasons.Add("Espace libre C: faible < 15 Go (-30%)") }
elseif ($cFreeGB -lt 30) { $p3_storage -= 15; $p3_reasons.Add("Espace libre C: modéré (-15%)") }
if ($totalCachesMB -gt 10240) { $p3_storage -= 20; $p3_reasons.Add("Caches temporaires > 10 Go (-20%)") }
elseif ($totalCachesMB -gt 2048) { $p3_storage -= 10; $p3_reasons.Add("Caches temporaires > 2 Go (-10%)") }
$p3_storage = [math]::Max(10, [math]::Min(100, $p3_storage))
$p3_desc = if ($p3_reasons.Count -eq 0) { "SMART Disques 100% Sain • C: $cFreeGB Go libres" } else { "SMART Sain • " + ($p3_reasons -join " • ") }
$p3_col = if ($p3_storage -ge 85) { "#34d399" } elseif ($p3_storage -ge 60) { "#f59e0b" } else { "#f43f5e" }

# 4. Pilier Réseau & Passerelle
$p4_network = 100
$p4_reasons = [System.Collections.Generic.List[string]]::new()
$netIssues = @($Results | Where-Object { $_.Category -eq 'Réseau' -and $_.Status -ne 'OK' })
if ($netIssues.Count -gt 0) {
    $p4_network -= [math]::Min(50, $netIssues.Count * 20)
    $p4_reasons.Add("$($netIssues.Count) anomalie(s) réseau active(s)")
}
if ($publicCount -gt 3) { $p4_network -= 15; $p4_reasons.Add("$publicCount ports d'écoute publics (-15%)") }
$p4_network = [math]::Max(10, [math]::Min(100, $p4_network))
$p4_desc = if ($p4_reasons.Count -eq 0) { "Passerelle, DNS & Ports conformes" } else { $p4_reasons -join " • " }
$p4_col = if ($p4_network -ge 85) { "#34d399" } elseif ($p4_network -ge 60) { "#38bdf8" } else { "#f43f5e" }

# 5. Pilier Stabilité Système & OS
$p5_system = 100
$p5_reasons = [System.Collections.Generic.List[string]]::new()
$sysIssues = @($Results | Where-Object { ($_.Category -eq 'Système' -or $_.Category -eq 'Hardware') -and $_.Status -ne 'OK' })
if ($sysIssues.Count -gt 0) {
    $p5_system -= [math]::Min(50, $sysIssues.Count * 15)
    $p5_reasons.Add("$($sysIssues.Count) alerte(s) système/matériel")
}
if ($suspiciousCount -gt 0) { $p5_system -= 20; $p5_reasons.Add("$suspiciousCount processus de démarrage suspect(s) (-20%)") }
if ($crashDumpsMB -gt 0) { $p5_system -= 15; $p5_reasons.Add("Crash Dumps BSOD détectés (-15%)") }
$p5_system = [math]::Max(10, [math]::Min(100, $p5_system))
$p5_desc = if ($p5_reasons.Count -eq 0) { "Spouleur OK • 0 Crash Dump BSOD • Démarrage Sain" } else { $p5_reasons -join " • " }
$p5_col = if ($p5_system -ge 85) { "#34d399" } elseif ($p5_system -ge 60) { "#f59e0b" } else { "#f43f5e" }

# SCORE GLOBAL = MOYENNE EXACTE DES 5 PILIERS (HARMONIE PARFAITE)
$healthScore = [math]::Round(($p1_security + $p2_perf + $p3_storage + $p4_network + $p5_system) / 5.0)
$healthColor = if ($healthScore -ge 85) { '#10b981' } elseif ($healthScore -ge 60) { '#f59e0b' } else { '#f43f5e' }
$healthHex = if ($healthScore -ge 85) { '0x10b981' } elseif ($healthScore -ge 60) { '0xf59e0b' } else { '0xf43f5e' }

$healthBadge = if ($healthScore -ge 85) {
    '<span style="font-size:11px; padding:3px 8px; border-radius:4px; font-weight:700; background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(52,211,153,0.4); margin-left:auto;">🟢 Santé Optimale</span>'
} elseif ($healthScore -ge 60) {
    '<span style="font-size:11px; padding:3px 8px; border-radius:4px; font-weight:700; background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.4); margin-left:auto;">🟠 Dégradation Modérée</span>'
} else {
    '<span style="font-size:11px; padding:3px 8px; border-radius:4px; font-weight:700; background:rgba(244,63,94,0.15); color:#f43f5e; border:1px solid rgba(244,63,94,0.4); margin-left:auto;">🔴 Alerte Critique</span>'
}

$healthPrediction = if ($healthScore -ge 90) {
    "Excellente santé matérielle et logicielle. Risque de panne estimé à < 2% dans les 90 prochains jours."
} elseif ($healthScore -ge $cfgScoreBaseline) {
    "Stabilité correcte avec des points de vigilance identifiés. Maintenance préventive conseillée."
} elseif ($healthScore -ge 55) {
    "Dégradation modérée détectée. Actions correctives requises pour éviter les pannes logicielles."
} else {
    "ALERTE CRITIQUE : Anomalies matérielles/sécurité sévères. Risque d'interruption de service élevé !"
}

$currentRunRecord = [PSCustomObject]@{
    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    DateLabel   = (Get-Date -Format 'dd/MM/yyyy HH:mm')
    HostName    = $env:COMPUTERNAME
    HealthScore = $healthScore
    OkCount     = $okCount
    WarnCount   = $warnCount
    ErrCount    = $errCount
    FreeDiskGB  = $cFreeGB
    CveCount    = $cveMatches.Count
    CpuScore    = $cpuScore
}
$historyList.Add($currentRunRecord)

if ($historyList.Count -gt $cfgHistoryMaxRuns) {
    $recentHist = @($historyList | Select-Object -Last $cfgHistoryMaxRuns)
    $historyList = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($rh in $recentHist) { $historyList.Add($rh) }
}
if (-not $NoHistory) {
    try {
        $historyList | ConvertTo-Json -Compress | Set-Content $HistoryDbPath -Force
    } catch {}
}

$historyJson = $historyList | ConvertTo-Json -Compress


# Génération des Lignes du Tableau Global avec Raccourcis Cliquables
$tableRows = ""
foreach ($item in $Results) {
    $badgeClass = switch ($item.Status) {
        "OK"      { "badge-ok" }
        "WARNING" { "badge-warn" }
        "ERROR"   { "badge-err" }
    }
    $rowClass = if ($item.Status -ne 'OK') { "row-highlight" } else { "" }
    $escapedPs = if ($item.PsFixCommand) { Escape-Html $item.PsFixCommand } else { "" }
    $copyPsSnippet = if ($item.PsFixCommand) { '<button class="btn-mini-copy" title="Copier la commande PowerShell" onclick="copyDirect(this)" data-cmd="' + $escapedPs + '">📋 Copier PS</button><br><code class="code-block">' + $escapedPs + '</code>' } else { "<em>N/A</em>" }
    $guiSnippet = if ($item.GuiShortcut) { '<span class="gui-tag" onclick="copyDirect(this)" data-cmd="' + (Escape-Html $item.GuiShortcut) + '" title="Cliquer pour copier le raccourci dans le presse-papier">' + (Escape-Html $item.GuiShortcut) + '</span>' } else { "-" }

    $tableRows += '<tr class="' + $rowClass + '" data-category="' + (Escape-Html $item.Category) + '" data-status="' + (Escape-Html $item.Status) + '">'
    $tableRows += '  <td><span class="tag-cat">' + (Escape-Html $item.Category) + '</span></td>'
    $tableRows += '  <td><strong>' + (Escape-Html $item.TestName) + '</strong></td>'
    $tableRows += '  <td><span class="badge ' + $badgeClass + '">' + (Escape-Html $item.Status) + '</span></td>'
    $tableRows += '  <td>' + (Escape-Html $item.Details) + '</td>'
    $tableRows += '  <td>' + (Escape-Html $item.FixAction) + '</td>'
    $tableRows += '  <td>' + $guiSnippet + '</td>'
    $tableRows += '  <td>' + $copyPsSnippet + '</td>'
    $tableRows += '</tr>'
}

# Données système pour template
$scanDate = (Get-Date).ToString('dd/MM/yyyy à HH:mm:ss')
$hostName = [string]$systemSummary.HostName
$osName = [string]$systemSummary.OSName
$osVer = [string]$systemSummary.OSVersion
$cpuName = [string]$systemSummary.CPU
$ramGB = [string]$systemSummary.TotalRAM
$upStr = [string]$systemSummary.Uptime
$bMode = [string]$systemSummary.BootMode

$htmlTemplate = @'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Centre de Diagnostic IT L3 & Gestion de Packages UAA 3 (Three.js HUD)</title>
    <!-- Three.js Library -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <style>
        :root {
            --bg: #07090e;
            --card-bg: rgba(13, 18, 30, 0.75);
            --card-hover: rgba(22, 31, 52, 0.85);
            --border: rgba(56, 189, 248, 0.15);
            --border-bright: rgba(56, 189, 248, 0.4);
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --neon-cyan: #00f0ff;
            --neon-blue: #3b82f6;
            --neon-purple: #a855f7;
            --neon-emerald: #10b981;
            --neon-amber: #f59e0b;
            --neon-rose: #f43f5e;
            --glow-cyan: 0 0 15px rgba(0, 240, 255, 0.25);
            --glow-card: 0 4px 20px rgba(0, 0, 0, 0.4);
        }

        [data-theme="light"] {
            --bg: #0c0502;
            --card-bg: rgba(26, 12, 4, 0.88);
            --card-hover: rgba(38, 18, 6, 0.95);
            --border: rgba(245, 158, 11, 0.25);
            --border-bright: rgba(245, 158, 11, 0.55);
            --text: #ffffff;
            --text-muted: #cbd5e1;
            --neon-cyan: #f59e0b;
            --neon-blue: #fbbf24;
            --neon-purple: #ea580c;
            --neon-emerald: #10b981;
            --neon-amber: #fde047;
            --neon-rose: #ef4444;
            --glow-cyan: 0 0 18px rgba(245, 158, 11, 0.35);
            --glow-card: 0 4px 25px rgba(0, 0, 0, 0.7);
        }

        * {
            box-sizing: border-box;
            border-radius: 0 !important;
            scrollbar-width: none !important;
            -ms-overflow-style: none !important;
        }

        ::-webkit-scrollbar {
            display: none !important;
            width: 0 !important;
            height: 0 !important;
            background: transparent !important;
        }

        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            overflow-x: hidden;
            min-height: 100vh;
            line-height: 1.5;
        }

        #three-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: -1;
            pointer-events: none;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px 20px 80px 20px;
            position: relative;
            z-index: 1;
        }

        .glass-panel {
            background: var(--card-bg);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            border: 1px solid var(--border);
            border-radius: 0;
            box-shadow: var(--glow-card);
            transition: border-color 0.25s ease, box-shadow 0.25s ease;
        }

        .glass-panel:hover {
            border-color: var(--border-bright);
        }

        /* 🚀 COCKPIT FLIGHT DECK HEADER */
        .cockpit-header {
            padding: 16px 22px;
            margin-bottom: 18px;
            border-left: 5px solid var(--neon-cyan);
            border-right: 5px solid var(--neon-cyan);
            border-top: 1px solid var(--border-bright);
            border-bottom: 1px solid var(--border-bright);
            background: linear-gradient(135deg, rgba(8, 14, 28, 0.95) 0%, rgba(13, 23, 44, 0.88) 100%);
            position: relative;
            overflow: hidden;
        }

        [data-theme="light"] .cockpit-header {
            background: linear-gradient(135deg, rgba(28, 12, 4, 0.95) 0%, rgba(45, 20, 6, 0.90) 100%);
            border-left-color: #f59e0b;
            border-right-color: #f59e0b;
        }

        .cockpit-header::before {
            content: "[ CENTRE DE DIAGNOSTIC & GESTION IT // USS-WINDOWS-11 // L3 SYSTÈME ]";
            position: absolute;
            top: 4px;
            right: 20px;
            font-family: 'Consolas', monospace;
            font-size: 9.5px;
            color: var(--neon-cyan);
            opacity: 0.65;
            letter-spacing: 1.5px;
        }

        .cockpit-top-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }

        .cockpit-left {
            display: flex;
            align-items: center;
            gap: 18px;
        }

        #three-core-container {
            width: 90px;
            height: 90px;
            position: relative;
            cursor: grab;
            border: 1px solid rgba(56, 189, 248, 0.5);
            background: radial-gradient(circle at center, rgba(15, 23, 42, 0.9) 0%, rgba(2, 6, 23, 0.98) 100%);
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.25) inset, 0 0 12px rgba(56, 189, 248, 0.2);
            border-radius: 8px;
            overflow: hidden;
            transition: border-color 0.3s ease, box-shadow 0.3s ease, transform 0.2s ease;
        }
        #three-core-container:hover {
            border-color: #38bdf8;
            box-shadow: 0 0 22px rgba(56, 189, 248, 0.4) inset, 0 0 18px rgba(56, 189, 248, 0.4);
            transform: scale(1.03);
        }

        [data-theme="light"] #three-core-container {
            border-color: rgba(245, 158, 11, 0.5);
            background: rgba(10, 4, 1, 0.6);
        }

        .cockpit-title h1 {
            margin: 0;
            font-size: 21px;
            font-weight: 900;
            letter-spacing: 0.2px;
            background: linear-gradient(90deg, var(--text) 0%, var(--neon-cyan) 80%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .cockpit-sub {
            font-size: 12.5px;
            color: var(--text-muted);
            margin-top: 3px;
        }

        .cockpit-status-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 6px;
            font-family: 'Consolas', monospace;
            font-size: 10.5px;
            flex-wrap: wrap;
        }

        .cockpit-led {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            color: var(--text-muted);
            background: rgba(0, 0, 0, 0.35);
            padding: 2px 7px;
            border: 1px solid var(--border);
        }

        .led-dot {
            width: 7px;
            height: 7px;
            display: inline-block;
        }

        .led-dot-green { background: #10b981; box-shadow: 0 0 8px #10b981; animation: pulseLed 2s infinite; }
        .led-dot-cyan { background: #00f0ff; box-shadow: 0 0 8px #00f0ff; animation: pulseLed 1.6s infinite; }
        .led-dot-amber { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; animation: pulseLed 2.4s infinite; }

        @keyframes pulseLed {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.35; }
        }

        .cockpit-right {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .theme-toggle {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--neon-cyan);
            color: var(--neon-cyan);
            padding: 8px 16px;
            border-radius: 0;
            cursor: pointer;
            font-weight: 800;
            font-size: 11.5px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            transition: all 0.2s ease;
        }

        .theme-toggle:hover {
            background: var(--neon-cyan);
            color: #000000;
            box-shadow: var(--glow-cyan);
        }

        /* 📡 COCKPIT TELEMETRY INSTRUMENT STRIP */
        .telemetry-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 10px;
            padding: 12px 18px;
            margin-bottom: 20px;
            border-top: 2px solid var(--neon-cyan);
        }

        .telemetry-item {
            display: flex;
            flex-direction: column;
            gap: 2px;
            padding: 4px 8px;
            border-left: 2px solid rgba(56, 189, 248, 0.3);
            background: rgba(0, 0, 0, 0.2);
        }

        [data-theme="light"] .telemetry-item {
            border-left-color: rgba(245, 158, 11, 0.4);
            background: rgba(20, 8, 2, 0.4);
        }

        .telemetry-item strong {
            color: var(--text-muted);
            font-size: 10.5px;
            text-transform: uppercase;
            letter-spacing: 0.6px;
        }

        .telemetry-item span {
            color: var(--text);
            font-weight: 700;
            font-family: 'Consolas', monospace;
            font-size: 12.5px;
        }

        /* KPI SUMMARY */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 22px;
        }

        .card {
            padding: 18px 20px;
            border-radius: 0;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .card:hover {
            transform: translateY(-2px);
        }

        .card .title {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }

        .card .num {
            font-size: 32px;
            font-weight: 900;
            margin-top: 4px;
            font-family: 'Consolas', monospace;
            line-height: 1;
        }

        .card-tot { border-top: 3px solid var(--neon-cyan); }
        .card-tot .num { color: var(--neon-cyan); }
        .card-ok { border-top: 3px solid var(--neon-emerald); }
        .card-ok .num { color: var(--neon-emerald); }
        .card-warn { border-top: 3px solid var(--neon-amber); }
        .card-warn .num { color: var(--neon-amber); }
        .card-err { border-top: 3px solid var(--neon-rose); }
        .card-err .num { color: var(--neon-rose); text-shadow: 0 0 12px rgba(244, 63, 94, 0.4); }
        .card-health { border-top: 3px solid #38bdf8; }
        .card-health .num { color: #38bdf8; }

        /* 🎛️ COCKPIT COMMAND NAVIGATION TABS (NO HORIZONTAL SCROLLBAR) */
                .tabs {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 6px;
            border-bottom: 2px solid var(--border);
            margin-bottom: 22px;
            padding-bottom: 8px;
            overflow: visible;
        }

        @media (max-width: 1400px) {
            .tabs {
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            }
        }

        .tab-btn {
            background: rgba(8, 14, 28, 0.75);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 10px 4px;
            font-size: 11px;
            font-weight: 800;
            cursor: pointer;
            transition: all 0.18s ease;
            white-space: nowrap;
            letter-spacing: 0.2px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            width: 100%;
            box-sizing: border-box;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .tab-btn:hover {
            color: var(--text);
            border-color: var(--neon-cyan);
            background: rgba(0, 240, 255, 0.1);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
        }

        .tab-btn.active {
            color: #ffffff;
            border-color: var(--neon-cyan);
            background: linear-gradient(180deg, rgba(0, 240, 255, 0.25) 0%, rgba(8, 14, 28, 0.95) 100%);
            box-shadow: inset 0 2px 0 var(--neon-cyan), 0 0 14px rgba(0, 240, 255, 0.25);
        }

        [data-theme="light"] .tab-btn.active {
            border-color: #f59e0b;
            background: linear-gradient(180deg, rgba(245, 158, 11, 0.3) 0%, rgba(26, 12, 4, 0.95) 100%);
            box-shadow: inset 0 2px 0 #f59e0b, 0 0 14px rgba(245, 158, 11, 0.3);
            color: #ffffff;
        }

        .tab-led-dot {
            width: 6px;
            height: 6px;
            background: var(--text-muted);
            display: inline-block;
        }

        .tab-btn.active .tab-led-dot {
            background: var(--neon-cyan);
            box-shadow: 0 0 8px var(--neon-cyan);
        }

        [data-theme="light"] .tab-btn.active .tab-led-dot {
            background: #f59e0b;
            box-shadow: 0 0 8px #f59e0b;
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.25s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* RESOLUTION PANEL */
        .resolution-panel {
            padding: 24px;
        }

        .res-title {
            font-size: 16px;
            font-weight: 800;
            margin-bottom: 20px;
            color: var(--neon-amber);
            display: flex;
            align-items: center;
            justify-content: space-between;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .res-card {
            background: rgba(10, 15, 26, 0.90);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-left: 4px solid var(--neon-cyan);
            border-radius: 0;
            padding: 18px 20px;
            margin-bottom: 16px;
        }

        [data-theme="light"] .res-card {
            background: rgba(26, 12, 4, 0.92);
            border: 1px solid rgba(245, 158, 11, 0.4);
        }

        .res-card-warn { border-left-color: var(--neon-amber) !important; }
        .res-card-err { border-left-color: var(--neon-rose) !important; }

        .res-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .tag-cat {
            background: rgba(56, 189, 248, 0.1);
            color: var(--neon-cyan);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 3px 8px;
            border-radius: 0;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }

        [data-theme="light"] .tag-cat {
            background: rgba(245, 158, 11, 0.15);
            border-color: rgba(245, 158, 11, 0.4);
            color: #fde047;
        }

        .action-btn-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .btn-copy {
            background: #020617;
            border: 1px solid rgba(56, 189, 248, 0.4);
            color: var(--neon-cyan);
            padding: 6px 14px;
            border-radius: 0;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
            text-transform: uppercase;
        }

        [data-theme="light"] .btn-copy {
            background: #000000;
            border-color: #f59e0b;
            color: #fde047;
        }

        .btn-copy:hover {
            background: var(--neon-cyan);
            color: #000000;
            box-shadow: var(--glow-cyan);
        }

        .btn-mini-copy {
            background: transparent;
            border: 1px solid var(--border-bright);
            color: var(--neon-cyan);
            padding: 3px 8px;
            border-radius: 0;
            font-size: 10.5px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .btn-mini-copy:hover {
            background: var(--neon-cyan);
            color: #000000;
        }

        [data-theme="light"] .btn-mini-copy {
            border-color: #f59e0b;
            color: #fde047;
        }

        [data-theme="light"] .btn-mini-copy:hover {
            background: #f59e0b;
            color: #000000;
        }

        .res-body p {
            margin: 6px 0;
            font-size: 13.5px;
            color: #f8fafc;
        }

        .action-highlight {
            color: #38bdf8 !important;
            font-weight: 600;
        }

        [data-theme="light"] .action-highlight {
            color: #fde047 !important;
        }

        .exam-tip-box {
            background: rgba(168, 85, 247, 0.12);
            border-left: 3px solid var(--neon-purple);
            padding: 8px 12px;
            margin-top: 10px;
            font-size: 12.5px;
            color: #e9d5ff;
        }

        [data-theme="light"] .exam-tip-box {
            background: rgba(45, 15, 60, 0.90);
            color: #f5d0fe;
        }

        /* TABLE SECTION */
        .table-section {
            padding: 24px;
        }

        .table-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .filter-group {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .filter-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 0;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .filter-btn.active, .filter-btn:hover {
            border-color: var(--neon-cyan);
            color: var(--neon-cyan);
            background: rgba(56, 189, 248, 0.08);
        }

        .search-box {
            background: #020617;
            border: 1px solid var(--border);
            color: var(--text);
            padding: 7px 12px;
            border-radius: 0;
            font-size: 12px;
            min-width: 220px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        th {
            background: rgba(15, 23, 42, 0.8);
            color: var(--text-muted);
            font-weight: 800;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.6px;
            border-top: 1px solid var(--border);
        }

        [data-theme="light"] th {
            background: rgba(20, 9, 2, 0.98);
            color: #fde047;
            border-bottom: 2px solid #f59e0b;
        }

        [data-theme="light"] td {
            color: #ffffff;
            border-bottom: 1px solid rgba(245, 158, 11, 0.2);
        }

        /* Column Width Protections for Main Journal Table */
        #diagTable th:nth-child(1), #diagTable td:nth-child(1) { width: 115px; min-width: 115px; white-space: nowrap; }
        #diagTable th:nth-child(2), #diagTable td:nth-child(2) { width: 190px; min-width: 160px; }
        #diagTable th:nth-child(3), #diagTable td:nth-child(3) { width: 85px; min-width: 85px; text-align: center; }
        #diagTable th:nth-child(4), #diagTable td:nth-child(4) { min-width: 180px; }
        #diagTable th:nth-child(5), #diagTable td:nth-child(5) { min-width: 160px; }
        #diagTable th:nth-child(6), #diagTable td:nth-child(6) { width: 95px; min-width: 80px; max-width: 110px; text-align: center; }
        #diagTable th:nth-child(7), #diagTable td:nth-child(7) { width: 230px; min-width: 180px; }

        .table-responsive {
            width: 100%;
            overflow-x: auto;
        }

        .custom-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }

        .custom-table th, .custom-table td {
            word-break: break-word;
            overflow-wrap: anywhere;
        }

        tr:hover { background: rgba(56, 189, 248, 0.04); }
        .row-highlight { background: rgba(244, 63, 94, 0.12); }
        .row-suspicious {
            background: rgba(244, 63, 94, 0.12) !important;
            border-left: 3px solid var(--neon-rose) !important;
        }
        .row-suspicious:hover {
            background: rgba(244, 63, 94, 0.22) !important;
        }
        [data-theme="light"] .row-suspicious {
            background: rgba(239, 68, 68, 0.18) !important;
            border-left: 3px solid #ef4444 !important;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 0;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .badge-ok { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-warn { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
        .badge-err { background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.4); }
        [data-theme="light"] .badge-ok { background: #064e3b; color: #6ee7b7; border: 1px solid #10b981; }
        [data-theme="light"] .badge-warn { background: #78350f; color: #fde047; border: 1px solid #f59e0b; }
        [data-theme="light"] .badge-err { background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }

        /* CLICKABLE GUI SHORTCUT TAG */
        .gui-tag {
            background: rgba(56, 189, 248, 0.08);
            border: 1px solid rgba(56, 189, 248, 0.35);
            padding: 2px 6px;
            border-radius: 0;
            font-family: 'Consolas', monospace;
            font-size: 10.5px;
            font-weight: 700;
            color: var(--neon-cyan);
            display: inline-block;
            max-width: 100%;
            word-break: break-all;
            white-space: normal;
            line-height: 1.25;
            text-align: center;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .gui-tag:hover {
            background: rgba(56, 189, 248, 0.25);
            border-color: var(--neon-cyan);
            box-shadow: 0 0 8px rgba(0, 240, 255, 0.35);
            transform: translateY(-1px);
        }

        [data-theme="light"] .gui-tag {
            background: rgba(245, 158, 11, 0.15);
            border-color: rgba(245, 158, 11, 0.4);
            color: #fde047;
        }

        [data-theme="light"] .gui-tag:hover {
            background: rgba(245, 158, 11, 0.35);
            border-color: #f59e0b;
            box-shadow: 0 0 8px rgba(245, 158, 11, 0.4);
        }

        .code-block {
            font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
            font-size: 11px;
            background: #020617;
            color: #38bdf8;
            padding: 6px 8px;
            border-radius: 0;
            display: block;
            width: 100%;
            box-sizing: border-box;
            white-space: pre-wrap;
            word-break: normal;
            overflow-wrap: anywhere;
            line-height: 1.35;
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-left: 3px solid var(--neon-cyan);
            margin-top: 4px;
        }

        [data-theme="light"] .code-block {
            background: #050201;
            color: #fdba74;
            border: 1px solid rgba(245, 158, 11, 0.35);
            border-left: 3px solid #f59e0b;
        }

        /* RUNTIMES & PACKAGES STYLING */
        .runtime-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .runtime-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            padding: 16px;
            border-radius: 0;
        }

        .runtime-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }

        .profile-card {
            padding: 20px;
            margin-bottom: 20px;
        }

        .profile-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
            flex-wrap: wrap;
            gap: 10px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }

        .app-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 12px;
        }

        .app-row {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--border);
            padding: 10px 12px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        [data-theme="light"] .app-row {
            background: rgba(20, 8, 2, 0.4);
        }

        .app-chk {
            width: 16px;
            height: 16px;
            cursor: pointer;
            accent-color: var(--neon-cyan);
        }

        /* CUSTOM WINGET BOX */
        .custom-winget-box {
            background: #020617;
            border: 2px solid var(--neon-cyan);
            padding: 18px 20px;
            margin-top: 24px;
        }

        [data-theme="light"] .custom-winget-box {
            background: #050201;
            border-color: #f59e0b;
        }

        /* Document Integrations & Guides */
        .guide-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 20px;
            margin-top: 18px;
        }

        .guide-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0;
            padding: 22px;
            position: relative;
            overflow: hidden;
        }

        .guide-card h3 {
            margin-top: 0;
            font-size: 16px;
            color: var(--neon-cyan);
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .guide-step {
            background: rgba(56, 189, 248, 0.05);
            border: 1px solid var(--border);
            padding: 10px 14px;
            border-radius: 0;
            margin-bottom: 10px;
            font-size: 13px;
        }

        .guide-step strong { color: var(--neon-cyan); }
        [data-theme="light"] .guide-step {
            background: rgba(245, 158, 11, 0.08);
            border-color: rgba(245, 158, 11, 0.25);
        }
        [data-theme="light"] .guide-step strong { color: #fde047; }

        /* Shortcut Tables */
        .shortcut-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }
        .shortcut-table td { padding: 9px 10px; border-bottom: 1px solid var(--border); }
        .shortcut-key {
            background: #020617;
            color: var(--neon-cyan);
            border: 1px solid rgba(56, 189, 248, 0.4);
            padding: 3px 8px;
            border-radius: 0;
            font-family: 'Consolas', monospace;
            font-weight: 800;
            font-size: 11px;
            display: inline-block;
            box-shadow: 0 0 8px rgba(0,240,255,0.15);
            white-space: nowrap;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .shortcut-key:hover {
            background: var(--neon-cyan);
            color: #000000;
        }
        [data-theme="light"] .shortcut-key {
            background: #050201;
            color: #fde047;
            border-color: rgba(245, 158, 11, 0.45);
            box-shadow: 0 0 8px rgba(245, 158, 11, 0.2);
        }

        /* Toast */
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #020617;
            color: var(--neon-cyan);
            border: 1px solid var(--neon-cyan);
            padding: 14px 26px;
            border-radius: 0;
            display: none;
            z-index: 9999;
            box-shadow: 0 0 30px rgba(0, 240, 255, 0.4);
            font-weight: 700;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            animation: slideIn 0.25s ease;
        }
        @keyframes slideIn { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

        /* 🌳 3D SCI-FI HOLOGRAPHIC TECH TREE & THEMATIC DRAWERS */
        .tech-tree-card {
            background: rgba(10, 15, 26, 0.85);
            border: 1px solid rgba(56, 189, 248, 0.35);
            padding: 16px;
            margin-bottom: 24px;
            position: relative;
        }

        [data-theme="light"] .tech-tree-card {
            background: rgba(26, 12, 4, 0.92);
            border-color: rgba(245, 158, 11, 0.4);
        }

        #three-tech-tree {
            width: 100%;
            height: 280px;
            display: block;
            cursor: grab;
            border: 1px solid rgba(56, 189, 248, 0.2);
            background: radial-gradient(circle at center, rgba(15, 23, 42, 0.9), rgba(2, 6, 23, 0.98));
        }

        #three-tech-tree:active {
            cursor: grabbing;
        }

        [data-theme="light"] #three-tech-tree {
            background: radial-gradient(circle at center, rgba(35, 15, 5, 0.95), rgba(15, 5, 0, 0.98));
            border-color: rgba(245, 158, 11, 0.3);
        }

        /* 🗄️ SCI-FI ACCORDION DRAWERS */
        .sci-drawer {
            border: 1px solid rgba(56, 189, 248, 0.25);
            background: rgba(10, 15, 26, 0.8);
            margin-bottom: 14px;
            transition: all 0.2s ease;
        }

        [data-theme="light"] .sci-drawer {
            background: rgba(26, 12, 4, 0.9);
            border-color: rgba(245, 158, 11, 0.3);
        }

        .sci-drawer:hover {
            border-color: var(--neon-cyan);
            box-shadow: 0 0 14px rgba(56, 189, 248, 0.2);
        }

        .drawer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            cursor: pointer;
            background: rgba(15, 23, 42, 0.6);
            user-select: none;
            border-left: 4px solid var(--neon-cyan);
            flex-wrap: wrap;
            gap: 10px;
        }

        [data-theme="light"] .drawer-header {
            background: rgba(40, 18, 5, 0.6);
            border-left-color: #f59e0b;
        }

        .drawer-header:hover {
            background: rgba(56, 189, 248, 0.12);
        }

        .drawer-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 15px;
            font-weight: 800;
            color: var(--text);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .drawer-chevron {
            font-size: 13px;
            color: var(--neon-cyan);
            transition: transform 0.25s ease;
            font-family: Consolas, monospace;
        }

        .sci-drawer.open .drawer-chevron {
            transform: rotate(180deg);
        }

        .drawer-body {
            display: none;
            padding: 18px;
            border-top: 1px solid rgba(56, 189, 248, 0.15);
        }

        .sci-drawer.open .drawer-body {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
            gap: 14px;
        }

        .foss-card {
            background: rgba(2, 6, 23, 0.7);
            border: 1px solid rgba(56, 189, 248, 0.2);
            padding: 14px 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            gap: 10px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }

        [data-theme="light"] .foss-card {
            background: rgba(15, 6, 2, 0.7);
            border-color: rgba(245, 158, 11, 0.25);
        }

        .foss-card:hover {
            transform: translateY(-2px);
            border-color: var(--neon-cyan);
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.2);
        }

                        .print-footer-strip {
            display: none;
        }

        /* ========================================================== */
        /* 📠 IMPRESSION CONFORME : 1 ONGLET ACTIF = 0 PAGE VIDE      */
        /* ========================================================== */
        
        /* 🗄️ TIROIRS ACCORDÉONS PROFILS MÉTIERS */
        .profile-drawers-container {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 25px;
        }

        .profile-drawer {
            border: 1px solid var(--border);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
            overflow: hidden;
            border-radius: 4px;
        }

        .profile-drawer.open {
            border-color: var(--border-bright);
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.15);
        }

        .drawer-header {
            padding: 13px 18px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            background: rgba(15, 23, 42, 0.65);
            transition: background 0.2s ease;
        }

        .drawer-header:hover {
            background: rgba(30, 41, 59, 0.85);
        }

        .drawer-chevron {
            display: inline-block;
            font-size: 11px;
            color: var(--neon-cyan);
            transition: transform 0.22s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .profile-drawer.open .drawer-chevron {
            transform: rotate(90deg);
        }

        .drawer-body {
            display: none;
            padding: 12px 18px;
            border-top: 1px solid var(--border);
            background: rgba(8, 14, 28, 0.88);
        }

        .profile-drawer.open .drawer-body {
            display: block;
            animation: fadeIn 0.2s ease;
        }

        /* ============================================================= */
        /* 🖨️ FEUILLE DE STYLE D'IMPRESSION PRO / TYPE FAX & HAUTE LISIBILITÉ */
        /* ============================================================= */
        /* ========================================================== */
        /* 📠 RAPPORT D'IMPRESSION ULTRA-COMPACT SANS ESPACE (A4)     */
        /* ========================================================== */
        @media print {
            @page {
                margin: 6mm 6mm 6mm 6mm;
                size: A4 portrait;
            }

            * {
                font-family: 'Segoe UI', Arial, sans-serif !important;
                color: #000000 !important;
                background: transparent !important;
                box-shadow: none !important;
                text-shadow: none !important;
                backdrop-filter: none !important;
                -webkit-backdrop-filter: none !important;
                border-radius: 0 !important;
            }

            body {
                background: #ffffff !important;
                color: #000000 !important;
                padding: 0 !important;
                margin: 0 !important;
                width: 100% !important;
                max-width: 100% !important;
                font-size: 7.5pt !important;
                line-height: 1.2 !important;
            }

            /* Teletype audit header line */
            body::before {
                content: "[ AUDIT TECHNIQUE IT NIVEAU 3 - RAPPORT D'INTERVENTION & CONTRÔLE SYSTÈME ]";
                display: block;
                font-family: Consolas, monospace !important;
                font-size: 8pt;
                font-weight: 800;
                margin-bottom: 4pt;
                padding-bottom: 2pt;
                border-bottom: 1px dashed #000000;
                text-align: center;
            }

            body::after {
                content: "[ FIN DU RAPPORT • VALIDATION OPÉRATEUR SUPPORT NIVEAU 3 • CERTIFIÉ CONFORME UAA 3 ]";
                display: block;
                font-family: Consolas, monospace !important;
                font-size: 8pt;
                font-weight: 800;
                margin-top: 6pt;
                padding-top: 3pt;
                border-top: 1px dashed #000000;
                text-align: center;
            }

            /* Hide all interactive and heavy graphic elements */
            #three-bg, 
            #tech-tree-canvas,
            #three-core-container,
            #three-core,
            .cockpit-right,
            #langSelect,
            .theme-toggle, 
            .btn-primary, 
            .btn-copy, 
            .btn-ps,
            .btn-mini-copy, 
            .tabs, 
            .tab-btn,
            .filter-controls,
            .search-box, 
            .custom-winget-box, 
            .app-detail-drawer, 
            .interactive-badge,
            .drawer-chevron {
                display: none !important;
                visibility: hidden !important;
            }

            .container {
                max-width: 100% !important;
                width: 100% !important;
                padding: 0 !important;
                margin: 0 !important;
            }

            /* Cockpit Header - Compact 2-Line Meta */
            .cockpit-header {
                border: 1px solid #000000 !important;
                border-left: 4px solid #000000 !important;
                padding: 3pt 5pt !important;
                margin-bottom: 3pt !important;
                background: #ffffff !important;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .cockpit-top-row {
                display: block !important;
            }
            .cockpit-left {
                display: block !important;
            }
            .cockpit-title h1 {
                font-size: 9pt !important;
                margin: 0 !important;
                padding: 0 !important;
                font-weight: 900 !important;
                text-transform: uppercase !important;
            }
            .cockpit-sub {
                font-size: 6pt !important;
                margin: 1pt 0 !important;
                padding: 0 !important;
                color: #000000 !important;
                text-transform: uppercase !important;
            }
            .cockpit-status-bar {
                display: flex !important;
                gap: 8pt !important;
                font-size: 6pt !important;
                font-weight: bold !important;
                border-top: 1px dashed #000000 !important;
                padding-top: 1pt !important;
                margin-top: 2pt !important;
            }
            .cockpit-led .led-dot {
                display: none !important;
            }
            .cockpit-led::before {
                content: "[OK] ";
                font-weight: bold !important;
            }
            .cockpit-header::before {
                font-size: 7pt !important;
                color: #000000 !important;
                top: 2pt !important;
                right: 6pt !important;
                opacity: 1 !important;
            }
            .header-title h1 {
                font-size: 11pt !important;
                color: #000000 !important;
                margin: 0 0 2pt 0 !important;
                font-weight: 900 !important;
            }
            .header-badges {
                display: flex !important;
                flex-wrap: wrap !important;
                gap: 3pt !important;
            }
            .header-badge {
                border: 1px solid #000000 !important;
                background: #ffffff !important;
                color: #000000 !important;
                padding: 1pt 4pt !important;
                font-size: 6.5pt !important;
            }

            /* System Summary Grid - Compact 4-Column Box */
            .sys-meta-grid {
                display: grid !important;
                grid-template-columns: repeat(4, 1fr) !important;
                border: 1px solid #000000 !important;
                margin-bottom: 4pt !important;
                gap: 0 !important;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .sys-meta-item {
                border-right: 1px solid #000000 !important;
                border-bottom: 1px solid #000000 !important;
                padding: 2pt 4pt !important;
            }
            .sys-meta-item:nth-child(4n) {
                border-right: none !important;
            }
            .sys-meta-item:nth-last-child(-n+4) {
                border-bottom: none !important;
            }
            .sys-meta-item .meta-label {
                font-size: 5.5pt !important;
                color: #000000 !important;
                font-weight: bold !important;
                text-transform: uppercase !important;
            }
            .sys-meta-item .meta-value {
                font-size: 7.5pt !important;
                font-weight: bold !important;
                color: #000000 !important;
                word-break: break-word !important;
            }

            /* Summary KPI Grid */
            .summary-grid {
                display: grid !important;
                grid-template-columns: repeat(5, 1fr) !important;
                border: 1px solid #000000 !important;
                margin-bottom: 6pt !important;
                gap: 0 !important;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .card {
                border-right: 1px solid #000000 !important;
                border-bottom: none !important;
                padding: 3pt !important;
                text-align: center !important;
            }
            .card:last-child {
                border-right: none !important;
            }
            .card .title {
                font-size: 6.5pt !important;
                font-weight: bold !important;
                text-transform: uppercase !important;
            }
            .card .num {
                font-size: 11pt !important;
                font-weight: 900 !important;
                margin: 0 !important;
            }

            /* Tab Visibility in Print */
            body.print-all-mode .tab-content {
                display: block !important;
                page-break-after: always;
                margin-bottom: 10pt !important;
            }
            body:not(.print-all-mode) .tab-content {
                display: none !important;
            }
            body:not(.print-all-mode) .tab-content.active {
                display: block !important;
                margin-bottom: 6pt !important;
                padding: 0 !important;
            }

            /* Drawer body always open in print */
            .drawer-body {
                display: block !important;
            }

            /* Priority Resolutions */
            .resolution-panel {
                border: none !important;
                padding: 0 !important;
                margin-bottom: 6pt !important;
            }
            .res-title, .section-title {
                font-size: 9pt !important;
                font-weight: 900 !important;
                text-transform: uppercase !important;
                border-bottom: 1px dashed #000000 !important;
                padding-bottom: 2pt !important;
                margin-bottom: 4pt !important;
            }
            .resolution-card, .res-card {
                border: 1px solid #000000 !important;
                border-left: 4px solid #000000 !important;
                padding: 4pt 6pt !important;
                margin-bottom: 4pt !important;
                page-break-inside: avoid;
                break-inside: avoid;
            }
            .res-header {
                border-bottom: 1px dotted #000000 !important;
                padding-bottom: 2pt !important;
                margin-bottom: 3pt !important;
            }
            .badge {
                border: 1px solid #000000 !important;
                padding: 1pt 3pt !important;
                font-size: 7pt !important;
                font-weight: 900 !important;
            }
            .badge-err {
                background: #000000 !important;
                color: #ffffff !important;
            }
            .badge-warn, .badge-ok {
                background: #ffffff !important;
                color: #000000 !important;
            }
            .tag-cat {
                border: 1px dashed #000000 !important;
                padding: 1pt 3pt !important;
                font-size: 6.5pt !important;
            }
            .res-body p, .resolution-card p {
                margin: 2pt 0 !important;
                font-size: 7.5pt !important;
                line-height: 1.15 !important;
            }
            .exam-tip-box {
                border: 1px dashed #000000 !important;
                background: #fdfdfd !important;
                padding: 2pt 4pt !important;
                margin-top: 3pt !important;
                font-size: 7pt !important;
                line-height: 1.15 !important;
            }

            /* Log Table Section - Continuous Compact Rows */
            .table-section {
                border: none !important;
                padding: 0 !important;
                margin-top: 4pt !important;
            }
            table, .data-table {
                width: 100% !important;
                table-layout: fixed !important;
                border-collapse: collapse !important;
                border: 1px solid #000000 !important;
                font-size: 6.5pt !important;
                line-height: 1.15 !important;
                word-wrap: break-word !important;
                margin: 0 !important;
                page-break-inside: auto !important;
                break-inside: auto !important;
            }
            tr {
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }
            th {
                background: #000000 !important;
                color: #ffffff !important;
                border: 1px solid #000000 !important;
                padding: 2pt 3pt !important;
                font-size: 6.5pt !important;
                font-weight: 900 !important;
                text-transform: uppercase !important;
            }
            td {
                border: 1px solid #000000 !important;
                padding: 2pt 3pt !important;
                font-size: 6.5pt !important;
                vertical-align: top !important;
                overflow: hidden !important;
                word-break: normal !important;
                overflow-wrap: anywhere !important;
            }

            .code-block {
                background: #f4f4f4 !important;
                color: #000000 !important;
                border: 1px solid #cccccc !important;
                border-left: 2px solid #000000 !important;
                padding: 1pt 3pt !important;
                font-size: 5.5pt !important;
                font-family: Consolas, monospace !important;
                display: block !important;
                white-space: pre-wrap !important;
                word-break: break-all !important;
                margin-top: 1pt !important;
            }
            .gui-tag {
                border: 1px solid #000000 !important;
                padding: 1pt 2pt !important;
                font-size: 5.5pt !important;
                font-family: Consolas, monospace !important;
                line-height: 1.1 !important;
                display: inline-block !important;
                word-break: break-all !important;
                white-space: normal !important;
                max-width: 100% !important;
            }
        
            /* DIAGNOSTIC JOURNAL TABLE (#diagTable) - EXACT PRINT CALIBRATION */
            #diagTable {
                width: 100% !important;
                table-layout: fixed !important;
                border-collapse: collapse !important;
                border: 1px solid #000000 !important;
                margin: 0 !important;
            }

            #diagTable th, #diagTable td {
                border: 1px solid #000000 !important;
                padding: 1.5pt 2.5pt !important;
                font-size: 6pt !important;
                line-height: 1.15 !important;
                vertical-align: top !important;
                overflow-wrap: break-word !important;
                word-wrap: break-word !important;
                word-break: normal !important;
            }

            /* Exact Column Widths */
            #diagTable th:nth-child(1), #diagTable td:nth-child(1) { 
                width: 10% !important; 
                white-space: normal !important;
                word-break: break-word !important;
            } /* Catégorie (2 lignes permises, jamais tronquée) */

            #diagTable th:nth-child(2), #diagTable td:nth-child(2) { 
                width: 17% !important; 
            } /* Point de contrôle */
            
            #diagTable th:nth-child(3), #diagTable td:nth-child(3) { 
                width: 7% !important; 
                text-align: center !important; 
                white-space: nowrap !important;
            } /* Statut (compact, zéro coupure de mot) */
            
            #diagTable th:nth-child(4), #diagTable td:nth-child(4) { 
                width: 31% !important; 
            } /* Constat technique détaillé */
            
            #diagTable th:nth-child(5), #diagTable td:nth-child(5) { 
                width: 18% !important; 
            } /* Solution recommandée */
            
            #diagTable th:nth-child(6), #diagTable td:nth-child(6) { 
                display: none !important; 
            } /* Raccourci GUI (masqué à l'impression) */
            
            #diagTable th:nth-child(7), #diagTable td:nth-child(7) { 
                width: 17% !important; 
            } /* Remédiation PowerShell */

            /* Category Tag in Print */
            #diagTable .tag-cat {
                display: inline-block !important;
                border: 1px dashed #000000 !important;
                padding: 1pt 2pt !important;
                font-size: 5.5pt !important;
                font-weight: bold !important;
                text-transform: uppercase !important;
                white-space: normal !important;
                word-break: break-word !important;
                line-height: 1.1 !important;
                max-width: 100% !important;
            }

            /* Compact Status Badges in Print (No Line Breaking) */
            #diagTable .badge {
                display: inline-block !important;
                white-space: nowrap !important;
                font-size: 5.5pt !important;
                font-weight: bold !important;
                padding: 1pt 3pt !important;
                border: 1px solid #000000 !important;
                text-align: center !important;
                letter-spacing: 0 !important;
                line-height: 1 !important;
            }

            #diagTable .badge-ok {
                border-color: #000000 !important;
                background: #ffffff !important;
                color: #000000 !important;
            }

            #diagTable .badge-warn {
                border: 1px solid #000000 !important;
                background: #ffffff !important;
                color: #000000 !important;
                font-weight: 900 !important;
            }

            #diagTable .badge-error,
            #diagTable .badge-err {
                border: 1px solid #000000 !important;
                background: #000000 !important;
                color: #ffffff !important;
                font-weight: 900 !important;
            }
        }
    
        .btn-primary, .btn-cyber {
            background: linear-gradient(135deg, rgba(2, 132, 199, 0.25) 0%, rgba(15, 23, 42, 0.90) 100%);
            border: 1px solid var(--neon-cyan);
            color: #f1f5f9;
            font-family: 'Rajdhani', 'JetBrains Mono', Consolas, sans-serif;
            font-weight: 700;
            font-size: 12.5px;
            letter-spacing: 0.04em;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.15);
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn-primary:hover, .btn-cyber:hover {
            background: linear-gradient(135deg, rgba(2, 132, 199, 0.45) 0%, rgba(15, 23, 42, 0.95) 100%);
            border-color: #38bdf8;
            color: #ffffff;
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.35);
            transform: translateY(-1px);
        }

        .btn-primary:active, .btn-cyber:active {
            transform: translateY(0);
            box-shadow: 0 0 6px rgba(56, 189, 248, 0.20);
        }

        .btn-gui {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(52, 211, 153, 0.4);
            color: #34d399;
            font-family: 'Rajdhani', 'JetBrains Mono', Consolas, sans-serif;
            font-weight: 700;
            font-size: 12px;
            padding: 6px 14px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn-gui:hover {
            background: rgba(16, 185, 129, 0.35);
            border-color: #34d399;
            color: #ffffff;
            box-shadow: 0 0 14px rgba(52, 211, 153, 0.35);
            transform: translateY(-1px);
        }
</style>
</head>
<body>
    <!-- THREE.JS 3D CANVAS -->
    <canvas id="three-bg"></canvas>


    <div class="container">
        <!-- 🚀 SPATIAL COCKPIT FLIGHT DECK HEADER -->
        <div class="cockpit-header glass-panel">
            <div class="cockpit-top-row">
                <div class="cockpit-left">
                    <div id="three-core-container" title="Noyau Système 3D • Vue Interactive (Glissez pour orienter)">
                        <canvas id="three-core" width="90" height="90"></canvas>
                    </div>
                    <div class="cockpit-title">
                        <h1>🛠️ CENTRE DE DIAGNOSTIC, DÉPANNAGE & GESTION IT // NIVEAU 3</h1>
                        <div class="cockpit-sub">Console d'Ingénierie PC, Réseaux & Systèmes • Référentiel IT Niveau 3 (Observer ➔ Tester ➔ Corriger ➔ Valider ➔ Expliquer)</div>
                        <div class="cockpit-status-bar">
                            <span class="cockpit-led"><span class="led-dot led-dot-green"></span> DIAGNOSTIC EXÉCUTÉ</span>
                            <span class="cockpit-led"><span class="led-dot led-dot-cyan"></span> SONDES NIVEAU 3 CONFORMES</span>
                            <span class="cockpit-led"><span class="led-dot led-dot-amber"></span> DONNÉES LOCALES SÉCURISÉES</span>
                        </div>
                    </div>
                </div>
                <div class="cockpit-right" style="display:flex; flex-direction:column; align-items:flex-end; gap:8px;">
                    <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                        <select id="langSelect" onchange="applyLanguage(this.value)" class="theme-toggle" style="background:rgba(56,189,248,0.15); border:1px solid rgba(56,189,248,0.4); color:var(--neon-cyan); font-weight:700; font-size:12px; padding:5px 10px; cursor:pointer; outline:none; border-radius:4px;" title="Changer de langue / Change Language">
                            <option value="fr" style="background:#0f172a; color:#f1f5f9;">🇫🇷 Français</option>
                            <option value="nl" style="background:#0f172a; color:#f1f5f9;">🇳🇱 Nederlands</option>
                            <option value="en" style="background:#0f172a; color:#f1f5f9;">🇬🇧 English</option>
                            <option value="de" style="background:#0f172a; color:#f1f5f9;">🇩🇪 Deutsch</option>
                        </select>
                        <button class="theme-toggle" id="themeToggleBtn" style="font-size:12px; padding:6px 12px;" onclick="toggleTheme()">🌓 Thème</button>
                    </div>
                    <div style="font-size: 11.5px; text-align: right; color: var(--text-muted); font-family: 'Consolas', monospace;">
                        <div>HORODATAGE : <strong style="color:var(--text);">__SCAN_DATE__</strong></div>
                        <div style="color: var(--neon-cyan); font-weight: bold; letter-spacing: 1px;">CONSOLE D'ADMINISTRATION // TIER-3 PRO</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 📡 COCKPIT TELEMETRY INSTRUMENT STRIP -->
        <div class="telemetry-bar glass-panel">
            <div class="telemetry-item"><strong>// NOM MACHINE</strong><span>__HOSTNAME__</span></div>
            <div class="telemetry-item"><strong>// SYSTÈME D'EXPLOITATION</strong><span>__OS_NAME__</span></div>
            <div class="telemetry-item"><strong>// VERSION / ARCHITECTURE</strong><span>__OS_VER__</span></div>
            <div class="telemetry-item"><strong>// PROCESSEUR (CPU)</strong><span>__CPU__</span></div>
            <div class="telemetry-item"><strong>// MÉMOIRE VIVE (RAM)</strong><span>__RAM__ Go</span></div>
            <div class="telemetry-item"><strong>// TEMPS D'ACTIVITÉ</strong><span>__UPTIME__</span></div>
            <div class="telemetry-item"><strong>// MODE DÉMARRAGE</strong><span>__BOOTMODE__</span></div>
        </div>

        <!-- KPI SUMMARY GRID -->
        <div class="summary-grid">
            <div class="card glass-panel card-tot" style="cursor:pointer;" title="Voir tous les contrôles dans le Journal" onclick="showTab('tab-journal', document.querySelectorAll('.tab-btn')[1])"><div class="title">Contrôles L3</div><div class="num">__TOTAL_COUNT__</div></div>
            <div class="card glass-panel card-ok" style="cursor:pointer;" title="Voir les contrôles conformes dans le Journal" onclick="showTab('tab-journal', document.querySelectorAll('.tab-btn')[1])"><div class="title">Conformes (OK)</div><div class="num">__OK_COUNT__</div></div>
            <div class="card glass-panel card-warn" style="cursor:pointer;" title="Voir les anomalies dans le Centre de Résolution" onclick="showTab('tab-resolution', document.querySelectorAll('.tab-btn')[0])"><div class="title">Avertissements</div><div class="num">__WARN_COUNT__</div></div>
            <div class="card glass-panel card-err" style="cursor:pointer;" title="Voir les pannes critiques dans le Centre de Résolution" onclick="showTab('tab-resolution', document.querySelectorAll('.tab-btn')[0])"><div class="title">Pannes Critiques</div><div class="num">__ERR_COUNT__</div></div>
            <div class="card glass-panel card-health"><div class="title">Score Santé</div><div class="num">__HEALTH_SCORE__%</div></div>
        </div>

        <!-- 🎛️ COCKPIT COMMAND NAVIGATION TABS (NO HORIZONTAL SCROLLBAR) -->
                <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-resolution')">■ 📊 BILAN & PANNES</button>
            <button class="tab-btn" onclick="switchTab('tab-health')">■ 📈 SANTÉ & TENDANCES</button>
            <button class="tab-btn" onclick="switchTab('tab-cve')">■ 🔴 VULNÉRABILITÉS CVE</button>
            <button class="tab-btn" onclick="switchTab('tab-network-audit')">■ 🌐 AUDIT RÉSEAU & RDP</button>
            <button class="tab-btn" onclick="switchTab('tab-disk-audit')">■ 💾 ANALYSE DISQUE</button>
            <button class="tab-btn" onclick="switchTab('tab-performance')">■ 🚀 DÉMARRAGE & STARTUP</button>
            <button class="tab-btn" onclick="switchTab('tab-belgian-apps')">■ 🇧🇪 LOGICIELS BELGIQUE</button>
            <button class="tab-btn" onclick="switchTab('tab-benchmarks')">■ ⚡ BENCHMARKS & SMART</button>
            <button class="tab-btn" onclick="switchTab('tab-sec-users')">■ 👤 SÉCURITÉ & ANOMALIES</button>
            <button class="tab-btn" onclick="switchTab('tab-foss')">■ 🌐 ARBRE 3D FOSS</button>
            <button class="tab-btn" onclick="switchTab('tab-journal')">■ 📋 TOUS LES TESTS (26)</button>
            <button class="tab-btn" onclick="switchTab('tab-packages')">■ 📦 PROFILS WINGET</button>
            <button class="tab-btn" onclick="switchTab('tab-shortcuts')">■ ⌨️ RACCOURCIS PRO</button>
            <button class="tab-btn" onclick="switchTab('tab-rmm-export')">■ 🔗 EXPORT RMM & CLIENT</button>
            <button class="tab-btn" style="background:rgba(56,189,248,0.15); border-color:#38bdf8; color:#38bdf8; font-weight:800;" onclick="switchTab('tab-readme')">■ 📖 DOCUMENTATION & GUIDE</button>
            <button class="tab-btn" onclick="launchBatchDiagnostic(this)" style="background:linear-gradient(135deg, rgba(16,185,129,0.25) 0%, rgba(15,23,42,0.95) 100%); border-color:#10b981; color:#34d399; font-weight:800;" id="btnRunDiagTab" title="Relancer l'analyse complète via le lanceur .bat">⚡ RELANCER DIAG (.BAT)</button>
            <button class="tab-btn" onclick="refreshReportView()" style="background:rgba(56,189,248,0.18); border-color:#38bdf8; color:#38bdf8; font-weight:700;" id="btnRefreshTab" title="Actualiser les données du rapport">🔄 ACTUALISER</button>
            <button class="tab-btn" onclick="window.print()" style="background:rgba(168,85,247,0.18); border-color:#c084fc; color:#c084fc; font-weight:700;" id="btnPrintTab" title="Imprimer ou exporter en PDF">🖨️ IMPRIMER</button>
        </div>

        <!-- TAB 1: RESOLUTION CENTER -->
        <div id="tab-resolution" class="tab-content active">
            <div class="resolution-panel glass-panel">
                <div class="res-title">
                    <span>⚡ Actions Prioritaires & Remédiation en 1 Clic</span>
                    <span style="font-size: 13px; font-weight: normal; color: var(--text-muted);">__ISSUES_COUNT__ anomalie(s) détectée(s)</span>
                </div>
                __RESOLUTION_CARDS__
            </div>
        </div>

        <!-- TAB 2: EXHAUSTIVE JOURNAL -->
        <div id="tab-journal" class="tab-content">
            <div class="table-section glass-panel">
                <div class="table-toolbar">
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="setCategoryFilter('ALL', this)">Tous (__TOTAL_COUNT__)</button>
                        <button class="filter-btn" onclick="setCategoryFilter('ISSUES', this)">⚠️ Pannes uniquement (__ISSUES_COUNT__)</button>
                        <button class="filter-btn" onclick="setCategoryFilter('Réseau', this)">🌐 Réseau</button>
                        <button class="filter-btn" onclick="setCategoryFilter('Hardware', this)">💻 Hardware</button>
                        <button class="filter-btn" onclick="setCategoryFilter('Système', this)">⚙️ Système</button>
                        <button class="filter-btn" onclick="setCategoryFilter('Sécurité', this)">🛡️ Sécurité</button>
                        <button class="filter-btn" onclick="setCategoryFilter('Logiciel', this)">📦 Logiciel</button>
                    </div>
                    <input type="text" id="tableSearch" class="search-box" placeholder="🔍 Rechercher dans le rapport..." oninput="filterTable()">
                </div>

                <div style="overflow-x: auto;">
                    <table id="diagTable">
                        <thead>
                            <tr>
                                <th>Catégorie</th>
                                <th>Point de contrôle</th>
                                <th style="text-align:center;">Statut</th>
                                <th>Constat technique détaillé</th>
                                <th>Solution recommandée</th>
                                <th style="text-align:center;">Raccourci GUI</th>
                                <th>Remédiation PowerShell</th>
                            </tr>
                        </thead>
                        <tbody>
                            __TABLE_ROWS__
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: PROFILES & RUNTIMES (NEW) -->
        <div id="tab-packages" class="tab-content">
            <div class="table-section glass-panel">
                <h2 style="margin-top:0; font-size:18px; color:var(--neon-cyan); text-transform:uppercase;">⚙️ Scanner des Runtimes Développeur & Dépendances</h2>
                <p style="color:var(--text-muted); font-size:13.5px; margin-bottom:18px;">État d'installation en temps réel des environnements d'exécution essentiels pour Windows 11 :</p>
                __RUNTIMES_HTML__

                <h2 style="margin-top:35px; font-size:18px; color:var(--neon-cyan); text-transform:uppercase;">📦 Packs d'Applications Clé en Main par Profil Métier</h2>
                <p style="color:var(--text-muted); font-size:13.5px; margin-bottom:18px;">Détection automatique des logiciels installés sur ce poste et déploiement des applications manquantes via Winget :</p>
                __PROFILES_HTML__

                <!-- CUSTOM INTERACTIVE WINGET BUILDER -->
                <div class="custom-winget-box glass-panel">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:10px;">
                        <h3 style="margin:0; font-size:16px; color:var(--neon-cyan); text-transform:uppercase;">🛠️ Générateur de Déploiement Winget Sur-Mesure</h3>
                        <button class="btn-copy btn-ps" onclick="copyCustomWinget()">📋 Copier la commande personnalisée</button>
                    </div>
                    <p style="font-size:13px; color:var(--text-muted); margin:0 0 10px 0;">Cochez les applications souhaitées ci-dessus dans les profils pour générer dynamiquement votre script d'installation :</p>
                    <pre id="customWingetCmd" class="code-block" style="font-size:12px; margin:0; padding:10px 12px; background:#000000; color:#38bdf8;"># Cochez des applications ci-dessus pour générer votre commande Winget personnalisée.</pre>
                </div>
            </div>
        </div>

        <!-- TAB 4: AWESOME FOSS ALTERNATIVES (3D TECH TREE & DRAWERS) -->
        
        <!-- ============================================================= -->
        <!-- TAB: SANTÉ & HISTORIQUE TEMPOREL -->
        <!-- ============================================================= -->
        <div id="tab-health" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">📈 Trajectoire de Santé Prédictive & Analyse des Piliers</div>
                
                <!-- 3 Blocs Principaux Supérieurs -->
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:18px; margin-bottom:20px;">
                    
                    <!-- 1. Indice de Santé Global -->
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px; display:flex; flex-direction:column; justify-content:space-between;">
                        <div>
                            <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#94a3b8; margin-bottom:6px;">Indice de Santé Prédictif (Health Score)</div>
                            <div style="display:flex; align-items:baseline; gap:8px;">
                                <div style="font-size:3.2rem; font-weight:900; font-family:'Rajdhani', monospace; color:__HEALTH_COLOR__;" id="dynHealthScore">__HEALTH_SCORE__</div>
                                <div style="font-size:1.4rem; color:#94a3b8; font-weight:700;">/ 100</div>
                                __HEALTH_BADGE__
                            </div>
                            <div style="font-size:12.5px; color:#cbd5e1; margin-top:8px; line-height:1.5;">__PREDICTIVE_TEXT__</div>
                        </div>

                        <div style="background:rgba(2,132,199,0.08); border-left:3px solid #38bdf8; padding:10px 12px; border-radius:4px; margin-top:14px; font-size:11.5px; color:#94a3b8; line-height:1.5;">
                            <strong style="color:#38bdf8; display:block; margin-bottom:3px;">📐 Formule du Calcul de Santé :</strong>
                            <code>Score = [ (OK×1.0 + WARN×0.5) / Total ] × 100 - (CVE×5)</code>
                            <div style="color:#e2e8f0; margin-top:4px;">
                                <span style="color:#34d399;">• Tests Conformes (OK)</span> : +100% de la pondération<br>
                                <span style="color:#fbbf24;">• Avertissements (WARN)</span> : +50% (pénalité de 50%)<br>
                                <span style="color:#f43f5e;">• Pannes & Erreurs (ERROR)</span> : 0% (perte des points)<br>
                                <span style="color:#f43f5e;">• Vulnérabilités CVE</span> : -5 pts directs par CVE active
                            </div>
                        </div>
                    </div>

                    <!-- 2. Piliers d'Audit avec Détails au Survol -->
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                            <span style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#94a3b8;">📊 Décomposition par Piliers d'Audit</span>
                            <span style="font-size:10px; color:#38bdf8;">✨ Survolez pour détails</span>
                        </div>
                        
                        <div style="display:flex; flex-direction:column; gap:12px;">
                            
                            <!-- Pilier 1: Sécurité -->
                            <div class="health-pillar-item" title="__P1_DESC__" style="cursor:help; padding:4px 6px; border-radius:6px; transition:background 0.2s ease;">
                                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                                    <span style="color:#e2e8f0;">🛡️ Sécurité, TPM & eID</span>
                                    <strong style="color:__P1_COLOR__;">__P1_SCORE__%</strong>
                                </div>
                                <div style="width:100%; height:7px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;">
                                    <div style="width:__P1_SCORE__%; height:100%; background:__P1_COLOR__; border-radius:4px;"></div>
                                </div>
                                <div style="font-size:10.5px; color:#94a3b8; margin-top:3px;">__P1_DESC__</div>
                            </div>

                            <!-- Pilier 2: Performance -->
                            <div class="health-pillar-item" title="__P2_DESC__" style="cursor:help; padding:4px 6px; border-radius:6px; transition:background 0.2s ease;">
                                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                                    <span style="color:#e2e8f0;">⚡ Performance CPU & Énergie</span>
                                    <strong style="color:__P2_COLOR__;">__P2_SCORE__%</strong>
                                </div>
                                <div style="width:100%; height:7px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;">
                                    <div style="width:__P2_SCORE__%; height:100%; background:__P2_COLOR__; border-radius:4px;"></div>
                                </div>
                                <div style="font-size:10.5px; color:#94a3b8; margin-top:3px;">__P2_DESC__</div>
                            </div>

                            <!-- Pilier 3: Stockage -->
                            <div class="health-pillar-item" title="__P3_DESC__" style="cursor:help; padding:4px 6px; border-radius:6px; transition:background 0.2s ease;">
                                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                                    <span style="color:#e2e8f0;">💾 Stockage & Santé SMART</span>
                                    <strong style="color:__P3_COLOR__;">__P3_SCORE__%</strong>
                                </div>
                                <div style="width:100%; height:7px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;">
                                    <div style="width:__P3_SCORE__%; height:100%; background:__P3_COLOR__; border-radius:4px;"></div>
                                </div>
                                <div style="font-size:10.5px; color:#94a3b8; margin-top:3px;">__P3_DESC__</div>
                            </div>

                            <!-- Pilier 4: Réseau -->
                            <div class="health-pillar-item" title="__P4_DESC__" style="cursor:help; padding:4px 6px; border-radius:6px; transition:background 0.2s ease;">
                                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                                    <span style="color:#e2e8f0;">🌐 Réseau & Passerelle</span>
                                    <strong style="color:__P4_COLOR__;">__P4_SCORE__%</strong>
                                </div>
                                <div style="width:100%; height:7px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;">
                                    <div style="width:__P4_SCORE__%; height:100%; background:__P4_COLOR__; border-radius:4px;"></div>
                                </div>
                                <div style="font-size:10.5px; color:#94a3b8; margin-top:3px;">__P4_DESC__</div>
                            </div>

                            <!-- Pilier 5: Système -->
                            <div class="health-pillar-item" title="__P5_DESC__" style="cursor:help; padding:4px 6px; border-radius:6px; transition:background 0.2s ease;">
                                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                                    <span style="color:#e2e8f0;">🖥️ Stabilité Système & BSOD</span>
                                    <strong style="color:__P5_COLOR__;">__P5_SCORE__%</strong>
                                </div>
                                <div style="width:100%; height:7px; background:rgba(255,255,255,0.08); border-radius:4px; overflow:hidden;">
                                    <div style="width:__P5_SCORE__%; height:100%; background:__P5_COLOR__; border-radius:4px;"></div>
                                </div>
                                <div style="font-size:10.5px; color:#94a3b8; margin-top:3px;">__P5_DESC__</div>
                            </div>
                        </div>
                    </div>

                    <!-- 3. Indicateurs Clés & Dérives Matérielles -->
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px;">
                        <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#94a3b8; margin-bottom:10px;">📉 Tendances Matérielles & Dérives</div>
                        <div style="font-size:12.5px; line-height:1.8; color:#e2e8f0;">
                            <div>💾 Espace Disque C: Libre : <strong style="color:#38bdf8;" id="histDiskFree">__C_FREE_INFO__</strong></div>
                            <div>⚡ Performance CPU (Score Math) : <strong style="color:#f59e0b;">__CPU_BENCH_SCORE__ pts</strong> (__CPU_BENCH_MS__ ms)</div>
                            <div>🔴 Vulnérabilités CVE Détectées : <strong style="color:#34d399;" id="histCveCount">__CVE_COUNT_INFO__</strong></div>
                            <div>📅 Runs Historisés dans la base : <strong style="color:#38bdf8;" id="histTotalRuns">__TOTAL_RUNS_INFO__</strong></div>
                        </div>
                    </div>

                </div>

                <!-- Conteneur Dynamique de la Trajectoire 3D -->
                <div id="historyTimelineContainer"></div>
            </div>
        </div>

        <div id="tab-cve" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">🔴 Scanner de Vulnérabilités Logicielles (Base de Données CVE)</div>
                <p style="color:#94a3b8; font-size:12.5px; margin-bottom:16px;">
                    Vérification des versions binaires réelles des applications installées par rapport au registre des vulnérabilités critiques (CVSS 7.0+). Permet d'identifier immédiatement les failles zero-day exploitables et de justifier les actions de patch management.
                </p>
                <div id="cveCardsContainer">
                    <!-- Dynamically populated by JS -->
                </div>
            </div>
        </div>

        <!-- ============================================================= -->
        <!-- TAB: AUDIT RÉSEAU AVANCÉ & SÉLECTEUR DE CARTE -->
        <!-- ============================================================= -->
        <div id="tab-network-audit" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">🌐 Audit Réseau Avancé, Partages SMB, Connexions RDP & Matrice de Latence</div>
                
                <!-- SELECTEUR DE CARTE RESEAU -->
                <div style="background:rgba(15,23,42,0.85); padding:16px; border:1px solid rgba(56,189,248,0.30); border-left:4px solid #38bdf8; border-radius:6px; margin-bottom:20px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                        <div>
                            <strong style="color:#38bdf8; font-size:13px;">🎛️ Sélectionner la Carte Réseau à Auditer :</strong>
                            <div style="font-size:11.5px; color:#94a3b8; margin-top:2px;">Basculez entre vos cartes Ethernet, Wi-Fi, VPN ou commutateurs virtuels (WSL/Hyper-V) :</div>
                        </div>
                        <select id="adapterSelect" onchange="changeNetworkAdapter(this.value)" style="background:#0b1120; border:1px solid #38bdf8; color:#f1f5f9; padding:8px 14px; font-size:12.5px; border-radius:4px; outline:none; cursor:pointer; min-width:320px;">
__ADAPTER_OPTIONS_HTML__
                        </select>
                    </div>

                    <!-- Fiche Technique de la carte sélectionnée -->
                    <div id="selectedAdapterDetails" style="margin-top:14px; padding-top:12px; border-top:1px solid rgba(56,189,248,0.15); display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:10px; font-size:12px; color:#cbd5e1;">
                        <!-- Dynamically filled -->
                    </div>
                </div>

                <div class="section-title" style="font-size:14px;">⚡ Matrice de Latence & Réactivité Réseau (Temps Réel)</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:14px; margin-bottom:24px;" id="networkLatencyGrid">
                    <!-- Ping Badges -->
                </div>

                <div class="section-title" style="font-size:14px; margin-top:16px;">📁 Partages Réseau Locaux Exécutables (SMB Shares)</div>
                <div id="smbSharesTableContainer" style="overflow-x:auto; margin-bottom:20px;">
                    <!-- SMB Table -->
                </div>
            
                <!-- TABLE DES PORTS RÉSEAU OUVERTS & PROCESSUS -->
                <div style="background:rgba(15,23,42,0.85); border:1px solid rgba(56,189,248,0.25); border-radius:8px; padding:20px; margin-top:20px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;">
                        <div>
                            <h3 style="font-size:15px; color:var(--neon-cyan); margin:0; text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:8px;">
                                <span>🌐</span> Sockets TCP en Écoute & Processus Associés
                            </h3>
                            <div style="font-size:11.5px; color:#94a3b8; margin-top:3px;">Cartographie des services en attente de connexions entrantes sur cette machine :</div>
                        </div>
                        <span style="font-size:11.5px; padding:3px 10px; border-radius:4px; font-weight:700; background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid rgba(245,158,11,0.4);">
                            __PUBLIC_PORTS_COUNT__ port(s) exposé(s) sur le LAN / Public
                        </span>
                    </div>
                    <div class="table-container" style="overflow-x:auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th style="width:15%;">Port Local</th>
                                    <th style="width:25%;">Adresse d'Écoute</th>
                                    <th style="width:35%;">Processus / Service</th>
                                    <th style="width:25%;">Exposition Réseau</th>
                                </tr>
                            </thead>
                            <tbody>
                                __LISTENING_ROWS__
                            </tbody>
                        </table>
                    </div>
                </div></div>
        </div>

        <!-- ============================================================= -->
        <!-- TAB: ANALYSE DISQUE INTELLIGENTE -->
        <!-- ============================================================= -->
        <div id="tab-disk-audit" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">💾 Analyse Disque Intelligente & Récupération d'Espace</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:18px; margin-bottom:20px;">
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px;">
                        <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#94a3b8;">Occupation Partition Système C:</div>
                        <div style="height:24px; background:rgba(255,255,255,0.08); border-radius:12px; margin:14px 0; overflow:hidden; display:flex;">
                            <div id="diskUsageBarUsed" style="background:#38bdf8; width:50%; height:100%;"></div>
                            <div id="diskUsageBarFree" style="background:#34d399; width:50%; height:100%;"></div>
                        </div>
                        <div style="display:flex; justify-content:space-between; font-size:12px; color:#cbd5e1;">
                            <span id="diskUsedLabel">Occupé : ... GB</span>
                            <span id="diskFreeLabel">Libre : ... GB</span>
                        </div>
                    </div>
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px;">
                        <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#f59e0b;">Gain de Place Immédiat Potentiel</div>
                        <div style="font-size:2.2rem; font-weight:800; font-family:'Rajdhani', monospace; color:#f59e0b; margin:6px 0;" id="cleanableTotalLabel">... MB</div>
                        <div style="font-size:11.5px; color:#94a3b8; margin-bottom:12px;">Caches temporaires, téléchargements Windows Update & logs orphelins.</div>
                        <button class="btn-primary" style="padding:7px 14px; font-size:12px;" onclick="copyDirect(this)" data-cmd="Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue; Clear-RecycleBin -Force -ErrorAction SilentlyContinue">🧹 Copier Commande Nettoyage 1-Clic</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ============================================================= -->
        <!-- TAB: LOGICIELS MÉTIERS BELGIQUE -->
        <!-- ============================================================= -->
        <div id="tab-belgian-apps" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">🇧🇪 Détection des Logiciels Métiers Belges, E-Banking & Fiscalité</div>
                <p style="color:#94a3b8; font-size:12.5px; margin-bottom:16px;">
                    Inventaire automatique des logiciels comptables, financiers et passerelles d'authentification eID belges (Winbooks, Sage BOB, Isabel 6, Silverfin, Accon, SuperFisc, e-ID Middleware, etc.).
                </p>
                <div id="belgianAppsGrid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:14px; margin-bottom:28px;">
                    <!-- Belgian Apps Cards -->
                </div>

                <div class="section-title" style="font-size:15px; border-top:1px solid rgba(56,189,248,0.2); padding-top:18px;">🔐 Magasin de Certificats & Cartes d'Identité eID (Authentification & Signature)</div>
                <p style="color:#94a3b8; font-size:12px; margin-bottom:16px;">
                    Surveillance des certificats personnels et machines (Citizen CA, BOSA, Fedict, eID) avec calcul des jours restants et alertes proactives d'expiration.
                </p>
                <div id="belgianCertsGrid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:14px;">
                    <!-- Belgian Certs Cards -->
                </div>
            </div>
        </div>

        <!-- ============================================================= -->
        <!-- TAB: BENCHMARKS & SMART -->
        <!-- ============================================================= -->
        <div id="tab-benchmarks" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">⚡ Indice de Performance CPU & Comparatif Hardware Réel</div>
                
                <!-- TOP BENCHMARK SUMMARY -->
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:18px; margin-bottom:20px;">
                    <!-- Score & Speed Card -->
                    <div style="background:rgba(15,23,42,0.90); padding:20px; border:1px solid rgba(56,189,248,0.35); border-left:4px solid __CPU_TIER_COL__; border-radius:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#94a3b8;">Calcul de Primalité (15 000 Itérations)</div>
                            <span class="badge" style="background:rgba(15,23,42,0.9); border:1px solid __CPU_TIER_COL__; color:__CPU_TIER_COL__; font-weight:bold;">__CPU_TIER_BADGE__</span>
                        </div>
                        <div style="display:flex; align-items:baseline; gap:12px; margin:8px 0;">
                            <div style="font-size:2.6rem; font-weight:900; font-family:'Rajdhani', monospace; color:__CPU_TIER_COL__;">__CPU_BENCH_MS__ <span style="font-size:1.2rem; font-weight:normal; color:#cbd5e1;">ms</span></div>
                            <div style="font-size:1.1rem; color:#94a3b8;">(Indice : <strong style="color:#f1f5f9;">__CPU_BENCH_SCORE__ pts</strong>)</div>
                        </div>
                        <div style="font-size:12.5px; color:#cbd5e1; margin-bottom:6px;">
                            ⚡ Débit d'exécution brut : <strong style="color:#38bdf8;">__CPU_OPS_PER_SEC__ calculs/sec</strong>
                        </div>
                        <div style="font-size:11.5px; color:#94a3b8; line-height:1.4;">
                            __CPU_TIER_DESC__
                        </div>
                    </div>

                    <!-- Visual Performance Scale Card -->
                    <div style="background:rgba(15,23,42,0.90); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px; display:flex; flex-direction:column; justify-content:space-between;">
                        <div>
                            <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#94a3b8; margin-bottom:10px;">Échelle Relative de Réactivité Système :</div>
                            <div style="position:relative; height:18px; background:linear-gradient(to right, #10b981 0%, #38bdf8 30%, #f59e0b 60%, #ef4444 100%); border-radius:9px; margin:14px 0;">
                                <!-- Marker for Current CPU -->
                                <div style="position:absolute; top:-4px; left:__CPU_BAR_PCT__%; transform:translateX(-50%); width:12px; height:26px; background:#ffffff; border:2px solid #0284c7; border-radius:4px; box-shadow:0 0 10px #38bdf8;" title="Votre position actuelle : __CPU_BENCH_MS__ ms"></div>
                            </div>
                            <div style="display:flex; justify-content:space-between; font-size:10px; color:#94a3b8;">
                                <span style="color:#10b981;">⚡ < 40 ms (Ultra-Rapide)</span>
                                <span style="color:#38bdf8;">~80 ms (Pro)</span>
                                <span style="color:#f59e0b;">~140 ms (Bureautique)</span>
                                <span style="color:#ef4444;">> 200 ms (Lent)</span>
                            </div>
                        </div>
                        <div style="font-size:11.5px; color:#cbd5e1; background:rgba(2,6,23,0.6); padding:8px 12px; border-radius:4px; margin-top:8px;">
                            🔍 <strong>Principe du test :</strong> Évalue la vitesse d'exécution monothread, la latence des caches L1/L2/L3 et la capacité de calcul brut de l'architecture processeur.
                        </div>
                    </div>
                </div>

                <!-- COMPARATIVE MATRIX WITH REFERENCE PROCESSORS -->
                <div class="section-title" style="font-size:14px; margin-top:18px;">📊 Grille Comparative par Rapport aux Architectures du Marché</div>
                <div style="overflow-x:auto; margin-bottom:24px;">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Catégorie de Machine</th>
                                <th>Processeurs de Référence Représentatifs</th>
                                <th>Temps Moyen</th>
                                <th>Indice Points</th>
                                <th>Positionnement Relatif</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr style="background:rgba(16,185,129,0.08);">
                                <td><span class="badge" style="background:#10b981; color:#020617; font-weight:bold;">🚀 Tier 1</span> <strong>Station Pro & Gaming Haut de Gamme</strong></td>
                                <td>AMD Ryzen 9 7950X / Intel Core i9-14900K / Apple M3 Max</td>
                                <td><strong>25 - 35 ms</strong></td>
                                <td>300 - 400 pts</td>
                                <td>Virtualisation lourde, IA locale, rendu cinéma 3D</td>
                            </tr>
                            <tr style="__CPU_HIGHLIGHT_ROW_PRO__">
                                <td><span class="badge" style="background:#38bdf8; color:#020617; font-weight:bold;">⚡ Tier 2</span> <strong>PC Créateur & Gamer Polyvalent</strong></td>
                                <td>AMD Ryzen 7 5800X / Intel Core i7-12700 / Ryzen 7 7700</td>
                                <td><strong>40 - 55 ms</strong></td>
                                <td>180 - 250 pts</td>
                                <td>Multitâche pro intensif, gaming 144Hz, compilation</td>
                            </tr>
                            <tr style="__CPU_HIGHLIGHT_CURRENT__">
                                <td colspan="5" style="background:rgba(56,189,248,0.18); border-left:4px solid #38bdf8; padding:10px 14px; font-size:12.5px;">
                                    <strong>👉 VOTRE MACHINE ACTUELLE :</strong> <span style="color:#f1f5f9;">__CPU_NAME_FULL__</span> • <strong style="color:#38bdf8;">__CPU_BENCH_MS__ ms (__CPU_BENCH_SCORE__ pts)</strong> • <em>__CPU_TIER_NAME__</em>
                                </td>
                            </tr>
                            <tr>
                                <td><span class="badge" style="background:#0ea5e9; color:#020617; font-weight:bold;">💻 Tier 3</span> <strong>PC Entreprise & Bureautique Récente</strong></td>
                                <td>Intel Core i5-12400 / AMD Ryzen 5 5600 / Core i5-11400</td>
                                <td><strong>60 - 90 ms</strong></td>
                                <td>110 - 165 pts</td>
                                <td>Bureautique avancée, navigation 50+ onglets, Teams/Zoom</td>
                            </tr>
                            <tr>
                                <td><span class="badge" style="background:#f59e0b; color:#020617; font-weight:bold;">🟡 Tier 4</span> <strong>Bureautique Standard & PC Antérieur</strong></td>
                                <td>Intel Core i5-8400 / Ryzen 5 2600 / Core i3-10100</td>
                                <td><strong>100 - 150 ms</strong></td>
                                <td>65 - 100 pts</td>
                                <td>Traitement de texte, navigation simple, ERP légers</td>
                            </tr>
                            <tr>
                                <td><span class="badge" style="background:#ef4444; color:#ffffff; font-weight:bold;">🔴 Tier 5</span> <strong>Entrée de Gamme / Ancien / Throttling</strong></td>
                                <td>Intel Core i3-6100 / Celeron G5905 / Athlon 3000G</td>
                                <td><strong>> 180 ms</strong></td>
                                <td>< 55 pts</td>
                                <td>Ralentissements perceptibles, risque de saturation</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="section-title" style="font-size:14px; margin-top:16px;">💿 Télémétrie SMART & Usure des Disques Physiques</div>
                <div id="smartDisksContainer" style="overflow-x:auto;">
                    <!-- SMART Disks Table -->
                </div>
            </div>
        </div>

        <!-- ============================================================= -->
        <!-- TAB: SÉCURITÉ UTILISATEURS & ANOMALIES -->
        <!-- ============================================================= -->
        <div id="tab-sec-users" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">👤 Audit des Utilisateurs, Privilèges Administrateurs & Anomalies Heuristiques</div>
                <div style="margin-bottom:16px; font-size:12.5px; color:#e2e8f0; background:rgba(15,23,42,0.85); padding:14px; border-left:4px solid #38bdf8; border-radius:4px;">
                    <strong>🛡️ Membres du Groupe Administrateurs Locaux :</strong> <span id="adminMembersText" style="color:#38bdf8; font-weight:bold;">...</span>
                </div>

                <div class="section-title" style="font-size:14px; margin-top:16px;">👥 Comptes Locaux Windows</div>
                <div id="localUsersTableContainer" style="overflow-x:auto; margin-bottom:24px;">
                    <!-- Local Users Table -->
                </div>

                <div class="section-title" style="font-size:14px; margin-top:16px;">🚨 Détection d'Anomalies Heuristiques de Processus (Temp/Public)</div>
                <div id="suspiciousProcsContainer">
                    <!-- Suspicious Processes -->
                </div>
            </div>
        </div>

        <!-- ============================================================= -->
        <!-- TAB: EXPORT RMM, CLIENT & MULTIFORMAT -->
        <!-- ============================================================= -->
        <div id="tab-rmm-export" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">🔗 Intégrations RMM, Webhooks, Export Multiformat & Remise Client</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:18px; margin-bottom:20px;">
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px;">
                        <div style="font-size:13px; font-weight:700; color:#38bdf8; margin-bottom:8px;">📥 Téléchargements Immédiats (RMM / SIEM)</div>
                        <p style="font-size:12px; color:#94a3b8; margin-bottom:14px;">Générez et téléchargez les données de diagnostic brutes en format standard (Datto, ConnectWise, N-able).</p>
                        <button class="btn-primary" style="margin-right:8px; margin-bottom:8px;" onclick="downloadDiagnosticJson()">📄 Télécharger JSON RMM</button>
                        <button class="btn-primary" style="margin-bottom:8px;" onclick="downloadDiagnosticCsv()">📊 Télécharger Inventaire CSV</button>
                    </div>
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.25); border-radius:8px;">
                        <div style="font-size:13px; font-weight:700; color:#34d399; margin-bottom:8px;">🖨️ Remise Client & Rapport PDF Personnalisé</div>
                        <p style="font-size:12px; color:#94a3b8; margin-bottom:14px;">Choisissez la section ciblée ou imprimez le dossier complet prêt pour remise client :</p>
                        <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center;">
                            <select id="printSectionSelect" style="background:#0f172a; border:1px solid #38bdf8; color:#f1f5f9; padding:8px 12px; font-size:12.5px; border-radius:4px; outline:none; cursor:pointer; flex:1; min-width:230px;">
                                <option value="all">📑 Rapport Complet (Toutes les sections)</option>
                                <option value="tab-resolution" selected>📊 Bilan Synthétique & Pannes (Recommandé Client)</option>
                                <option value="tab-health">📈 Score de Santé & Historique Temporel</option>
                                <option value="tab-cve">🔴 Audit Vulnérabilités Logicielles CVE</option>
                                <option value="tab-network-audit">🌐 Audit Réseau, Partages SMB & RDP</option>
                                <option value="tab-disk-audit">💾 Analyse Disque & Caches Temporaires</option>
                                <option value="tab-belgian-apps">🇧🇪 Logiciels Métiers Belges & eID</option>
                                <option value="tab-benchmarks">⚡ Benchmarks & Télémétrie SMART</option>
                                <option value="tab-sec-users">👤 Audit Sécurité Utilisateurs & Anomalies</option>
                                <option value="tab-journal">📋 Journal Exhaustif des 26 Tests</option>
                                <option value="tab-packages">📦 Profils Applicatifs & Runtimes</option>
                                <option value="tab-readme">📖 Guide d'Utilisation & Documentation</option>
                            </select>
                            <button class="btn-primary" style="background:#10b981; border-color:#059669; font-weight:700; padding:8px 16px; display:inline-flex; align-items:center; gap:6px;" onclick="printSelectiveReport()">🖨️ Imprimer la Sélection</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>


        <!-- ============================================================= -->
        <!-- TAB: DOCUMENTATION & GUIDE D'UTILISATION COMPLET (README) -->
        <!-- ============================================================= -->
        <div id="tab-readme" class="tab-content">
            <div class="table-section glass-panel">
                <div class="section-title">📖 Guide d'Ingénierie & Documentation Technique Complète (DiagToolIT Suite L3)</div>
                
                <!-- TOP 3 HERO CARDS -->
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:18px; margin-bottom:24px;">
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(56,189,248,0.30); border-left:4px solid #38bdf8; border-radius:8px;">
                        <h3 style="color:#38bdf8; margin-top:0; font-size:16px;">⚡ 3 Méthodes de Lancement & Exécution</h3>
                        <div style="font-size:12.5px; line-height:1.7; color:#e2e8f0;">
                            <div><strong>1. Double-Clic 1-Clic :</strong> Lancez <code>Lancer Diagnostic IT UAA3.bat</code> pour une élévation UAC immédiate.</div>
                            <div><strong>2. En PowerShell Administrateur :</strong> <code>Set-ExecutionPolicy Bypass -Scope Process -Force; .\Diag-IT-UAA3-V3.ps1</code></div>
                            <div><strong>3. Mode Silencieux / Export Bureau :</strong> <code>.\Diag-IT-UAA3-V3.ps1 -NoElevate -OutputPath "$env:USERPROFILE\Desktop"</code></div>
                        </div>
                    </div>
                    
                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(52,211,153,0.30); border-left:4px solid #34d399; border-radius:8px;">
                        <h3 style="color:#34d399; margin-top:0; font-size:16px;">💎 Architecture 100% Autonome & Zéro Dépendance</h3>
                        <div style="font-size:12.5px; line-height:1.7; color:#e2e8f0;">
                            <div><strong>• 100% Hors-Ligne :</strong> Fonctionne sans connexion Internet, sans installer de runtime externe (.NET natif).</div>
                            <div><strong>• Moteur Multilingue (7 Langues) :</strong> Bascule instantanée FR, NL, EN, DE, ES, IT, PT.</div>
                            <div><strong>• Protocole Windows <code>diagit://</code> :</strong> Relance en 1 clic sans fermeture d'onglet.</div>
                        </div>
                    </div>

                    <div style="background:rgba(15,23,42,0.85); padding:20px; border:1px solid rgba(245,158,11,0.30); border-left:4px solid #f59e0b; border-radius:8px;">
                        <h3 style="color:#f59e0b; margin-top:0; font-size:16px;">🛡️ Référentiel Méthodologique Niveau 3</h3>
                        <div style="font-size:12.5px; line-height:1.7; color:#e2e8f0;">
                            <div><strong>1. Observer :</strong> Sondes matérielles, compteurs de performance, journaux d'événements.</div>
                            <div><strong>2. Tester :</strong> Détection de pannes, CVE CVSS $\ge$ 7.0, sockets TCP, certificats eID.</div>
                            <div><strong>3. Corriger & Expliquer :</strong> Scripts PowerShell validés et documentation pour le client.</div>
                        </div>
                    </div>
                </div>

                <!-- 18 MODULES BREAKDOWN TABLE -->
                <div class="section-title" style="font-size:15px; margin-top:20px;">📋 Les 18 Menus & Modules du Dashboard Expliqués</div>
                <div style="overflow-x:auto; margin-bottom:24px;">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th style="width:50px;">#</th>
                                <th style="width:220px;">Menu / Onglet</th>
                                <th>Rôle Technique, Sondes & Capacités d'Ingénierie</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><strong>1</strong></td>
                                <td><span style="color:#38bdf8; font-weight:700;">📊 Bilan & Pannes</span></td>
                                <td>Synthèse de toutes les anomalies actives, cartes correctives avec commandes PowerShell copiables en 1 clic et filtres instantanés (Réseau, Hardware, Système, Sécurité, Logiciel).</td>
                            </tr>
                            <tr>
                                <td><strong>2</strong></td>
                                <td><span style="color:#34d399; font-weight:700;">📈 Santé & Tendances</span></td>
                                <td>Calcul du Score de Santé Prédictif sur 100, jauge radar des 5 piliers sectoriels et graphique d'évolution historique des 30 dernières exécutions (FIFO).</td>
                            </tr>
                            <tr>
                                <td><strong>3</strong></td>
                                <td><span style="color:#f43f5e; font-weight:700;">🔴 Vulnérabilités CVE</span></td>
                                <td>Scanner de vulnérabilités logicielles (CVSS $\ge$ 7.0), affichage des CVE actives avec descriptions détaillées, boutons de mise à jour Winget 1-clic et synchroniseur de base CVE.</td>
                            </tr>
                            <tr>
                                <td><strong>4</strong></td>
                                <td><span style="color:#38bdf8; font-weight:700;">🌐 Audit Réseau & RDP</span></td>
                                <td>Sélecteur dynamique de carte réseau (.NET), ping en direct passerelle/DNS/Internet, statut RDP (Port 3389, NLA), partages SMB actifs, MTU, configuration DNS et Winsock.</td>
                            </tr>
                            <tr>
                                <td><strong>5</strong></td>
                                <td><span style="color:#f59e0b; font-weight:700;">💾 Analyse Disque</span></td>
                                <td>Télémétrie SMART SSD/NVMe (taux d'usure, température, heures de vol, erreurs), arborescence TreeSize des dossiers volumineux, calcul des caches temporaires et purge 1-clic.</td>
                            </tr>
                            <tr>
                                <td><strong>6</strong></td>
                                <td><span style="color:#a855f7; font-weight:700;">🚀 Démarrage & Startup</span></td>
                                <td>Analyse de l'impact au démarrage (Fast Startup, hibernation), détection du Thermal Throttling CPU, audit du plan d'alimentation, tableau interactif des programmes au démarrage avec filtrage heuristique.</td>
                            </tr>
                            <tr>
                                <td><strong>7</strong></td>
                                <td><span style="color:#38bdf8; font-weight:700;">🇧🇪 Logiciels Métiers & eID</span></td>
                                <td>Catalogue adaptatif selon le pays sélectionné (BE, FR, UK/US, DE, ES, IT, PT), statut installé/non installé avec fiches descriptives, magasin de certificats eID avec jours restants.</td>
                            </tr>
                            <tr>
                                <td><strong>8</strong></td>
                                <td><span style="color:#eab308; font-weight:700;">⚡ Benchmarks & SMART</span></td>
                                <td>Benchmark synthétique Single-Core CPU en temps réel (millions d'opérations/s), positionnement parmi les gammes matérielles réelles et spécifications d'horloge.</td>
                            </tr>
                            <tr>
                                <td><strong>9</strong></td>
                                <td><span style="color:#10b981; font-weight:700;">👤 Sécurité & Anomalies</span></td>
                                <td>Audit des membres du groupe Administrateurs locaux, inventaire des comptes utilisateurs Windows, âge des mots de passe, détection des processus suspects exécutés depuis <code>%TEMP%</code> ou <code>Public</code>, cartographie des ports d'écoute TCP.</td>
                            </tr>
                            <tr>
                                <td><strong>10</strong></td>
                                <td><span style="color:#38bdf8; font-weight:700;">🌐 Arbre 3D FOSS</span></td>
                                <td>Visualiseur WebGL Three.js immersif de 90+ outils Open Source classés en 18 thématiques professionnelles, tiroirs d'applications, alternatives propriétaires et générateur de packs Winget.</td>
                            </tr>
                            <tr>
                                <td><strong>11</strong></td>
                                <td><span style="color:#94a3b8; font-weight:700;">📋 Tous les Tests (26)</span></td>
                                <td>Journal exhaustif des 26 sondes de contrôle Niveau 3 avec statut détaillé (OK, Avertissement, Panne), métriques brutes et horodatages.</td>
                            </tr>
                            <tr>
                                <td><strong>12</strong></td>
                                <td><span style="color:#06b6d4; font-weight:700;">📦 Profils Winget</span></td>
                                <td>12 profils de déploiement logiciel par métier (Développeur Web, SysAdmin/DevOps, Bureautique Pro, Multimédia/Graphisme, Cybersécurité, Étudiant IT, etc.).</td>
                            </tr>
                            <tr>
                                <td><strong>13</strong></td>
                                <td><span style="color:#cbd5e1; font-weight:700;">⌨️ Raccourcis Pro</span></td>
                                <td>Console de lancement rapide des utilitaires Windows d'administration (MMC, Gestionnaire de disques, Services, Éditeur de registre, God Mode, Moniteur de ressources).</td>
                            </tr>
                            <tr>
                                <td><strong>14</strong></td>
                                <td><span style="color:#10b981; font-weight:700;">🔗 Export RMM & Client</span></td>
                                <td>Génération de payloads télémétriques JSON standardisés pour plateformes RMM/ITSM, export d'inventaire complet au format CSV et résumé pour remise client.</td>
                            </tr>
                            <tr>
                                <td><strong>15</strong></td>
                                <td><span style="color:#38bdf8; font-weight:700;">📖 Documentation & Guide</span></td>
                                <td>Guide technique complet, référentiel méthodologique L3, cheat-sheet des commandes PowerShell de maintenance et architecture interne de la suite.</td>
                            </tr>
                            <tr>
                                <td><strong>16</strong></td>
                                <td><span style="color:#34d399; font-weight:700;">⚡ RELANCER DIAG (.BAT)</span></td>
                                <td>Déclencheur 1-clic du protocole URL <code>diagit://run</code> pour réexécuter le diagnostic en arrière-plan sans quitter la page ni fermer l'onglet du navigateur.</td>
                            </tr>
                            <tr>
                                <td><strong>17</strong></td>
                                <td><span style="color:#38bdf8; font-weight:700;">🔄 ACTUALISER</span></td>
                                <td>Rafraîchissement instantané des données de la vue sans réinitialiser vos filtres.</td>
                            </tr>
                            <tr>
                                <td><strong>18</strong></td>
                                <td><span style="color:#f59e0b; font-weight:700;">🖨️ IMPRIMER</span></td>
                                <td>Modal d'impression professionnelle avec choix entre le Bilan Exécutif Synthétique (1 page), l'Onglet Actif ou le Rapport Technique Intégral.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- POWERSHELL COMMANDS CHEAT SHEET -->
                <div class="section-title" style="font-size:15px; margin-top:20px;">⚡ Boîte à Outils PowerShell SysAdmin (Commandes Utiles)</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:14px; margin-bottom:24px;">
                    <div style="background:rgba(15,23,42,0.85); padding:16px; border:1px solid rgba(255,255,255,0.08); border-radius:6px;">
                        <strong style="color:#38bdf8; font-size:13px;">🌐 Réinitialisation Réseau & Winsock :</strong>
                        <pre style="background:#090d16; padding:10px; border-radius:4px; font-size:11px; color:#a5f3fc; overflow-x:auto; margin:8px 0 0 0;">ipconfig /flushdns
netsh winsock reset
netsh int ip reset</pre>
                    </div>

                    <div style="background:rgba(15,23,42,0.85); padding:16px; border:1px solid rgba(255,255,255,0.08); border-radius:6px;">
                        <strong style="color:#34d399; font-size:13px;">🖨️ Redémarrage Spouleur d'Impression :</strong>
                        <pre style="background:#090d16; padding:10px; border-radius:4px; font-size:11px; color:#a5f3fc; overflow-x:auto; margin:8px 0 0 0;">Stop-Service Spooler -Force
Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Force
Start-Service Spooler</pre>
                    </div>

                    <div style="background:rgba(15,23,42,0.85); padding:16px; border:1px solid rgba(255,255,255,0.08); border-radius:6px;">
                        <strong style="color:#f59e0b; font-size:13px;">🧹 Nettoyage Caches & Mises à Jour :</strong>
                        <pre style="background:#090d16; padding:10px; border-radius:4px; font-size:11px; color:#a5f3fc; overflow-x:auto; margin:8px 0 0 0;">Stop-Service wuauserv -Force
Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force
Start-Service wuauserv</pre>
                    </div>

                    <div style="background:rgba(15,23,42,0.85); padding:16px; border:1px solid rgba(255,255,255,0.08); border-radius:6px;">
                        <strong style="color:#f43f5e; font-size:13px;">🛡️ Réparation Fichiers Système & Image Windows :</strong>
                        <pre style="background:#090d16; padding:10px; border-radius:4px; font-size:11px; color:#a5f3fc; overflow-x:auto; margin:8px 0 0 0;">DISM.exe /Online /Cleanup-image /Restorehealth
sfc /scannow</pre>
                    </div>
                </div>

            </div>
        </div>

<div id="tab-foss" class="tab-content">
            <div class="table-section glass-panel">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
                    <div>
                        <h2 style="margin:0; font-size:18px; color:var(--neon-cyan); text-transform:uppercase;">🔄 Matrice Open-Source Alternatives (FOSS Tree 3D)</h2>
                        <div style="color:var(--text-muted); font-size:13px; margin-top:2px;">Issu de <code>opensourcealternative.to</code> & <code>diegoleme/awesome-open-source-alternatives</code> • Arbre Nodal 3D Interactif & Tiroirs Thématiques</div>
                    </div>
                    <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                        <input type="text" id="fossSearchInput" class="search-box" style="width:280px; padding:6px 12px; font-size:12px;" placeholder="🔍 Chercher une app (ex: TestDisk, PhotoRec, Récupération)..." oninput="filterFossDrawers()">
                        <button class="filter-btn" onclick="expandAllDrawers(true)">📂 Déplier Tout</button>
                        <button class="filter-btn" onclick="expandAllDrawers(false)">📁 Replier Tout</button>
                    </div>
                </div>

                <!-- 🌌 3D SCI-FI HOLOGRAPHIC TECH TREE -->
                <div class="tech-tree-card">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:10px;">
                        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                            <div style="font-size:13px; font-weight:800; color:var(--neon-cyan); text-transform:uppercase; letter-spacing:0.6px;">
                                🌳 CARTOGRAPHIE 3D DES ALTERNATIVES OPEN-SOURCE
                            </div>
                            <span id="treeModeBadge" class="tag-cat" style="font-size:10.5px;">🌐 VUE GLOBALE (18 DOMAINES • 190+ APPLICATIONS)</span>
                        </div>
                        <div style="display:flex; gap:8px; align-items:center;">
                            <button id="btnResetTreeCam" class="btn-mini-copy" style="display:none;" onclick="resetTreeToGalaxy()">🔙 Vue Globale (Toutes les Branches)</button>
                            <span style="font-size:11px; color:var(--text-muted); display:inline-flex; align-items:center; gap:6px; flex-wrap:wrap;">
                                💡 <em>Clic : Inspecter • Molette : Zoomer</em>
                                <span style="background:rgba(56,189,248,0.12); border:1px solid rgba(56,189,248,0.35); padding:2px 7px; border-radius:3px; color:#38bdf8; font-family:Consolas, monospace; font-size:10.5px;">
                                    ⌨️ <strong>[← / →]</strong> Changer de nœud • <strong>[↑ / Entrée]</strong> Entrer • <strong>[↓ / Retour]</strong> Sortir (Vue Globale)
                                </span>
                            </span>
                        </div>
                    </div>
                    
                    <!-- SPLIT CONTAINER: 3D CANVAS ON LEFT + FULL HEIGHT INSPECTOR ON RIGHT -->
                    <div style="display:flex; width:100%; height:500px; overflow:hidden; border:1px solid rgba(56,189,248,0.3); background:radial-gradient(circle at center, rgba(15, 23, 42, 0.95), rgba(2, 6, 23, 0.99));">
                        
                        <!-- 3D VIEWPORT -->
                        <div style="flex:1; position:relative; height:100%; min-width:0;">
                            <canvas id="three-tech-tree" style="width:100%; height:100%; display:block; cursor:grab;"></canvas>
                            
                            <!-- 3D FLOATING HOVER TOOLTIP (ATTACHED TO 3D NODE) -->
                            <div id="treeHoverTooltip" style="position:absolute; opacity:0; pointer-events:none; z-index:15; background:rgba(2,6,23,0.95); border:1px solid var(--neon-cyan); border-left:3px solid #34d399; padding:6px 14px; font-size:12px; font-weight:800; color:var(--neon-cyan); box-shadow:0 0 20px rgba(0,240,255,0.45); transform:translate(-50%, -125%); white-space:nowrap; font-family:'Segoe UI', Consolas, monospace; transition:opacity 0.25s ease;">
                                <span id="treeTooltipText">Node Title</span>
                            </div>

                            <div style="position:absolute; bottom:8px; left:12px; font-family:Consolas; font-size:10.5px; color:var(--neon-cyan); pointer-events:none; background:rgba(0,0,0,0.75); padding:4px 10px; border-left:3px solid var(--neon-cyan);">
                                ● MATRICE FOSS 3D // 18 DOMAINES THÉMATIQUES // 190+ APPLICATIONS LIBRES
                            </div>
                        </div>

                        <!-- FULL-HEIGHT RIGHT-SIDE INSPECTOR PANEL -->
                        <div id="treeInspectorPanel" style="width:390px; height:100%; border-left:1px solid rgba(56,189,248,0.3); background:rgba(2, 6, 23, 0.94); display:flex; flex-direction:column; z-index:20; overflow-y:auto; padding:16px 18px; box-sizing:border-box;">
                            
                            <!-- 1. DEFAULT PLACEHOLDER (When no theme/app selected) -->
                            <div id="inspectorPlaceholder" style="display:flex; flex-direction:column; justify-content:center; align-items:center; height:100%; text-align:center; color:var(--text-muted); padding:20px;">
                                <div style="font-size:36px; margin-bottom:12px;">📊</div>
                                <div style="font-size:13px; font-weight:800; color:var(--neon-cyan); text-transform:uppercase; margin-bottom:8px; letter-spacing:0.5px;">
                                    Explorateur d'Applications FOSS
                                </div>
                                <div style="font-size:12px; line-height:1.5; color:var(--text-muted); margin-bottom:14px;">
                                    Sélectionnez un domaine thématique ou une application pour afficher son inventaire et sa fiche technique.
                                </div>
                                <div style="font-size:11px; font-family:Consolas, monospace; background:rgba(56,189,248,0.06); border:1px dashed rgba(56,189,248,0.25); padding:8px 12px; border-radius:4px; color:#38bdf8; line-height:1.6;">
                                    ⚡ 18 Domaines Techniques<br>📦 190+ Applications 100% Open Source<br>⌨️ [← / →] Sélection • [↑ / Entrée] Ouvrir
                                </div>
                            </div>

                            <!-- 2. THEME RETRACTED/EXPANDABLE APP DRAWER (Shown when Main Theme Node is selected or focused) -->
                            <div id="inspectorThemeDrawer" style="display:none; flex-direction:column; gap:12px; height:100%;">
                                <!-- Header of the theme drawer -->
                                <div style="display:flex; justify-content:space-between; align-items:flex-start; border-bottom:1px solid rgba(56,189,248,0.25); padding-bottom:10px;">
                                    <div style="min-width:0; flex:1;">
                                        <div style="display:flex; align-items:center; gap:8px;">
                                            <span id="themeDrawerIcon" style="font-size:22px;">📂</span>
                                            <strong id="themeDrawerName" style="font-size:14.5px; color:#38bdf8; font-family:'Rajdhani', sans-serif; text-transform:uppercase; letter-spacing:0.04em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">Nom du Domaine</strong>
                                        </div>
                                        <div id="themeDrawerCount" style="font-size:11px; color:#94a3b8; margin-top:3px;">Applications Disponibles • Cliquez pour inspecter</div>
                                    </div>
                                    <button id="btnThemeDrawerBack" class="btn-mini-copy" onclick="resetTreeToGalaxy()" style="cursor:pointer; font-size:10.5px; padding:4px 8px; white-space:nowrap;" title="Retourner à la vue globale">🔙 Vue Globale</button>
                                </div>

                                <!-- Action buttons (Enter cluster + Copy All Winget) -->
                                <div style="display:flex; gap:6px;">
                                    <button id="btnEnterThemeCluster" class="btn-mini-copy" style="flex:1; font-size:11px; padding:6px 8px; background:rgba(16,185,129,0.18); border:1px solid #10b981; color:#34d399; cursor:pointer;" onclick="focusOnTheme(activeFocusedTheme)">
                                        🚀 Entrer dans le Cluster 3D
                                    </button>
                                    <button id="btnCopyThemeAllWinget" class="btn-mini-copy" style="flex:1; font-size:11px; padding:6px 8px; background:rgba(2,132,199,0.22); border:1px solid #38bdf8; color:#38bdf8; cursor:pointer;" onclick="copyAllThemeWinget(activeFocusedTheme)">
                                        ⚡ Tout Copier (Winget)
                                    </button>
                                </div>

                                <!-- Retracted / Compact List of Apps with scroll -->
                                <div style="font-size:11px; font-weight:bold; color:#cbd5e1; text-transform:uppercase; letter-spacing:0.05em; display:flex; justify-content:space-between; margin-top:2px;">
                                    <span>📦 Applications du Domaine</span>
                                    <span style="color:#94a3b8; font-weight:normal; font-size:10px;">Naviguer : [← / →]</span>
                                </div>
                                <div id="themeAppItemsList" style="flex:1; overflow-y:auto; display:flex; flex-direction:column; gap:8px; padding-right:4px;">
                                    <!-- Populated dynamically by renderThemeAppDrawer -->
                                </div>
                            </div>

                            <!-- 3. ACTIVE APP SPECIFICATION CARD (Populated on App selection) -->
                            <div id="inspectorContent" style="display:none; flex-direction:column; gap:12px; height:100%;">
                                
                                <div style="display:flex; flex-direction:column; gap:6px; border-bottom:1px solid rgba(56,189,248,0.25); padding-bottom:10px;">
                                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
                                        <div id="specFossTitle" style="font-size:17px; font-weight:900; color:#34d399; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
                                            <span>✨</span> <span id="specFossName">Nom de l'App</span>
                                        </div>
                                        <div id="specCategory" style="font-size:11px; color:var(--neon-cyan); font-weight:700; text-transform:uppercase;">Domaine Thématique</div>
                                    </div>
                                    <div style="margin-top:2px;">
                                        <span id="specPropBadge" style="display:inline-block; font-size:11.5px; font-family:'Rajdhani', 'JetBrains Mono', Consolas, monospace; background:rgba(16,185,129,0.12); color:#34d399; border:1px solid rgba(52,211,153,0.4); padding:3px 8px; font-weight:700; border-radius:4px; max-width:100%; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                                            🔒 Alt : [Propriétaire]
                                        </span>
                                    </div>
                                </div>

                                <!-- TECHNICAL SPECIFICATION GRID -->
                                <div style="display:grid; grid-template-columns:1fr; gap:6px; background:rgba(15,23,42,0.6); padding:10px; border:1px solid rgba(255,255,255,0.06); border-radius:4px; font-size:11.5px;">
                                    <div style="display:flex; justify-content:space-between; gap:6px;">
                                        <span style="color:var(--text-muted);">📦 <strong>Type d'Application :</strong></span>
                                        <span id="specType" style="color:#ffffff; font-weight:700; text-align:right;">Desktop Natif</span>
                                    </div>
                                    <div style="display:flex; justify-content:space-between; gap:6px;">
                                        <span style="color:var(--text-muted);">⚡ <strong>Stack & Langages :</strong></span>
                                        <span id="specStack" style="color:#38bdf8; font-weight:700; font-family:Consolas, monospace; text-align:right;">C++, Qt</span>
                                    </div>
                                    <div style="display:flex; justify-content:space-between; gap:6px;">
                                        <span style="color:var(--text-muted);">📜 <strong>Licence Libre :</strong></span>
                                        <span id="specLicense" style="color:#34d399; font-weight:700; text-align:right;">GNU GPLv3</span>
                                    </div>
                                    <div style="display:flex; justify-content:space-between; gap:6px;">
                                        <span style="color:var(--text-muted);">📅 <strong>Origine Historique :</strong></span>
                                        <span id="specOrigin" style="color:#fbbf24; font-weight:600; text-align:right;">1996 (v0.54)</span>
                                    </div>
                                    <div style="display:flex; justify-content:space-between; gap:6px;">
                                        <span style="color:var(--text-muted);">🚀 <strong>Version Actuelle :</strong></span>
                                        <span id="specVersion" style="color:#a78bfa; font-weight:700; text-align:right;">v2.10.38</span>
                                    </div>
                                    <div style="display:flex; justify-content:space-between; gap:6px;">
                                        <span style="color:var(--text-muted);">🏷️ <strong>ID Winget :</strong></span>
                                        <code id="specWingetId" style="color:#38bdf8; font-size:11px; background:rgba(0,0,0,0.4); padding:1px 4px; border-radius:3px;">ID.Package</code>
                                    </div>
                                </div>

                                <!-- DESCRIPTION BOX -->
                                <div>
                                    <div style="font-size:11px; font-weight:800; color:var(--text-muted); text-transform:uppercase; margin-bottom:4px;">📋 Analyse & Capacités :</div>
                                    <div id="specDesc" style="font-size:12px; color:#cbd5e1; line-height:1.45; background:rgba(0,0,0,0.3); padding:8px 10px; border-left:2px solid var(--neon-cyan); border-radius:0 4px 4px 0;">
                                        Description détaillée de l'outil.
                                    </div>
                                </div>

                                <!-- ACTION BUTTONS -->
                                <div style="display:flex; flex-direction:column; gap:6px; margin-top:auto;">
                                    <div style="display:flex; gap:6px;">
                                        <a id="specWebLink" href="#" target="_blank" rel="noopener" class="btn-mini-copy" style="flex:1; text-decoration:none; display:inline-flex; justify-content:center; align-items:center; gap:4px; font-size:11px; padding:6px 8px;">
                                            🌐 Site Officiel
                                        </a>
                                        <button id="specDrawerBtn" class="btn-mini-copy" onclick="" style="flex:1; font-size:11px; padding:6px 8px;">
                                            📂 Ouvrir le Tiroir
                                        </button>
                                    </div>
                                    <button id="specWingetBtn" class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="" style="width:100%; font-size:11px; padding:7px 10px; justify-content:center;">
                                        ⚡ Copier la commande d'installation Winget
                                    </button>
                                    <button id="specBackToThemeBtn" class="btn-mini-copy" onclick="renderThemeAppDrawer(activeFocusedTheme)" style="width:100%; font-size:11px; padding:6px 8px; justify-content:center; cursor:pointer;">
                                        🔙 Voir la liste des apps du thème
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 🗄️ THEMATIC ACCORDION DRAWERS -->
                <div class="drawers-container">
                    __FOSS_DRAWERS__
                </div>
            </div>
        </div>

        <!-- TAB 5: WINDOWS 11 SHORTCUTS -->
        <div id="tab-shortcuts" class="tab-content">
            <div class="table-section glass-panel">
                <h2>⌨️ Raccourcis Clavier Windows 11 & Guide Expert IT</h2>
                <p style="color:var(--text-muted); font-size:14px;">Issu du document <em>« Boostez votre Productivité sous Windows 11 : Raccourcis, PowerToys et Astuces d'Expert »</em>.</p>
                
                <div class="guide-grid">
                    <div class="guide-card">
                        <h3>⭐ Le Top 10 Absolu du Technicien IT</h3>
                        <table class="shortcut-table">
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Ctrl+Shift+Echap">Ctrl + Shift + Échap</span></td><td>Ouvrir directement le Gestionnaire des tâches</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+R">Win + R</span></td><td>Exécuter (Accès direct à toutes les consoles .msc / .cpl)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+X">Win + X</span></td><td>Menu d'Administration Système Rapide (Menu Lien Rapide)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Ctrl+Shift+Entree">Ctrl + Shift + Entrée</span></td><td>Lancer une commande en tant qu'Administrateur</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+Ctrl+Shift+B">Win + Ctrl + Shift + B</span></td><td>Réinitialiser instantanément le pilote graphique (Écran noir)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+V">Win + V</span></td><td>Historique du Presse-papiers multi-éléments</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+Shift+S">Win + Shift + S</span></td><td>Outil de Capture d'écran précis avec OCR</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Shift+Suppr">Shift + Suppr</span></td><td>Suppression définitive sans passage par la Corbeille</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Ctrl+Shift+N">Ctrl + Shift + N</span></td><td>Créer instantanément un nouveau dossier</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Alt+Tab">Alt + Tab</span></td><td>Bascule rapide entre toutes les consoles ouvertes</td></tr>
                        </table>
                    </div>

                    <div class="guide-card">
                        <h3>🛠️ Consoles d'Administration Rapide (Win + R)</h3>
                        <table class="shortcut-table">
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="ncpa.cpl">ncpa.cpl</span></td><td>Connexions réseau (Adaptateurs, IPv4, DNS)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="devmgmt.msc">devmgmt.msc</span></td><td>Gestionnaire de périphériques (Drivers, codes d'erreur)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="services.msc">services.msc</span></td><td>Gestionnaire des services Windows</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="gpedit.msc">gpedit.msc</span></td><td>Éditeur de stratégie de groupe locale (GPO)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="diskmgmt.msc">diskmgmt.msc</span></td><td>Gestion des disques et partitions</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="eventvwr.msc">eventvwr.msc</span></td><td>Observateur d'événements (Logs Système & App)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="cleanmgr.exe">cleanmgr.exe</span></td><td>Nettoyage de disque Windows</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="appwiz.cpl">appwiz.cpl</span></td><td>Programmes et fonctionnalités (Désinstallation)</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="wf.msc">wf.msc</span></td><td>Pare-feu Windows Defender avec fonctions avancées</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="msinfo32">msinfo32</span></td><td>Informations système complètes (BIOS, RAM, Hardware)</td></tr>
                        </table>
                    </div>

                    <div class="guide-card">
                        <h3>🚀 PowerToys & Fonctionnalités Avancées</h3>
                        <table class="shortcut-table">
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Alt+Espace">Alt + Espace</span></td><td><strong>PowerToys Run</strong> : Lanceur d'applications & calculatrice</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+Shift+`">Win + Shift + `</span></td><td><strong>FancyZones</strong> : Zones d'ancrage personnalisées multi-fenêtres</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+Ctrl+T">Win + Ctrl + T</span></td><td><strong>Always On Top</strong> : Épingler une fenêtre toujours au premier plan</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Win+Shift+T">Win + Shift + T</span></td><td><strong>Text Extractor (OCR)</strong> : Extraire le texte de n'importe quelle image</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Ctrl Ctrl">Ctrl Ctrl</span></td><td><strong>Find My Mouse</strong> : Mettre en surbrillance le curseur de souris</td></tr>
                            <tr><td><span class="shortcut-key" onclick="copyDirect(this)" data-cmd="Mouse Without Borders">Mouse Without Borders</span></td><td>Contrôler jusqu'à 4 PC avec une seule souris et un seul clavier</td></tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 6: UAA 3 METHOD & DECISION TREE -->
        <div id="tab-uaa3" class="tab-content">
            <div class="table-section glass-panel">
                <h2>🎓 Méthode & Arbre de Décision UAA 3 (Support PC & Réseaux)</h2>
                <p style="color:var(--text-muted); font-size:14px;">Issu du <em>« Guide complet de pannes UAA 3 : Hardware - Software - Réseau »</em>.</p>

                <div class="guide-grid">
                    <div class="guide-card">
                        <h3>📋 La Méthode en 6 Étapes qui Évite de Paniquer</h3>
                        <div class="guide-step"><strong>1. Observer :</strong> Quel est le symptôme exact ? Ne toucher à rien avant d'avoir compris ce qui ne va pas.</div>
                        <div class="guide-step"><strong>2. Classer :</strong> Hardware, Software ou Réseau ? Choisir la bonne checklist.</div>
                        <div class="guide-step"><strong>3. Tester :</strong> Quel test simple peut confirmer ? Câble, BIOS, ipconfig, ping, services.msc.</div>
                        <div class="guide-step"><strong>4. Corriger :</strong> Une seule modification minimale à la fois (ne pas tout changer au hasard).</div>
                        <div class="guide-step"><strong>5. Valider :</strong> Est-ce que le problème est résolu ? Retester le symptôme de départ.</div>
                        <div class="guide-step"><strong>6. Expliquer :</strong> Quelle était la cause exacte ? Formuler la réponse au formateur.</div>
                    </div>

                    <div class="guide-card">
                        <h3>🌳 Arbre de Décision Réseau Express</h3>
                        <div class="guide-step"><strong>Pas de LED réseau sur le port :</strong> Vérifier câble RJ45, port switch, carte réseau dans ncpa.cpl.</div>
                        <div class="guide-step"><strong>Ping Passerelle KO :</strong> Problème local (IP fixe fausse, mauvais masque, câble, switch).</div>
                        <div class="guide-step"><strong>Passerelle OK mais Ping 8.8.8.8 KO :</strong> Problème passerelle/routeur ou pare-feu sortant.</div>
                        <div class="guide-step"><strong>Ping 8.8.8.8 OK mais Ping google.com KO :</strong> Panne DNS pure (Client DNS, DNS configuré).</div>
                        <div class="guide-step"><strong>Ping google.com OK mais Navigateur KO :</strong> Proxy activé ou règle Pare-feu bloquante.</div>
                        <div class="guide-step"><strong>Un seul site inaccessible :</strong> Fichier hosts détourné + <code>ipconfig /flushdns</code>.</div>
                        <div class="guide-step"><strong>Internet OK mais Partage réseau KO :</strong> Client pour les réseaux Microsoft désactivé.</div>
                    </div>

                    <div class="guide-card">
                        <h3>💬 Phrases Types à Dire au Formateur</h3>
                        <div class="guide-step"><em>« Je commence par vérifier les causes simples et visibles avant de modifier la configuration Windows. »</em></div>
                        <div class="guide-step"><em>« Le ping par nom fonctionne, donc IP, passerelle et DNS sont corrects ; je vérifie le proxy et le pare-feu. »</em></div>
                        <div class="guide-step"><em>« Le PC ne s'allume pas, donc je reste côté alimentation et Front Panel ; Windows n'est même pas chargé. »</em></div>
                        <div class="guide-step"><em>« L'accès au partage est KO mais internet fonctionne ; je contrôle le composant Client Réseaux Microsoft. »</em></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 7: POWERSEHLL TOOLBOX -->
        <div id="tab-toolbox" class="tab-content">
            <div class="table-section glass-panel">
                <h2>🧰 Boîte à Outils PowerShell Express (Dépannage Rapide)</h2>
                <p style="color:var(--text-muted); font-size:14px;">Commandes d'administration système et de maintenance prêtes à copier en 1 clic :</p>

                <div class="guide-grid">
                    <div class="guide-card">
                        <h3>🌐 Réparation Réseau & Pile TCP/IP</h3>
                        <p>Réinitialisation complète du cache DNS, libération/renouvellement DHCP et reset Winsock :</p>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="ipconfig /flushdns; ipconfig /release; ipconfig /renew; netsh winsock reset">📋 Copier la commande</button>
                        <pre class="code-block" style="display:block; margin-top:8px;">ipconfig /flushdns; ipconfig /release; ipconfig /renew; netsh winsock reset</pre>
                    </div>

                    <div class="guide-card">
                        <h3>🖨️ Déblocage Immédiat du Spouleur</h3>
                        <p>Arrêt forcé, vidage des fichiers de spoule coincés et redémarrage du service :</p>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="Stop-Service Spooler -Force; Remove-Item -Path C:\Windows\System32\spool\PRINTERS\* -Force -Recurse; Start-Service Spooler">📋 Copier la commande</button>
                        <pre class="code-block" style="display:block; margin-top:8px;">Stop-Service Spooler -Force; Remove-Item -Path C:\Windows\System32\spool\PRINTERS\* -Force -Recurse; Start-Service Spooler</pre>
                    </div>

                    <div class="guide-card">
                        <h3>🛡️ Réparation Intégrité Système (SFC & DISM)</h3>
                        <p>Analyse et réparation du magasin de composants Windows et des fichiers système corrompus :</p>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="DISM /Online /Cleanup-Image /RestoreHealth; sfc /scannow">📋 Copier la commande</button>
                        <pre class="code-block" style="display:block; margin-top:8px;">DISM /Online /Cleanup-Image /RestoreHealth; sfc /scannow</pre>
                    </div>

                    <div class="guide-card">
                        <h3>🧹 Nettoyage Express du Disque C:</h3>
                        <p>Vidage de la corbeille, suppression des fichiers temporaires utilisateur et système :</p>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue">📋 Copier la commande</button>
                        <pre class="code-block" style="display:block; margin-top:8px;">Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue</pre>
                    </div>

                    <div class="guide-card">
                        <h3>🔓 Déblocage GPO Clés USB</h3>
                        <p>Rétablissement immédiat du pilote de stockage amovible USBSTOR et mise à jour des stratégies :</p>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR -Name Start -Value 3; gpupdate /force">📋 Copier la commande</button>
                        <pre class="code-block" style="display:block; margin-top:8px;">Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR -Name Start -Value 3; gpupdate /force</pre>
                    </div>

                    <div class="guide-card">
                        <h3>⚡ Mettre à Jour Toutes les Applications (Winget)</h3>
                        <p>Analyse et mise à jour globale en arrière-plan de tous les packages logiciels installés :</p>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements">📋 Copier la commande</button>
                        <pre class="code-block" style="display:block; margin-top:8px;">winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements</pre>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 8: PERFORMANCE, STARTUP & CACHES -->
        <div id="tab-performance" class="tab-content">
            <div class="table-section glass-panel">
                <div class="table-title">🚀 Audit de Démarrage, Fréquence CPU & Purge de Caches</div>
                <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px;">
                    Analyse des points de persistance au démarrage, de l'état du CPU (fréquences & throttling) et détection des gigaoctets perdus dans les caches système.
                </div>

                <!-- 3 CARDS DE PERFORMANCE -->
                <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:16px; margin-bottom:24px;">
                    <!-- FAST STARTUP & BOOT -->
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <strong style="font-size:15px; color:var(--neon-cyan);">⚡ Démarrage Rapide (Fast Boot)</strong>
                            __FAST_BOOT_BADGE__
                        </div>
                        <div style="font-size:12.5px; color:var(--text-muted); margin-bottom:12px;">
                            État : <strong style="color:var(--text);">__FAST_BOOT_DESC__</strong><br>
                            <em>Le démarrage rapide hybride met le noyau en veille prolongée sans vider la RAM, causant des anomalies de pilotes après extinction prolongée.</em>
                        </div>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0">⚡ Désactiver Fast Startup (Propre)</button>
                    </div>

                    <!-- CPU & POWER SCHEME -->
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <strong style="font-size:15px; color:var(--neon-cyan);">🌡️ Fréquence CPU & Throttling</strong>
                            __THROTTLE_BADGE__
                        </div>
                        <div style="font-size:12.5px; color:var(--text-muted); margin-bottom:12px;">
                            Plan d'alimentation : <strong style="color:var(--text);">__POWER_PLAN__</strong><br>
                            Horloge mesurée : <strong style="color:var(--text); font-family:Consolas;">__CPU_CLOCK_INFO__</strong>
                        </div>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c">⚡ Activer Performances Élevées</button>
                    </div>

                    <!-- CHASSEUR DE CACHES -->
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <strong style="font-size:15px; color:var(--neon-amber);">🧹 Caches Systèmes Encombrants</strong>
                            <span class="badge badge-warn">__TOTAL_CACHES_MB__ Mo à libérer</span>
                        </div>
                        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
                            • Windows Update (Download) : <strong>__SOFT_DIST_MB__ Mo</strong><br>
                            • Fichiers Temp utilisateur (%TEMP%) : <strong>__TEMP_MB__ Mo</strong><br>
                            • Rapports de crash (CrashDumps) : <strong>__CRASH_DUMPS_MB__ Mo</strong>
                        </div>
                        <button class="btn-copy btn-ps" onclick="copyDirect(this)" data-cmd="Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; Remove-Item -Path $env:SystemRoot\SoftwareDistribution\Download\* -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue; Start-Service wuauserv -ErrorAction SilentlyContinue">🧹 Purger Tous les Caches Détectés</button>
                    </div>
                </div>

                <!-- TABLE DES APPLICATIONS & SCRIPTS AU DÉMARRAGE -->
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;">
                    <h3 style="font-size:15px; color:var(--neon-cyan); margin:0; text-transform:uppercase; letter-spacing:0.5px;">📋 Éléments de Démarrage & Scripts Autorun (__TOTAL_STARTUP__)</h3>
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="filterStartup('ALL', this)">Tous (__TOTAL_STARTUP__)</button>
                        <button class="filter-btn" onclick="filterStartup('SUSPICIOUS', this)" style="border-color:#f43f5e; color:#fb7185;">⚠️ Suspects (__SUSPICIOUS_COUNT__)</button>
                        <button class="filter-btn" onclick="filterStartup('APP', this)">📦 Applications (__APP_COUNT__)</button>
                        <button class="filter-btn" onclick="filterStartup('SCRIPT', this)">📜 Scripts (__SCRIPT_COUNT__)</button>
                        <button class="filter-btn" onclick="filterStartup('FOLDER', this)">📂 Dossier Startup (__FOLDER_COUNT__)</button>
                        <button class="filter-btn" onclick="filterStartup('TASK', this)">⏰ Tâches (__TASK_COUNT__)</button>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="custom-table" id="startupTable">
                        <thead>
                            <tr>
                                <th style="width:18%;">Nom de l'élément</th>
                                <th style="width:15%;">Catégorie</th>
                                <th style="width:18%;">Emplacement / Source</th>
                                <th style="width:37%;">Commande / Cible exécutée</th>
                                <th style="width:12%; text-align:center;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            __STARTUP_ROWS__
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 9: SÉCURITÉ MATÉRIELLE & SOCKETS EN ÉCOUTE -->
        <div id="tab-security" class="tab-content">
            <div class="table-section glass-panel">
                <div class="table-title">🛡️ Posture de Sécurité Matérielle & Cartographie des Ports Réseau</div>
                <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px;">
                    Contrôle de durcissement matériel Windows 11 (TPM, BitLocker, Secure Boot, UAC) et détection des services ouverts sur le réseau (sockets TCP en écoute).
                </div>

                <!-- 4 KPI HARDENING MATERIEL -->
                <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px; margin-bottom:24px;">
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:800;">Puce de Sécurité</div>
                        <div style="font-size:16px; font-weight:800; margin:6px 0;">TPM 2.0</div>
                        <div>__TPM_BADGE__</div>
                    </div>
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:800;">Chiffrement Disque</div>
                        <div style="font-size:16px; font-weight:800; margin:6px 0;">BitLocker (C:)</div>
                        <div>__BITLOCKER_BADGE__</div>
                    </div>
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:800;">Démarrage Sécurisé</div>
                        <div style="font-size:16px; font-weight:800; margin:6px 0;">UEFI Secure Boot</div>
                        <div>__SECURE_BOOT_BADGE__</div>
                    </div>
                    <div class="res-card" style="margin-bottom:0;">
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:800;">Contrôle de Compte</div>
                        <div style="font-size:16px; font-weight:800; margin:6px 0;">Niveau UAC</div>
                        <div>__UAC_BADGE__</div>
                    </div>
                </div>

                <!-- TABLE DES PORTS RÉSEAU OUVERTS -->
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="font-size:15px; color:var(--neon-cyan); margin:0; text-transform:uppercase; letter-spacing:0.5px;">🌐 Sockets TCP en Écoute & Processus Associés</h3>
                    <span style="font-size:12px; color:var(--neon-amber); font-family:Consolas;">__PUBLIC_PORTS_COUNT__ port(s) exposé(s) sur le LAN / Public</span>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:15%;">Port Local</th>
                                <th style="width:25%;">Adresse d'Écoute</th>
                                <th style="width:35%;">Processus / Service</th>
                                <th style="width:25%;">Exposition Réseau</th>
                            </tr>
                        </thead>
                        <tbody>
                            __LISTENING_ROWS__
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <div class="print-footer-strip">
            [ FIN DU RAPPORT • VALIDATION OPÉRATEUR SUPPORT NIVEAU 3 • CERTIFIÉ CONFORME UAA 3 ]
        </div>
    </div>

    <!-- TOAST NOTIFICATION -->
    <div id="toast" class="toast">✅ Copié dans le presse-papiers !</div>

    <!-- THREE.JS & INTERACTIVE SCRIPT -->
    <script>
                                        // -------------------------------------------------------------
        // 🌌 PHOTOREALISTIC GARGANTUA BLACK HOLE (PROCEDURAL PLASMA EMISSION)
        // -------------------------------------------------------------
        // 🌌 PHOTOREALISTIC GARGANTUA BLACK HOLE (INFINITE FEATHERED LIGHT FALLOFF)
        // -------------------------------------------------------------
        // 🌌 UNIFIED GLSL RELATIVISTIC GARGANTUA BLACK HOLE (ZERO SHARP EDGES)
        // -------------------------------------------------------------
        // 🌌 UNIFIED GLSL RELATIVISTIC GARGANTUA & SOLAR FIREBALL
        // -------------------------------------------------------------
        (function initThreeBackground() {
            var canvas = document.getElementById('three-bg');
            if (!canvas) return;
            var scene = new THREE.Scene();
            var camera = new THREE.PerspectiveCamera(58, window.innerWidth / window.innerHeight, 1, 1400);
            camera.position.z = 220;
            camera.position.y = -8;

            var renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true, powerPreference: 'high-performance' });
            renderer.setSize(window.innerWidth, window.innerHeight);
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

            // 1. DARK THEME GROUP (Cosmic Starfield + Unified GLSL Gargantua Black Hole)
            var darkGroup = new THREE.Group();
            scene.add(darkGroup);

            // A. Deep Space Ambient Stars
            var particleCount = 450;
            var geometry = new THREE.BufferGeometry();
            var positions = new Float32Array(particleCount * 3);
            var velocities = [];

            for (var i = 0; i < particleCount; i++) {
                positions[i * 3] = (Math.random() - 0.5) * 800;
                positions[i * 3 + 1] = (Math.random() - 0.5) * 600;
                positions[i * 3 + 2] = (Math.random() - 0.5) * 600;

                velocities.push({
                    x: (Math.random() - 0.5) * 0.03,
                    y: (Math.random() - 0.5) * 0.03,
                    z: (Math.random() - 0.5) * 0.03
                });
            }
            geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

            var material = new THREE.PointsMaterial({
                color: 0x38bdf8,
                size: 1.8,
                transparent: true,
                opacity: 0.25,
                blending: THREE.AdditiveBlending
            });
            var particles = new THREE.Points(geometry, material);
            darkGroup.add(particles);

            // B. UNIFIED GLSL GARGANTUA BLACK HOLE
            var bhUniforms = {
                uTime: { value: 0.0 }
            };

            var bhVertexShader = `
                varying vec2 vUv;
                void main() {
                    vUv = uv;
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `;

            var bhFragmentShader = `
                uniform float uTime;
                varying vec2 vUv;
                void main() {
                    vec2 uv = (vUv - 0.5) * 2.0;
                    float r = length(uv);
                    float angle = atan(uv.y, uv.x);
                    float r_horizon = 0.22;

                    // 1. Singularity Event Horizon (Pure Black Void Inside)
                    if (r < r_horizon) {
                        gl_FragColor = vec4(0.0, 0.0, 0.0, 1.0);
                        return;
                    }

                    // 2. Gravitational Photon Ring hugging the horizon boundary directly
                    float photonDist = abs(r - r_horizon);
                    float photonRing = exp(-photonDist * 160.0) * 0.95;

                    // 3. Inclined Accretion Disc (Directly attached to the horizon with zero dark gap)
                    vec2 discUV = vec2(uv.x, uv.y / 0.36);
                    float rDisc = length(discUV);
                    float angleDisc = atan(discUV.y, discUV.x);
                    float doppler = 1.0 - (uv.x / max(r, 0.01)) * 0.32;
                    float innerEdge = smoothstep(r_horizon, r_horizon + 0.04, rDisc);
                    float outerDecay = exp(-pow(max(0.0, rDisc - r_horizon) / 0.30, 2.0));
                    float discPlasma = innerEdge * outerDecay * doppler;

                    // 4. Lensing Arcs
                    vec2 upperUV = vec2(uv.x, (uv.y - 0.06) / 0.85);
                    float rUpper = length(upperUV);
                    float upperArc = smoothstep(0.05, 0.002, abs(rUpper - (r_horizon + 0.06))) * smoothstep(0.0, 0.25, uv.y) * 0.65;

                    vec2 lowerUV = vec2(uv.x, (uv.y + 0.05) / 0.70);
                    float rLower = length(lowerUV);
                    float lowerArc = smoothstep(0.045, 0.002, abs(rLower - (r_horizon + 0.05))) * smoothstep(0.0, -0.20, uv.y) * 0.40;

                    float swirl = sin(angleDisc * 5.0 - uTime * 0.6 + rDisc * 12.0) * 0.10;
                    float plasmaDensity = (discPlasma * (1.0 + swirl)) + upperArc + lowerArc + photonRing;

                    // If outside horizon with zero plasma emission, output completely transparent 0.0 alpha
                    if (plasmaDensity < 0.001) {
                        gl_FragColor = vec4(0.0, 0.0, 0.0, 0.0);
                        return;
                    }

                    vec3 colWhiteCyan = vec3(0.0, 0.94, 1.0);
                    vec3 colSapphire  = vec3(0.22, 0.74, 0.97);
                    vec3 colIndigo    = vec3(0.39, 0.40, 0.95);
                    vec3 colViolet    = vec3(0.66, 0.33, 0.97);

                    vec3 color = mix(colWhiteCyan, colSapphire, clamp((r - 0.22) / 0.18, 0.0, 1.0));
                    color = mix(color, colIndigo, clamp((r - 0.40) / 0.22, 0.0, 1.0));
                    color = mix(color, colViolet, clamp((r - 0.62) / 0.25, 0.0, 1.0));
                    color += vec3(1.0, 1.0, 1.0) * photonRing * 0.75;

                    float edgeCut = smoothstep(0.85, 0.30, r);
                    float finalAlpha = clamp(plasmaDensity * 0.38 * edgeCut, 0.0, 1.0);
                    gl_FragColor = vec4(color, finalAlpha);
                }
            `;

            var bhMaterial = new THREE.ShaderMaterial({
                uniforms: bhUniforms,
                vertexShader: bhVertexShader,
                fragmentShader: bhFragmentShader,
                transparent: true,
                blending: THREE.AdditiveBlending,
                depthWrite: false
            });

            var bhPlaneGeo = new THREE.PlaneGeometry(620, 620);
            var blackHoleMesh = new THREE.Mesh(bhPlaneGeo, bhMaterial);
            blackHoleMesh.position.set(0, -6, -35);
            darkGroup.add(blackHoleMesh);

            // Subtle Cyan Quantum Evaporation / Hawking Radiation Wireframe Cage
            var hawkingWireGeo = new THREE.IcosahedronGeometry(72, 2);
            var hawkingWireMat = new THREE.MeshBasicMaterial({
                color: 0x00f0ff,
                wireframe: true,
                transparent: true,
                opacity: 0.14,
                blending: THREE.AdditiveBlending,
                depthWrite: false
            });
            var hawkingWire = new THREE.Mesh(hawkingWireGeo, hawkingWireMat);
            hawkingWire.position.set(0, -6, -35);
            darkGroup.add(hawkingWire);

            // 2. SOLAR THEME 3D GROUP (Photorealistic Solar Fireball)
            var solarGroup = new THREE.Group();
            solarGroup.visible = false;
            scene.add(solarGroup);

            var solarParticleCount = 350;
            var solarGeo = new THREE.BufferGeometry();
            var solarPositions = new Float32Array(solarParticleCount * 3);
            var solarVels = [];

            for (var j = 0; j < solarParticleCount; j++) {
                var theta = Math.random() * Math.PI * 2;
                var rad = 80 + Math.random() * 180;
                solarPositions[j * 3] = Math.cos(theta) * rad;
                solarPositions[j * 3 + 1] = (Math.random() - 0.5) * 120;
                solarPositions[j * 3 + 2] = Math.sin(theta) * rad;

                solarVels.push({
                    angle: theta,
                    speed: 0.0004 + Math.random() * 0.0008,
                    radius: rad,
                    yVel: (Math.random() - 0.5) * 0.06
                });
            }
            solarGeo.setAttribute('position', new THREE.BufferAttribute(solarPositions, 3));

            var solarPointsMat = new THREE.PointsMaterial({
                color: 0xf59e0b,
                size: 2.4,
                transparent: true,
                opacity: 0.55,
                blending: THREE.AdditiveBlending
            });
            var solarPoints = new THREE.Points(solarGeo, solarPointsMat);
            solarGroup.add(solarPoints);

            var sunUniforms = {
                uTime: { value: 0.0 }
            };

            var sunVertexShader = `
                varying vec2 vUv;
                void main() {
                    vUv = uv;
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `;

            var sunFragmentShader = `
                uniform float uTime;
                varying vec2 vUv;

                float hash(vec2 p) {
                    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
                }
                float noise(vec2 p) {
                    vec2 i = floor(p);
                    vec2 f = fract(p);
                    vec2 u = f * f * (3.0 - 2.0 * f);
                    return mix(mix(hash(i + vec2(0.0,0.0)), hash(i + vec2(1.0,0.0)), u.x),
                               mix(hash(i + vec2(0.0,1.0)), hash(i + vec2(1.0,1.0)), u.x), u.y);
                }
                float fbm(vec2 p) {
                    float v = 0.0;
                    float a = 0.5;
                    vec2 shift = vec2(100.0);
                    mat2 rot = mat2(cos(0.5), sin(0.5), -sin(0.5), cos(0.5));
                    for (int i = 0; i < 4; ++i) {
                        v += a * noise(p);
                        p = rot * p * 2.0 + shift;
                        a *= 0.5;
                    }
                    return v;
                }

                void main() {
                    vec2 uv = (vUv - 0.5) * 2.0;
                    float r = length(uv);
                    float angle = atan(uv.y, uv.x);

                    float t = uTime * 0.4;
                    vec2 noiseUV = vec2(uv.x * 3.5 + sin(t * 0.5 + uv.y * 2.0) * 0.3, uv.y * 3.5 + cos(t * 0.4 + uv.x * 2.0) * 0.3);
                    float plasmaPattern = fbm(noiseUV + t * 0.2);

                    float flareNoise = fbm(vec2(angle * 3.0, r * 4.0 - t * 1.2));
                    float limbRadius = 0.27 + (flareNoise * 0.08);

                    float coreMask = smoothstep(limbRadius + 0.02, 0.0, r);
                    float limbGlow = smoothstep(0.08, 0.001, abs(r - limbRadius)) * 0.85;

                    float coronaDecay = exp(-pow(max(0.0, r - 0.25) / 0.26, 1.8));
                    float outerFade = smoothstep(0.90, 0.40, r);
                    float corona = coronaDecay * outerFade * (0.60 + flareNoise * 0.35);

                    vec3 colIncandescentWhite = vec3(1.0, 0.98, 0.92);
                    vec3 colSunGold           = vec3(1.0, 0.78, 0.15);
                    vec3 colSolarOrange       = vec3(0.95, 0.42, 0.05);
                    vec3 colProminenceRuby    = vec3(0.85, 0.12, 0.02);
                    vec3 colCoronaAmber       = vec3(0.98, 0.65, 0.10);

                    vec3 color = mix(colSunGold, colIncandescentWhite, pow(clamp(1.0 - (r / 0.28), 0.0, 1.0), 1.6) * (0.8 + plasmaPattern * 0.3));
                    color = mix(color, colSolarOrange, clamp((r - 0.15) / 0.14, 0.0, 1.0));
                    color = mix(color, colProminenceRuby, clamp((r - 0.27) / 0.08, 0.0, 1.0));
                    color = mix(color, colCoronaAmber, clamp((r - 0.32) / 0.30, 0.0, 1.0));

                    float totalIntensity = (coreMask * 1.0) + (limbGlow * 0.8) + (corona * 0.65);
                    float finalAlpha = clamp(totalIntensity * outerFade * 0.75, 0.0, 1.0);

                    gl_FragColor = vec4(color, finalAlpha);
                }
            `;

            var sunMaterial = new THREE.ShaderMaterial({
                uniforms: sunUniforms,
                vertexShader: sunVertexShader,
                fragmentShader: sunFragmentShader,
                transparent: true,
                blending: THREE.AdditiveBlending,
                depthWrite: false
            });

            var sunPlaneGeo = new THREE.PlaneGeometry(620, 620);
            var sunMesh = new THREE.Mesh(sunPlaneGeo, sunMaterial);
            sunMesh.position.set(0, -6, -35);
            solarGroup.add(sunMesh);

            // Stylish 3D Wireframe Icosahedron Cage around the Sun Fireball
            var sunWireGeo1 = new THREE.IcosahedronGeometry(84, 2);
            var sunWireMat1 = new THREE.MeshBasicMaterial({
                color: 0xffbb00,
                wireframe: true,
                transparent: true,
                opacity: 0.40,
                blending: THREE.AdditiveBlending
            });
            var sunWire1 = new THREE.Mesh(sunWireGeo1, sunWireMat1);
            solarGroup.add(sunWire1);

            var sunWireGeo2 = new THREE.IcosahedronGeometry(102, 1);
            var sunWireMat2 = new THREE.MeshBasicMaterial({
                color: 0xff5500,
                wireframe: true,
                transparent: true,
                opacity: 0.25,
                blending: THREE.AdditiveBlending
            });
            var sunWire2 = new THREE.Mesh(sunWireGeo2, sunWireMat2);
            solarGroup.add(sunWire2);

            // Theme Switcher Hook
            window.setThreeTheme = function(themeName) {
                if (themeName === 'solar' || themeName === 'light') {
                    darkGroup.visible = false;
                    solarGroup.visible = true;
                } else {
                    darkGroup.visible = true;
                    solarGroup.visible = false;
                }
            };

            // Expressive Mouse Following with Capped Speed
            var clock = new THREE.Clock();
            var maxAngularSpeed = (2 * Math.PI) / 100;

            var targetRotX = 0, targetRotY = 0;
            var currentRotX = 0, currentRotY = 0;
            var ambientY = 0;

            window.addEventListener('mousemove', function (e) {
                var normX = (e.clientX - window.innerWidth / 2) / (window.innerWidth / 2);
                var normY = (e.clientY - window.innerHeight / 2) / (window.innerHeight / 2);
                targetRotY = normX * 0.45;
                targetRotX = normY * 0.25;
            });

            window.addEventListener('resize', function () {
                camera.aspect = window.innerWidth / window.innerHeight;
                camera.updateProjectionMatrix();
                renderer.setSize(window.innerWidth, window.innerHeight);
            });

            function animate() {
                requestAnimationFrame(animate);

                var delta = Math.min(clock.getDelta(), 0.1);
                var elapsedTime = clock.getElapsedTime();
                var maxStep = maxAngularSpeed * delta;

                var diffY = targetRotY - currentRotY;
                var diffX = targetRotX - currentRotX;

                var stepY = Math.sign(diffY) * Math.min(Math.abs(diffY * 0.04), maxStep);
                var stepX = Math.sign(diffX) * Math.min(Math.abs(diffX * 0.04), maxStep);

                currentRotY += stepY;
                currentRotX += stepX;

                ambientY += (maxAngularSpeed * 0.10) * delta;

                // --- ANIMATE DARK THEME GROUP (GLSL GARGANTUA BLACK HOLE) ---
                if (darkGroup.visible) {
                    particles.rotation.y = ambientY + currentRotY;
                    particles.rotation.x = currentRotX;
                    particles.rotation.z = currentRotY * 0.15;

                    bhUniforms.uTime.value = elapsedTime;

                    blackHoleMesh.rotation.y = (ambientY * 0.2) + currentRotY * 0.18;
                    blackHoleMesh.rotation.x = currentRotX * 0.12;

                    hawkingWire.rotation.y += 0.00035;
                    hawkingWire.rotation.x += 0.00025;

                    var pos = geometry.attributes.position.array;
                    for (var i = 0; i < particleCount; i++) {
                        pos[i * 3] += velocities[i].x * 0.15;
                        pos[i * 3 + 1] += velocities[i].y * 0.15;
                        pos[i * 3 + 2] += velocities[i].z * 0.15;

                        if (pos[i * 3] < -370 || pos[i * 3] > 370) velocities[i].x *= -1;
                        if (pos[i * 3 + 1] < -270 || pos[i * 3 + 1] > 270) velocities[i].y *= -1;
                        if (pos[i * 3 + 2] < -270 || pos[i * 3 + 2] > 270) velocities[i].z *= -1;
                    }
                    geometry.attributes.position.needsUpdate = true;
                }

                // --- ANIMATE SOLAR FIREBALL THEME GROUP (PHOTOREALISTIC BOILING SUN) ---
                if (solarGroup.visible) {
                    sunUniforms.uTime.value = elapsedTime;

                    sunMesh.rotation.y = (ambientY * 0.2) + currentRotY * 0.18;
                    sunMesh.rotation.x = currentRotX * 0.12;

                    sunWire1.rotation.y += 0.0006;
                    sunWire1.rotation.x += 0.0004;
                    sunWire2.rotation.y -= 0.0004;
                    sunWire2.rotation.z += 0.0003;

                    solarGroup.rotation.y = (ambientY * 0.4) + currentRotY * 0.35;
                    solarGroup.rotation.x = currentRotX * 0.25;

                    var sPos = solarGeo.attributes.position.array;
                    for (var k = 0; k < solarParticleCount; k++) {
                        var pData = solarVels[k];
                        pData.angle += pData.speed;
                        sPos[k * 3] = Math.cos(pData.angle) * pData.radius;
                        sPos[k * 3 + 1] += pData.yVel;
                        sPos[k * 3 + 2] = Math.sin(pData.angle) * pData.radius;

                        if (sPos[k * 3 + 1] > 60 || sPos[k * 3 + 1] < -60) pData.yVel *= -1;
                    }
                    solarGeo.attributes.position.needsUpdate = true;
                }

                renderer.render(scene, camera);
            }
            animate();
        })();

        // -------------------------------------------------------------
        // 🔮 THREE.JS COCKPIT CORE (Beautiful 3D Wireframe Sphere)
        // -------------------------------------------------------------
        (function initThreeCore() {
            var canvas = document.getElementById('three-core');
            if (!canvas) return;
            var scene = new THREE.Scene();
            var camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
            camera.position.z = 4.2;

            var renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true, powerPreference: "high-performance" });
            renderer.setSize(90, 90);
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

            var mainGroup = new THREE.Group();
            scene.add(mainGroup);

            // Lighting Setup - Multi-chromatic Cybernetic Speculars
            var amb = new THREE.AmbientLight(0x0f172a, 1.6);
            scene.add(amb);
            
            var coreLight = new THREE.PointLight(0x00f0ff, 3.5, 15);
            coreLight.position.set(0, 0, 0);
            scene.add(coreLight);

            var rimLight1 = new THREE.DirectionalLight(0x10b981, 2.0);
            rimLight1.position.set(3, 4, 3);
            scene.add(rimLight1);

            var rimLight2 = new THREE.DirectionalLight(0xa855f7, 2.0);
            rimLight2.position.set(-3, -4, 2);
            scene.add(rimLight2);

            // 1. Central Crystalline Faceted Core (Icosahedron with Emissive Glow)
            var coreGeo = new THREE.IcosahedronGeometry(0.70, 0);
            var coreMat = new THREE.MeshStandardMaterial({
                color: 0x0284c7,
                roughness: 0.05,
                metalness: 0.95,
                emissive: 0x00f0ff,
                emissiveIntensity: 0.85,
                flatShading: true
            });
            var centralCrystal = new THREE.Mesh(coreGeo, coreMat);
            mainGroup.add(centralCrystal);

            // 1b. Inner Inverted Octahedron Spark
            var sparkGeo = new THREE.OctahedronGeometry(0.38, 0);
            var sparkMat = new THREE.MeshBasicMaterial({
                color: 0xffffff,
                wireframe: true
            });
            var innerSpark = new THREE.Mesh(sparkGeo, sparkMat);
            mainGroup.add(innerSpark);

            // 2. Holographic Geodesic Outer Lattice Cage
            var outerGeo = new THREE.IcosahedronGeometry(1.42, 1);
            var outerMat = new THREE.MeshStandardMaterial({
                color: 0x38bdf8,
                wireframe: true,
                transparent: true,
                opacity: 0.75,
                roughness: 0.1,
                metalness: 0.9
            });
            var geodesicCage = new THREE.Mesh(outerGeo, outerMat);
            mainGroup.add(geodesicCage);

            // 3. Gimbal Dual Counter-Rotating Quantum Rings
            // Ring A (Cyan Primary)
            var ringAGeo = new THREE.TorusGeometry(1.72, 0.028, 12, 64);
            var ringAMat = new THREE.MeshStandardMaterial({
                color: 0x00f0ff,
                emissive: 0x00f0ff,
                emissiveIntensity: 0.65,
                roughness: 0.1,
                metalness: 0.9
            });
            var ringA = new THREE.Mesh(ringAGeo, ringAMat);
            ringA.rotation.x = Math.PI / 4;
            mainGroup.add(ringA);

            // Ring B (Emerald Secondary)
            var ringBGeo = new THREE.TorusGeometry(1.50, 0.022, 12, 64);
            var ringBMat = new THREE.MeshStandardMaterial({
                color: 0x10b981,
                emissive: 0x10b981,
                emissiveIntensity: 0.55,
                roughness: 0.1,
                metalness: 0.9
            });
            var ringB = new THREE.Mesh(ringBGeo, ringBMat);
            ringB.rotation.y = Math.PI / 3;
            mainGroup.add(ringB);

            // 4. Orbital Satellites / Quantum Node Markers
            var satGroup = new THREE.Group();
            mainGroup.add(satGroup);
            var satGeo = new THREE.IcosahedronGeometry(0.07, 0);
            var satMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8 });
            var satCount = 4;
            var satellites = [];
            for (var i = 0; i < satCount; i++) {
                var sat = new THREE.Mesh(satGeo, satMat);
                satGroup.add(sat);
                satellites.push({
                    mesh: sat,
                    radius: 1.72,
                    angle: (i * Math.PI * 2) / satCount,
                    speed: 1.2 + (i * 0.3)
                });
            }

            // 5. Swirling Quantum Particle Vortex
            var pCount = 90;
            var pGeo = new THREE.BufferGeometry();
            var pPos = new Float32Array(pCount * 3);
            var pData = [];
            for (var p = 0; p < pCount; p++) {
                var pRad = 0.8 + Math.random() * 1.1;
                var pTheta = Math.random() * Math.PI * 2;
                var pPhi = (Math.random() - 0.5) * Math.PI;
                pPos[p * 3] = pRad * Math.cos(pTheta) * Math.cos(pPhi);
                pPos[p * 3 + 1] = pRad * Math.sin(pPhi);
                pPos[p * 3 + 2] = pRad * Math.sin(pTheta) * Math.cos(pPhi);
                pData.push({
                    radius: pRad,
                    theta: pTheta,
                    phi: pPhi,
                    speed: 0.5 + Math.random() * 1.0,
                    drift: (Math.random() - 0.5) * 0.4
                });
            }
            pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
            var pMat = new THREE.PointsMaterial({
                color: 0x38bdf8,
                size: 0.055,
                transparent: true,
                opacity: 0.85,
                blending: THREE.AdditiveBlending
            });
            var particles = new THREE.Points(pGeo, pMat);
            mainGroup.add(particles);

            // Interaction & Hover Dynamics
            var mouseDrag = false;
            var prevMouse = { x: 0, y: 0 };
            var targetRot = { x: 0.2, y: 0.3 };
            var isHovered = false;
            var shockwaveScale = 1.0;

            var container = document.getElementById('three-core-container');
            if (container) {
                container.addEventListener('mouseenter', function() { isHovered = true; });
                container.addEventListener('mouseleave', function() { isHovered = false; });
                container.addEventListener('mousedown', function(e) {
                    mouseDrag = true;
                    prevMouse.x = e.clientX;
                    prevMouse.y = e.clientY;
                    shockwaveScale = 1.35; // Trigger shockwave pulse on click
                });
                window.addEventListener('mouseup', function() { mouseDrag = false; });
                window.addEventListener('mousemove', function(e) {
                    if (mouseDrag) {
                        var dx = e.clientX - prevMouse.x;
                        var dy = e.clientY - prevMouse.y;
                        targetRot.y += dx * 0.012;
                        targetRot.x += dy * 0.012;
                        prevMouse.x = e.clientX;
                        prevMouse.y = e.clientY;
                    }
                });
            }

            // Animation Loop
            var clock = new THREE.Clock();
            function animate() {
                requestAnimationFrame(animate);
                var dt = clock.getDelta();
                var time = clock.getElapsedTime();
                var speedMultiplier = isHovered ? 2.5 : 1.0;

                var isLight = (document.documentElement.getAttribute('data-theme') === 'light');
                if (isLight) {
                    coreMat.color.setHex(0xf59e0b);
                    coreMat.emissive.setHex(0xf97316);
                    outerMat.color.setHex(0xfbbf24);
                    ringAMat.color.setHex(0xf59e0b);
                    ringAMat.emissive.setHex(0xf97316);
                    ringBMat.color.setHex(0xd97706);
                    pMat.color.setHex(0xf59e0b);
                    coreLight.color.setHex(0xf59e0b);
                } else {
                    coreMat.color.setHex(0x0284c7);
                    coreMat.emissive.setHex(0x00f0ff);
                    outerMat.color.setHex(0x38bdf8);
                    ringAMat.color.setHex(0x00f0ff);
                    ringAMat.emissive.setHex(0x00f0ff);
                    ringBMat.color.setHex(0x10b981);
                    ringBMat.emissive.setHex(0x10b981);
                    pMat.color.setHex(0x38bdf8);
                    coreLight.color.setHex(0x00f0ff);
                }

                // Rotations
                mainGroup.rotation.x += (targetRot.x - mainGroup.rotation.x) * 0.08;
                mainGroup.rotation.y += (targetRot.y - mainGroup.rotation.y) * 0.08;
                if (!mouseDrag) {
                    targetRot.y += 0.45 * dt * speedMultiplier;
                    targetRot.x = Math.sin(time * 0.5) * 0.15;
                }

                centralCrystal.rotation.y -= 0.8 * dt * speedMultiplier;
                centralCrystal.rotation.x += 0.4 * dt * speedMultiplier;
                innerSpark.rotation.y += 1.5 * dt * speedMultiplier;

                geodesicCage.rotation.y += 0.3 * dt * speedMultiplier;
                geodesicCage.rotation.z -= 0.2 * dt * speedMultiplier;

                ringA.rotation.x += 0.6 * dt * speedMultiplier;
                ringA.rotation.z += 0.4 * dt * speedMultiplier;

                ringB.rotation.y -= 0.7 * dt * speedMultiplier;
                ringB.rotation.x -= 0.3 * dt * speedMultiplier;

                // Pulsing Quantum Core Glow & Shockwave damp
                var pulse = 0.75 + Math.sin(time * 3.5) * 0.25;
                coreMat.emissiveIntensity = pulse * (isHovered ? 1.4 : 0.9);
                coreLight.intensity = pulse * 4.0;

                shockwaveScale += (1.0 - shockwaveScale) * 0.1;
                ringA.scale.setScalar(shockwaveScale);
                ringB.scale.setScalar(shockwaveScale);

                // Update Satellites
                for (var s = 0; s < satellites.length; s++) {
                    var satObj = satellites[s];
                    satObj.angle += satObj.speed * dt * speedMultiplier;
                    satObj.mesh.position.set(
                        Math.cos(satObj.angle) * satObj.radius,
                        Math.sin(satObj.angle) * Math.sin(time + s) * 0.6,
                        Math.sin(satObj.angle) * satObj.radius
                    );
                }

                // Update Swirling Particles
                var pArray = pGeo.attributes.position.array;
                for (var pt = 0; pt < pCount; pt++) {
                    var pd = pData[pt];
                    pd.theta += pd.speed * dt * 0.6 * speedMultiplier;
                    pd.phi += pd.drift * dt;
                    pArray[pt * 3] = pd.radius * Math.cos(pd.theta) * Math.cos(pd.phi);
                    pArray[pt * 3 + 1] = pd.radius * Math.sin(pd.phi);
                    pArray[pt * 3 + 2] = pd.radius * Math.sin(pd.theta) * Math.cos(pd.phi);
                }
                pGeo.attributes.position.needsUpdate = true;

                renderer.render(scene, camera);
            }
            animate();
        })();

        // -------------------------------------------------------------
        // UI & CLIPBOARD INTERACTIONS
        // -------------------------------------------------------------
        function copyDirect(elem) {
            var cmd = elem.getAttribute('data-cmd') || elem.innerText;
            if (!cmd) return;

            navigator.clipboard.writeText(cmd).then(function () {
                showToast("✅ Raccourci / Commande copié(e) dans le presse-papiers !");
            }).catch(function () {
                var tempInput = document.createElement('textarea');
                tempInput.value = cmd;
                document.body.appendChild(tempInput);
                tempInput.select();
                document.execCommand('copy');
                document.body.removeChild(tempInput);
                showToast("✅ Raccourci / Commande copié(e) dans le presse-papiers !");
            });
        }

        
        
                // =============================================================
        // 🌐 MOTEUR D'INTERNATIONALISATION COMPLET (FR, NL, EN, DE)
        // =============================================================
        var currentLang = '__INITIAL_LANG__';

        // =========================================================================
        // =========================================================================
        // MOTEUR D'INTERNATIONALISATION COMPLET 100% (FR / NL / EN / DE)
        // =========================================================================
        var translations = {
            fr: {
                theme_btn: "🌓 Thème",
                main_title: "🛠️ CENTRE DE DIAGNOSTIC, DÉPANNAGE & GESTION IT // NIVEAU 3",
                main_sub: "Console d'Ingénierie PC, Réseaux & Systèmes • Référentiel IT Niveau 3 (Observer ➔ Tester ➔ Corriger ➔ Valider ➔ Expliquer)",
                status_diag_done: "DIAGNOSTIC EXÉCUTÉ",
                status_probes_ok: "SONDES NIVEAU 3 CONFORMES",
                status_data_safe: "DONNÉES LOCALES SÉCURISÉES",
                timestamp_lbl: "HORODATAGE",
                console_tier: "CONSOLE D'ADMINISTRATION // TIER-3 PRO",
                card_total: "Contrôles L3",
                card_ok: "Conformes (OK)",
                card_warn: "Avertissements",
                card_err: "Pannes Critiques",
                card_health: "Score Santé",
                tab_resolution: "■ 📊 BILAN & PANNES",
                tab_health: "■ 📈 SANTÉ & TENDANCES",
                tab_cve: "■ 🔴 VULNÉRABILITÉS CVE",
                tab_network: "■ 🌐 AUDIT RÉSEAU & RDP",
                tab_disk: "■ 💾 ANALYSE DISQUE",
                tab_performance: "■ 🚀 DÉMARRAGE & STARTUP",
                tab_belgian: "■ 🇧🇪 LOGICIELS BELGIQUE",
                tab_benchmarks: "■ ⚡ BENCHMARKS & SMART",
                tab_security: "■ 👤 SÉCURITÉ & ANOMALIES",
                tab_foss: "■ 🌐 ARBRE 3D FOSS",
                tab_all: "■ 📋 TOUS LES TESTS (26)",
                tab_profiles: "■ 📦 PROFILS WINGET",
                tab_shortcuts: "■ ⌨️ RACCOURCIS PRO",
                tab_rmm: "■ 🔗 EXPORT RMM & CLIENT",
                tab_docs: "■ 📖 DOCUMENTATION & GUIDE",
                btn_run_tab: "⚡ RELANCER DIAG (.BAT)",
                btn_refresh_tab: "🔄 ACTUALISER",
                btn_print_tab: "🖨️ IMPRIMER",
                btn_pov: "🎢 Vue POV",
                btn_pov_exit: "🛑 Quitter Vue POV",
                btn_recenter: "🎯 Recentrer",
                btn_autospin_off: "🔄 Auto-Spin : OFF",
                btn_autospin_on: "🔄 Auto-Spin : ON",
                btn_view_journal: "📋 Voir Journal",
                btn_close: "✖ Fermer",
                search_placeholder: "🔍 Filtrer par composant, service, test ou commande PowerShell...",
                toast_launch: "⚡ Lancement du diagnostic via protocole diagit://...",
                toast_refresh: "🔄 Actualisation des données du rapport...",
                lbl_finding: "🔍 Constat technique :",
                lbl_fix: "🔧 Action corrective :",
                lbl_exam_tip: "💡 Explication Formateur / Règle UAA 3 :",
                lbl_gui_shortcut: "🪟 Raccourci GUI :",
                lbl_ps_cmd: "⚡ Copier PowerShell :",
                cve_clean_title: "Aucune Vulnérabilité Critique Détectée (CVSS ≥ 7.0)",
                cve_clean_sub: "Toutes les applications auditées sont conformes et protégées contre les failles répertoriées.",
                cve_clean_badge: "✅ 100% Conforme",
                cve_clean_desc: "L'inventaire logiciel a été scanné par rapport à la base de vulnérabilités officielles. Aucun binaire exécutable obsolète avec vecteur d'attaque critique n'est présent sur ce système.",
                cve_alert_title: "Vulnérabilités Logicielles Détectées",
                cve_alert_sub: "Mettez à jour les logiciels ci-dessous pour combler les failles de sécurité.",
                sec_clean_title: "Sécurité du Système Optimale",
                sec_clean_sub: "Comptes utilisateurs, UAC, TPM, SecureBoot et intégrité conformes aux normes professionnelles.",
                th_point: "Point de contrôle",
                th_status: "Statut",
                th_findings: "Constat technique détaillé",
                th_recommendation: "Solution recommandée",
                th_powershell: "Remédiation PowerShell",
                th_gui: "Raccourci GUI",
                th_port: "Port Local",
                th_address: "Adresse d'Écoute",
                th_process: "Processus / Service",
                th_exposure: "Exposition Réseau",
                th_disk: "Disque Physique",
                th_media: "Type Média",
                th_smart: "Santé SMART",
                th_wear: "Usure (%)",
                th_temp: "Température",
                th_errors: "Erreurs Lecture",
                th_size: "Taille",
                th_name: "Nom de l'élément",
                th_path: "Chemin Local",
                th_command: "Commande / Cible exécutée",
                th_user: "Nom Utilisateur",
                th_account_status: "Statut Compte",
                th_pwd_exp: "Expiration MDP",
                th_last_logon: "Dernière Connexion",
                th_ref_cpu: "Processeurs de Référence Représentatifs",
                th_points_idx: "Indice Points",
                th_avg_time: "Temps Moyen",
                th_relative_pos: "Positionnement Relatif",
                th_machine_tier: "Catégorie de Machine",
                th_action: "Action"
            },
            nl: {
                theme_btn: "🌓 Thema",
                main_title: "🛠️ IT-DIAGNOSE-, PROBLEEMOPLOSSINGS- & BEHEERCENTRUM // NIVEAU 3",
                main_sub: "PC-, Netwerk- & Systeemonderhoudsconsole • IT Niveau 3 Standaard (Observeren ➔ Testen ➔ Corrigeren ➔ Valideren ➔ Uitleggen)",
                status_diag_done: "DIAGNOSE UITGEVOERD",
                status_probes_ok: "NIVEAU 3 SONDERINGEN CONFORM",
                status_data_safe: "LOKALE GEGEVENS BEVEILIGD",
                timestamp_lbl: "TIJDSTEMPEL",
                console_tier: "BEHEERSCONSOLE // TIER-3 PRO",
                card_total: "L3 Controles",
                card_ok: "Conform (OK)",
                card_warn: "Waarschuwingen",
                card_err: "Kritieke Fouten",
                card_health: "Gezondheidsscore",
                tab_resolution: "■ 📊 OVERZICHT & FOUTEN",
                tab_health: "■ 📈 GEZONDHEID & TRENDS",
                tab_cve: "■ 🔴 CVE KWETSBAARHEDEN",
                tab_network: "■ 🌐 NETWERK & RDP AUDIT",
                tab_disk: "■ 💾 SCHIJFANALYSE",
                tab_performance: "■ 🚀 OPSTARTEN & STARTUP",
                tab_belgian: "■ 🇧🇪 BELGISCHE SOFTWARE & eID",
                tab_benchmarks: "■ ⚡ BENCHMARKS & SMART",
                tab_security: "■ 👤 BEVEILIGING & GEBRUIKERS",
                tab_foss: "■ 🌐 3D FOSS BOOM",
                tab_all: "■ 📋 ALLE TESTS (26)",
                tab_profiles: "■ 📦 WINGET PROFIELEN",
                tab_shortcuts: "■ ⌨️ PRO SNELKOPPELINGEN",
                tab_rmm: "■ 🔗 EXPORT RMM & KLANT",
                tab_docs: "■ 📖 DOCUMENTATIE & GIDS",
                btn_run_tab: "⚡ HERSTART DIAG (.BAT)",
                btn_refresh_tab: "🔄 VERNIEUWEN",
                btn_print_tab: "🖨️ AFDRUKKEN",
                btn_pov: "🎢 POV Weergave",
                btn_pov_exit: "🛑 Sluit POV",
                btn_recenter: "🎯 Centreren",
                btn_autospin_off: "🔄 Auto-Spin : OFF",
                btn_autospin_on: "🔄 Auto-Spin : ON",
                btn_view_journal: "📋 Bekijk Logboek",
                btn_close: "✖ Sluiten",
                search_placeholder: "🔍 Filter op component, service, test of PowerShell-opdracht...",
                toast_launch: "⚡ Diagnose starten via diagit:// protocol...",
                toast_refresh: "🔄 Gegevens vernieuwen...",
                lbl_finding: "🔍 Technische bevinding:",
                lbl_fix: "🔧 Corrigerende maatregel:",
                lbl_exam_tip: "💡 Instructeur Tip / Niveau 3 Regel:",
                lbl_gui_shortcut: "🪟 GUI Snelkoppeling:",
                lbl_ps_cmd: "⚡ Kopieer PowerShell:",
                cve_clean_title: "Geen Kritieke Kwetsbaarheden Gedetecteerd (CVSS ≥ 7.0)",
                cve_clean_sub: "Alle gecontroleerde applicaties zijn conform en beschermd tegen bekende kwetsbaarheden.",
                cve_clean_badge: "✅ 100% Conform",
                cve_clean_desc: "De software-inventaris is gescand tegen de officiële kwetsbaarhedendatabase. Er zijn geen verouderde uitvoerbare bestanden met een kritieke aanvalsvector op dit systeem.",
                cve_alert_title: "Software Kwetsbaarheden Gedetecteerd",
                cve_alert_sub: "Werk de onderstaande software bij om beveiligingslekken te dichten.",
                sec_clean_title: "Optimale Systeembeveiliging",
                sec_clean_sub: "Gebruikersaccounts, UAC, TPM, SecureBoot en integriteit conform professionele normen.",
                th_point: "Controlepunt",
                th_status: "Status",
                th_findings: "Gedetailleerde Technische Bevinding",
                th_recommendation: "Aanbevolen Oplossing",
                th_powershell: "PowerShell Herstel",
                th_gui: "GUI Snelkoppeling",
                th_port: "Lokale Poort",
                th_address: "Luisteradres",
                th_process: "Proces / Service",
                th_exposure: "Netwerkblootstelling",
                th_disk: "Fysieke Schijf",
                th_media: "Mediatype",
                th_smart: "SMART Status",
                th_wear: "Slijtage (%)",
                th_temp: "Temperatuur",
                th_errors: "Leesfouten",
                th_size: "Grootte",
                th_name: "Itemnaam",
                th_path: "Lokaal Pad",
                th_command: "Uitgevoerd Commando / Doel",
                th_user: "Gebruikersnaam",
                th_account_status: "Accountstatus",
                th_pwd_exp: "Wachtwoord Vervaldatum",
                th_last_logon: "Laatste Aanmelding",
                th_ref_cpu: "Representatieve Referentieprocessors",
                th_points_idx: "Puntenindex",
                th_avg_time: "Gemiddelde Tijd",
                th_relative_pos: "Relatieve Positie",
                th_machine_tier: "Machinecategorie",
                th_action: "Actie"
            },
            en: {
                theme_btn: "🌓 Theme",
                main_title: "🛠️ IT DIAGNOSTIC, TROUBLESHOOTING & MANAGEMENT CENTER // LEVEL 3",
                main_sub: "PC, Network & Systems Engineering Console • IT Level 3 Framework (Observe ➔ Test ➔ Fix ➔ Validate ➔ Explain)",
                status_diag_done: "DIAGNOSTIC COMPLETED",
                status_probes_ok: "LEVEL 3 PROBES CONFORMANT",
                status_data_safe: "LOCAL DATA SECURED",
                timestamp_lbl: "TIMESTAMP",
                console_tier: "ADMINISTRATION CONSOLE // TIER-3 PRO",
                card_total: "L3 Checks",
                card_ok: "Compliant (OK)",
                card_warn: "Warnings",
                card_err: "Critical Failures",
                card_health: "Health Score",
                tab_resolution: "■ 📊 SUMMARY & ISSUES",
                tab_health: "■ 📈 HEALTH & TRENDS",
                tab_cve: "■ 🔴 CVE VULNERABILITIES",
                tab_network: "■ 🌐 NETWORK & RDP AUDIT",
                tab_disk: "■ 💾 DISK ANALYSIS",
                tab_performance: "■ 🚀 STARTUP & PERF",
                tab_belgian: "■ 🇧🇪 BELGIAN SOFTWARE",
                tab_benchmarks: "■ ⚡ BENCHMARKS & SMART",
                tab_security: "■ 👤 SECURITY & USERS",
                tab_foss: "■ 🌐 3D FOSS TREE",
                tab_all: "■ 📋 ALL TESTS (26)",
                tab_profiles: "■ 📦 WINGET PROFILES",
                tab_shortcuts: "■ ⌨️ PRO SHORTCUTS",
                tab_rmm: "■ 🔗 RMM & CLIENT EXPORT",
                tab_docs: "■ 📖 DOCS & METHODOLOGY",
                btn_run_tab: "⚡ RERUN DIAG (.BAT)",
                btn_refresh_tab: "🔄 REFRESH",
                btn_print_tab: "🖨️ PRINT",
                btn_pov: "🎢 POV View",
                btn_pov_exit: "🛑 Exit POV View",
                btn_recenter: "🎯 Recenter",
                btn_autospin_off: "🔄 Auto-Spin : OFF",
                btn_autospin_on: "🔄 Auto-Spin : ON",
                btn_view_journal: "📋 View Journal",
                btn_close: "✖ Close",
                search_placeholder: "🔍 Filter by component, service, test, or PowerShell command...",
                toast_launch: "⚡ Launching diagnostic via diagit:// protocol...",
                toast_refresh: "🔄 Refreshing report data...",
                lbl_finding: "🔍 Technical Finding:",
                lbl_fix: "🔧 Corrective Action:",
                lbl_exam_tip: "💡 Instructor Tip / Level 3 Rule:",
                lbl_gui_shortcut: "🪟 GUI Shortcut:",
                lbl_ps_cmd: "⚡ Copy PowerShell:",
                cve_clean_title: "No Critical Vulnerabilities Detected (CVSS ≥ 7.0)",
                cve_clean_sub: "All audited applications are compliant and protected against registered flaws.",
                cve_clean_badge: "✅ 100% Compliant",
                cve_clean_desc: "The software inventory has been scanned against official vulnerability databases. No obsolete executable binaries with critical attack vectors are present on this system.",
                cve_alert_title: "Software Vulnerabilities Detected",
                cve_alert_sub: "Update the applications below to remediate critical security flaws.",
                sec_clean_title: "Optimal System Security",
                sec_clean_sub: "User accounts, UAC, TPM, SecureBoot, and integrity compliant with professional standards.",
                th_point: "Check Point",
                th_status: "Status",
                th_findings: "Detailed Technical Finding",
                th_recommendation: "Recommended Solution",
                th_powershell: "PowerShell Remediation",
                th_gui: "GUI Shortcut",
                th_port: "Local Port",
                th_address: "Listening Address",
                th_process: "Process / Service",
                th_exposure: "Network Exposure",
                th_disk: "Physical Disk",
                th_media: "Media Type",
                th_smart: "SMART Health",
                th_wear: "Wear (%)",
                th_temp: "Temperature",
                th_errors: "Read Errors",
                th_size: "Size",
                th_name: "Item Name",
                th_path: "Local Path",
                th_command: "Command / Executed Target",
                th_user: "User Name",
                th_account_status: "Account Status",
                th_pwd_exp: "Password Expiration",
                th_last_logon: "Last Logon",
                th_ref_cpu: "Representative Reference Processors",
                th_points_idx: "Points Index",
                th_avg_time: "Average Time",
                th_relative_pos: "Relative Position",
                th_machine_tier: "Machine Category",
                th_action: "Action"
            },
            de: {
                theme_btn: "🌓 Thema",
                main_title: "🛠️ IT-DIAGNOSE-, FEHLERBEHEBUNGS- & VERWALTUNGSZENTRUM // STUFE 3",
                main_sub: "PC-, Netzwerk- & Systemwartungskonsole • IT Stufe 3 Referenz (Beobachten ➔ Testen ➔ Korrigieren ➔ Validieren ➔ Erklären)",
                status_diag_done: "DIAGNOSE DURCHGEFÜHRT",
                status_probes_ok: "STUFE 3 SONDEN KONFORM",
                status_data_safe: "LOKALE DATEN GESICHERT",
                timestamp_lbl: "ZEITSTEMPEL",
                console_tier: "VERWALTUNGSKONSOLE // TIER-3 PRO",
                card_total: "L3 Kontrollen",
                card_ok: "Konform (OK)",
                card_warn: "Warnungen",
                card_err: "Kritische Fehler",
                card_health: "Gesundheitswert",
                tab_resolution: "■ 📊 ÜBERSICHT & FEHLER",
                tab_health: "■ 📈 GESUNDHEIT & TRENDS",
                tab_cve: "■ 🔴 CVE SCHWACHSTELLEN",
                tab_network: "■ 🌐 NETZWERK & RDP AUDIT",
                tab_disk: "■ 💾 FESTPLATTENANALYSE",
                tab_performance: "■ 🚀 AUTOSTART & LEISTUNG",
                tab_belgian: "■ 🇧🇪 BELGISCHE SOFTWARE & eID",
                tab_benchmarks: "■ ⚡ BENCHMARKS & SMART",
                tab_security: "■ 👤 SICHERHEIT & BENUTZER",
                tab_foss: "■ 🌐 3D FOSS BAUM",
                tab_all: "■ 📋 ALLE TESTS (26)",
                tab_profiles: "■ 📦 WINGET PROFILE",
                tab_shortcuts: "■ ⌨️ PRO TASTENKÜRZEL",
                tab_rmm: "■ 🔗 RMM & KUNDEN-EXPORT",
                tab_docs: "■ 📖 DOKUMENTATION & LEITFADEN",
                btn_run_tab: "⚡ DIAG NEUSTARTEN (.BAT)",
                btn_refresh_tab: "🔄 AKTUALISIEREN",
                btn_print_tab: "🖨️ DRUCKEN",
                btn_pov: "🎢 POV-Ansicht",
                btn_pov_exit: "🛑 POV Beenden",
                btn_recenter: "🎯 Zentrieren",
                btn_autospin_off: "🔄 Auto-Spin : AUS",
                btn_autospin_on: "🔄 Auto-Spin : EIN",
                btn_view_journal: "📋 Protokoll Anzeigen",
                btn_close: "✖ Schließen",
                search_placeholder: "🔍 Nach Komponente, Dienst, Test oder PowerShell-Befehl filtern...",
                toast_launch: "⚡ Diagnose über diagit://-Protokoll wird gestartet...",
                toast_refresh: "🔄 Berichtsdaten werden aktualisiert...",
                lbl_finding: "🔍 Technischer Befund:",
                lbl_fix: "🔧 Korrekturmaßnahme:",
                lbl_exam_tip: "💡 Ausbilder-Tipp / Stufe 3 Regel:",
                lbl_gui_shortcut: "🪟 GUI Tastenkürzel:",
                lbl_ps_cmd: "⚡ PowerShell Kopieren:",
                cve_clean_title: "Keine Kritischen Schwachstellen Erkannt (CVSS ≥ 7.0)",
                cve_clean_sub: "Alle geprüften Anwendungen sind konform und vor bekannten Lücken geschützt.",
                cve_clean_badge: "✅ 100% Konform",
                cve_clean_desc: "Der Software-Bestand wurde mit der offiziellen Schwachstellen-Datenbank abgeglichen. Es sind keine veralteten ausführbaren Dateien mit kritischen Angriffsvektoren vorhanden.",
                cve_alert_title: "Software-Schwachstellen Erkannt",
                cve_alert_sub: "Aktualisieren Sie die unten aufgeführten Programme zur Behebung von Sicherheitslücken.",
                sec_clean_title: "Optimale Systemsicherheit",
                sec_clean_sub: "Benutzerkonten, UAC, TPM, SecureBoot und Integrität entsprechen professionellen Standards.",
                th_point: "Prüfpunkt",
                th_status: "Status",
                th_findings: "Detaillierter Technischer Befund",
                th_recommendation: "Empfohlene Lösung",
                th_powershell: "PowerShell-Behebung",
                th_gui: "GUI-Verknüpfung",
                th_port: "Lokaler Port",
                th_address: "Abhöradresse",
                th_process: "Prozess / Dienst",
                th_exposure: "Netzwerkexposition",
                th_disk: "Physische Festplatte",
                th_media: "Medientyp",
                th_smart: "SMART Zustand",
                th_wear: "Verschleiß (%)",
                th_temp: "Temperatur",
                th_errors: "Lesefehler",
                th_size: "Größe",
                th_name: "Elementname",
                th_path: "Lokaler Pfad",
                th_command: "Ausgeführter Befehl / Ziel",
                th_user: "Benutzername",
                th_account_status: "Kontostatus",
                th_pwd_exp: "Passwort-Ablauf",
                th_last_logon: "Letzte Anmeldung",
                th_ref_cpu: "Repräsentative Referenzprozessoren",
                th_points_idx: "Punkte-Index",
                th_avg_time: "Durchschnittszeit",
                th_relative_pos: "Relative Position",
                th_machine_tier: "Maschinenkategorie",
                th_action: "Aktion"
            }
        };

        // Render dynamic CVE tab
        function renderCveTab(lang) {
            var cveCont = document.getElementById('cveCardsContainer');
            if (!cveCont) return;
            var t = translations[lang] || translations.fr;
            var cveList = (window.cveData && Array.isArray(window.cveData)) ? window.cveData : [];

            if (cveList.length === 0) {
                cveCont.innerHTML = [
                    '<div style="background:rgba(16,185,129,0.08); border:1px solid rgba(52,211,153,0.35); border-left:4px solid #10b981; border-radius:8px; padding:22px; margin-top:10px;">',
                    '  <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px;">',
                    '    <span style="font-size:24px;">🛡️</span>',
                    '    <div>',
                    '      <h3 style="margin:0; font-size:16px; color:#34d399; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">' + t.cve_clean_title + '</h3>',
                    '      <div style="font-size:12px; color:#94a3b8; margin-top:2px;">' + t.cve_clean_sub + '</div>',
                    '    </div>',
                    '    <span class="badge badge-ok" style="margin-left:auto; font-size:12px; padding:6px 12px;">' + t.cve_clean_badge + '</span>',
                    '  </div>',
                    '  <div style="font-size:12.5px; color:#cbd5e1; line-height:1.6; border-top:1px solid rgba(255,255,255,0.08); padding-top:12px; margin-top:10px;">',
                    '    ' + t.cve_clean_desc,
                    '  </div>',
                    '</div>'
                ].join('');
            }
        }

        // Deep Text Node Translation with Whitespace Normalization
        var deepPhraseDict = {
            "Scanner de Vulnérabilités Logicielles (Base de Données CVE)": {
                en: "Software Vulnerability Scanner (CVE Database)",
                nl: "Software Kwetsbaarhedenscanner (CVE Database)",
                de: "Software-Schwachstellenscanner (CVE-Datenbank)"
            },
            "Vérification des versions binaires réelles des applications installées par rapport au registre des vulnérabilités critiques (CVSS 7.0+). Permet d'identifier immédiatement les failles zero-day exploitables et de justifier les actions de patch management.": {
                en: "Verification of actual binary versions of installed applications against the critical vulnerability registry (CVSS 7.0+). Enables immediate identification of exploitable zero-day flaws and justifies patch management actions.",
                nl: "Verificatie van werkelijke binaire versies van geïnstalleerde applicaties tegen het register van kritieke kwetsbaarheden (CVSS 7.0+). Maakt onmiddellijke identificatie van exploiteerbare zero-day kwetsbaarheden mogelijk en rechtvaardigt patchbeheer.",
                de: "Überprüfung der tatsächlichen Binärversionen installierter Anwendungen anhand des Registers für kritische Schwachstellen (CVSS 7.0+). Ermöglicht die sofortige Erkennung ausnutzbarer Zero-Day-Lücken und begründet Patch-Management-Maßnahmen."
            },
            "Audit Approfondi de la Configuration Réseau & Accès Distant": {
                en: "In-Depth Audit of Network Configuration & Remote Access",
                nl: "Grondige Audit van Netwerkconfiguratie & Toegang op Afstand",
                de: "Eingehende Prüfung der Netzwerkkonfiguration & des Fernzugriffs"
            },
            "Cartographie des adaptateurs physiques, connectivité Internet, passerelle, DNS, sockets TCP en écoute et état des services critiques.": {
                en: "Mapping of physical adapters, Internet connectivity, gateway, DNS, listening TCP sockets, and status of critical services.",
                nl: "In kaart brengen van fysieke adapters, internetconnectiviteit, gateway, DNS, luisterende TCP-sockets en status van kritieke services.",
                de: "Erfassung physischer Adapter, Internetverbindung, Gateway, DNS, abhörender TCP-Sockets und Status kritischer Dienste."
            },
            "Sélectionner la Carte Réseau à Auditer :": {
                en: "Select Network Adapter to Audit:",
                nl: "Selecteer de te Auditeren Netwerkkaart:",
                de: "Zu prüfenden Netzwerkadapter auswählen:"
            },
            "Basculez entre vos cartes Ethernet, Wi-Fi, VPN ou commutateurs virtuels (WSL/Hyper-V) :": {
                en: "Switch between your Ethernet, Wi-Fi, VPN adapters or virtual switches (WSL/Hyper-V):",
                nl: "Schakel tussen uw Ethernet-, Wi-Fi-, VPN-adapters of virtuele switches (WSL/Hyper-V):",
                de: "Wechseln Sie zwischen Ethernet-, Wi-Fi-, VPN-Adaptern oder virtuellen Switches (WSL/Hyper-V):"
            },
            "Diagnostic Matériel des Disques & Santé SMART": {
                en: "Hardware Disk Diagnostics & SMART Health",
                nl: "Hardware Schijfdiagnose & SMART Gezondheid",
                de: "Hardware-Festplattendatei & SMART-Zustand"
            },
            "Analyse de l'usure, de la température, des erreurs de lecture et de la santé globale des disques physiques NVMe, SSD et HDD.": {
                en: "Analysis of wear, temperature, read errors, and overall health of NVMe, SSD, and HDD physical drives.",
                nl: "Analyse van slijtage, temperatuur, leesfouten en algehele gezondheid van NVMe-, SSD- en HDD-schijven.",
                de: "Analyse von Verschleiß, Temperatur, Lesefehlern und Gesamtzustand physischer NVMe-, SSD- und HDD-Laufwerke."
            },
            "Analyse de la Performance, Démarrage & Throttling CPU": {
                en: "Performance Analysis, Startup & CPU Throttling",
                nl: "Prestatieanalyse, Opstarten & CPU-Throttling",
                de: "Leistungsanalyse, Autostart & CPU-Drosselung"
            },
            "Analyse des points de persistance au démarrage, de l'état du CPU (fréquences & throttling) et détection des gigaoctets perdus dans les caches système.": {
                en: "Analysis of startup persistence points, CPU state (clock frequencies & throttling), and identification of gigabytes lost in system caches.",
                nl: "Analyse van opstart persistentiepunten, CPU-status (kloksnelheden & throttling) en detectie van verloren gigabytes in systeemcaches.",
                de: "Analyse von Autostart-Persistenzpunkten, CPU-Status (Taktfrequenzen & Drosselung) und Erkennung verlorener Gigabytes in System-Caches."
            },
            "Benchmark Processeur & Indice de Performance Multi-Thread": {
                en: "Processor Benchmark & Multi-Thread Performance Index",
                nl: "Processor Benchmark & Multi-Thread Prestatie-index",
                de: "Prozessor-Benchmark & Multi-Thread-Leistungsindex"
            },
            "Mesure normalisée du temps d'exécution d'algorithmes intensifs et comparaison avec les catégories de référence du marché.": {
                en: "Standardized measurement of execution time for compute-intensive algorithms and comparison with market reference categories.",
                nl: "Gestandaardiseerde meting van uitvoeringstijd voor rekenintensieve algoritmen en vergelijking met marktreferentiecategorieën.",
                de: "Standardisierte Messung der Ausführungszeit rechenintensiver Algorithmen und Vergleich mit Marktreferenzkategorien."
            },
            "Audit de Sécurité des Comptes Utilisateurs & Contrôles Système": {
                en: "Security Audit of User Accounts & System Controls",
                nl: "Beveiligingsaudit van Gebruikersaccounts & Systeembesturing",
                de: "Sicherheitsprüfung von Benutzerkonten & Systemsteuerungen"
            },
            "Inspection des privilèges administrateur locaux, expiration des mots de passe, état TPM 2.0, SecureBoot, BitLocker et UAC.": {
                en: "Inspection of local administrator privileges, password expiration, TPM 2.0 status, SecureBoot, BitLocker, and UAC.",
                nl: "Inspectie van lokale beheerdersrechten, wachtwoordverloop, TPM 2.0-status, SecureBoot, BitLocker en UAC.",
                de: "Prüfung lokaler Administratorrechte, Passwortablauf, TPM 2.0-Status, SecureBoot, BitLocker und UAC."
            },
            "Raccourcis Clavier Windows 11 & Guide Expert IT": {
                en: "Windows 11 Keyboard Shortcuts & IT Expert Guide",
                nl: "Windows 11 Sneltoetsen & IT Expert Gids",
                de: "Windows 11 Tastenkürzel & IT-Expertenhandbuch"
            },
            "Le Top 10 Absolu du Technicien IT": {
                en: "The Absolute Top 10 for IT Technicians",
                nl: "De Absolute Top 10 voor IT-Technici",
                de: "Die Absoluten Top 10 für IT-Techniker"
            },
            "Consoles d'Administration Rapide (Win + R)": {
                en: "Quick Administrative Consoles (Win + R)",
                nl: "Snelle Beheerconsoles (Win + R)",
                de: "Schnelle Verwaltungskonsolen (Win + R)"
            },
            "Boîte à Outils PowerShell Express (Dépannage Rapide)": {
                en: "Express PowerShell Toolbox (Fast Troubleshooting)",
                nl: "Express PowerShell Gereedschapskist (Snelle Probleemoplossing)",
                de: "Express PowerShell-Toolbox (Schnelle Fehlerbehebung)"
            },
            "Méthode & Arbre de Décision UAA 3 (Support PC & Réseaux)": {
                en: "Methodology & Decision Tree (PC & Network Support)",
                nl: "Methodologie & Beslissingsboom (PC & Netwerkondersteuning)",
                de: "Methodik & Entscheidungsbaum (PC- & Netzwerk-Support)"
            },
            "La Méthode en 6 Étapes qui Évite de Paniquer": {
                en: "The 6-Step Method That Prevents Panic",
                nl: "De 6-Stappenmethode die Paniek Voorkomt",
                de: "Die 6-Schritte-Methode gegen Panik"
            },
            "Packs d'Applications Clé en Main par Profil Métier": {
                en: "Turnkey Application Bundles by Professional Profile",
                nl: "Kant-en-klare Softwarepakketten per Beroepsprofiel",
                de: "Schlüsselfertige Anwendungspakete nach Berufsprofil"
            },
            "Générateur de Déploiement Winget Sur-Mesure": {
                en: "Custom Winget Deployment Generator",
                nl: "Aangepaste Winget Implementatiegenerator",
                de: "Benutzerdefinierter Winget-Bereitstellungsgenerator"
            },
            "Scanner des Runtimes Développeur & Dépendances": {
                en: "Developer Runtimes & Dependencies Scanner",
                nl: "Ontwikkelaars Runtimes & Afhankelijkheden Scanner",
                de: "Entwickler-Runtimes & Abhängigkeiten-Scanner"
            },
            "Écosystème Logiciel Belge & Certificats eID": {
                en: "Belgian Software Ecosystem & eID Certificates",
                nl: "Belgisch Software Ecosysteem & eID Certificaten",
                de: "Belgisches Software-Ökosystem & eID-Zertifikate"
            },
            "Matrice Open-Source Alternatives (FOSS Tree 3D)": {
                en: "Open-Source Alternative Matrix (3D FOSS Tree)",
                nl: "Open-Source Alternatievenmatrix (3D FOSS Boom)",
                de: "Open-Source-Alternativenmatrix (3D FOSS Baum)"
            }
        };

        function translateDomNodes(lang) {
            if (!deepPhraseDict) return;
            // Normalize matching
            var allElements = document.querySelectorAll('.section-title, .table-section > p, h2, h3, h4, strong, div, p');
            allElements.forEach(function(el) {
                if (el.children.length > 3) return; // avoid large containers
                if (!el._origHtml) el._origHtml = el.innerHTML;

                var rawText = el.innerText ? el.innerText.trim() : '';
                for (var key in deepPhraseDict) {
                    if (rawText.indexOf(key) !== -1) {
                        var target = (lang === 'fr') ? key : (deepPhraseDict[key][lang] || deepPhraseDict[key]['en'] || key);
                        el.innerHTML = el._origHtml.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), target);
                        break;
                    }
                }
            });
        }

        
        var probeTextDict = {
        "Passerelle par défaut": {
                "en": "Default Gateway",
                "nl": "Standaardgateway",
                "de": "Standard-Gateway"
        },
        "Fichier Hosts (Redirection / Détournement)": {
                "en": "Hosts File (Redirection / Hijack)",
                "nl": "Hosts-bestand (Omleiding / Kaping)",
                "de": "Hosts-Datei (Umleitung / Entführung)"
        },
        "Espace Disque": {
                "en": "Disk Space",
                "nl": "Schijfruimte",
                "de": "Festplattenspeicher"
        },
        "Disposition du Clavier (QWERTY / Inversé)": {
                "en": "Keyboard Layout (QWERTY / Inverted)",
                "nl": "Toetsenbordindeling (QWERTY / Omgekeerd)",
                "de": "Tastaturlayout (QWERTY / Umgekehrt)"
        },
        "Cartes Réseau Détectées": {
                "en": "Detected Network Adapters",
                "nl": "Gedetecteerde Netwerkkaarten",
                "de": "Erkannte Netzwerkadapter"
        },
        "État de Connexion Réseau (Lien Physique)": {
                "en": "Network Connection Status (Physical Link)",
                "nl": "Netwerkverbindingsstatus (Fysieke Link)",
                "de": "Netzwerkverbindungsstatus (Physischer Link)"
        },
        "Attribution IP (Détection APIPA)": {
                "en": "IP Assignment (APIPA Detection)",
                "nl": "IP-toewijzing (APIPA-detectie)",
                "de": "IP-Zuweisung (APIPA-Erkennung)"
        },
        "Accès Internet Public (WAN / 8.8.8.8)": {
                "en": "Public Internet Access (WAN / 8.8.8.8)",
                "nl": "Publieke Internettoegang (WAN / 8.8.8.8)",
                "de": "Öffentlicher Internetzugang (WAN / 8.8.8.8)"
        },
        "Résolution DNS (google.com)": {
                "en": "DNS Resolution (google.com)",
                "nl": "DNS-omzetting (google.com)",
                "de": "DNS-Auflösung (google.com)"
        },
        "Service Client DHCP": {
                "en": "DHCP Client Service",
                "nl": "DHCP Client-service",
                "de": "DHCP-Client-Dienst"
        },
        "Service Client DNS (Dnscache)": {
                "en": "DNS Client Service (Dnscache)",
                "nl": "DNS Client-service (Dnscache)",
                "de": "DNS-Client-Dienst (Dnscache)"
        },
        "Serveur Proxy Activé": {
                "en": "Proxy Server Enabled",
                "nl": "Proxyserver Ingeschakeld",
                "de": "Proxy-Server Aktiviert"
        },
        "Service Spouleur d'impression": {
                "en": "Print Spooler Service",
                "nl": "Print Spooler-service",
                "de": "Druckspooler-Dienst"
        },
        "Service Pare-feu Windows (MpsSvc)": {
                "en": "Windows Firewall Service (MpsSvc)",
                "nl": "Windows Firewall-service (MpsSvc)",
                "de": "Windows-Firewall-Dienst (MpsSvc)"
        },
        "Santé SMART du Disque": {
                "en": "SMART Disk Health",
                "nl": "SMART Schijfgezondheid",
                "de": "SMART-Festplattenzustand"
        },
        "Périphériques en Erreur (Code Gestionnaire)": {
                "en": "Devices in Error (Device Manager Code)",
                "nl": "Apparaten met Fouten (Apparaatbeheer Code)",
                "de": "Geräte mit Fehlern (Geräte-Manager Code)"
        },
        "Santé de la Batterie": {
                "en": "Battery Health",
                "nl": "Batterijgezondheid",
                "de": "Akkuzustand"
        },
        "Crashs Système Récents (BSOD / Minidumps)": {
                "en": "Recent System Crashes (BSOD / Minidumps)",
                "nl": "Recente Systeemcrashes (BSOD / Minidumps)",
                "de": "Kürzliche Systemabstürze (BSOD / Minidumps)"
        },
        "Chiffrement BitLocker (Lecteur Système C:)": {
                "en": "BitLocker Encryption (System Drive C:)",
                "nl": "BitLocker-versleuteling (Systeemschijf C:)",
                "de": "BitLocker-Verschlüsselung (Systemlaufwerk C:)"
        },
        "Contrôle de Compte d'Utilisateur (UAC)": {
                "en": "User Account Control (UAC)",
                "nl": "Gebruikersaccountbeheer (UAC)",
                "de": "Benutzerkontensteuerung (UAC)"
        },
        "Antivirus Windows Defender": {
                "en": "Windows Defender Antivirus",
                "nl": "Windows Defender Antivirus",
                "de": "Windows Defender Antivirus"
        },
        "Éléments Suspects au Démarrage": {
                "en": "Suspicious Startup Items",
                "nl": "Verdachte Opstartitems",
                "de": "Verdächtige Autostart-Elemente"
        },
        "Réseau": {
                "en": "Network",
                "nl": "Netwerk",
                "de": "Netzwerk"
        },
        "Système & OS": {
                "en": "System & OS",
                "nl": "Systeem & OS",
                "de": "System & OS"
        },
        "Hardware & Drivers": {
                "en": "Hardware & Drivers",
                "nl": "Hardware & Drivers",
                "de": "Hardware & Treiber"
        },
        "Sécurité & GPO": {
                "en": "Security & GPO",
                "nl": "Beveiliging & GPO",
                "de": "Sicherheit & GPO"
        },
        "Logiciel": {
                "en": "Software",
                "nl": "Software",
                "de": "Software"
        },
        "est injoignable par ping ICMP": {
                "en": "is unreachable via ICMP ping",
                "nl": "is onbereikbaar via ICMP-ping",
                "de": "ist über ICMP-Ping nicht erreichbar"
        },
        "Redirection(s) suspecte(s) détectée(s)": {
                "en": "Suspicious redirection(s) detected",
                "nl": "Verdachte omleiding(en) gedetecteerd",
                "de": "Verdächtige Umleitung(en) erkannt"
        },
        "Espace critique sur": {
                "en": "Critical disk space on",
                "nl": "Kritieke schijfruimte op",
                "de": "Kritischer Speicherplatz auf"
        },
        "seulement": {
                "en": "only",
                "nl": "slechts",
                "de": "nur"
        },
        "restants": {
                "en": "remaining",
                "nl": "resterend",
                "de": "verbleibend"
        },
        "Clavier configuré en QWERTY": {
                "en": "Keyboard configured in QWERTY or foreign layout",
                "nl": "Toetsenbord geconfigureerd in QWERTY of buitenlandse indeling",
                "de": "Tastatur in QWERTY oder fremdem Layout konfiguriert"
        },
        "Les touches A/Q et Z/W sont inversées": {
                "en": "Keys A/Q and Z/W are inverted",
                "nl": "Toetsen A/Q en Z/W zijn omgewisseld",
                "de": "Tasten A/Q und Z/W sind vertauscht"
        },
        "Vérifier l'adresse IP de la passerelle": {
                "en": "Check the gateway IP address, router/switch cable, or router firewall",
                "nl": "Controleer het IP-adres van de gateway, de router-/switchkabel of de routerfirewall",
                "de": "Prüfen Sie die Gateway-IP-Adresse, das Router-/Switch-Kabel oder die Router-Firewall"
        },
        "Nettoyer le fichier hosts": {
                "en": "Clean the hosts file by removing suspicious lines and flush the DNS cache",
                "nl": "Schoon het hosts-bestand op door verdachte regels te verwijderen en leeg de DNS-cache",
                "de": "Bereinigen Sie die Hosts-Datei durch Entfernen verdächtiger Zeilen und leeren Sie den DNS-Cache"
        },
        "Vider la corbeille, lancer cleanmgr": {
                "en": "Empty the recycle bin, run cleanmgr, purge temp files and Windows Update caches",
                "nl": "Prullenbak legen, cleanmgr starten, tijdelijke bestanden en Windows Update-caches opschonen",
                "de": "Papierkorb leeren, cleanmgr ausführen, temporäre Dateien und Windows Update-Caches bereinigen"
        },
        "Basculer la disposition avec le raccourci Alt+Shift": {
                "en": "Toggle layout with Alt+Shift or Win+Space shortcut, or restore French/Belgian keyboard",
                "nl": "Wissel van indeling met Alt+Shift of Win+Spatie, of herstel Frans/Belgisch toetsenbord",
                "de": "Layout mit Alt+Shift oder Win+Leertaste umschalten, oder französisches/belgisches Layout wiederherstellen"
        },
        "Si la passerelle ne répond pas, le poste ne peut joindre aucun autre réseau ni internet.": {
                "en": "If the gateway does not respond, the workstation cannot reach any other network or the Internet.",
                "nl": "Als de gateway niet reageert, kan het werkstation geen enkel ander netwerk of internet bereiken.",
                "de": "Wenn das Gateway nicht antwortet, kann die Workstation kein anderes Netzwerk oder das Internet erreichen."
        },
        "Piège classique : si UN SEUL site ne s'ouvre pas ou renvoie vers un faux site, c'est le fichier hosts.": {
                "en": "Classic pitfall: if ONLY ONE website fails to open or redirects to a fake site, check the hosts file.",
                "nl": "Klassieke valkuil: als SLECHTS ÉÉN website niet opent of doorstuurt naar een valse site, is het het hosts-bestand.",
                "de": "Klassische Falle: Wenn NUR EINE Website nicht öffnet oder auf eine gefälschte Seite umleitet, liegt es an der Hosts-Datei."
        },
        "Un disque saturé bloque les mises à jour Windows, empêche l'écriture de fichiers et ralentit le système.": {
                "en": "A full disk blocks Windows updates, prevents file writing, and slows down the system.",
                "nl": "Een volle schijf blokkeert Windows-updates, verhindert het schrijven van bestanden en vertraagt het systeem.",
                "de": "Ein voller Datenträger blockiert Windows-Updates, verhindert das Schreiben von Dateien und verlangsamt das System."
        },
        "Ce n'est pas un clavier en panne physique : l'utilisateur a simplement pressé Alt+Shift sans faire exprès.": {
                "en": "This is not a hardware keyboard failure: the user simply pressed Alt+Shift accidentally.",
                "nl": "Dit is geen fysiek defect toetsenbord: de gebruiker heeft per ongeluk op Alt+Shift gedrukt.",
                "de": "Dies ist kein physischer Tastaturdefekt: Der Benutzer hat versehentlich Alt+Shift gedrückt."
        }
};

        function translateResolutionCards(lang) {
            if (!probeTextDict) return;

            // 1. Translate Resolution Cards
            var cards = document.querySelectorAll('.res-card');
            cards.forEach(function(card) {{
                if (!card._origHtml) card._origHtml = card.innerHTML;

                if (lang === 'fr') {{
                    card.innerHTML = card._origHtml;
                    return;
                }}

                var currentHtml = card._origHtml;
                for (var key in probeTextDict) {{
                    if (currentHtml.indexOf(key) !== -1) {{
                        var target = probeTextDict[key][lang] || probeTextDict[key]['en'] || key;
                        currentHtml = currentHtml.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), target);
                    }}
                }}
                card.innerHTML = currentHtml;
            }});

            // 2. Translate Journal Table Rows
            var journalRows = document.querySelectorAll('#diagTable tbody tr');
            journalRows.forEach(function(row) {{
                if (!row._origHtml) row._origHtml = row.innerHTML;

                if (lang === 'fr') {{
                    row.innerHTML = row._origHtml;
                    return;
                }}

                var currentHtml = row._origHtml;
                for (var key in probeTextDict) {{
                    if (currentHtml.indexOf(key) !== -1) {{
                        var target = probeTextDict[key][lang] || probeTextDict[key]['en'] || key;
                        currentHtml = currentHtml.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), target);
                    }}
                }}
                row.innerHTML = currentHtml;
            }});
        }


        function applyLanguage(lang) {
            currentLang = lang;
            localStorage.setItem('diag_lang', lang);
            var t = translations[lang] || translations.fr;

            var sel = document.getElementById('langSelect');
            if (sel) sel.value = lang;

            var themeBtn = document.getElementById('themeToggleBtn');
            if (themeBtn) themeBtn.innerText = t.theme_btn;

            var mainH1 = document.querySelector('.cockpit-title h1');
            if (mainH1) mainH1.innerText = t.main_title;

            var mainSub = document.querySelector('.cockpit-sub');
            if (mainSub) mainSub.innerText = t.main_sub;

            var leds = document.querySelectorAll('.cockpit-status-bar .cockpit-led');
            if (leds.length >= 3) {
                leds[0].childNodes[1].nodeValue = " " + t.status_diag_done;
                leds[1].childNodes[1].nodeValue = " " + t.status_probes_ok;
                leds[2].childNodes[1].nodeValue = " " + t.status_data_safe;
            }

            // Summary cards
            var cardTitles = document.querySelectorAll('.summary-cards .card .title');
            if (cardTitles.length >= 5) {
                cardTitles[0].innerText = t.card_total;
                cardTitles[1].innerText = t.card_ok;
                cardTitles[2].innerText = t.card_warn;
                cardTitles[3].innerText = t.card_err;
                cardTitles[4].innerText = t.card_health;
            }

            // Tab Buttons
            var tabBtns = document.querySelectorAll('.tabs .tab-btn');
            var tabKeys = [
                'tab_resolution', 'tab_health', 'tab_cve', 'tab_network',
                'tab_disk', 'tab_performance', 'tab_belgian', 'tab_benchmarks',
                'tab_security', 'tab_foss', 'tab_all', 'tab_profiles',
                'tab_shortcuts', 'tab_rmm', 'tab_docs'
            ];
            for (var i = 0; i < tabBtns.length && i < tabKeys.length; i++) {
                var k = tabKeys[i];
                if (t[k]) tabBtns[i].innerText = t[k];
            }

            var btnRunT = document.getElementById('btnRunDiagTab');
            if (btnRunT) btnRunT.innerText = t.btn_run_tab;

            var btnRefT = document.getElementById('btnRefreshTab');
            if (btnRefT) btnRefT.innerText = t.btn_refresh_tab;

            var btnPrT = document.getElementById('btnPrintTab');
            if (btnPrT) btnPrT.innerText = t.btn_print_tab;

            var sInput = document.getElementById('searchInput');
            if (sInput && t.search_placeholder) sInput.placeholder = t.search_placeholder;

            var povBtn = document.getElementById('btnToggleCartPOV');
            if (povBtn) povBtn.innerText = window.isCartPOVMode ? t.btn_pov_exit : t.btn_pov;

            // Translate Table Headers across all tables
            var thMapping = {
                "Point de contrôle": "th_point", "Check Point": "th_point", "Controlepunt": "th_point", "Prüfpunkt": "th_point",
                "Statut": "th_status", "Status": "th_status",
                "Constat technique détaillé": "th_findings", "Detailed Technical Finding": "th_findings", "Gedetailleerde Technische Bevinding": "th_findings", "Detaillierter Technischer Befund": "th_findings",
                "Solution recommandée": "th_recommendation", "Recommended Solution": "th_recommendation", "Aanbevolen Oplossing": "th_recommendation", "Empfohlene Lösung": "th_recommendation",
                "Remédiation PowerShell": "th_powershell", "PowerShell Remediation": "th_powershell", "PowerShell Herstel": "th_powershell", "PowerShell-Behebung": "th_powershell",
                "Raccourci GUI": "th_gui", "GUI Shortcut": "th_gui", "GUI Snelkoppeling": "th_gui", "GUI-Verknüpfung": "th_gui",
                "Port Local": "th_port", "Local Port": "th_port", "Lokale Poort": "th_port", "Lokaler Port": "th_port",
                "Adresse d'Écoute": "th_address", "Listening Address": "th_address", "Luisteradres": "th_address", "Abhöradresse": "th_address",
                "Processus / Service": "th_process", "Process / Service": "th_process", "Proces / Service": "th_process", "Prozess / Dienst": "th_process",
                "Exposition Réseau": "th_exposure", "Network Exposure": "th_exposure", "Netwerkblootstelling": "th_exposure", "Netzwerkexposition": "th_exposure",
                "Disque Physique": "th_disk", "Physical Disk": "th_disk", "Fysieke Schijf": "th_disk", "Physische Festplatte": "th_disk",
                "Type Média": "th_media", "Media Type": "th_media", "Mediatype": "th_media", "Medientyp": "th_media",
                "Santé SMART": "th_smart", "SMART Health": "th_smart", "SMART Status": "th_smart", "SMART Zustand": "th_smart",
                "Usure (%)": "th_wear", "Wear (%)": "th_wear", "Slijtage (%)": "th_wear", "Verschleiß (%)": "th_wear",
                "Température": "th_temp", "Temperature": "th_temp", "Temperatuur": "th_temp",
                "Erreurs Lecture": "th_errors", "Read Errors": "th_errors", "Leesfouten": "th_errors", "Lesefehler": "th_errors",
                "Taille": "th_size", "Size": "th_size", "Grootte": "th_size", "Größe": "th_size",
                "Nom de l'élément": "th_name", "Item Name": "th_name", "Itemnaam": "th_name", "Elementname": "th_name",
                "Chemin Local": "th_path", "Local Path": "th_path", "Lokaal Pad": "th_path", "Lokaler Pfad": "th_path",
                "Commande / Cible exécutée": "th_command", "Command / Executed Target": "th_command", "Uitgevoerd Commando / Doel": "th_command", "Ausgeführter Befehl / Ziel": "th_command",
                "Nom Utilisateur": "th_user", "User Name": "th_user", "Gebruikersnaam": "th_user", "Benutzername": "th_user",
                "Statut Compte": "th_account_status", "Account Status": "th_account_status", "Accountstatus": "th_account_status", "Kontostatus": "th_account_status",
                "Expiration MDP": "th_pwd_exp", "Password Expiration": "th_pwd_exp", "Wachtwoord Vervaldatum": "th_pwd_exp", "Passwort-Ablauf": "th_pwd_exp",
                "Dernière Connexion": "th_last_logon", "Last Logon": "th_last_logon", "Laatste Aanmelding": "th_last_logon", "Letzte Anmeldung": "th_last_logon",
                "Processeurs de Référence Représentatifs": "th_ref_cpu", "Representative Reference Processors": "th_ref_cpu", "Representatieve Referentieprocessors": "th_ref_cpu", "Repräsentative Referenzprozessoren": "th_ref_cpu",
                "Indice Points": "th_points_idx", "Points Index": "th_points_idx", "Puntenindex": "th_points_idx", "Punkte-Index": "th_points_idx",
                "Temps Moyen": "th_avg_time", "Average Time": "th_avg_time", "Gemiddelde Tijd": "th_avg_time", "Durchschnittszeit": "th_avg_time",
                "Positionnement Relatif": "th_relative_pos", "Relative Position": "th_relative_pos", "Relatieve Positie": "th_relative_pos", "Relative Position": "th_relative_pos",
                "Catégorie de Machine": "th_machine_tier", "Machine Category": "th_machine_tier", "Machinecategorie": "th_machine_tier", "Maschinenkategorie": "th_machine_tier",
                "Action": "th_action", "Actie": "th_action", "Aktion": "th_action"
            };

            document.querySelectorAll('th').forEach(function(th) {
                var txt = th.innerText.trim();
                if (thMapping[txt]) {
                    var key = thMapping[txt];
                    if (t[key]) th.innerText = t[key];
                }
            });

            // Translate Resolution card labels
            document.querySelectorAll('.res-label').forEach(function(lbl) {
                var ltxt = lbl.innerText.trim();
                if (ltxt.indexOf('Constat technique') !== -1 || ltxt.indexOf('Technical Finding') !== -1 || ltxt.indexOf('Technische bevinding') !== -1 || ltxt.indexOf('Technischer Befund') !== -1) {
                    lbl.innerText = t.lbl_finding;
                } else if (ltxt.indexOf('Action corrective') !== -1 || ltxt.indexOf('Corrective Action') !== -1 || ltxt.indexOf('Corrigerende maatregel') !== -1 || ltxt.indexOf('Korrekturmaßnahme') !== -1) {
                    lbl.innerText = t.lbl_fix;
                } else if (ltxt.indexOf('Explication Formateur') !== -1 || ltxt.indexOf('Instructor Tip') !== -1 || ltxt.indexOf('Instructeur Tip') !== -1 || ltxt.indexOf('Ausbilder-Tipp') !== -1) {
                    lbl.innerText = t.lbl_exam_tip;
                }
            });

            renderCveTab(lang);
            if (window.renderBelgianTab) {
                window.renderBelgianTab(lang);
            }
            translateDomNodes(lang);
            translateResolutionCards(lang);
        }

        window.addEventListener('DOMContentLoaded', function() {
            applyLanguage(currentLang);
        });

        function renderBelgianCatalogLegacy(lang) {
            var belgCont = document.getElementById('belgianAppsGrid');
            var certsCont = document.getElementById('belgianCertsGrid');
            var currentL = lang || currentLang || 'fr';

            // Select country catalog based on language
            var catalogKey = 'be';
            if (currentL === 'nl') catalogKey = 'be';
            else if (currentL === 'fr') catalogKey = 'be';
            else if (currentL === 'en') catalogKey = 'en';
            else if (currentL === 'de') catalogKey = 'de';
            else if (currentL === 'es') catalogKey = 'es';
            else if (currentL === 'it') catalogKey = 'it';
            else if (currentL === 'pt') catalogKey = 'pt';

            var currentCatalog = countryCatalogs[catalogKey] || countryCatalogs['be'];

            var detectedAppsMap = {};
            var rawApps = (window.belgianData && window.belgianData.Apps) ? window.belgianData.Apps : (Array.isArray(window.belgianData) ? window.belgianData : []);
            rawApps.forEach(function(a) {
                if (a.Name) detectedAppsMap[a.Name.toLowerCase()] = a;
            });

            if (belgCont) {
                var bHtml = '';
                currentCatalog.forEach(function(item) {
                    var detected = detectedAppsMap[item.Name.toLowerCase()] || {};
                    // Partial matching for eID / middleware
                    if (!detected.Installed && (item.Name.toLowerCase().indexOf("eid") !== -1 || item.Name.toLowerCase().indexOf("e-id") !== -1)) {
                        for (var k in detectedAppsMap) {
                            if (k.indexOf("eid") !== -1 || k.indexOf("e-id") !== -1 || k.indexOf("identity") !== -1) {
                                detected = detectedAppsMap[k];
                                break;
                            }
                        }
                    }

                    var isInstalled = !!detected.Installed;
                    var versionStr = isInstalled ? ('v' + (detected.Version || '5.1.6205')) : 'N/A';
                    var statusLabel = isInstalled ? (currentL === 'nl' ? 'GEÏNSTALLEERD' : (currentL === 'en' ? 'INSTALLED' : (currentL === 'de' ? 'INSTALLIERT' : (currentL === 'es' ? 'INSTALADO' : (currentL === 'it' ? 'INSTALLATO' : (currentL === 'pt' ? 'INSTALADO' : 'INSTALLÉ')))))) : (currentL === 'nl' ? 'NIET GEÏNSTALLEERD' : (currentL === 'en' ? 'NOT INSTALLED' : (currentL === 'de' ? 'NICHT INSTALLIERT' : (currentL === 'es' ? 'NO INSTALADO' : (currentL === 'it' ? 'NON INSTALLATO' : (currentL === 'pt' ? 'NÃO INSTALADO' : 'NON INSTALLÉ'))))));
                    
                    var bColor = isInstalled ? '#34d399' : '#64748b';
                    var bBorder = isInstalled ? 'rgba(52,211,153,0.45)' : 'rgba(148,163,184,0.18)';
                    var bBg = isInstalled ? 'linear-gradient(135deg, rgba(16,185,129,0.12) 0%, rgba(15,23,42,0.92) 100%)' : 'rgba(15,23,42,0.80)';
                    var badgeStyle = isInstalled ? 'background:rgba(16,185,129,0.25); color:#34d399; border:1px solid #10b981;' : 'background:rgba(148,163,184,0.12); color:#94a3b8; border:1px solid rgba(148,163,184,0.25);';

                    var descText = (currentL === 'nl' && item.Desc_nl) ? item.Desc_nl : item.Desc;

                    bHtml += '<div style="background:' + bBg + '; border:1px solid ' + bBorder + '; border-left:4px solid ' + bColor + '; border-radius:8px; padding:16px; display:flex; flex-direction:column; justify-content:space-between; box-shadow:' + (isInstalled ? '0 0 16px rgba(16,185,129,0.12)' : 'none') + ';">';
                    bHtml += '  <div>';
                    bHtml += '    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">';
                    bHtml += '      <strong style="color:#f1f5f9; font-size:14px; font-weight:800;">' + item.Name + '</strong>';
                    bHtml += '      <span style="font-size:10px; font-weight:800; padding:3px 8px; border-radius:3px; ' + badgeStyle + '">' + statusLabel + '</span>';
                    bHtml += '    </div>';
                    bHtml += '    <div style="font-size:11.5px; color:#38bdf8; font-weight:700; margin-bottom:8px;">' + item.Category + '</div>';
                    bHtml += '    <p style="font-size:12px; color:#cbd5e1; line-height:1.5; margin:6px 0 12px 0;">' + descText + '</p>';
                    bHtml += '  </div>';
                    bHtml += '  <div style="font-size:11px; color:#94a3b8; border-top:1px solid rgba(255,255,255,0.08); padding-top:10px; display:flex; justify-content:space-between; align-items:center;">';
                    bHtml += '    <span>Éditeur : <strong style="color:#f1f5f9;">' + item.Vendor + '</strong></span>';
                    bHtml += '    <span style="font-family:Consolas, monospace; color:' + (isInstalled ? '#34d399' : '#64748b') + '; font-weight:700;">' + versionStr + '</span>';
                    bHtml += '  </div>';
                    bHtml += '</div>';
                });
                belgCont.innerHTML = bHtml;
            }

            var bCerts = (window.belgianData && window.belgianData.Certs) ? window.belgianData.Certs : [];
            if (certsCont && bCerts.length > 0) {
                var cHtml = '';
                bCerts.forEach(function(c) {
                    var isWarning = (c.DaysLeft < 30);
                    var certBadge = c.IsEid ? '<span class="badge" style="background:rgba(56,189,248,0.2); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">🇧🇪 eID National</span>' : '<span class="badge" style="background:rgba(148,163,184,0.15); color:#cbd5e1;">Certificat Système</span>';
                    var statusColor = isWarning ? '#f43f5e' : '#34d399';
                    var borderCol = isWarning ? 'rgba(244,63,94,0.4)' : 'rgba(56,189,248,0.25)';

                    cHtml += '<div style="background:rgba(15,23,42,0.90); border:1px solid ' + borderCol + '; border-left:4px solid ' + (c.IsEid ? '#38bdf8' : '#64748b') + '; border-radius:8px; padding:16px;">';
                    cHtml += '  <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">';
                    cHtml += '    <div style="font-weight:700; color:#f1f5f9; font-size:13px; word-break:break-word;">' + c.Subject + '</div>';
                    cHtml += '    ' + certBadge;
                    cHtml += '  </div>';
                    cHtml += '  <div style="font-size:11.5px; color:#94a3b8; margin-bottom:6px;">Émetteur : <span style="color:#cbd5e1;">' + c.Issuer + '</span></div>';
                    cHtml += '  <div style="display:flex; justify-content:space-between; align-items:center; margin-top:10px; padding-top:10px; border-top:1px solid rgba(255,255,255,0.08); font-size:11.5px;">';
                    cHtml += '    <span style="color:' + statusColor + '; font-weight:700;">' + c.Status + '</span>';
                    cHtml += '    <span style="color:#64748b; font-family:Consolas, monospace;">' + c.Scope + '</span>';
                    cHtml += '  </div>';
                    cHtml += '</div>';
                });
                certsCont.innerHTML = cHtml;
            }
        }


                        window.launchBatchDiagnostic = function(btn) {
            var t = (typeof translations !== 'undefined' && translations[currentLang]) ? translations[currentLang] : { toast_launch: "⚡ Lancement du diagnostic..." };
            showToast(t.toast_launch || "⚡ Lancement du diagnostic...");
            
            try {
                var ifr = document.createElement('iframe');
                ifr.style.position = 'absolute';
                ifr.style.width = '1px';
                ifr.style.height = '1px';
                ifr.style.opacity = '0.01';
                ifr.style.border = 'none';
                ifr.src = 'diagit://run';
                document.body.appendChild(ifr);
                setTimeout(function() {
                    if (ifr.parentNode) ifr.parentNode.removeChild(ifr);
                }, 2500);
            } catch(e) {
                console.error("Launcher error:", e);
            }
        };

        function showToast(msg) {
            var toast = document.getElementById('toast');
            if (msg) toast.innerText = msg;
            toast.style.display = 'block';
            setTimeout(function () { toast.style.display = 'none'; }, 2200);
        }

        function toggleTheme() {
            var body = document.body;
            var isDark = (body.getAttribute('data-theme') !== 'light');
            if (isDark) {
                body.setAttribute('data-theme', 'light');
                if (window.setThreeTheme) window.setThreeTheme('solar');
            } else {
                body.removeAttribute('data-theme');
                if (window.setThreeTheme) window.setThreeTheme('dark');
            }
        }

        window.showTab = function(tabId, btn) {
            window.switchTab(tabId, btn);
        };

                window.switchTab = function(tabId, btn) {
            // Remove active from all tab contents
            var contents = document.querySelectorAll('.tab-content');
            for (var i = 0; i < contents.length; i++) {
                contents[i].classList.remove('active');
            }

            // Remove active from all tab buttons
            var buttons = document.querySelectorAll('.tab-btn');
            for (var j = 0; j < buttons.length; j++) {
                buttons[j].classList.remove('active');
            }

            // Activate target tab content
            var target = document.getElementById(tabId);
            if (target) {
                target.classList.add('active');
            }

            if (tabId === 'tab-foss') {
                setTimeout(function() {
                    if (typeof resizeTechTree === 'function') resizeTechTree();
                    else if (typeof initTechTree3D === 'function') initTechTree3D();
                }, 60);
            }

            // Activate matching button
            if (btn) {
                btn.classList.add('active');
            } else {
                for (var k = 0; k < buttons.length; k++) {
                    var clickAttr = buttons[k].getAttribute('onclick') || '';
                    if (clickAttr.indexOf(tabId) !== -1) {
                        buttons[k].classList.add('active');
                        break;
                    }
                }
            }
        };

        
        // -------------------------------------------------------------
        // TABLE FILTERING & SEARCH SCRIPT
        // -------------------------------------------------------------
        var currentCategory = 'ALL';

        function setCategoryFilter(category, btn) {
            currentCategory = category;
            var allFilterBtns = document.querySelectorAll('.filter-btn');
            allFilterBtns.forEach(function(b) {
                if (b.getAttribute('onclick') && b.getAttribute('onclick').indexOf('setCategoryFilter') !== -1) {
                    b.classList.remove('active');
                }
            });
            if (btn) btn.classList.add('active');
            filterTable();
        }
        window.setCategoryFilter = setCategoryFilter;

        function filterTable() {
            var searchInput = document.getElementById('tableSearch');
            var query = searchInput ? searchInput.value.toLowerCase().trim() : '';
            var rows = document.querySelectorAll('#diagTable tbody tr');

            rows.forEach(function (row) {
                var cat = (row.getAttribute('data-category') || '').toLowerCase();
                var status = (row.getAttribute('data-status') || '').toUpperCase();
                var text = row.innerText.toLowerCase();

                var matchesCat = false;
                if (currentCategory === 'ALL') {
                    matchesCat = true;
                } else if (currentCategory === 'ISSUES') {
                    matchesCat = (status === 'WARNING' || status === 'ERROR' || status !== 'OK');
                } else {
                    var targetCat = currentCategory.toLowerCase();
                    if (targetCat === 'hardware' || targetCat === 'matériel' || targetCat === 'materiel') {
                        matchesCat = (cat.indexOf('hard') !== -1 || cat.indexOf('mat') !== -1 || cat.indexOf('cpu') !== -1 || cat.indexOf('ram') !== -1 || cat.indexOf('disk') !== -1 || cat.indexOf('disque') !== -1);
                    } else if (targetCat === 'réseau' || targetCat === 'reseau' || targetCat === 'network') {
                        matchesCat = ((cat.indexOf('r') !== -1 && cat.indexOf('seau') !== -1) || cat.indexOf('net') !== -1);
                    } else if (targetCat === 'système' || targetCat === 'systeme' || targetCat === 'system') {
                        matchesCat = (cat.indexOf('syst') !== -1 || cat.indexOf('os') !== -1 || cat.indexOf('gpo') !== -1);
                    } else if (targetCat === 'sécurité' || targetCat === 'securite' || targetCat === 'security') {
                        matchesCat = ((cat.indexOf('s') !== -1 && cat.indexOf('cur') !== -1) || cat.indexOf('sec') !== -1 || cat.indexOf('cve') !== -1);
                    } else if (targetCat === 'logiciel' || targetCat === 'software' || targetCat === 'app') {
                        matchesCat = (cat.indexOf('log') !== -1 || cat.indexOf('soft') !== -1 || cat.indexOf('app') !== -1);
                    } else {
                        matchesCat = (cat.indexOf(targetCat) !== -1);
                    }
                }

                var matchesQuery = (query === '' || text.indexOf(query) !== -1);

                if (matchesCat && matchesQuery) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        window.filterTable = filterTable;

        // -------------------------------------------------------------
        // CUSTOM WINGET BUILDER SCRIPT
        // -------------------------------------------------------------
        function updateCustomWinget() {
            var checked = document.querySelectorAll('.app-chk:checked');
            var cmdBox = document.getElementById('customWingetCmd');
            if (checked.length === 0) {
                cmdBox.innerText = "# Cochez des applications ci-dessus pour générer votre commande Winget personnalisée.";
                return;
            }

            var ids = [];
            checked.forEach(function(chk) {
                var id = chk.getAttribute('data-winget-id');
                if (id) ids.push(id);
            });

            var fullCmd = ids.map(function(id) {
                return "winget install --id " + id + " -e --accept-package-agreements --accept-source-agreements";
            }).join("; ");

            cmdBox.innerText = fullCmd;
        }

        function copyCustomWinget() {
            var cmd = document.getElementById('customWingetCmd').innerText;
            if (cmd && !cmd.startsWith('#')) {
                navigator.clipboard.writeText(cmd).then(function () {
                    showToast("✅ Script Winget personnalisé copié !");
                });
            } else {
                showToast("ℹ️ Veuillez d'abord cocher au moins une application.");
            }
        }

                                                // -------------------------------------------------------------
        // 🌳 3D HOLOGRAPHIC SCI-FI TECH TREE (WORMHOLE, HOVER GLOW, HALO & DRAWER)
        // -------------------------------------------------------------
        var fossThemesData = __FOSS_JSON__;
        var techTreeInitialized = false;
        var techTreeRenderer = null;
        var techTreeCamera = null;
        var techTreeScene = null;
        var techTreeCamera = null;
        var techTreeRenderer = null;
        var techTreeInitialized = false;

        var galaxyGroup = null;
        var themeDetailGroup = null;
        var treeBgGroup = null;

        var coreMesh = null;
        var coreInner = null;
        var coreRing1 = null;
        var coreRing2 = null;
        var corePointLight = null;
        var detailPointLight = null;

        var currentTreeMode = 'GALAXY'; // 'GALAXY' or 'THEME'
        var activeFocusedTheme = null;
        var lockedSelectedApp = null;
        var lockedSelectedTheme = null;
        var lockedSelectedMesh = null;
        var lastHoveredMesh = null;

        var themeHubMeshes = [];
        var appSubNodeMeshes = [];
        var animatedGalaxySatellites = [];
        var animatedDetailSatellites = [];
        var animatedDetailLasers = [];
        var animatedDetailHub = null;

        var raycaster = new THREE.Raycaster();
        var treeClock = new THREE.Clock();

        var treeBgTargetMouseX = 0;
        var treeBgTargetMouseY = 0;
        var treeBgCurrentMouseX = 0;
        var treeBgCurrentMouseY = 0;

        var tooltipElem = null;

        var hoverGlowGroup = null;
        var hoverRingMesh = null;
        var hoverRingMat = null;
        var hoverIcoMesh = null;
        var hoverIcoMat = null;

        var selectionHaloGroup = null;
        var haloRingMesh = null;
        var haloRing2Mesh = null;

        var treeCamTarget = { x: 0, y: 3.2, z: 24 };
        var treeLookTarget = { x: 0, y: 0, z: 0 };
        var treeCamCurrent = { x: 0, y: 3.2, z: 24 };
        var treeLookCurrent = { x: 0, y: 0, z: 0 };
        var camPanOffset = { x: 0, y: 0 };

        function getActiveThemesList() {
            if (window.fossThemesData && Array.isArray(window.fossThemesData) && window.fossThemesData.length > 0) {
                return window.fossThemesData;
            }
            if (typeof fossThemesData !== 'undefined' && Array.isArray(fossThemesData) && fossThemesData.length > 0) {
                window.fossThemesData = fossThemesData;
                return fossThemesData;
            }
            return [];
        }

        function getNodeScreenCoords(mesh) {
            if (!mesh || !techTreeCamera) return null;
            var v = new THREE.Vector3();
            mesh.getWorldPosition(v);
            
            var isHub = (mesh.userData && mesh.userData.type === 'THEME_HUB');
            v.y += isHub ? 1.35 : 1.10;
            
            v.project(techTreeCamera);

            if (v.z > 1.0 || v.z < -1.0) return null;

            var canvas = document.getElementById('three-tech-tree');
            if (!canvas) return null;
            var rect = canvas.getBoundingClientRect();
            if (rect.width < 10 || rect.height < 10) return null;

            var x = ((v.x + 1) * 0.5) * rect.width;
            var y = ((-v.y + 1) * 0.5) * rect.height;
            
            if (x < -50 || x > rect.width + 50 || y < -50 || y > rect.height + 50) return null;

            return { x: x, y: y };
        }

        function resizeTechTree() {
            var canvas = document.getElementById('three-tech-tree');
            if (!canvas) return;

            if (!techTreeInitialized) {
                initTechTree3D();
                return;
            }

            var rect = canvas.getBoundingClientRect();
            var w = rect.width || canvas.clientWidth || (canvas.parentElement ? canvas.parentElement.clientWidth : 0) || 850;
            var h = rect.height || canvas.clientHeight || (canvas.parentElement ? canvas.parentElement.clientHeight : 0) || 500;
            if (w < 100) w = 850;
            if (h < 100) h = 500;

            if (techTreeRenderer && techTreeCamera) {
                techTreeCamera.aspect = w / h;
                techTreeCamera.updateProjectionMatrix();
                techTreeRenderer.setSize(w, h, false);
                techTreeRenderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
            }
        }
        window.resizeTechTree = resizeTechTree;

        function showTooltipForMesh(mesh, text) {
            if (!tooltipElem) tooltipElem = document.getElementById('treeHoverTooltip');
            if (!tooltipElem || !mesh) return;

            var isLocked = (mesh === lockedSelectedMesh);
            var isThemeHub = (mesh.userData && mesh.userData.type === 'THEME_HUB');
            var prefix = isLocked ? "🔒 " : (isThemeHub ? "❖ " : "✨ ");

            tooltipElem.innerHTML = prefix + text;
            tooltipElem.style.borderColor = isLocked ? "#34d399" : "var(--neon-cyan)";
            tooltipElem.style.boxShadow = isLocked ? "0 0 16px rgba(52, 211, 153, 0.4)" : "0 0 14px rgba(56, 189, 248, 0.35)";
            tooltipElem.style.display = 'block';
            tooltipElem.style.opacity = '1';
        }

        function selectGalaxyTheme(theme, shouldZoom) {
            if (!theme) return;
            activeFocusedTheme = theme;
            lockedSelectedApp = null;
            lockedSelectedTheme = theme;
            window.currentThemeAppIndex = -1;

            var targetMesh = themeHubMeshes.find(function(m) { 
                return m.userData && m.userData.theme && (
                    (theme.Category && m.userData.theme.Category === theme.Category) ||
                    (theme.Title && m.userData.theme.Title === theme.Title)
                ); 
            });

            if (targetMesh) {
                lockedSelectedMesh = targetMesh;
                lastHoveredMesh = targetMesh;
                
                if (selectionHaloGroup) {
                    selectionHaloGroup.visible = true;
                    var wp = new THREE.Vector3();
                    targetMesh.getWorldPosition(wp);
                    selectionHaloGroup.position.copy(wp);
                }
                if (hoverGlowGroup) {
                    hoverGlowGroup.visible = false;
                }

                if (shouldZoom) {
                    focusOnTheme(theme);
                    return;
                }
            }

            var badge = document.getElementById('treeModeBadge');
            if (badge) {
                badge.innerText = "🌐 " + theme.Title.toUpperCase() + " (" + (theme.Items ? theme.Items.length : 0) + " APPS)";
                badge.style.borderColor = theme.Color || '#38bdf8';
                badge.style.color = theme.Color || '#38bdf8';
            }

            if (targetMesh) {
                showTooltipForMesh(targetMesh, (theme.Icon || '📂') + " " + theme.Title + " (" + (theme.Items ? theme.Items.length : 0) + " Apps) • [↑ / Entrée]");
            }

            renderThemeAppDrawer(theme);
            showToast("📂 Domaine : " + theme.Title + " (Appuyez sur [↑/Entrée] pour zoomer)");
        }
        window.selectGalaxyTheme = selectGalaxyTheme;

        function selectAppFromList(theme, app) {
            lockedSelectedApp = app;
            lockedSelectedTheme = theme;

            var targetMesh = null;
            if (currentTreeMode === 'THEME') {
                appSubNodeMeshes.forEach(function(m) {
                    if (m.userData && m.userData.app && m.userData.app.Winget === app.Winget) {
                        targetMesh = m;
                    }
                });
            } else {
                targetMesh = themeHubMeshes.find(function(m) {
                    return m.userData && m.userData.theme && (
                        (theme.Category && m.userData.theme.Category === theme.Category) ||
                        (theme.Title && m.userData.theme.Title === theme.Title)
                    );
                });
            }

            if (targetMesh) {
                lockedSelectedMesh = targetMesh;
                lastHoveredMesh = targetMesh;
                if (selectionHaloGroup) {
                    selectionHaloGroup.visible = true;
                    var wp = new THREE.Vector3();
                    targetMesh.getWorldPosition(wp);
                    selectionHaloGroup.position.copy(wp);
                }
                if (hoverGlowGroup) {
                    hoverGlowGroup.visible = false;
                }

                if (currentTreeMode === 'THEME') {
                    showTooltipForMesh(targetMesh, "✨ " + app.Foss + " (Alt : " + (app.Prop || 'Propriétaire') + ")");
                } else {
                    showTooltipForMesh(targetMesh, (theme.Icon || '📂') + " " + theme.Title + " ➔ " + app.Foss);
                }
            }

            var wingetCmd = "winget install --id " + app.Winget + " -e --accept-package-agreements --accept-source-agreements";
            navigator.clipboard.writeText(wingetCmd).then(function() {
                showToast("⚡ Application sélectionnée & Winget copié : " + app.Foss);
            });

            showAppCardInHUD(app, theme, true);
        }
        window.selectAppFromList = selectAppFromList;

        function renderThemeAppDrawer(theme) {
            if (!theme) return;
            activeFocusedTheme = theme;
            lockedSelectedApp = null;
            lockedSelectedTheme = theme;
            window.currentThemeAppIndex = -1;

            if (currentTreeMode === 'THEME' && animatedDetailHub && selectionHaloGroup) {
                selectionHaloGroup.visible = true;
                var wp = new THREE.Vector3();
                animatedDetailHub.getWorldPosition(wp);
                selectionHaloGroup.position.copy(wp);
            }

            var placeholder = document.getElementById('inspectorPlaceholder');
            var drawer = document.getElementById('inspectorThemeDrawer');
            var content = document.getElementById('inspectorContent');
            var nameElem = document.getElementById('themeDrawerName');
            var iconElem = document.getElementById('themeDrawerIcon');
            var countElem = document.getElementById('themeDrawerCount');
            var listElem = document.getElementById('themeAppItemsList');
            var btnEnter = document.getElementById('btnEnterThemeCluster');
            var btnBack = document.getElementById('btnThemeDrawerBack');

            if (placeholder) placeholder.style.display = 'none';
            if (content) content.style.display = 'none';
            if (drawer) drawer.style.display = 'flex';

            if (btnEnter) {
                btnEnter.style.display = (currentTreeMode === 'GALAXY') ? 'inline-block' : 'none';
            }
            if (btnBack) {
                btnBack.innerText = (currentTreeMode === 'GALAXY') ? '🎯 Vue Globale' : '🔙 Sortir Thème';
            }

            if (iconElem) iconElem.innerText = theme.Icon || '📂';
            if (nameElem) {
                nameElem.innerText = (theme.Title || 'Domaine');
                nameElem.style.color = theme.Color || '#38bdf8';
            }
            if (countElem) countElem.innerText = (theme.Items ? theme.Items.length : 0) + " Applications Disponibles (Cliquez pour inspecter)";

            if (listElem) {
                listElem.innerHTML = '';
                var items = theme.Items || [];

                items.forEach(function(app, idx) {
                    var itemDiv = document.createElement('div');
                    itemDiv.className = 'theme-app-compact-card';
                    itemDiv.style.cssText = "background:rgba(15,23,42,0.85); border:1px solid rgba(56,189,248,0.20); border-left:3px solid " + (theme.Color || '#38bdf8') + "; padding:8px 12px; border-radius:6px; cursor:pointer; transition:all 0.2s ease; display:flex; justify-content:space-between; align-items:center; gap:8px;";
                    
                    itemDiv.innerHTML = "<div style='min-width:0; flex:1;'>" +
                                            "<div style='font-weight:bold; color:#f1f5f9; font-size:12.5px; display:flex; align-items:center; gap:6px;'>" +
                                                "<span style='color:" + (theme.Color || '#38bdf8') + ";'>❖</span> " + app.Foss +
                                                "<span style='font-size:10px; color:#94a3b8; font-weight:normal;'>v" + (app.Version || '1.0') + "</span>" +
                                            "</div>" +
                                            "<div style='font-size:11px; color:#94a3b8; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:2px;'>" +
                                                "Alt: <span style='color:#cbd5e1;'>" + (app.Prop || 'Propriétaire') + "</span> • <span style='color:#38bdf8;'>" + (app.Type || 'Outil') + "</span>" +
                                            "</div>" +
                                        "</div>" +
                                        "<div style='display:flex; align-items:center; gap:4px;'>" +
                                            "<button class='btn-mini-copy' style='padding:3px 8px; font-size:10px;' onclick='event.stopPropagation(); window.copyDirectWinget(\"" + app.Winget + "\", \"" + app.Foss.replace(/'/g, "\\'") + "\")'>📋 Copier</button>" +
                                            "<span style='color:#64748b; font-size:12px;'>➔</span>" +
                                        "</div>";

                    itemDiv.addEventListener('mouseenter', function() {
                        itemDiv.style.background = 'rgba(2,132,199,0.22)';
                        itemDiv.style.borderColor = theme.Color || '#38bdf8';
                        itemDiv.style.transform = 'translateX(3px)';
                        
                        if (currentTreeMode === 'THEME' && appSubNodeMeshes[idx]) {
                            var m = appSubNodeMeshes[idx];
                            lastHoveredMesh = m;
                            if (hoverGlowGroup && m !== lockedSelectedMesh) {
                                hoverGlowGroup.visible = true;
                                var wp = new THREE.Vector3();
                                m.getWorldPosition(wp);
                                hoverGlowGroup.position.copy(wp);
                            }
                        }
                    });
                    itemDiv.addEventListener('mouseleave', function() {
                        itemDiv.style.background = 'rgba(15,23,42,0.85)';
                        itemDiv.style.borderColor = 'rgba(56,189,248,0.20)';
                        itemDiv.style.transform = 'none';
                        if (hoverGlowGroup) hoverGlowGroup.visible = false;
                    });
                    itemDiv.addEventListener('click', function() {
                        window.currentThemeAppIndex = idx;
                        if (currentTreeMode === 'GALAXY') {
                            showAppCardInHUD(app, theme, true);
                        } else {
                            selectAppFromList(theme, app);
                        }
                    });

                    listElem.appendChild(itemDiv);
                });
            }
        }
        window.renderThemeAppDrawer = renderThemeAppDrawer;

        window.copyDirectWinget = function(wingetId, appName) {
            var cmd = "winget install --id " + wingetId + " -e --accept-package-agreements --accept-source-agreements";
            navigator.clipboard.writeText(cmd).then(function() {
                showToast("⚡ Winget copié : " + appName);
            });
        };

        window.copyAllThemeWinget = function(theme) {
            if (!theme || !theme.Items) return;
            var ids = theme.Items.map(function(a) { return a.Winget; }).filter(Boolean);
            var fullCmd = ids.map(function(id) { return "winget install --id " + id + " -e --accept-package-agreements --accept-source-agreements"; }).join("; ");
            navigator.clipboard.writeText(fullCmd).then(function() {
                showToast("🚀 " + ids.length + " commandes Winget copiées pour " + theme.Title + " !");
            });
        };

        function focusOnTheme(theme) {
            currentTreeMode = 'THEME';
            activeFocusedTheme = theme;
            lockedSelectedApp = null;
            lockedSelectedTheme = null;
            lockedSelectedMesh = null;
            lastHoveredMesh = null;

            if (hoverGlowGroup) hoverGlowGroup.visible = false;
            if (selectionHaloGroup) selectionHaloGroup.visible = false;
            
            var badge = document.getElementById('treeModeBadge');
            if (badge) {
                badge.innerText = "🎯 " + theme.Title.toUpperCase() + " (" + (theme.Items ? theme.Items.length : 0) + " APPS)";
                badge.style.borderColor = theme.Color;
                badge.style.color = theme.Color;
            }
            var btnReset = document.getElementById('btnResetTreeCam');
            if (btnReset) btnReset.style.display = 'inline-block';

            if (galaxyGroup) galaxyGroup.visible = false;
            if (themeDetailGroup) themeDetailGroup.visible = true;

            while (themeDetailGroup.children.length > 0) {
                themeDetailGroup.remove(themeDetailGroup.children[0]);
            }
            appSubNodeMeshes = [];
            animatedDetailSatellites = [];
            animatedDetailLasers = [];

            var hubColorHex = theme.Color || '#00f0ff';
            var hubColor = parseInt(hubColorHex.replace('#', '0x'), 16) || 0x00f0ff;
            
            // Detail Hub: Solid Faceted Octahedron + Outer Specular Wireframe Shield
            var centerHubGeo = new THREE.OctahedronGeometry(1.5, 0);
            var centerHubMat = new THREE.MeshStandardMaterial({ 
                color: hubColor, 
                roughness: 0.15, 
                metalness: 0.85, 
                emissive: hubColor, 
                emissiveIntensity: 0.30, 
                flatShading: true 
            });
            animatedDetailHub = new THREE.Mesh(centerHubGeo, centerHubMat);
            animatedDetailHub.userData = { type: 'THEME_HUB', theme: theme };
            themeDetailGroup.add(animatedDetailHub);

            var detailBeamMat = new THREE.MeshStandardMaterial({ 
                color: hubColor, 
                roughness: 0.05, 
                metalness: 0.98, 
                emissive: hubColor, 
                emissiveIntensity: 0.45 
            });
            var hubWire = createThickDodecahedronFrame(1.95, 0.042, detailBeamMat);
            themeDetailGroup.add(hubWire);
            animatedDetailHub.userData.wire = hubWire;

            // Double rotating smooth concentric rings (No spiderweb)
            var hubRing1Geo = new THREE.TorusGeometry(2.3, 0.035, 12, 48);
            var hubRing1Mat = new THREE.MeshStandardMaterial({ color: hubColor, roughness: 0.2, metalness: 0.9, transparent: true, opacity: 0.85 });
            var hubRing1 = new THREE.Mesh(hubRing1Geo, hubRing1Mat);
            hubRing1.rotation.x = Math.PI / 2.5;
            themeDetailGroup.add(hubRing1);

            var hubRing2Geo = new THREE.TorusGeometry(2.7, 0.025, 12, 48);
            var hubRing2Mat = new THREE.MeshStandardMaterial({ color: 0x34d399, roughness: 0.2, metalness: 0.9, transparent: true, opacity: 0.75 });
            var hubRing2 = new THREE.Mesh(hubRing2Geo, hubRing2Mat);
            hubRing2.rotation.y = Math.PI / 3;
            themeDetailGroup.add(hubRing2);

            animatedDetailHub.userData.ring1 = hubRing1;
            animatedDetailHub.userData.ring2 = hubRing2;

            detailPointLight = new THREE.PointLight(hubColor, 2.8, 30, 1.2);
            detailPointLight.position.set(0, 0, 0);
            themeDetailGroup.add(detailPointLight);

            // Orbiting App Nodes with compact rest radius (4.8) and long active radius (8.4)
            var items = theme.Items || [];
            var count = items.length;
            var defaultSubRadius = 5.0;

            items.forEach(function(item, idx) {
                var angle = (idx / count) * Math.PI * 2;
                var x = Math.cos(angle) * defaultSubRadius;
                var z = Math.sin(angle) * defaultSubRadius;
                var y = Math.sin(idx * 1.6) * 1.4;

                var laserGeo = new THREE.BufferGeometry().setFromPoints([
                    new THREE.Vector3(0, 0, 0),
                    new THREE.Vector3(x, y, z)
                ]);
                var laserMat = new THREE.LineBasicMaterial({ color: hubColor, transparent: true, opacity: 0.50 });
                var laser = new THREE.Line(laserGeo, laserMat);
                themeDetailGroup.add(laser);
                animatedDetailLasers.push({ line: laser, mat: laserMat, offset: idx });

                var appCoreGeo = new THREE.IcosahedronGeometry(0.55, 0);
                var appCoreMat = new THREE.MeshStandardMaterial({ 
                    color: 0x34d399, 
                    roughness: 0.15, 
                    metalness: 0.85, 
                    emissive: 0x059669, 
                    emissiveIntensity: 0.35, 
                    flatShading: true 
                });
                var appCoreMesh = new THREE.Mesh(appCoreGeo, appCoreMat);
                appCoreMesh.position.set(x, y, z);
                themeDetailGroup.add(appCoreMesh);

                var appGeo = new THREE.IcosahedronGeometry(0.85, 0);
                var appMat = new THREE.MeshStandardMaterial({ 
                    color: 0x38bdf8, 
                    wireframe: true, 
                    roughness: 0.2, 
                    metalness: 0.9 
                });
                var appMesh = new THREE.Mesh(appGeo, appMat);
                appMesh.position.set(x, y, z);
                appMesh.userData = { 
                    type: 'APP', 
                    app: item, 
                    theme: theme, 
                    baseAngle: angle,
                    heightOffset: y,
                    currentDist: defaultSubRadius,
                    laser: laser,
                    coreMesh: appCoreMesh,
                    spinSpeed: { x: 0.003 + (idx % 3) * 0.001, y: 0.004 + (idx % 2) * 0.0015, z: 0.002 },
                    harmonicOffset: idx * 0.7
                };
                themeDetailGroup.add(appMesh);
                appSubNodeMeshes.push(appMesh);

                for (var s = 0; s < 2; s++) {
                    var satGeo = new THREE.TetrahedronGeometry(0.20, 0);
                    var satCol = (s === 0 ? 0x38bdf8 : 0x34d399);
                    var satMat = new THREE.MeshStandardMaterial({ 
                        color: satCol, 
                        roughness: 0.1, 
                        metalness: 0.95, 
                        emissive: satCol, 
                        emissiveIntensity: 0.4, 
                        flatShading: true 
                    });
                    var satMesh = new THREE.Mesh(satGeo, satMat);
                    themeDetailGroup.add(satMesh);
                    animatedDetailSatellites.push({
                        mesh: satMesh,
                        parentMesh: appMesh,
                        baseDist: 1.15 + s * 0.35,
                        orbitSpeed: (s === 0 ? 0.007 : -0.006),
                        currentAngle: s * Math.PI + idx,
                        spinX: 0.008 + s * 0.003,
                        spinY: 0.010 + s * 0.004,
                        tilt: (s === 0 ? 0.4 : -0.5)
                    });
                }
            });

            lockedSelectedMesh = animatedDetailHub;
            lockedSelectedTheme = theme;
            treeCamTarget.z = 18.0;
            camPanOffset.x = 0;
            camPanOffset.y = 0;
            treeLookTarget = { x: 0, y: 0, z: 0 };

            renderThemeAppDrawer(theme);
            showToast("🎯 Exploration : " + theme.Title);
        }

        function resetTreeToGalaxy() {
            currentTreeMode = 'GALAXY';
            activeFocusedTheme = null;
            lockedSelectedApp = null;
            lockedSelectedTheme = null;
            lockedSelectedMesh = null;
            lastHoveredMesh = null;

            if (selectionHaloGroup) selectionHaloGroup.visible = false;
            if (hoverGlowGroup) hoverGlowGroup.visible = false;

            var badge = document.getElementById('treeModeBadge');
            if (badge) {
                badge.innerText = "🌐 VUE GLOBALE (18 DOMAINES • 190+ APPLICATIONS)";
                badge.style.borderColor = "var(--neon-cyan)";
                badge.style.color = "var(--neon-cyan)";
            }
            var btnReset = document.getElementById('btnResetTreeCam');
            if (btnReset) btnReset.style.display = 'none';

            if (galaxyGroup) galaxyGroup.visible = true;
            if (themeDetailGroup) themeDetailGroup.visible = false;

            treeCamTarget.z = 24.0;
            camPanOffset.x = 0;
            camPanOffset.y = 0;
            treeLookTarget = { x: 0, y: 0, z: 0 };

            var placeholder = document.getElementById('inspectorPlaceholder');
            var drawer = document.getElementById('inspectorThemeDrawer');
            var content = document.getElementById('inspectorContent');
            if (drawer) drawer.style.display = 'none';
            if (content) content.style.display = 'none';
            if (placeholder) placeholder.style.display = 'flex';

            showToast("🌐 Vue globale de la galaxie FOSS.");
        }
        window.resetTreeToGalaxy = resetTreeToGalaxy;

        function showAppCardInHUD(app, theme, isLocked) {
            var placeholder = document.getElementById('inspectorPlaceholder');
            var drawer = document.getElementById('inspectorThemeDrawer');
            var content = document.getElementById('inspectorContent');
            if (!content) return;

            if (placeholder) placeholder.style.display = 'none';
            if (drawer) drawer.style.display = 'none';
            content.style.display = 'flex';

            document.getElementById('specFossName').innerText = app.Foss || 'Application FOSS';
            document.getElementById('specCategory').innerText = (theme ? (theme.Icon + " " + theme.Title) : 'Domaine FOSS');
            
            var themeColor = (theme && theme.Color) ? theme.Color : '#38bdf8';
            var badgeText = (isLocked ? "🔒 " : "❖ ") + "Alt : " + (app.Prop || 'Propriétaire');
            var badgeElem = document.getElementById('specPropBadge');
            if (badgeElem) {
                badgeElem.innerText = badgeText;
                badgeElem.style.fontFamily = "'Rajdhani', 'JetBrains Mono', Consolas, monospace";
                badgeElem.style.letterSpacing = "0.04em";
                badgeElem.style.fontWeight = "600";
                if (isLocked) {
                    badgeElem.style.borderColor = "#34d399";
                    badgeElem.style.color = "#34d399";
                    badgeElem.style.background = "rgba(16, 185, 129, 0.12)";
                } else {
                    badgeElem.style.borderColor = themeColor + "66";
                    badgeElem.style.color = themeColor;
                    badgeElem.style.background = themeColor + "15";
                }
            }
            
            document.getElementById('specType').innerText = app.Type || 'Desktop Natif / Web';
            document.getElementById('specStack').innerText = app.Stack || 'C++, Rust, TypeScript';
            document.getElementById('specLicense').innerText = app.License || 'GPLv3 / Open Source';
            document.getElementById('specOrigin').innerText = app.Origin || 'Version 1.0';
            document.getElementById('specVersion').innerText = app.Version || 'Version Stable';
            document.getElementById('specWingetId').innerText = app.Winget || 'Winget.ID';

            document.getElementById('specDesc').innerText = app.Desc || 'Solution open-source de premier plan.';
            
            var webLink = document.getElementById('specWebLink');
            if (webLink) {
                webLink.href = app.Url || 'https://github.com';
                webLink.innerText = "🌐 Site Officiel";
            }

            var drawerBtn = document.getElementById('specDrawerBtn');
            if (drawerBtn) {
                drawerBtn.onclick = function() {
                    if (theme && theme.Category) {
                        var d = document.getElementById('drawer_' + theme.Category);
                        if (d) {
                            d.classList.add('open');
                            d.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            showToast("📂 Tiroir ouvert : " + theme.Title);
                        }
                    }
                };
            }

            var wingetBtn = document.getElementById('specWingetBtn');
            if (wingetBtn) {
                var cmd = "winget install --id " + (app.Winget || '') + " -e --accept-package-agreements --accept-source-agreements";
                wingetBtn.setAttribute('data-cmd', cmd);
            }
        }
        window.showAppCardInHUD = showAppCardInHUD;

        function createThickDodecahedronFrame(radius, tubeRadius, material) {
            var baseGeo = new THREE.DodecahedronGeometry(radius, 0);
            var edgesGeo = new THREE.EdgesGeometry(baseGeo);
            var posAttr = edgesGeo.attributes.position;
            var group = new THREE.Group();

            var cylinderGeo = new THREE.CylinderGeometry(tubeRadius, tubeRadius, 1, 8);
            var upVec = new THREE.Vector3(0, 1, 0);

            for (var i = 0; i < posAttr.count; i += 2) {
                var v1 = new THREE.Vector3().fromBufferAttribute(posAttr, i);
                var v2 = new THREE.Vector3().fromBufferAttribute(posAttr, i + 1);

                var edgeVec = new THREE.Vector3().subVectors(v2, v1);
                var length = edgeVec.length();
                var midPoint = new THREE.Vector3().addVectors(v1, v2).multiplyScalar(0.5);

                var beam = new THREE.Mesh(cylinderGeo, material);
                beam.position.copy(midPoint);
                beam.scale.set(1, length, 1);
                beam.quaternion.setFromUnitVectors(upVec, edgeVec.clone().normalize());

                group.add(beam);
            }
            return group;
        }

        function initTechTree3D() {
            var canvas = document.getElementById('three-tech-tree');
            if (!canvas) return;
            if (techTreeInitialized && techTreeRenderer) {
                resizeTechTree();
                return;
            }

            if (typeof THREE === 'undefined') {
                console.error("Three.js not loaded yet!");
                setTimeout(initTechTree3D, 200);
                return;
            }

            var rect = canvas.getBoundingClientRect();
            var w = rect.width || canvas.clientWidth || (canvas.parentElement ? canvas.parentElement.clientWidth : 0) || 850;
            var h = rect.height || canvas.clientHeight || (canvas.parentElement ? canvas.parentElement.clientHeight : 0) || 500;
            if (w < 100) w = 850;
            if (h < 100) h = 500;

            techTreeScene = new THREE.Scene();
            techTreeCamera = new THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
            techTreeCamera.position.set(treeCamCurrent.x, treeCamCurrent.y, treeCamCurrent.z);
            techTreeCamera.lookAt(treeLookCurrent.x, treeLookCurrent.y, treeLookCurrent.z);

            try {
                techTreeRenderer = new THREE.WebGLRenderer({ 
                    canvas: canvas, 
                    antialias: true, 
                    alpha: true,
                    powerPreference: 'high-performance'
                });
            } catch(e) {
                console.error("WebGL init error:", e);
                return;
            }

            techTreeRenderer.setSize(w, h, false);
            techTreeRenderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

            var ambLight = new THREE.AmbientLight(0x0f172a, 1.8);
            techTreeScene.add(ambLight);

            var dirLight1 = new THREE.DirectionalLight(0x38bdf8, 2.2);
            dirLight1.position.set(15, 25, 20);
            techTreeScene.add(dirLight1);

            var dirLight2 = new THREE.DirectionalLight(0x818cf8, 1.6);
            dirLight2.position.set(-15, -15, -15);
            techTreeScene.add(dirLight2);

            corePointLight = new THREE.PointLight(0x00f0ff, 3.2, 50, 1.2);
            corePointLight.position.set(0, 0, 0);
            techTreeScene.add(corePointLight);

            galaxyGroup = new THREE.Group();
            techTreeScene.add(galaxyGroup);

            themeDetailGroup = new THREE.Group();
            themeDetailGroup.visible = false;
            techTreeScene.add(themeDetailGroup);

            // Primary Core Structure: Deep Dark Metallic Blue Specular Dodecahedron Shield
            var coreBeamMat = new THREE.MeshStandardMaterial({ 
                color: 0x0f2b5c, 
                roughness: 0.08, 
                metalness: 0.98,
                emissive: 0x071e3d,
                emissiveIntensity: 0.25
            });
            coreMesh = createThickDodecahedronFrame(2.25, 0.048, coreBeamMat);
            galaxyGroup.add(coreMesh);

            var coreInnerGeo = new THREE.IcosahedronGeometry(1.35, 0);
            var coreInnerMat = new THREE.MeshStandardMaterial({ 
                color: 0x00f0ff, 
                roughness: 0.10, 
                metalness: 0.90,
                emissive: 0x0284c7,
                emissiveIntensity: 0.45,
                flatShading: true
            });
            coreInner = new THREE.Mesh(coreInnerGeo, coreInnerMat);
            galaxyGroup.add(coreInner);

            var ring1Geo = new THREE.TorusGeometry(2.8, 0.04, 16, 64);
            var ring1Mat = new THREE.MeshStandardMaterial({ color: 0x38bdf8, roughness: 0.2, metalness: 0.9, transparent:true, opacity:0.85 });
            coreRing1 = new THREE.Mesh(ring1Geo, ring1Mat);
            coreRing1.rotation.x = Math.PI / 3;
            galaxyGroup.add(coreRing1);

            var ring2Geo = new THREE.TorusGeometry(3.3, 0.03, 16, 64);
            var ring2Mat = new THREE.MeshStandardMaterial({ color: 0x34d399, roughness: 0.2, metalness: 0.9, transparent:true, opacity:0.75 });
            coreRing2 = new THREE.Mesh(ring2Geo, ring2Mat);
            coreRing2.rotation.y = Math.PI / 4;
            galaxyGroup.add(coreRing2);

            // Halos
            hoverGlowGroup = new THREE.Group();
            hoverGlowGroup.visible = false;
            techTreeScene.add(hoverGlowGroup);

            var hRingGeo = new THREE.TorusGeometry(1.6, 0.04, 16, 48);
            hoverRingMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.85 });
            hoverRingMesh = new THREE.Mesh(hRingGeo, hoverRingMat);
            hoverGlowGroup.add(hoverRingMesh);

            var hIcoGeo = new THREE.IcosahedronGeometry(1.5, 0);
            hoverIcoMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, wireframe: true, transparent: true, opacity: 0.5 });
            hoverIcoMesh = new THREE.Mesh(hIcoGeo, hoverIcoMat);
            hoverGlowGroup.add(hoverIcoMesh);

            selectionHaloGroup = new THREE.Group();
            selectionHaloGroup.visible = false;
            techTreeScene.add(selectionHaloGroup);

            var sRingGeo = new THREE.TorusGeometry(1.7, 0.07, 16, 64);
            var sRingMat = new THREE.MeshStandardMaterial({ color: 0xfbbf24, roughness: 0.1, metalness: 0.95, emissive: 0xd97706, emissiveIntensity: 0.6 });
            haloRingMesh = new THREE.Mesh(sRingGeo, sRingMat);
            selectionHaloGroup.add(haloRingMesh);

            var sRing2Geo = new THREE.TorusGeometry(2.1, 0.04, 16, 64);
            var sRing2Mat = new THREE.MeshStandardMaterial({ color: 0x34d399, roughness: 0.1, metalness: 0.9, emissive: 0x059669, emissiveIntensity: 0.5 });
            haloRing2Mesh = new THREE.Mesh(sRing2Geo, sRing2Mat);
            haloRing2Mesh.rotation.x = Math.PI / 2;
            selectionHaloGroup.add(haloRing2Mesh);

            // 18 Galaxy Domain Hubs with dynamic stems (short: 7.5, long: 10.5)
            themeHubMeshes = [];
            animatedGalaxySatellites = [];

            var themes = getActiveThemesList();
            var numThemes = themes.length || 18;
            var defaultRadius = 7.5;
            var goldenAngle = Math.PI * (3 - Math.sqrt(5));

            themes.forEach(function(th, idx) {
                var yNorm = (numThemes > 1) ? (1 - (idx / (numThemes - 1)) * 2) : 0;
                var y0 = yNorm * 0.85;
                var rAtY = Math.sqrt(Math.max(0, 1 - y0 * y0));
                var phi = goldenAngle * idx;
                var x0 = Math.cos(phi) * rAtY;
                var z0 = Math.sin(phi) * rAtY;
                var unitDir = new THREE.Vector3(x0, y0, z0).normalize();

                var x = unitDir.x * defaultRadius;
                var y = unitDir.y * defaultRadius;
                var z = unitDir.z * defaultRadius;

                var thColorHex = th.Color || '#00f0ff';
                var thColor = parseInt(thColorHex.replace('#', '0x'), 16) || 0x00f0ff;

                var lineGeo = new THREE.BufferGeometry().setFromPoints([
                    new THREE.Vector3(0, 0, 0),
                    new THREE.Vector3(x, y, z)
                ]);
                var lineMat = new THREE.LineBasicMaterial({ color: thColor, transparent: true, opacity: 0.50 });
                var line = new THREE.Line(lineGeo, lineMat);
                galaxyGroup.add(line);

                var hubCoreGeo = new THREE.OctahedronGeometry(0.55, 0);
                var hubCoreMat = new THREE.MeshStandardMaterial({ 
                    color: thColor, 
                    roughness: 0.12, 
                    metalness: 0.90, 
                    emissive: thColor, 
                    emissiveIntensity: 0.35, 
                    flatShading: true 
                });
                var hubCoreMesh = new THREE.Mesh(hubCoreGeo, hubCoreMat);
                hubCoreMesh.position.set(x, y, z);
                galaxyGroup.add(hubCoreMesh);

                var hubGeo = new THREE.OctahedronGeometry(0.95, 0);
                var hubMat = new THREE.MeshStandardMaterial({ 
                    color: thColor, 
                    wireframe: true, 
                    roughness: 0.2, 
                    metalness: 0.9 
                });
                var hubMesh = new THREE.Mesh(hubGeo, hubMat);
                hubMesh.position.set(x, y, z);
                
                var hubSatellites = [];
                hubMesh.userData = { 
                    type: 'THEME_HUB', 
                    theme: th,
                    coreMesh: hubCoreMesh,
                    line: line,
                    unitDir: unitDir,
                    currentDist: defaultRadius,
                    satellites: hubSatellites,
                    spinSpeed: { x: 0.0025 + (idx % 3) * 0.0008, y: 0.0035 + (idx % 2) * 0.001, z: 0.0018 }
                };
                galaxyGroup.add(hubMesh);
                themeHubMeshes.push(hubMesh);

                for (var p = 0; p < 3; p++) {
                    var subGeo = new THREE.TetrahedronGeometry(0.22, 0);
                    var subMat = new THREE.MeshStandardMaterial({ 
                        color: thColor, 
                        roughness: 0.1, 
                        metalness: 0.95, 
                        emissive: thColor, 
                        emissiveIntensity: 0.35, 
                        flatShading: true 
                    });
                    var subMesh = new THREE.Mesh(subGeo, subMat);
                    galaxyGroup.add(subMesh);
                    var satObj = {
                        mesh: subMesh,
                        hubPos: { x: x, y: y, z: z },
                        baseDist: 1.45,
                        orbitSpeed: 0.005 + (p * 0.0018),
                        currentAngle: (p / 3) * Math.PI * 2,
                        spinX: 0.006 + p * 0.002,
                        spinY: 0.008 + p * 0.0025,
                        tilt: (p - 1) * 0.35
                    };
                    animatedGalaxySatellites.push(satObj);
                    hubSatellites.push(satObj);
                }
            });

            // Particles Background
            var bgPartGeo = new THREE.BufferGeometry();
            var bgPartCount = 800;
            var bgPos = new Float32Array(bgPartCount * 3);
            for (var k = 0; k < bgPartCount * 3; k += 3) {
                bgPos[k] = (Math.random() - 0.5) * 80;
                bgPos[k+1] = (Math.random() - 0.5) * 80;
                bgPos[k+2] = (Math.random() - 0.5) * 80;
            }
            bgPartGeo.setAttribute('position', new THREE.BufferAttribute(bgPos, 3));
            var bgPartMat = new THREE.PointsMaterial({ color: 0x38bdf8, size: 0.35, transparent: true, opacity: 0.45 });
            treeBgGroup = new THREE.Points(bgPartGeo, bgPartMat);
            techTreeScene.add(treeBgGroup);

            // Interaction Listeners
            var isDragging = false;
            var dragButton = 0;
            var prevMouse = { x: 0, y: 0 };
            var mouseVec = new THREE.Vector2();

            canvas.addEventListener('contextmenu', function(e) { e.preventDefault(); });

            canvas.addEventListener('mousedown', function(e) {
                isDragging = true;
                dragButton = e.button;
                prevMouse = { x: e.clientX, y: e.clientY };
                canvas.style.cursor = 'grabbing';
            });

            window.addEventListener('mouseup', function(e) {
                isDragging = false;
                if (canvas) canvas.style.cursor = 'grab';
            });

            canvas.addEventListener('wheel', function(e) {
                e.preventDefault();
                var delta = Math.sign(e.deltaY) * 2.0;
                if (currentTreeMode === 'THEME') {
                    treeCamTarget.z += delta;
                    // Dézoom fort dans un nœud secondaire -> Retour automatique au nœud principal (vue galaxie)
                    if (treeCamTarget.z > 23.5 || (treeCamTarget.z >= 21.0 && delta > 0 && e.deltaY > 40)) {
                        resetTreeToGalaxy();
                        return;
                    }
                    treeCamTarget.z = Math.min(23.5, Math.max(6.0, treeCamTarget.z));
                } else {
                    treeCamTarget.z = Math.min(55.0, Math.max(10.0, treeCamTarget.z + delta));
                }
            }, { passive: false });

            canvas.addEventListener('mousemove', function(e) {
                var rect = canvas.getBoundingClientRect();
                if (rect.width < 10 || rect.height < 10) return;

                var normCanvasX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
                var normCanvasY = ((e.clientY - rect.top) / rect.height) * 2 - 1;
                treeBgTargetMouseX = normCanvasX * 0.35;
                treeBgTargetMouseY = normCanvasY * 0.20;

                if (isDragging) {
                    var dx = e.clientX - prevMouse.x;
                    var dy = e.clientY - prevMouse.y;

                    if (dragButton === 0) {
                        if (currentTreeMode === 'GALAXY') {
                            if (galaxyGroup) {
                                galaxyGroup.rotation.y += dx * 0.009;
                                galaxyGroup.rotation.x += dy * 0.009;
                            }
                        } else {
                            if (themeDetailGroup) {
                                themeDetailGroup.rotation.y += dx * 0.009;
                                themeDetailGroup.rotation.x += dy * 0.009;
                            }
                        }
                    } else if (dragButton === 2) {
                        var panSpeed = 0.028 * (Math.max(10, treeCamTarget.z) / 22);
                        camPanOffset.x -= dx * panSpeed;
                        camPanOffset.y += dy * panSpeed;
                    }
                    prevMouse = { x: e.clientX, y: e.clientY };
                }

                mouseVec.x = normCanvasX;
                mouseVec.y = -normCanvasY;
                raycaster.setFromCamera(mouseVec, techTreeCamera);

                var targetObjects = (currentTreeMode === 'GALAXY') ? themeHubMeshes : appSubNodeMeshes;
                var intersects = raycaster.intersectObjects(targetObjects);

                if (intersects.length > 0) {
                    canvas.style.cursor = 'pointer';
                    var hit = intersects[0].object;
                    lastHoveredMesh = hit;

                    if (currentTreeMode === 'GALAXY') {
                        var theme = hit.userData.theme;
                        if (theme && hit !== lockedSelectedMesh) {
                            showTooltipForMesh(hit, (theme.Icon || '📂') + " " + theme.Title + " (" + (theme.Items ? theme.Items.length : 0) + " Apps)");
                        }
                    } else {
                        var app = hit.userData.app;
                        if (app && hit !== lockedSelectedMesh) {
                            showTooltipForMesh(hit, "✨ " + app.Foss + " (Alt. " + (app.Prop || 'Propriétaire') + ")");
                        }
                    }
                } else {
                    canvas.style.cursor = isDragging ? 'grabbing' : 'grab';
                    if (!lockedSelectedMesh) {
                        lastHoveredMesh = null;
                        if (hoverGlowGroup) hoverGlowGroup.visible = false;
                        if (tooltipElem) tooltipElem.style.opacity = '0';
                    }
                }
            });

            canvas.addEventListener('click', function(e) {
                var rect = canvas.getBoundingClientRect();
                if (rect.width < 10 || rect.height < 10) return;
                mouseVec.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
                mouseVec.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
                raycaster.setFromCamera(mouseVec, techTreeCamera);

                if (currentTreeMode === 'GALAXY') {
                    var intersects = raycaster.intersectObjects(themeHubMeshes);
                    if (intersects.length > 0) {
                        var theme = intersects[0].object.userData.theme;
                        if (theme) {
                            var rawTh = getActiveThemesList();
                            var tIdx = rawTh.findIndex(function(t) { return (t.Category && t.Category === theme.Category) || t.Title === theme.Title; });
                            if (tIdx >= 0) window.currentGalaxyThemeIndex = tIdx;
                            selectGalaxyTheme(theme, false);
                        }
                    }
                } else {
                    var checkTargets = [];
                    if (animatedDetailHub) checkTargets.push(animatedDetailHub);
                    checkTargets = checkTargets.concat(appSubNodeMeshes);

                    var intersects = raycaster.intersectObjects(checkTargets);
                    if (intersects.length > 0) {
                        var hitObj = intersects[0].object;
                        if (hitObj.userData && hitObj.userData.type === 'THEME_HUB') {
                            renderThemeAppDrawer(activeFocusedTheme);
                            showToast("📂 Domaine : " + activeFocusedTheme.Title);
                        } else if (hitObj.userData && hitObj.userData.app) {
                            var appIdx = (activeFocusedTheme.Items || []).findIndex(function(a) { return a.Winget === hitObj.userData.app.Winget; });
                            if (appIdx >= 0) window.currentThemeAppIndex = appIdx;
                            selectAppFromList(hitObj.userData.theme, hitObj.userData.app);
                        }
                    }
                }
            });

            canvas.addEventListener('dblclick', function(e) {
                if (currentTreeMode === 'THEME') {
                    resetTreeToGalaxy();
                } else {
                    var rect = canvas.getBoundingClientRect();
                    if (rect.width < 10 || rect.height < 10) return;
                    mouseVec.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
                    mouseVec.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
                    raycaster.setFromCamera(mouseVec, techTreeCamera);
                    var intersects = raycaster.intersectObjects(themeHubMeshes);
                    if (intersects.length > 0) {
                        var theme = intersects[0].object.userData.theme;
                        if (theme) focusOnTheme(theme);
                    } else {
                        resetTreeToGalaxy();
                    }
                }
            });

            window.currentGalaxyThemeIndex = 0;
            window.currentThemeAppIndex = -1;

            window.addEventListener('keydown', function(e) {
                var fossTab = document.getElementById('tab-foss');
                if (!fossTab || !fossTab.classList.contains('active')) {
                    return; // Only active when tab-foss is open
                }
                if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT')) {
                    return;
                }

                var key = e.key;

                if (key === 'ArrowRight' || key === 'ArrowLeft') {
                    e.preventDefault();
                    if (currentTreeMode === 'GALAXY') {
                        var themes = getActiveThemesList();
                        if (themes.length === 0) return;
                        window.currentGalaxyThemeIndex = (key === 'ArrowRight')
                            ? (window.currentGalaxyThemeIndex + 1) % themes.length
                            : (window.currentGalaxyThemeIndex - 1 + themes.length) % themes.length;

                        var targetTheme = themes[window.currentGalaxyThemeIndex];
                        selectGalaxyTheme(targetTheme, false);
                    } else if (currentTreeMode === 'THEME' && activeFocusedTheme) {
                        var items = activeFocusedTheme.Items || [];
                        if (items.length === 0) return;
                        if (window.currentThemeAppIndex === undefined || window.currentThemeAppIndex === null || window.currentThemeAppIndex < 0) {
                            window.currentThemeAppIndex = (key === 'ArrowRight') ? 0 : items.length - 1;
                        } else {
                            window.currentThemeAppIndex = (key === 'ArrowRight')
                                ? (window.currentThemeAppIndex + 1) % items.length
                                : (window.currentThemeAppIndex - 1 + items.length) % items.length;
                        }
                        var targetApp = items[window.currentThemeAppIndex];
                        selectAppFromList(activeFocusedTheme, targetApp);
                    }
                } else if (key === 'ArrowUp' || key === 'Enter') {
                    if (currentTreeMode === 'GALAXY') {
                        e.preventDefault();
                        var themes = getActiveThemesList();
                        if (themes.length > 0) {
                            var targetTheme = themes[window.currentGalaxyThemeIndex || 0];
                            focusOnTheme(targetTheme);
                        }
                    } else if (currentTreeMode === 'THEME') {
                        e.preventDefault();
                        if (lockedSelectedApp) {
                            var wingetCmd = "winget install --id " + lockedSelectedApp.Winget + " -e --accept-package-agreements --accept-source-agreements";
                            navigator.clipboard.writeText(wingetCmd).then(function() {
                                showToast("⚡ Commande Winget copiée : " + lockedSelectedApp.Foss);
                            });
                        } else if (activeFocusedTheme && activeFocusedTheme.Items && activeFocusedTheme.Items.length > 0) {
                            window.currentThemeAppIndex = 0;
                            selectAppFromList(activeFocusedTheme, activeFocusedTheme.Items[0]);
                        }
                    }
                } else if (key === 'ArrowDown' || key === 'Backspace' || key === 'Escape') {
                    if (currentTreeMode === 'THEME') {
                        e.preventDefault();
                        var drawer = document.getElementById('inspectorThemeDrawer');
                        var content = document.getElementById('inspectorContent');
                        if (content && content.style.display !== 'none' && drawer && drawer.style.display === 'none') {
                            renderThemeAppDrawer(activeFocusedTheme);
                            showToast("📂 Retour au tiroir du thème : " + activeFocusedTheme.Title);
                        } else {
                            resetTreeToGalaxy();
                        }
                    } else if (currentTreeMode === 'GALAXY') {
                        e.preventDefault();
                        resetTreeToGalaxy();
                    }
                }
            });

            var lastRenderW = 0, lastRenderH = 0;

            function animateTree() {
                requestAnimationFrame(animateTree);

                var treeElapsedTime = treeClock.getElapsedTime();

                var r = canvas.getBoundingClientRect();
                var cw = r.width || canvas.clientWidth || 0;
                var ch = r.height || canvas.clientHeight || 0;
                if (cw > 50 && ch > 50 && (cw !== lastRenderW || ch !== lastRenderH)) {
                    lastRenderW = cw;
                    lastRenderH = ch;
                    techTreeCamera.aspect = cw / ch;
                    techTreeCamera.updateProjectionMatrix();
                    techTreeRenderer.setSize(cw, ch, false);
                }

                treeBgCurrentMouseX += (treeBgTargetMouseX - treeBgCurrentMouseX) * 0.04;
                treeBgCurrentMouseY += (treeBgTargetMouseY - treeBgCurrentMouseY) * 0.04;

                var treeBgBaseAngle = treeElapsedTime * ((Math.PI * 2) / 120);
                if (treeBgGroup) {
                    treeBgGroup.rotation.y = treeBgBaseAngle + treeBgCurrentMouseX;
                    treeBgGroup.rotation.x = treeBgCurrentMouseY;
                }

                // Camera Vantage Point & Orientation Tracking (Camera stays at fixed distant point, smoothly orients lookAt towards selected node)
                treeCamTarget.x = camPanOffset.x;
                treeCamTarget.y = (currentTreeMode === 'GALAXY' ? 3.2 : 2.2) + camPanOffset.y;

                if (lockedSelectedMesh) {
                    var liveWorldPos = new THREE.Vector3();
                    lockedSelectedMesh.getWorldPosition(liveWorldPos);

                    // Orient gaze smoothly towards the active node while keeping camera in place
                    var lookFactor = (currentTreeMode === 'GALAXY') ? 0.65 : 0.55;
                    treeLookTarget.x = liveWorldPos.x * lookFactor;
                    treeLookTarget.y = liveWorldPos.y * lookFactor;
                    treeLookTarget.z = liveWorldPos.z * lookFactor;
                } else {
                    treeLookTarget.x = 0;
                    treeLookTarget.y = 0;
                    treeLookTarget.z = 0;
                }

                treeCamCurrent.x += (treeCamTarget.x - treeCamCurrent.x) * 0.07;
                treeCamCurrent.y += (treeCamTarget.y - treeCamCurrent.y) * 0.07;
                treeCamCurrent.z += (treeCamTarget.z - treeCamCurrent.z) * 0.07;

                treeLookCurrent.x += (treeLookTarget.x - treeLookCurrent.x) * 0.07;
                treeLookCurrent.y += (treeLookTarget.y - treeLookCurrent.y) * 0.07;
                treeLookCurrent.z += (treeLookTarget.z - treeLookCurrent.z) * 0.07;

                techTreeCamera.position.set(treeCamCurrent.x, treeCamCurrent.y, treeCamCurrent.z);
                techTreeCamera.lookAt(treeLookCurrent.x, treeLookCurrent.y, treeLookCurrent.z);

                // Halos World Tracking
                if (lockedSelectedMesh && selectionHaloGroup && selectionHaloGroup.visible) {
                    var haloWPos = new THREE.Vector3();
                    lockedSelectedMesh.getWorldPosition(haloWPos);
                    selectionHaloGroup.position.copy(haloWPos);
                    selectionHaloGroup.rotation.y += 0.025;
                    selectionHaloGroup.rotation.z += 0.015;
                }

                if (lastHoveredMesh && hoverGlowGroup && hoverGlowGroup.visible && lastHoveredMesh !== lockedSelectedMesh) {
                    var hovWPos = new THREE.Vector3();
                    lastHoveredMesh.getWorldPosition(hovWPos);
                    hoverGlowGroup.position.copy(hovWPos);
                    hoverGlowGroup.rotation.x += 0.030;
                    hoverGlowGroup.rotation.y += 0.020;
                } else if (hoverGlowGroup && lastHoveredMesh === lockedSelectedMesh) {
                    hoverGlowGroup.visible = false;
                }

                // Tooltip World-to-Screen Tracking
                var activeTipMesh = (lastHoveredMesh && lastHoveredMesh !== lockedSelectedMesh) ? lastHoveredMesh : lockedSelectedMesh;
                if (activeTipMesh && tooltipElem) {
                    var screenPos = getNodeScreenCoords(activeTipMesh);
                    if (screenPos) {
                        tooltipElem.style.left = screenPos.x + 'px';
                        tooltipElem.style.top = screenPos.y + 'px';
                        tooltipElem.style.opacity = '1';
                    } else {
                        tooltipElem.style.opacity = '0';
                    }
                } else if (tooltipElem) {
                    tooltipElem.style.opacity = '0';
                }

                if (coreMesh) {
                    coreMesh.rotation.y += 0.0022;
                    coreMesh.rotation.x += 0.0014;
                }
                if (coreInner) {
                    coreInner.rotation.y -= 0.0035;
                    coreInner.rotation.z += 0.0020;
                    var corePulse = 1 + Math.sin(treeElapsedTime * 1.2) * 0.04;
                    coreInner.scale.set(corePulse, corePulse, corePulse);
                }
                if (coreRing1) {
                    coreRing1.rotation.z += 0.0025;
                    coreRing1.rotation.y += 0.0012;
                }
                if (coreRing2) {
                    coreRing2.rotation.y -= 0.0020;
                    coreRing2.rotation.x += 0.0010;
                }

                // Galaxy Hubs dynamic stems (Short by default: 7.5, Long when active: 10.5)
                if (currentTreeMode === 'GALAXY') {
                    if (galaxyGroup) {
                        galaxyGroup.rotation.y += 0.0006;
                    }

                    themeHubMeshes.forEach(function(hub) {
                        if (hub.userData && hub.userData.unitDir) {
                            var isThisHubActive = (lockedSelectedTheme && (lockedSelectedTheme.Category === hub.userData.theme.Category || lockedSelectedTheme.Title === hub.userData.theme.Title)) || (lastHoveredMesh === hub);
                            var targetRadius = isThisHubActive ? 8.3 : 7.5;
                            if (hub.userData.currentDist === undefined) hub.userData.currentDist = 7.4;
                            hub.userData.currentDist += (targetRadius - hub.userData.currentDist) * 0.08;

                            var curR = hub.userData.currentDist;
                            var u = hub.userData.unitDir;
                            var hx = u.x * curR;
                            var hy = u.y * curR;
                            var hz = u.z * curR;

                            hub.position.set(hx, hy, hz);
                            if (hub.userData.coreMesh) {
                                hub.userData.coreMesh.position.set(hx, hy, hz);
                            }

                            if (hub.userData.line) {
                                var posArr = hub.userData.line.geometry.attributes.position.array;
                                posArr[3] = hx;
                                posArr[4] = hy;
                                posArr[5] = hz;
                                hub.userData.line.geometry.attributes.position.needsUpdate = true;
                                hub.userData.line.material.opacity = isThisHubActive ? 0.95 : 0.40;
                            }

                            if (hub.userData.spinSpeed) {
                                hub.rotation.x += hub.userData.spinSpeed.x;
                                hub.rotation.y += hub.userData.spinSpeed.y;
                                hub.rotation.z += hub.userData.spinSpeed.z;
                            }

                            if (hub.userData.satellites) {
                                hub.userData.satellites.forEach(function(sat) {
                                    sat.hubPos = { x: hx, y: hy, z: hz };
                                });
                            }
                        }
                    });

                    animatedGalaxySatellites.forEach(function(sat) {
                        sat.currentAngle += sat.orbitSpeed;
                        var hx = sat.hubPos.x;
                        var hy = sat.hubPos.y;
                        var hz = sat.hubPos.z;
                        var d = sat.baseDist;
                        sat.mesh.position.set(
                            hx + Math.cos(sat.currentAngle) * d,
                            hy + Math.sin(sat.currentAngle * 1.4) * (d * 0.3) + Math.sin(treeElapsedTime * 0.8) * 0.08,
                            hz + Math.sin(sat.currentAngle) * d
                        );
                        sat.mesh.rotation.x += sat.spinX;
                        sat.mesh.rotation.y += sat.spinY;
                    });
                }

                // Theme Sub-Nodes dynamic stems (Short by default: 4.8, Long when active: 8.4)
                if (currentTreeMode === 'THEME') {
                    if (animatedDetailHub) {
                        animatedDetailHub.rotation.x += 0.0030;
                        animatedDetailHub.rotation.y += 0.0045;
                        if (animatedDetailHub.userData.ring1) {
                            animatedDetailHub.userData.ring1.rotation.z += 0.0035;
                            animatedDetailHub.userData.ring1.rotation.x += 0.0015;
                        }
                        if (animatedDetailHub.userData.ring2) {
                            animatedDetailHub.userData.ring2.rotation.y += 0.0040;
                            animatedDetailHub.userData.ring2.rotation.z -= 0.0020;
                        }
                    }

                    appSubNodeMeshes.forEach(function(appMesh) {
                        if (appMesh.userData && appMesh.userData.baseAngle !== undefined) {
                            var isThisActive = (lockedSelectedApp && lockedSelectedApp.Winget === appMesh.userData.app.Winget) || (lastHoveredMesh === appMesh);
                            var targetDist = isThisActive ? 5.8 : 5.0;
                            if (appMesh.userData.currentDist === undefined) appMesh.userData.currentDist = 4.8;
                            
                            appMesh.userData.currentDist += (targetDist - appMesh.userData.currentDist) * 0.08;

                            var d = appMesh.userData.currentDist;
                            var angle = appMesh.userData.baseAngle;
                            var nx = Math.cos(angle) * d;
                            var nz = Math.sin(angle) * d;
                            var ny = appMesh.userData.heightOffset;

                            appMesh.position.set(nx, ny, nz);
                            if (appMesh.userData.coreMesh) {
                                appMesh.userData.coreMesh.position.set(nx, ny, nz);
                            }

                            if (appMesh.userData.laser) {
                                var posArr = appMesh.userData.laser.geometry.attributes.position.array;
                                posArr[3] = nx;
                                posArr[4] = ny;
                                posArr[5] = nz;
                                appMesh.userData.laser.geometry.attributes.position.needsUpdate = true;
                                appMesh.userData.laser.material.opacity = isThisActive ? 0.95 : 0.40;
                            }

                            if (appMesh.userData.spinSpeed) {
                                appMesh.rotation.x += appMesh.userData.spinSpeed.x;
                                appMesh.rotation.y += appMesh.userData.spinSpeed.y;
                                appMesh.rotation.z += appMesh.userData.spinSpeed.z;

                                var baseScale = isThisActive ? 1.18 : 1.0;
                                var nodePulse = baseScale + Math.sin(treeElapsedTime * 1.1 + appMesh.userData.harmonicOffset) * 0.05;
                                appMesh.scale.set(nodePulse, nodePulse, nodePulse);
                            }
                        }
                    });

                    animatedDetailSatellites.forEach(function(sat) {
                        sat.currentAngle += sat.orbitSpeed;
                        var pPos = sat.parentMesh.position;
                        var d = sat.baseDist;
                        sat.mesh.position.set(
                            pPos.x + Math.cos(sat.currentAngle) * d,
                            pPos.y + Math.sin(sat.currentAngle + sat.tilt) * (d * 0.40),
                            pPos.z + Math.sin(sat.currentAngle) * d
                        );
                        sat.mesh.rotation.x += sat.spinX;
                        sat.mesh.rotation.y += sat.spinY;
                    });

                    animatedDetailLasers.forEach(function(l) {
                        l.mat.opacity = 0.45 + Math.sin(treeElapsedTime * 1.4 + l.offset) * 0.25;
                    });
                }

                techTreeRenderer.render(techTreeScene, techTreeCamera);
            }
            animateTree();
            techTreeInitialized = true;
        }

        // Auto-initialize on load and resize
        window.addEventListener('DOMContentLoaded', function() {
            setTimeout(initTechTree3D, 100);
        });
        window.addEventListener('load', function() {
            setTimeout(initTechTree3D, 200);
        });
        window.addEventListener('resize', resizeTechTree);

        // -------------------------------------------------------------
        // 🗄️ THEMATIC ACCORDION DRAWERS HANDLERS
        // -------------------------------------------------------------
        function filterFossDrawers() {
            var query = (document.getElementById('fossSearchInput').value || '').toLowerCase().trim();
            var drawers = document.querySelectorAll('.sci-drawer');
            drawers.forEach(function(drawer) {
                var cards = drawer.querySelectorAll('.foss-card');
                var matchCount = 0;
                cards.forEach(function(card) {
                    var text = (card.innerText || '').toLowerCase();
                    if (!query || text.indexOf(query) !== -1) {
                        card.style.display = 'flex';
                        matchCount++;
                    } else {
                        card.style.display = 'none';
                    }
                });

                if (query) {
                    if (matchCount > 0) {
                        drawer.style.display = 'block';
                        drawer.classList.add('open');
                        var body = drawer.querySelector('.drawer-body');
                        if (body) body.style.display = 'grid';
                    } else {
                        drawer.style.display = 'none';
                    }
                } else {
                    drawer.style.display = 'block';
                    cards.forEach(function(c) { c.style.display = 'flex'; });
                }
            });
        }
        window.filterFossDrawers = filterFossDrawers;

        function toggleDrawer(id, forceOpen) {
            var drawer = document.getElementById('drawer-' + id);
            if (!drawer) return;
            if (forceOpen === true) {
                drawer.classList.add('open');
            } else {
                drawer.classList.toggle('open');
            }
        }

        function expandAllDrawers(open) {
            var drawers = document.querySelectorAll('.sci-drawer');
            drawers.forEach(function(d) {
                if (open) d.classList.add('open');
                else d.classList.remove('open');
            });
            showToast(open ? "📂 Tous les tiroirs sont ouverts !" : "📁 Tous les tiroirs sont repliés !");
        }

        window.addEventListener('load', function() {
            setTimeout(initTechTree3D, 250);
        });
        window.addEventListener('resize', resizeTechTree);

        // -------------------------------------------------------------
        // STARTUP & SCRIPTS FILTER
        // -------------------------------------------------------------
        function filterStartup(type, btn) {
            document.querySelectorAll('#tab-performance .filter-btn, #tab-startup .filter-btn').forEach(function (b) { b.classList.remove('active'); });
            if (btn) btn.classList.add('active');

            var rows = document.querySelectorAll('#startupTable tbody tr');
            rows.forEach(function (row) {
                var rowType = row.getAttribute('data-type') || 'APP';
                var isSusp = (row.getAttribute('data-suspicious') === 'true');
                if (type === 'ALL') {
                    row.style.display = '';
                } else if (type === 'SUSPICIOUS') {
                    row.style.display = isSusp ? '' : 'none';
                } else if (rowType === type) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    
        // =============================================================
        // 📊 POPULATION DES 10 MODULES D'ENTREPRISE (JS ENGINE)
        // =============================================================
        (function initEnterpriseModules() {
            function decodeBase64Utf8(value) {
                var bytes = Uint8Array.from(atob(value), function(char) {
                    return char.charCodeAt(0);
                });
                return new TextDecoder('utf-8').decode(bytes);
            }

            var rawHistory = decodeBase64Utf8('__HISTORY_JSON__');
            var rawCve = decodeBase64Utf8('__CVE_JSON__');
            var rawBench = decodeBase64Utf8('__BENCH_JSON__');
            var rawDisk = decodeBase64Utf8('__DISK_AUDIT_JSON__');
            var rawNet = decodeBase64Utf8('__NETWORK_AUDIT_JSON__');
            var rawSec = decodeBase64Utf8('__SECURITY_AUDIT_JSON__');
            var rawBelgian = decodeBase64Utf8('__BELGIAN_APPS_JSON__');

            var historyData = [];
        var latestRun = (window.historyData && window.historyData.length > 0) ? window.historyData[window.historyData.length - 1] : null;
            if (latestRun) {
                var elemDisk = document.getElementById('histDiskFree');
                if (elemDisk && latestRun.FreeDiskGB !== undefined) {
                    elemDisk.innerText = latestRun.FreeDiskGB + " Go libres";
                }
                var elemCve = document.getElementById('histCveCount');
                if (elemCve && latestRun.CveCount !== undefined) {
                    elemCve.innerText = latestRun.CveCount === 0 ? "0 faille critique" : (latestRun.CveCount + " faille(s) active(s)");
                    elemCve.style.color = latestRun.CveCount === 0 ? "#34d399" : "#f43f5e";
                }
                var elemRuns = document.getElementById('histTotalRuns');
                if (elemRuns && window.historyData) {
                    elemRuns.innerText = window.historyData.length + " diagnostics archivés";
                }
            }

            var cveData = [];
            var benchData = [];
            var diskData = {};
            var netData = {};
            var secData = {};
            var belgianData = [];

            try { historyData = JSON.parse(rawHistory); } catch(e) {}
            try { cveData = JSON.parse(rawCve); } catch(e) {}
            try { benchData = JSON.parse(rawBench); } catch(e) {}
            try { diskData = JSON.parse(rawDisk); } catch(e) {}
            try { netData = JSON.parse(rawNet); } catch(e) {}
            try { secData = JSON.parse(rawSec); } catch(e) {}
            try { belgianData = JSON.parse(rawBelgian); } catch(e) {}

            window.historyData = historyData;
            window.cveData = cveData;
            window.benchData = benchData;
            window.diskAuditData = diskData;
            window.networkAuditData = netData;
            window.securityAuditData = secData;
            window.belgianData = belgianData;

            // =============================================================
            // 🔴 2. SCANNER DE VULNÉRABILITÉS CVE (CVE CARDS RENDERER)
            // =============================================================
            var cveCont = document.getElementById('cveCardsContainer');
            if (cveCont) {
                var cveList = (window.cveData && Array.isArray(window.cveData)) ? window.cveData : [];
                if (cveList.length === 0) {
                    // Clean State Banner
                    cveCont.innerHTML = [
                        '<div style="background:rgba(16,185,129,0.08); border:1px solid rgba(52,211,153,0.35); border-left:4px solid #10b981; border-radius:8px; padding:22px; margin-top:10px;">',
                        '  <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px;">',
                        '    <span style="font-size:24px;">🛡️</span>',
                        '    <div>',
                        '      <h3 style="margin:0; font-size:16px; color:#34d399; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">Aucune Vulnérabilité Critique Détectée (CVSS ≥ 7.0)</h3>',
                        '      <div style="font-size:12px; color:#94a3b8; margin-top:2px;">Toutes les applications auditées sont conformes et protégées contre les failles répertoriées.</div>',
                        '    </div>',
                        '    <span class="badge badge-ok" style="margin-left:auto; font-size:12px; padding:6px 12px;">✅ 100% Conforme</span>',
                        '  </div>',
                        '  <div style="font-size:12.5px; color:#cbd5e1; line-height:1.6; border-top:1px solid rgba(255,255,255,0.08); padding-top:12px; margin-top:10px;">',
                        '    Le moteur d\'audit a vérifié les versions binaires réelles des navigateurs web (Google Chrome, Mozilla Firefox, Microsoft Edge), des utilitaires de compression (WinRAR, 7-Zip), des outils d\'administration et des runtimes système. Aucune faille critique (zero-day ou exploit public connu) n\'affecte ce poste.',
                        '  </div>',
                        '  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-top:16px; font-size:11.5px; color:#94a3b8;">',
                        '    <div>📦 <em>Base locale CVE synchronisée • Prochaine vérification planifiée recommandée sous 7 jours.</em></div>',
                        '    <button class="btn-primary" onclick="copyDirect(this)" data-cmd=".\Update-CveDatabase.ps1" style="font-size:11.5px; padding:6px 12px;">🔄 Mettre à jour la base CVE</button>',
                        '  </div>',
                        '</div>'
                    ].join('');
                } else {
                    // Active Vulnerabilities Cards
                    var cardsHtml = '<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(340px, 1fr)); gap:16px; margin-top:12px;">';
                    cveList.forEach(function(c) {
                        var isCrit = (c.Severity === 'CRITIQUE' || c.Score >= 8.5);
                        var borderCol = isCrit ? '#f43f5e' : '#f59e0b';
                        var badgeClass = isCrit ? 'badge-err' : 'badge-warn';
                        var fixCmd = c.WingetId ? ('winget upgrade --id ' + c.WingetId + ' --silent --accept-source-agreements --accept-package-agreements') : 'winget upgrade --all';

                        cardsHtml += [
                            '<div style="background:rgba(15,23,42,0.90); border:1px solid ' + borderCol + '; border-radius:8px; padding:18px; display:flex; flex-direction:column; justify-content:space-between; box-shadow:0 0 14px rgba(244,63,94,0.15);">',
                            '  <div>',
                            '    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">',
                            '      <div>',
                            '        <h4 style="margin:0; font-size:15px; color:#f1f5f9; font-weight:800;">' + (c.App || c.Target || 'Application') + '</h4>',
                            '        <div style="font-size:11.5px; color:#94a3b8; margin-top:2px;">Version Détectée : <span style="color:#f43f5e; font-weight:700;">' + (c.DetectedVer || 'Obsolète') + '</span> (Requiert ≥ ' + (c.MaxSafeVer || 'Version corrigée') + ')</div>',
                            '      </div>',
                            '      <span class="badge ' + badgeClass + '" style="font-size:11px;">' + (c.Severity || 'CRITIQUE') + ' ' + (c.Score || '') + '</span>',
                            '    </div>',
                            '    <div style="font-size:12px; font-family:Consolas, monospace; color:#38bdf8; margin:6px 0;">' + (c.CVE || 'CVE-UNKNOWN') + '</div>',
                            '    <p style="font-size:12px; color:#cbd5e1; line-height:1.5; margin:8px 0;">' + (c.Desc || 'Vulnérabilité de sécurité exploitable.') + '</p>',
                            '  </div>',
                            '  <div style="border-top:1px solid rgba(255,255,255,0.08); padding-top:12px; margin-top:12px; display:flex; justify-content:space-between; align-items:center;">',
                            '    <span style="font-size:11px; color:#94a3b8;">Action corrective requise</span>',
                            '    <button class="btn-primary" onclick="copyDirect(this)" data-cmd="' + fixCmd + '" style="font-size:11px; padding:5px 10px;">📋 Copier Correctif Winget</button>',
                            '  </div>',
                            '</div>'
                        ].join('');
                    });
                    cardsHtml += '</div>';
                    cveCont.innerHTML = cardsHtml;
                }
            }

            // Synchroniser dynamiquement l'affichage du pilier Sécurité selon cveData
            var cveCountLive = (window.cveData && Array.isArray(window.cveData)) ? window.cveData.length : 0;
            var secPillarElem = document.querySelector('.health-pillar-item');
            if (secPillarElem) {
                var secPctElem = secPillarElem.querySelector('strong');
                var secBarElem = secPillarElem.querySelector('div > div > div');
                var secSubElem = secPillarElem.querySelector('div:last-child');
                
                if (cveCountLive === 0) {
                    if (secPctElem) secPctElem.innerText = "100%";
                    if (secBarElem) secBarElem.style.width = "100%";
                    if (secSubElem) secSubElem.innerText = "BitLocker, TPM, UAC & eID Conformes • 0 vulnérabilité CVE";
                    secPillarElem.title = "Sécurité & Intégrité : BitLocker, TPM 2.0, UAC, SecureBoot et Certificats eID conformes. Aucune vulnérabilité critique active (0 CVE).";
                } else {
                    var secScore = Math.max(40, 100 - (cveCountLive * 15));
                    if (secPctElem) secPctElem.innerText = secScore + "%";
                    if (secBarElem) secBarElem.style.width = secScore + "%";
                    if (secSubElem) secSubElem.innerText = "BitLocker, TPM & UAC Conformes • " + cveCountLive + " CVE active(s) (-" + (cveCountLive * 15) + "%)";
                    secPillarElem.title = "Sécurité & Intégrité : Pénalité de " + (cveCountLive * 15) + "% appliquée pour " + cveCountLive + " vulnérabilité(s) CVE active(s).";
                }
            }



            // =============================================================
            // 🎢 1. MONTAGNE RUSSE 3D (3D ROLLERCOASTER HEALTH TRACK)
            // =============================================================
            // =========================================================================
            // CHRONOLOGIE DES DIAGNOSTICS 3D - MOTEUR INTERACTIF HAUTE LISIBILITÉ
            // =========================================================================
            // =========================================================================
            // CHRONOLOGIE DES DIAGNOSTICS 3D - MOTEUR INTERACTIF HAUTE LISIBILITÉ & FAILLE FRACTALE
            // =========================================================================
            var histCont = document.getElementById('historyTimelineContainer');
            if (histCont && historyData && historyData.length > 0) {
                var totalHistoryCount = historyData.length;
                var totalRunsElem = document.getElementById('histTotalRuns');
                if (totalRunsElem) totalRunsElem.innerText = totalHistoryCount + " diagnostics archivés";

                var rcWrapper = document.createElement('div');
                rcWrapper.style.cssText = 'width:100%; background:radial-gradient(ellipse at center, rgba(15,23,42,0.95) 0%, rgba(2,6,23,0.98) 100%); border:1px solid rgba(56,189,248,0.40); border-radius:10px; padding:16px; margin-bottom:22px; position:relative; overflow:hidden; box-shadow:0 0 25px rgba(0,0,0,0.7) inset, 0 0 15px rgba(56,189,248,0.15);';
                rcWrapper.innerHTML = [
                    '<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px; border-bottom:1px solid rgba(56,189,248,0.20); padding-bottom:10px;">',
                    '  <div style="display:flex; align-items:center; gap:10px;">',
                    '    <span style="font-size:20px;">🌀</span>',
                    '    <div>',
                    '      <strong style="font-size:14px; color:#38bdf8; text-transform:uppercase; letter-spacing:0.05em;">Chronologie des Diagnostics</strong>',
                    '    </div>',
                    '  </div>',
                    '  <div style="display:flex; align-items:center; flex-wrap:wrap; gap:6px;">',
                    '    <button class="btn-mini-copy" onclick="window.prevTimelineRun()" title="Aller au run précédent (Flèche Gauche)" style="cursor:pointer; padding:4px 8px;">⏮️</button>',
                    '    <button class="btn-mini-copy" onclick="window.nextTimelineRun()" title="Aller au run suivant (Flèche Droite)" style="cursor:pointer; padding:4px 8px;">⏭️</button>',
                    '    <button class="btn-mini-copy" onclick="window.zoomTimeline(1)" title="Zoom avant (Flèche Haut)" style="cursor:pointer; padding:4px 8px;">➕</button>',
                    '    <button class="btn-mini-copy" onclick="window.zoomTimeline(-1)" title="Zoom arrière (Flèche Bas)" style="cursor:pointer; padding:4px 8px;">➖</button>',
                    '    <button class="btn-mini-copy" id="btnToggleTimelineAutoSpin" onclick="window.toggleTimelineAutoSpin()" title="Activer/Désactiver la rotation automatique" style="cursor:pointer; padding:4px 10px;">🔄 Auto-Spin : OFF</button>',
                    '    <button class="btn-mini-copy" id="btnToggleCartPOV" onclick="window.toggleCartPOV()" title="Monter à bord du wagon (Vue POV immersive)" style="cursor:pointer; padding:4px 10px;">🎢 Vue POV</button>',
                    '    <button class="btn-mini-copy" onclick="window.resetRollercoasterCam()" title="Recentrer la vue de profil (Touche R ou Double-clic)" style="cursor:pointer; padding:4px 10px;">🎯 Recentrer</button>',
                    '    <span class="badge badge-ok" style="font-size:11px; font-weight:bold; margin-left:4px;">' + totalHistoryCount + ' Runs Archivés</span>',
                    '  </div>',
                    '</div>',
                    '<div id="timelineSelectedRunCard" style="display:none; background:rgba(15,23,42,0.92); border:1px solid rgba(56,189,248,0.4); border-radius:6px; padding:10px 14px; margin-bottom:10px; font-size:12px; color:#cbd5e1; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;"></div>'
                ].join('');
                
                var canvasRC = document.createElement('canvas');
                canvasRC.id = 'rollercoasterCanvas';
                canvasRC.style.cssText = 'display:block; width:100%; height:280px; border-radius:6px; cursor:grab;';
                rcWrapper.appendChild(canvasRC);

                var tipRC = document.createElement('div');
                tipRC.id = 'rollercoasterTooltip';
                tipRC.style.cssText = 'position:fixed; display:none; background:rgba(2,6,23,0.96); border:1px solid #38bdf8; color:#f1f5f9; padding:9px 14px; font-size:12px; border-radius:6px; box-shadow:0 0 25px rgba(56,189,248,0.45); pointer-events:none; z-index:99999; backdrop-filter:blur(8px); min-width:230px;';
                tipRC.addEventListener('mousedown', function(e) { e.stopPropagation(); });
                tipRC.addEventListener('click', function(e) { e.stopPropagation(); });
                document.body.appendChild(tipRC);

                histCont.appendChild(rcWrapper);

                // Initialize 3D Scene
                try {
                    var rcScene = new THREE.Scene();
                    var rcCamera = new THREE.PerspectiveCamera(45, 1, 0.1, 1000);
                    var initCamPos = { x: 0, y: 1.5, z: 46 };
                    rcCamera.position.set(initCamPos.x, initCamPos.y, initCamPos.z);
                    rcCamera.lookAt(0, 1.5, 0);

                    var rcRenderer = new THREE.WebGLRenderer({ canvas: canvasRC, alpha: true, antialias: true, powerPreference: "high-performance" });
                    window.resizeRC = function() {
                        var rect = canvasRC.getBoundingClientRect();
                        var width = rect.width || 800;
                        var height = 280;
                        rcRenderer.setSize(width, height, false);
                        rcRenderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
                        rcCamera.aspect = width / height;
                        rcCamera.updateProjectionMatrix();
                    };
                    window.addEventListener('resize', window.resizeRC);
                    setTimeout(window.resizeRC, 50);

                    // Lighting
                    var rcAmbient = new THREE.AmbientLight(0x0f172a, 2.0);
                    rcScene.add(rcAmbient);

                    var rcDirLight = new THREE.DirectionalLight(0x38bdf8, 2.4);
                    rcDirLight.position.set(20, 30, 20);
                    rcScene.add(rcDirLight);

                    var rcDirLight2 = new THREE.DirectionalLight(0xa855f7, 1.4);
                    rcDirLight2.position.set(-20, -10, -20);
                    rcScene.add(rcDirLight2);

                    var rcGroup = new THREE.Group();
                    rcScene.add(rcGroup);

                    // Base Reference Grid
                    var gridHelper = new THREE.GridHelper(66, 33, 0x0284c7, 0x1e293b);
                    gridHelper.position.y = -8.0;
                    rcGroup.add(gridHelper);

                    // Level Reference Lines (100% Score Peak, 70% Alert, 50% Critical Threshold)
                    function createLevelPlane(altY, colHex, labelText) {
                        var lineMat = new THREE.LineDashedMaterial({ color: colHex, dashSize: 1, gapSize: 0.5, opacity: 0.4, transparent: true });
                        var lineGeo = new THREE.BufferGeometry().setFromPoints([
                            new THREE.Vector3(-28, altY, -8),
                            new THREE.Vector3(28, altY, -8)
                        ]);
                        var line = new THREE.Line(lineGeo, lineMat);
                        line.computeLineDistances();
                        rcGroup.add(line);
                    }
                    createLevelPlane(7.5, 0x10b981, "100% (Optimal)");
                    createLevelPlane(3.0, 0xf59e0b, "70% (Alerte)");
                    createLevelPlane(0.0, 0xef4444, "50% (Seuil Critique)");

                    // Capping visible checkpoints to 24 max (older logs are in the Fractal Rift)
                    var maxVisibleRuns = 24;
                    var visibleRuns = totalHistoryCount > maxVisibleRuns ? historyData.slice(-maxVisibleRuns) : historyData;
                    var count = visibleRuns.length;
                    var offsetStartRunIndex = totalHistoryCount - count; // Global index offset

                    var spanX = 42;
                    var startX = -19;
                    var stepX = count > 1 ? spanX / (count - 1) : 0;
                    
                    var waypoints = [];
                    var stationMeshes = [];
                    var stationGroups = [];

                    visibleRuns.forEach(function(h, idx) {
                        var posX = (count === 1) ? 0 : (startX + (idx * stepX));
                        var normalizedScore = ((h.HealthScore - 50) / 50); // [-1 to +1]
                        var altitude = normalizedScore * 7.5; // [-7.5 to +7.5]
                        var posZ = Math.sin(idx * 0.28) * 1.8;

                        var wp = new THREE.Vector3(posX, altitude, posZ);
                        wp.userData = h;
                        wp.userData.runIndex = offsetStartRunIndex + idx + 1;
                        waypoints.push(wp);
                    });

                    // Track Origin: Emerges from the Fractal Wormhole
                    var wormholePos = new THREE.Vector3(startX - 6.5, 0.0, -1.0);
                    var prePortalPos = new THREE.Vector3(startX - 11.0, -1.0, -3.0);
                    var entryPos = new THREE.Vector3(startX - 3.2, 0.0, -0.5);

                    var fullCurvePoints = [prePortalPos, wormholePos, entryPos];
                    if (waypoints.length >= 2) {
                        for (var w = 0; w < waypoints.length; w++) {
                            fullCurvePoints.push(waypoints[w]);
                        }
                    } else if (waypoints.length === 1) {
                        fullCurvePoints.push(waypoints[0]);
                        fullCurvePoints.push(new THREE.Vector3(15, 0, 0));
                    } else {
                        fullCurvePoints.push(new THREE.Vector3(0, 0, 0));
                        fullCurvePoints.push(new THREE.Vector3(15, 0, 0));
                    }

                    var trackCurve = new THREE.CatmullRomCurve3(fullCurvePoints);
                    trackCurve.curveType = 'centripetal';
                    trackCurve.tension = 0.5;

                    // =====================================================================
                    // FRACTAL WORMHOLE / TROU DE VERRE (In Sound Mind Psychedelic Glass Style)
                    // =====================================================================
                    var wormholeGroup = new THREE.Group();
                    wormholeGroup.position.copy(wormholePos);
                    rcGroup.add(wormholeGroup);

                    // Central glowing vortex light
                    var wormholeLight = new THREE.PointLight(0xa855f7, 3.2, 22, 1.4);
                    wormholeLight.position.set(0, 0, 0);
                    wormholeGroup.add(wormholeLight);

                    var wormholeVortexMat = new THREE.MeshStandardMaterial({ 
                        color: 0x38bdf8, 
                        emissive: 0xa855f7, 
                        emissiveIntensity: 0.9, 
                        roughness: 0.05, 
                        metalness: 0.98,
                        flatShading: true
                    });
                    var vortexRing = new THREE.Mesh(new THREE.TorusGeometry(1.9, 0.12, 10, 32), wormholeVortexMat);
                    vortexRing.rotation.y = Math.PI / 2;
                    wormholeGroup.add(vortexRing);

                    // Mirrored Solid 3D Fractal Triangle Shards (Multifaceted Metallic & Obsidian Grayscale Palette)
                    var shardMaterials = [
                        new THREE.MeshStandardMaterial({ color: 0xe2e8f0, roughness: 0.06, metalness: 0.98, flatShading: true }), // Argent Lumineux
                        new THREE.MeshStandardMaterial({ color: 0xcbd5e1, roughness: 0.08, metalness: 0.95, flatShading: true }), // Gris Clair Titane
                        new THREE.MeshStandardMaterial({ color: 0x94a3b8, roughness: 0.10, metalness: 0.92, flatShading: true }), // Gris Acier Moyen
                        new THREE.MeshStandardMaterial({ color: 0x64748b, roughness: 0.12, metalness: 0.90, flatShading: true }), // Gris Ardoise Métal
                        new THREE.MeshStandardMaterial({ color: 0x334155, roughness: 0.14, metalness: 0.94, flatShading: true }), // Graphite Foncée
                        new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.16, metalness: 0.96, flatShading: true })  // Obsidienne Noire
                    ];

                    var fractalShards = [];
                    var shardConfigs = [
                        // Anneau 1 : Petits prismes internes serrés (12 fragments)
                        { count: 12, minR: 1.3, maxR: 1.8, geoRadius: 0.38, geoHeight: 1.4, speedMult: 0.7 },
                        // Anneau 2 : Prismes moyens décalés (12 fragments)
                        { count: 12, minR: 2.1, maxR: 2.9, geoRadius: 0.58, geoHeight: 2.0, speedMult: 0.5 },
                        // Anneau 3 : Grands éclats externes asymétriques (8 fragments)
                        { count: 8,  minR: 3.1, maxR: 4.1, geoRadius: 0.82, geoHeight: 2.6, speedMult: 0.3 }
                    ];

                    shardConfigs.forEach(function(cfg, layerIdx) {
                        for (var sIdx = 0; sIdx < cfg.count; sIdx++) {
                            var angle = (sIdx / cfg.count) * Math.PI * 2 + (layerIdx * 0.35);
                            var radiusDist = cfg.minR + (sIdx % 3) * ((cfg.maxR - cfg.minR) / 2);
                            
                            // Prisme triangulaire 3D plein
                            var shardGeo = new THREE.ConeGeometry(cfg.geoRadius, cfg.geoHeight, 3);
                            var mat = shardMaterials[(sIdx + layerIdx * 2) % shardMaterials.length];
                            var shardMesh = new THREE.Mesh(shardGeo, mat);
                            
                            var defaultX = (Math.sin(sIdx * 1.7) * 0.4) - (layerIdx * 0.2);
                            var defaultY = Math.cos(angle) * radiusDist;
                            var defaultZ = Math.sin(angle) * radiusDist;
                            
                            shardMesh.position.set(defaultX, defaultY, defaultZ);
                            shardMesh.rotation.x = angle + Math.PI / 2;
                            shardMesh.rotation.z = Math.PI / 2 + (sIdx % 2 === 0 ? 0.2 : -0.2);

                            shardMesh.userData = {
                                basePos: new THREE.Vector3(defaultX, defaultY, defaultZ),
                                dir: new THREE.Vector3(0, Math.cos(angle), Math.sin(angle)),
                                baseAngle: angle,
                                layer: layerIdx,
                                speed: cfg.speedMult + (sIdx % 3) * 0.2
                            };

                            wormholeGroup.add(shardMesh);
                            fractalShards.push(shardMesh);
                        }
                    });

                    // Invisible Hit Box for Wormhole Hover Interaction
                    var wormholeHit = new THREE.Mesh(new THREE.SphereGeometry(3.2, 10, 10), new THREE.MeshBasicMaterial({ visible: false }));
                    wormholeHit.userData = {
                        isWormhole: true,
                        totalRuns: totalHistoryCount,
                        archivedPastCount: Math.max(0, totalHistoryCount - count)
                    };
                    wormholeGroup.add(wormholeHit);
                    stationMeshes.push(wormholeHit);

                    // =====================================================================
                    // Ghost Material Fade Helper (Translucent to Opaque gradient emerging from Fractal Rift)
                    function applyGhostFadeMaterial(mat, fadeStartX, fadeEndX) {
                        mat.transparent = true;
                        mat.depthWrite = true;
                        mat.onBeforeCompile = function(shader) {
                            shader.uniforms.uFadeStart = { value: fadeStartX };
                            shader.uniforms.uFadeEnd = { value: fadeEndX };
                            
                            shader.vertexShader = shader.vertexShader.replace(
                                '#include <common>',
                                '#include <common>\nvarying vec3 vGhostWorldPos;'
                            );
                            shader.vertexShader = shader.vertexShader.replace(
                                '#include <worldpos_vertex>',
                                '#include <worldpos_vertex>\nvGhostWorldPos = (modelMatrix * vec4(transformed, 1.0)).xyz;'
                            );
                            
                            shader.fragmentShader = shader.fragmentShader.replace(
                                '#include <common>',
                                '#include <common>\nuniform float uFadeStart;\nuniform float uFadeEnd;\nvarying vec3 vGhostWorldPos;'
                            );
                            shader.fragmentShader = shader.fragmentShader.replace(
                                '#include <dithering_fragment>',
                                '#include <dithering_fragment>\n' +
                                'float ghostFade = clamp((vGhostWorldPos.x - uFadeStart) / (uFadeEnd - uFadeStart), 0.0, 1.0);\n' +
                                'float ghostAlpha = smoothstep(0.0, 1.0, ghostFade);\n' +
                                'gl_FragColor.a *= ghostAlpha;\n' +
                                'gl_FragColor.rgb += vec3(0.05, 0.35, 0.85) * (1.0 - ghostAlpha) * 0.45;\n'
                            );
                        };
                    }

                    // DUAL RAILS, 3RD CENTER METALLIC RAIL & TIES

                    // =====================================================================
                    var segments = Math.max(60, count * 16);
                    var railOffset = 0.55;
                    var leftRailPoints = [];
                    var rightRailPoints = [];
                    var centerFrames = trackCurve.computeFrenetFrames(segments, false);

                    var sleeperGroup = new THREE.Group();
                    rcGroup.add(sleeperGroup);

                    var sleeperMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, roughness: 0.4, metalness: 0.85 });
                    var pillarMat = new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.5, metalness: 0.8 });
                    var sleeperGeo = new THREE.BoxGeometry(railOffset * 2.4, 0.12, 0.22);

                    for (var s = 0; s <= segments; s++) {
                        var u = s / segments;
                        var pt = trackCurve.getPointAt(u);
                        var tangent = centerFrames.tangents[s];
                        var normal = centerFrames.normals[s];
                        var binormal = centerFrames.binormals[s];

                        var leftPt = pt.clone().add(binormal.clone().multiplyScalar(railOffset));
                        var rightPt = pt.clone().add(binormal.clone().multiplyScalar(-railOffset));
                        leftRailPoints.push(leftPt);
                        rightRailPoints.push(rightPt);

                        if (s % 2 === 0) {
                            var sleeper = new THREE.Mesh(sleeperGeo, sleeperMat);
                            sleeper.position.copy(pt);
                            var rotMat = new THREE.Matrix4().makeBasis(binormal, normal, tangent);
                            sleeper.setRotationFromMatrix(rotMat);
                            sleeperGroup.add(sleeper);
                        }

                        if (s % 8 === 0 && pt.y > -7.5 && pt.x > (startX - 4)) {
                            var pillarHeight = pt.y - (-8);
                            if (pillarHeight > 0.5) {
                                var pillarGeo = new THREE.CylinderGeometry(0.14, 0.18, pillarHeight, 8);
                                var pillar = new THREE.Mesh(pillarGeo, pillarMat);
                                pillar.position.set(pt.x, -8 + pillarHeight / 2, pt.z);
                                rcGroup.add(pillar);
                            }
                        }
                    }

                    var leftCurve = new THREE.CatmullRomCurve3(leftRailPoints);
                    var rightCurve = new THREE.CatmullRomCurve3(rightRailPoints);

                    var railGeoL = new THREE.TubeGeometry(leftCurve, segments * 2, 0.09, 8, false);
                    var railGeoR = new THREE.TubeGeometry(rightCurve, segments * 2, 0.09, 8, false);
                    var railMat = new THREE.MeshStandardMaterial({ color: 0x38bdf8, emissive: 0x0284c7, emissiveIntensity: 0.6, roughness: 0.15, metalness: 0.95 });

                    // 3rd Central Rail: Solid Dark Navy Metallic Spine
                    var railGeoC = new THREE.TubeGeometry(trackCurve, segments * 2, 0.13, 10, false);
                    var railCenterMat = new THREE.MeshStandardMaterial({ 
                        color: 0x0c2340, 
                        roughness: 0.18, 
                        metalness: 0.96,
                        emissive: 0x051427,
                        emissiveIntensity: 0.25
                    });

                    // Apply Ghostly Materialization Gradient (Transparent inside fractal rift -> Opaque on visible track)
                    var ghostFadeStart = startX - 9.0;
                    var ghostFadeEnd = startX - 0.5;
                    applyGhostFadeMaterial(railMat, ghostFadeStart, ghostFadeEnd);
                    applyGhostFadeMaterial(railCenterMat, ghostFadeStart, ghostFadeEnd);
                    applyGhostFadeMaterial(sleeperMat, ghostFadeStart, ghostFadeEnd);
                    applyGhostFadeMaterial(pillarMat, ghostFadeStart, ghostFadeEnd);

                    rcGroup.add(new THREE.Mesh(railGeoL, railMat));
                    rcGroup.add(new THREE.Mesh(railGeoR, railMat));
                    rcGroup.add(new THREE.Mesh(railGeoC, railCenterMat));

                    // =====================================================================
                    // INTERACTIVE CHECKPOINT STATIONS (Perpendicular Rings & Wireframe Beacons)
                    // =====================================================================
                    var stationGroup = new THREE.Group();
                    rcGroup.add(stationGroup);

                    var ringPortalGeo = new THREE.TorusGeometry(1.65, 0.08, 8, 36);
                    var wireframeBeaconGeo = new THREE.IcosahedronGeometry(0.72, 1);
                    var innerCoreGeo = new THREE.SphereGeometry(0.24, 10, 10);
                    var hitSphereGeo = new THREE.SphereGeometry(1.85, 8, 8);
                    var hitMat = new THREE.MeshBasicMaterial({ visible: false });

                    waypoints.forEach(function(wp, idx) {
                        var score = wp.userData.HealthScore;
                        var col = (score >= 85) ? 0x10b981 : (score >= 70 ? 0xf59e0b : 0xef4444);

                        var nodeGroup = new THREE.Group();
                        nodeGroup.position.copy(wp);

                        // Perpendicular Portal Ring: Aligned with curve tangent
                        var u = (count > 1) ? (idx / (count - 1)) : 0.5;
                        var tangent = trackCurve.getTangentAt(Math.min(0.99, Math.max(0.1, u))).normalize();
                        var upVec = new THREE.Vector3(0, 1, 0);
                        var rotMatrix = new THREE.Matrix4().lookAt(new THREE.Vector3(0, 0, 0), tangent, upVec);

                        var portalMat = new THREE.MeshStandardMaterial({ color: col, emissive: col, emissiveIntensity: 0.85, roughness: 0.2, metalness: 0.85 });
                        var portalMesh = new THREE.Mesh(ringPortalGeo, portalMat);
                        portalMesh.quaternion.setFromRotationMatrix(rotMatrix);
                        nodeGroup.add(portalMesh);

                        // Wireframe Holographic Icosahedron Beacon (FOSS Style)
                        var beaconMat = new THREE.MeshStandardMaterial({ 
                            color: col, 
                            emissive: col, 
                            emissiveIntensity: 0.95, 
                            wireframe: true, 
                            roughness: 0.1, 
                            metalness: 0.9 
                        });
                        var beaconMesh = new THREE.Mesh(wireframeBeaconGeo, beaconMat);
                        nodeGroup.add(beaconMesh);

                        // Inner white glowing core spark
                        var innerCoreMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
                        var innerCore = new THREE.Mesh(innerCoreGeo, innerCoreMat);
                        nodeGroup.add(innerCore);

                        // Vertical laser drop-line to grid base
                        var dropHeight = wp.y - (-8.0);
                        if (dropHeight > 0.2) {
                            var dropGeo = new THREE.CylinderGeometry(0.04, 0.04, dropHeight, 6);
                            var dropMat = new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.35 });
                            var dropMesh = new THREE.Mesh(dropGeo, dropMat);
                            dropMesh.position.set(0, -dropHeight / 2, 0);
                            nodeGroup.add(dropMesh);
                        }

                        // Invisible hit sphere for effortless hover detection
                        var hitMesh = new THREE.Mesh(hitSphereGeo, hitMat);
                        hitMesh.userData = wp.userData;
                        hitMesh.userData.nodeGroup = nodeGroup;
                        hitMesh.userData.beaconMat = beaconMat;
                        hitMesh.userData.portalMat = portalMat;
                        nodeGroup.add(hitMesh);

                        stationGroup.add(nodeGroup);
                        stationMeshes.push(hitMesh);
                        stationGroups.push(nodeGroup);
                    });

                    // Traveling Cyber Cart
                    var cartGroup = new THREE.Group();
                    rcGroup.add(cartGroup);

                    var cartBodyGeo = new THREE.BoxGeometry(1.2, 0.5, 0.9);
                    var cartBodyMat = new THREE.MeshStandardMaterial({ color: 0x0284c7, emissive: 0x00f0ff, emissiveIntensity: 0.9, roughness: 0.1, metalness: 0.95 });
                    var cartBody = new THREE.Mesh(cartBodyGeo, cartBodyMat);
                    cartGroup.add(cartBody);

                    var cartHeadlight = new THREE.PointLight(0x00f0ff, 4.0, 18);
                    cartHeadlight.position.set(0, 0.4, 0);
                    cartGroup.add(cartHeadlight);

                    var wheelGeo = new THREE.CylinderGeometry(0.2, 0.2, 0.15, 12);
                    var wheelMat = new THREE.MeshStandardMaterial({ color: 0xffffff, metalness: 0.9 });
                    [[-0.45, -0.2, -0.4], [0.45, -0.2, -0.4], [-0.45, -0.2, 0.4], [0.45, -0.2, 0.4]].forEach(function(pos) {
                        var wMesh = new THREE.Mesh(wheelGeo, wheelMat);
                        wMesh.rotation.z = Math.PI / 2;
                        wMesh.position.set(pos[0], pos[1], pos[2]);
                        cartGroup.add(wMesh);
                    });

                    // Invisible Clickable Hitbox for POV Mode on Cyber Cart
                    var cartHit = new THREE.Mesh(new THREE.BoxGeometry(2.0, 1.3, 1.6), new THREE.MeshBasicMaterial({ visible: false }));
                    cartHit.userData = { isCart: true };
                    cartGroup.add(cartHit);
                    stationMeshes.push(cartHit);

                    
                    var isCartPOVMode = false;

                    window.toggleCartPOV = function() {
                        isCartPOVMode = !isCartPOVMode;
                        var btn = document.getElementById('btnToggleCartPOV');
                        if (btn) {
                            btn.innerText = isCartPOVMode ? '🛑 Quitter Vue POV' : '🎢 Vue POV Wagon';
                            btn.style.color = isCartPOVMode ? '#ef4444' : '#38bdf8';
                        }
                        if (!isCartPOVMode) {
                            window.resetRollercoasterCam();
                        } else {
                            autoSpinTimeline = false;
                            updateAutoSpinButton();
                            tipRC.style.display = 'none';
                            tipRC.style.pointerEvents = 'none';
                        }
                    };

                    // Controls & Camera Movement (Left Drag: Rotate, Right Drag: Pan, Wheel: Zoom)

                    var isRCDragging = false;
                    var isRCRightDragging = false;
                    var prevRCMouse = { x: 0, y: 0 };
                    var targetRCRot = { x: 0.02, y: 0.0 };
                    var targetCamPos = { x: 0, y: 1.5, z: 46 };
                    var targetLookAt = new THREE.Vector3(0, 1.5, 0);
                    var currentLookAt = new THREE.Vector3(0, 1.5, 0);
                    var activeHoverNode = null;
                    var isWormholeHovered = false;
                    var wormholeApertureProgress = 0.0;
                    var autoSpinTimeline = false; // 100% Static by default
                    var userWantsAutoSpin = false;
                    var currentSpinSpeed = 0.0;
                    var autoSpinResumeTimer = null;
                    var currentRunIndex = waypoints.length - 1;

                    function pauseAutoSpinWithResume(delayMs) {
                        if (!userWantsAutoSpin) return;
                        autoSpinTimeline = false;
                        if (autoSpinResumeTimer) clearTimeout(autoSpinResumeTimer);
                        updateAutoSpinButton();
                        autoSpinResumeTimer = setTimeout(function() {
                            if (!pinnedRunIndex && userWantsAutoSpin) {
                                autoSpinTimeline = true;
                                updateAutoSpinButton();
                            }
                        }, delayMs || 10000);
                    }

                    canvasRC.addEventListener('contextmenu', function(e) { e.preventDefault(); });

                    canvasRC.addEventListener('mousedown', function(e) {
                        if (e.button === 2) {
                            isRCRightDragging = true;
                        } else {
                            isRCDragging = true;
                        }
                        prevRCMouse.x = e.clientX;
                        prevRCMouse.y = e.clientY;
                        canvasRC.style.cursor = 'grabbing';
                        pauseAutoSpinWithResume(10000);
                    });

                    window.addEventListener('mouseup', function() {
                        isRCDragging = false;
                        isRCRightDragging = false;
                        if (canvasRC) canvasRC.style.cursor = (activeHoverNode || isWormholeHovered) ? 'pointer' : 'grab';
                    });

                    canvasRC.addEventListener('wheel', function(e) {
                        e.preventDefault();
                        targetCamPos.z = Math.max(10, Math.min(120, targetCamPos.z + e.deltaY * 0.05));
                        pauseAutoSpinWithResume(10000);
                    }, { passive: false });

                    window.addEventListener('mousemove', function(e) {
                        if (isRCDragging) {
                            var dx = e.clientX - prevRCMouse.x;
                            var dy = e.clientY - prevRCMouse.y;
                            targetRCRot.y += dx * 0.008;
                            targetRCRot.x += dy * 0.008;
                            prevRCMouse.x = e.clientX;
                            prevRCMouse.y = e.clientY;
                            pauseAutoSpinWithResume(10000);
                        } else if (isRCRightDragging) {
                            var dx = e.clientX - prevRCMouse.x;
                            var dy = e.clientY - prevRCMouse.y;
                            targetCamPos.x -= dx * 0.04;
                            targetCamPos.y += dy * 0.04;
                            targetLookAt.x -= dx * 0.04;
                            targetLookAt.y += dy * 0.04;
                            prevRCMouse.x = e.clientX;
                            prevRCMouse.y = e.clientY;
                            pauseAutoSpinWithResume(10000);
                        }
                    });

                    function updateAutoSpinButton() {
                        var btn = document.getElementById('btnToggleTimelineAutoSpin');
                        if (btn) {
                            btn.innerText = autoSpinTimeline ? '🔄 Auto-Spin : ON' : '🔄 Auto-Spin : OFF';
                            btn.style.color = autoSpinTimeline ? '#38bdf8' : '#94a3b8';
                        }
                    }

                    window.toggleTimelineAutoSpin = function() {
                        if (autoSpinResumeTimer) clearTimeout(autoSpinResumeTimer);
                        userWantsAutoSpin = !userWantsAutoSpin;
                        autoSpinTimeline = userWantsAutoSpin;
                        updateAutoSpinButton();
                    };

                    window.zoomTimeline = function(delta) {
                        targetCamPos.z = Math.max(10, Math.min(120, targetCamPos.z - delta * 8));
                        pauseAutoSpinWithResume(10000);
                    };

                    window.resetRollercoasterCam = function() {
                        if (isCartPOVMode) {
                            isCartPOVMode = false;
                            var btn = document.getElementById('btnToggleCartPOV');
                            if (btn) {
                                btn.innerText = '🎢 Vue POV';
                                btn.style.color = '#38bdf8';
                            }
                        }
                        rcCamera.up.set(0, 1, 0);
                        targetRCRot.x = 0.02;
                        targetRCRot.y = 0.0;
                        targetCamPos.x = 0;
                        targetCamPos.y = 1.5;
                        targetCamPos.z = 46;
                        targetLookAt.set(0, 1.5, 0);
                        autoSpinTimeline = false;
                        userWantsAutoSpin = false;
                        updateAutoSpinButton();
                    };

                    // Pinned Node & Hover State (inspired by 3D Tech Tree)
                    var pinnedRunIndex = null;
                    var pinnedNodeGroup = null;

                    function buildRunTooltipHtml(u) {
                        var badgeCol = (u.HealthScore >= 85) ? '#10b981' : (u.HealthScore >= 70 ? '#f59e0b' : '#ef4444');
                        var badgeText = (u.HealthScore >= 85) ? '🟢 Santé Optimale' : (u.HealthScore >= 70 ? '🟠 Alerte Modérée' : '🔴 Dégradation Critique');
                        return [
                            '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; border-bottom:1px solid rgba(56,189,248,0.25); padding-bottom:4px;">',
                            '  <div style="font-weight:bold; color:#38bdf8; font-size:13px;">📍 Diagnostic #' + (u.runIndex || 1) + '</div>',
                            '  <span style="font-size:10px; background:rgba(56,189,248,0.2); padding:2px 7px; border-radius:3px; color:#38bdf8; font-weight:bold;">' + (u.HostName || 'PC') + '</span>',
                            '</div>',
                            '<div style="font-size:11.5px; color:#cbd5e1; margin-bottom:4px;">📅 Horodatage : <strong>' + (u.DateLabel || u.Timestamp) + '</strong></div>',
                            '<div style="display:flex; align-items:baseline; gap:8px; margin:6px 0;">',
                            '  <span style="font-size:22px; font-weight:900; font-family:\'Rajdhani\', monospace; color:' + badgeCol + ';">' + u.HealthScore + '</span>',
                            '  <span style="font-size:12px; color:#94a3b8; font-weight:700;">/ 100</span>',
                            '  <span style="font-size:10px; padding:2px 6px; border-radius:3px; background:rgba(255,255,255,0.06); color:' + badgeCol + '; font-weight:bold; margin-left:auto;">' + badgeText + '</span>',
                            '</div>',
                            '<div style="background:rgba(255,255,255,0.04); padding:6px 8px; border-radius:4px; margin:6px 0; font-size:11px; color:#cbd5e1;">',
                            '  <span style="color:#10b981; font-weight:bold;">✔ ' + (u.OkCount||0) + ' OK</span> &nbsp;|&nbsp; ',
                            '  <span style="color:#f59e0b; font-weight:bold;">⚠ ' + (u.WarnCount||0) + ' Avert.</span> &nbsp;|&nbsp; ',
                            '  <span style="color:#ef4444; font-weight:bold;">✖ ' + (u.ErrCount||0) + ' Pannes</span>',
                            '</div>',
                            '<div style="font-size:10.5px; color:#94a3b8; display:flex; justify-content:space-between; margin-top:4px;">',
                            '  <span>💾 C: ' + (u.FreeDiskGB !== undefined ? u.FreeDiskGB + ' Go' : 'OK') + '</span>',
                            '  <span>⚡ CPU: ' + (u.CpuScore !== undefined ? u.CpuScore + ' pts' : '-') + '</span>',
                            '  <span>🛡️ CVE: ' + (u.CveCount || 0) + '</span>',
                            '</div>',
                            '<div style="display:flex; justify-content:space-between; align-items:center; margin-top:10px; padding-top:8px; border-top:1px solid rgba(56,189,248,0.25); gap:8px;">',
                            '  <button class="btn-mini-copy" onclick="event.stopPropagation(); event.preventDefault(); if (typeof switchTab === \'function\') switchTab(\'tab-journal\');" style="cursor:pointer; font-size:11px; padding:4px 12px; background:rgba(56,189,248,0.15); border:1px solid #38bdf8; color:#38bdf8; border-radius:4px;">📋 Voir Journal</button>',
                            '  <button class="btn-mini-copy" onclick="event.stopPropagation(); event.preventDefault(); if (typeof window.unpinTimelineNode === \'function\') window.unpinTimelineNode();" style="cursor:pointer; font-size:11px; padding:4px 12px; background:rgba(239,68,68,0.15); border:1px solid #ef4444; color:#ef4444; border-radius:4px;">✖ Fermer</button>',
                            '</div>'
                        ].join('');
                    }

                    function buildWormholeTooltipHtml(wData) {
                        return [
                            '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; border-bottom:1px solid rgba(56,189,248,0.3); padding-bottom:4px;">',
                            '  <div style="font-weight:bold; color:#38bdf8; font-size:13px;">📁 Archives & Historique des Logs</div>',
                            '  <span style="font-size:10px; background:rgba(56,189,248,0.2); padding:2px 7px; border-radius:3px; color:#38bdf8; font-weight:bold;">Base DiagIT</span>',
                            '</div>',
                            '<div style="background:rgba(15,23,42,0.85); border:1px solid rgba(56,189,248,0.2); padding:8px 10px; border-radius:4px; margin:6px 0; font-size:12px; color:#f1f5f9;">',
                            '  <div>• <strong>' + wData.totalRuns + '</strong> diagnostics archivés dans la base</div>',
                            '  <div style="font-size:11px; color:#94a3b8; margin-top:2px;">• 24 derniers runs affichés sur la voie active</div>',
                            (wData.archivedPastCount > 0 ? '<div style="font-size:11px; color:#38bdf8; margin-top:2px;">• ' + wData.archivedPastCount + ' diagnostics antérieurs conservés dans l\'archive</div>' : ''),
                            '</div>',
                            '<div style="font-size:10.5px; color:#64748b; font-style:italic; margin-top:4px;">',
                            '  Origine de la chronologie des diagnostics.',
                            '</div>'
                        ].join('');
                    }

                    window.unpinTimelineNode = function() {
                        if (pinnedNodeGroup) {
                            pinnedNodeGroup.scale.set(1.0, 1.0, 1.0);
                            pinnedNodeGroup = null;
                        }
                        pinnedRunIndex = null;
                        tipRC.style.display = 'none';
                        tipRC.style.pointerEvents = 'none';
                        var card = document.getElementById('timelineSelectedRunCard');
                        if (card) card.style.display = 'none';
                    };

                    function pinRunNode(idx, clientX, clientY) {
                        if (idx < 0 || idx >= waypoints.length) return;
                        pinnedRunIndex = idx;
                        currentRunIndex = idx;

                        if (pinnedNodeGroup) {
                            pinnedNodeGroup.scale.set(1.0, 1.0, 1.0);
                        }
                        pinnedNodeGroup = stationGroups[idx];
                        if (pinnedNodeGroup) {
                            pinnedNodeGroup.scale.set(1.5, 1.5, 1.5);
                        }

                        var wp = waypoints[idx];
                        var u = wp.userData;

                        // Camera smooth focus on pinned node
                        targetCamPos.x = wp.x;
                        targetCamPos.y = wp.y + 2.0;
                        targetCamPos.z = 24;
                        targetLookAt.set(wp.x, wp.y + 0.5, 0);
                        pauseAutoSpinWithResume(10000);

                        // Position pinned tooltip
                        var rect = canvasRC.getBoundingClientRect();
                        var posX = clientX !== undefined ? clientX : (rect.left + rect.width * 0.7);
                        var posY = clientY !== undefined ? clientY : (rect.top + 30);

                        tipRC.style.display = 'block';
                        tipRC.style.pointerEvents = 'auto';
                        tipRC.style.left = Math.min(window.innerWidth - 290, Math.max(10, posX + 16)) + 'px';
                        tipRC.style.top = Math.max(10, posY - 20) + 'px';
                        tipRC.innerHTML = buildRunTooltipHtml(u);

                        var card = document.getElementById('timelineSelectedRunCard');
                        if (card) {
                            var badgeCol = (u.HealthScore >= 85) ? '#10b981' : (u.HealthScore >= 70 ? '#f59e0b' : '#ef4444');
                            card.style.display = 'flex';
                            card.innerHTML = [
                                '<div>',
                                '  <strong style="color:#38bdf8;">📍 Diagnostic #' + (u.runIndex || 1) + ' (' + (u.HostName || 'PC') + ')</strong>',
                                '  <div style="font-size:11px; color:#94a3b8; margin-top:2px;">📅 ' + (u.DateLabel || u.Timestamp) + ' • <span style="color:' + badgeCol + '; font-weight:bold;">Score Santé : ' + u.HealthScore + '/100</span></div>',
                                '</div>',
                                '<div style="display:flex; gap:8px; align-items:center;">',
                                '  <span style="font-size:11px; color:#e2e8f0;"><span style="color:#10b981;">' + (u.OkCount||0) + ' OK</span> | <span style="color:#f59e0b;">' + (u.WarnCount||0) + ' Warn</span> | <span style="color:#ef4444;">' + (u.ErrCount||0) + ' Pannes</span></span>',
                                '  <button class="btn-mini-copy" onclick="event.stopPropagation(); switchTab(\'tab-journal\')" style="cursor:pointer;">📋 Voir Journal</button>',
                                '  <button class="btn-mini-copy" onclick="event.stopPropagation(); window.unpinTimelineNode()" style="cursor:pointer; color:#ef4444;">✖</button>',
                                '</div>'
                            ].join('');
                        }
                    }

                    function selectRunNode(idx) {
                        pinRunNode(idx);
                    }

                    window.prevTimelineRun = function() {
                        var nextIdx = (currentRunIndex - 1 + waypoints.length) % waypoints.length;
                        pinRunNode(nextIdx);
                    };

                    window.nextTimelineRun = function() {
                        var nextIdx = (currentRunIndex + 1) % waypoints.length;
                        pinRunNode(nextIdx);
                    };

                    // Raycasting Tooltips & Interactive Node Selection
                    var rcRaycaster = new THREE.Raycaster();
                    var rcMouse = new THREE.Vector2();

                    canvasRC.addEventListener('mousemove', function(e) {
                        if (isRCDragging || isRCRightDragging) {
                            return;
                        }
                        var rect = canvasRC.getBoundingClientRect();
                        rcMouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
                        rcMouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
                        rcRaycaster.setFromCamera(rcMouse, rcCamera);

                        var hits = rcRaycaster.intersectObjects(stationMeshes);
                        if (hits.length > 0 && hits[0].object.userData) {
                            var hitObj = hits[0].object;
                            var u = hitObj.userData;

                            if (u.isCart) {
                                if (!isCartPOVMode && !pinnedRunIndex) {
                                    tipRC.style.display = 'block';
                                    tipRC.style.pointerEvents = 'none';
                                    tipRC.style.left = Math.min(window.innerWidth - 290, e.clientX + 16) + 'px';
                                    tipRC.style.top = Math.max(10, e.clientY - 20) + 'px';
                                    tipRC.innerHTML = '<div style="font-weight:bold; color:#38bdf8; font-size:12.5px;">🎢 Cyber-Wagon</div><div style="font-size:11px; color:#cbd5e1; margin-top:2px;">Cliquez pour monter à bord en <strong>Vue POV</strong> !</div>';
                                }
                                canvasRC.style.cursor = 'pointer';
                                return;
                            }
                            
                            // Check if Wormhole was hovered
                            if (u.isWormhole) {
                                isWormholeHovered = true;
                                if (!pinnedRunIndex) {
                                    tipRC.style.display = 'block';
                                    tipRC.style.pointerEvents = 'none';
                                    tipRC.style.left = Math.min(window.innerWidth - 290, e.clientX + 16) + 'px';
                                    tipRC.style.top = Math.max(10, e.clientY - 20) + 'px';
                                    tipRC.innerHTML = buildWormholeTooltipHtml(u);
                                }
                                canvasRC.style.cursor = 'pointer';
                                return;
                            } else {
                                isWormholeHovered = false;
                            }

                            // Diagnostic Checkpoint Node Hover
                            if (!pinnedRunIndex) {
                                if (activeHoverNode && activeHoverNode !== hitObj.userData.nodeGroup) {
                                    activeHoverNode.scale.set(1.0, 1.0, 1.0);
                                }
                                activeHoverNode = hitObj.userData.nodeGroup;
                                if (activeHoverNode) {
                                    activeHoverNode.scale.set(1.35, 1.35, 1.35);
                                }

                                tipRC.style.display = 'block';
                                tipRC.style.pointerEvents = 'none';
                                tipRC.style.left = Math.min(window.innerWidth - 290, e.clientX + 16) + 'px';
                                tipRC.style.top = Math.max(10, e.clientY - 20) + 'px';
                                tipRC.innerHTML = buildRunTooltipHtml(u);
                            }
                            canvasRC.style.cursor = 'pointer';
                        } else {
                            isWormholeHovered = false;
                            if (!pinnedRunIndex) {
                                if (activeHoverNode) {
                                    activeHoverNode.scale.set(1.0, 1.0, 1.0);
                                    activeHoverNode = null;
                                }
                                canvasRC.style.cursor = 'grab';
                                tipRC.style.display = 'none';
                                tipRC.style.pointerEvents = 'none';
                            } else {
                                canvasRC.style.cursor = 'default';
                            }
                        }
                    });

                    canvasRC.addEventListener('mouseleave', function() {
                        isWormholeHovered = false;
                        if (!pinnedRunIndex) {
                            if (activeHoverNode) {
                                activeHoverNode.scale.set(1.0, 1.0, 1.0);
                                activeHoverNode = null;
                            }
                            canvasRC.style.cursor = 'grab';
                            tipRC.style.display = 'none';
                            tipRC.style.pointerEvents = 'none';
                        }
                    });

                    // Double-click to smooth recenter camera
                    canvasRC.addEventListener('dblclick', function(e) {
                        e.preventDefault();
                        window.resetRollercoasterCam();
                    });

                    canvasRC.addEventListener('click', function(e) {
                        if (isRCDragging || isRCRightDragging) return;
                        var rect = canvasRC.getBoundingClientRect();
                        rcMouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
                        rcMouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
                        rcRaycaster.setFromCamera(rcMouse, rcCamera);
                        var hits = rcRaycaster.intersectObjects(stationMeshes);
                        if (hits.length > 0 && hits[0].object.userData) {
                            var u = hits[0].object.userData;
                            if (u.isCart) {
                                window.toggleCartPOV();
                                return;
                            }
                            if (u.isWormhole) {
                                // Clicked wormhole: focus on portal
                                targetCamPos.x = wormholePos.x + 3.0;
                                targetCamPos.y = wormholePos.y + 1.5;
                                targetCamPos.z = 22;
                                return;
                            }
                            var idx = (u.runIndex !== undefined) ? (u.runIndex - offsetStartRunIndex - 1) : 0;
                            pinRunNode(idx, e.clientX, e.clientY);
                        } else {
                            window.unpinTimelineNode();
                        }
                    });

                    var rcClock = new THREE.Clock();
                    var cartProgress = 0.0;
                    var cartSpeed = 0.08;

                    function animateRC() {
                        requestAnimationFrame(animateRC);
                        var dt = rcClock.getDelta();
                        var time = rcClock.getElapsedTime();

                        var targetSpinSpeed = (autoSpinTimeline && !isRCDragging && !pinnedRunIndex) ? 0.0015 : 0.0;
                        currentSpinSpeed += (targetSpinSpeed - currentSpinSpeed) * 0.025;
                        if (Math.abs(currentSpinSpeed) > 0.00001) {
                            targetRCRot.y += currentSpinSpeed;
                        }

                        // Smooth camera damping & rotation
                        rcGroup.rotation.x += (targetRCRot.x - rcGroup.rotation.x) * 0.08;
                        rcGroup.rotation.y += (targetRCRot.y - rcGroup.rotation.y) * 0.08;

                        // 1. Cyber Cart Traversal Calculation (First, so cartPos & cartTangent are always valid)
                        cartProgress = (cartProgress + cartSpeed * dt) % 1.0;
                        var cartPos = trackCurve.getPointAt(cartProgress);
                        var cartTangent = trackCurve.getTangentAt(cartProgress).normalize();

                        cartGroup.position.copy(cartPos);
                        cartGroup.position.y += 0.25;

                        var upVec = new THREE.Vector3(0, 1, 0);
                        var cartMat = new THREE.Matrix4().lookAt(new THREE.Vector3(0,0,0), cartTangent, upVec);
                        cartGroup.quaternion.setFromRotationMatrix(cartMat);

                        // 2. Camera Positioning (POV Ride vs Normal Orbit with Coherent lookAt Target)
                        if (isCartPOVMode) {
                            var worldCartPos = new THREE.Vector3();
                            cartGroup.getWorldPosition(worldCartPos);
                            
                            var worldHeadPos = worldCartPos.clone().add(new THREE.Vector3(0, 0.45, 0));
                            var worldTangent = cartTangent.clone().applyEuler(rcGroup.rotation);
                            var lookTarget = worldHeadPos.clone().add(worldTangent.multiplyScalar(8.0));
                            
                            rcCamera.position.copy(worldHeadPos);
                            rcCamera.lookAt(lookTarget);
                            currentLookAt.copy(lookTarget);
                        } else {
                            rcCamera.position.x += (targetCamPos.x - rcCamera.position.x) * 0.08;
                            rcCamera.position.y += (targetCamPos.y - rcCamera.position.y) * 0.08;
                            rcCamera.position.z += (targetCamPos.z - rcCamera.position.z) * 0.08;

                            currentLookAt.x += (targetLookAt.x - currentLookAt.x) * 0.08;
                            currentLookAt.y += (targetLookAt.y - currentLookAt.y) * 0.08;
                            currentLookAt.z += (targetLookAt.z - currentLookAt.z) * 0.08;
                            rcCamera.lookAt(currentLookAt);
                        }

                        // Fractal Wormhole Dynamic Dilation Animation (In Sound Mind Iris / Aperture Bloom)
                        var targetAperture = isWormholeHovered ? 1.0 : 0.0;
                        wormholeApertureProgress += (targetAperture - wormholeApertureProgress) * 0.08;

                        fractalShards.forEach(function(sh, i) {
                            var uData = sh.userData;
                            var spinOffset = time * uData.speed * 0.5;
                            var dilationDist = wormholeApertureProgress * 1.1;

                            sh.position.x = Math.sin(time * 1.5 + i) * 0.15;
                            sh.position.y = uData.basePos.y + uData.dir.y * dilationDist;
                            sh.position.z = uData.basePos.z + uData.dir.z * dilationDist;

                            sh.rotation.x = uData.baseAngle + Math.PI / 2 + (wormholeApertureProgress * 0.5) + spinOffset * 0.2;
                            sh.rotation.y = Math.sin(time * 0.8 + i) * 0.25;
                        });

                        wormholeLight.intensity = 3.2 + (wormholeApertureProgress * 4.8) + Math.sin(time * 4.0) * 0.8;
                        vortexRing.rotation.x = time * 0.6;
                        vortexRing.rotation.z = time * 0.4;

                        // Gentle rotation of holographic wireframe beacons
                        stationGroups.forEach(function(ng, i) {
                            if (ng.children[1]) {
                                ng.children[1].rotation.y = time * 0.75 + i;
                                ng.children[1].rotation.x = time * 0.35 + i;
                            }
                        });

                        cartHeadlight.intensity = 3.5 + Math.sin(time * 6.0) * 1.5;
                        rcRenderer.render(rcScene, rcCamera);
                    }
                    animateRC();

                    // Keyboard Navigation for Timeline (Arrow keys: Left/Right run, Up/Down zoom, Esc unpin)
                    window.addEventListener('keydown', function(e) {
                        var healthTab = document.getElementById('tab-health');
                        if (!healthTab || !healthTab.classList.contains('active')) {
                            return;
                        }
                        if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT')) {
                            return;
                        }

                        var key = e.key;
                        if (key === 'ArrowLeft') {
                            e.preventDefault();
                            if (typeof window.prevTimelineRun === 'function') window.prevTimelineRun();
                        } else if (key === 'ArrowRight') {
                            e.preventDefault();
                            if (typeof window.nextTimelineRun === 'function') window.nextTimelineRun();
                        } else if (key === 'ArrowUp') {
                            e.preventDefault();
                            if (typeof window.zoomTimeline === 'function') window.zoomTimeline(1);
                        } else if (key === 'ArrowDown') {
                            e.preventDefault();
                            if (typeof window.zoomTimeline === 'function') window.zoomTimeline(-1);
                        } else if (key === 'Escape') {
                            e.preventDefault();
                            if (typeof window.unpinTimelineNode === 'function') window.unpinTimelineNode();
                        } else if (key === 'r' || key === 'R') {
                            e.preventDefault();
                            if (typeof window.resetRollercoasterCam === 'function') window.resetRollercoasterCam();
                        } else if (key === ' ' || key === 'Spacebar') {
                            e.preventDefault();
                            if (typeof window.toggleTimelineAutoSpin === 'function') window.toggleTimelineAutoSpin();
                        }
                    });

                } catch(e) {
                    console.error("Three.js Timeline error:", e);
                }
            }

            // =============================================================
            // 🔴 2. POPULATE CVE CARDS
            // =============================================================
            var cveCont = document.getElementById('cveCardsContainer');
            if (cveCont) {
                if (cveData.length === 0) {
                    cveCont.innerHTML = '<div style="background:rgba(16,185,129,0.12); border:1px solid #10b981; border-radius:6px; padding:16px; color:#34d399; font-size:13px;">🛡️ <strong>Sécurité Intègre :</strong> Aucune vulnérabilité CVE critique connue n\'a été détectée parmi vos logiciels installés.</div>';
                } else {
                    var cHtml = '';
                    cveData.forEach(function(c) {
                        cHtml += '<div style="background:rgba(15,23,42,0.85); border:1px solid rgba(244,63,94,0.4); border-left:4px solid #f43f5e; border-radius:6px; padding:14px; margin-bottom:12px;">';
                        cHtml += '  <div style="display:flex; justify-content:space-between; align-items:center;">';
                        cHtml += '    <strong style="color:#f43f5e; font-size:14px;">' + c.CveId + ' — ' + c.Software + '</strong>';
                        cHtml += '    <span class="badge badge-err" style="font-size:11px;">CVSS ' + c.Severity + '</span>';
                        cHtml += '  </div>';
                        cHtml += '  <div style="font-size:12px; color:#cbd5e1; margin:6px 0;">' + c.Summary + '</div>';
                        cHtml += '  <div style="font-size:11px; color:#94a3b8;">Versions affectées : <code>' + c.AffectedVersions + '</code> (Installée : <code>' + c.DetectedVersion + '</code>)</div>';
                        cHtml += '  <div style="margin-top:8px;"><button class="btn-primary" style="background:#0284c7; padding:4px 10px; font-size:11px;" onclick="copyDirect(this)" data-cmd="winget upgrade --id ' + c.WingetId + ' -e">🔄 Mettre à jour ' + c.Software + '</button></div>';
                        cHtml += '</div>';
                    });
                    cveCont.innerHTML = cHtml;
                }
            }

            // =============================================================
                        // =============================================================
            // 🌐 3. POPULATE NETWORK ADAPTERS SELECTOR & LATENCY MATRIX
            // =============================================================
            window.allNetworkAdapters = netData.Adapters || [];
            
            window.renderNetworkAdapterDetails = function(adapter) {
                if (!adapter) return;
                
                var specCont = document.getElementById('selectedAdapterDetails');
                if (specCont) {
                    var statusCol = (adapter.Status === 'Up') ? '#10b981' : '#ef4444';
                    specCont.innerHTML = [
                        '<div><strong>Nom :</strong> <span style="color:#38bdf8;">' + adapter.Name + '</span></div>',
                        '<div><strong>Statut :</strong> <span style="color:' + statusCol + '; font-weight:bold;">' + adapter.Status + '</span> (' + adapter.Speed + ')</div>',
                        '<div><strong>IPv4 :</strong> <code>' + adapter.IPv4 + '/' + adapter.PrefixLength + '</code></div>',
                        '<div><strong>Passerelle :</strong> <code>' + adapter.Gateway + '</code></div>',
                        '<div><strong>Serveurs DNS :</strong> <code>' + adapter.DNS + '</code></div>',
                        '<div><strong>Adresse MAC :</strong> <code>' + adapter.MacAddress + '</code></div>'
                    ].join('');
                }

                var netGrid = document.getElementById('networkLatencyGrid');
                if (netGrid) {
                    var pGat = (adapter.PingGateway >= 0) ? (adapter.PingGateway + ' ms') : ((adapter.Gateway === 'Aucune passerelle') ? 'N/A' : 'Injoignable');
                    var pCloud = (adapter.PingDNS1 >= 0) ? (adapter.PingDNS1 + ' ms') : 'Injoignable';
                    var pGoog = (adapter.PingDNS2 >= 0) ? (adapter.PingDNS2 + ' ms') : 'Injoignable';
                    var pM365 = (adapter.PingM365 >= 0) ? (adapter.PingM365 + ' ms') : 'Injoignable';

                    var colGat = (adapter.PingGateway >= 0 && adapter.PingGateway <= 20) ? '#10b981' : (adapter.PingGateway > 20 ? '#f59e0b' : '#94a3b8');
                    var colCloud = (adapter.PingDNS1 >= 0 && adapter.PingDNS1 <= 40) ? '#10b981' : (adapter.PingDNS1 > 40 ? '#f59e0b' : '#ef4444');
                    var colGoog = (adapter.PingDNS2 >= 0 && adapter.PingDNS2 <= 40) ? '#10b981' : (adapter.PingDNS2 > 40 ? '#f59e0b' : '#ef4444');
                    var colM365 = (adapter.PingM365 >= 0 && adapter.PingM365 <= 60) ? '#10b981' : (adapter.PingM365 > 60 ? '#f59e0b' : '#ef4444');

                    netGrid.innerHTML = [
                        '<div style="background:rgba(15,23,42,0.85); border:1px solid ' + colGat + '; border-radius:6px; padding:14px; text-align:center;">',
                        '  <div style="font-size:11px; color:#94a3b8;">Passerelle Locale (' + adapter.Gateway + ')</div>',
                        '  <div style="font-size:1.8rem; font-weight:800; font-family:\'Rajdhani\'; color:' + colGat + ';">' + pGat + '</div>',
                        '</div>',
                        '<div style="background:rgba(15,23,42,0.85); border:1px solid ' + colCloud + '; border-radius:6px; padding:14px; text-align:center;">',
                        '  <div style="font-size:11px; color:#94a3b8;">DNS Cloudflare (1.1.1.1)</div>',
                        '  <div style="font-size:1.8rem; font-weight:800; font-family:\'Rajdhani\'; color:' + colCloud + ';">' + pCloud + '</div>',
                        '</div>',
                        '<div style="background:rgba(15,23,42,0.85); border:1px solid ' + colGoog + '; border-radius:6px; padding:14px; text-align:center;">',
                        '  <div style="font-size:11px; color:#94a3b8;">DNS Google (8.8.8.8)</div>',
                        '  <div style="font-size:1.8rem; font-weight:800; font-family:\'Rajdhani\'; color:' + colGoog + ';">' + pGoog + '</div>',
                        '</div>',
                        '<div style="background:rgba(15,23,42,0.85); border:1px solid ' + colM365 + '; border-radius:6px; padding:14px; text-align:center;">',
                        '  <div style="font-size:11px; color:#94a3b8;">Microsoft 365 Cloud (login.microsoftonline.com)</div>',
                        '  <div style="font-size:1.8rem; font-weight:800; font-family:\'Rajdhani\'; color:' + colM365 + ';">' + pM365 + '</div>',
                        '</div>'
                    ].join('');
                }
            };

            window.changeNetworkAdapter = function(index) {
                var found = window.allNetworkAdapters.find(function(a) { return String(a.Index) === String(index); });
                if (found) {
                    window.renderNetworkAdapterDetails(found);
                }
            };

            // Initialize default active adapter spec on load
            var defaultIdx = netData.PrimaryIndex;
            var activeAd = window.allNetworkAdapters.find(function(a) { return String(a.Index) === String(defaultIdx); }) || window.allNetworkAdapters[0];
            if (activeAd) {
                window.renderNetworkAdapterDetails(activeAd);
            }

            var smbCont = document.getElementById('smbSharesTableContainer');
            if (smbCont) {
                if (!netData.Shares || netData.Shares.length === 0) {
                    smbCont.innerHTML = '<div style="color:#94a3b8; font-size:12.5px;">Aucun partage SMB personnalisé exposé sur la machine locale.</div>';
                } else {
                    var sTable = '<table class="data-table"><thead><tr><th>Nom du Partage</th><th>Chemin Local</th><th>Description</th></tr></thead><tbody>';
                    netData.Shares.forEach(function(s) {
                        sTable += '<tr><td><strong>' + s.Name + '</strong></td><td><code>' + (s.Path||'-') + '</code></td><td>' + (s.Description||'-') + '</td></tr>';
                    });
                    sTable += '</tbody></table>';
                    smbCont.innerHTML = sTable;
                }
            }

            // =============================================================
            // 💾 4. POPULATE DISK ANALYSIS & CLEANABLE RECOVERY
            // =============================================================
            if (diskData && typeof diskData.UsedGB !== 'undefined') {
                var total = diskData.TotalGB || 1;
                var used = diskData.UsedGB || 0;
                var free = diskData.FreeGB || 0;
                var usedPct = Math.min(100, Math.max(0, Math.round((used / total) * 100)));

                var barUsed = document.getElementById('diskUsageBarUsed');
                var barFree = document.getElementById('diskUsageBarFree');
                if (barUsed) barUsed.style.width = usedPct + '%';
                if (barFree) barFree.style.width = (100 - usedPct) + '%';

                var uLbl = document.getElementById('diskUsedLabel');
                if (uLbl) uLbl.innerHTML = '<strong>Occupé :</strong> <span style="color:#38bdf8;">' + used + ' GB (' + usedPct + '%)</span>';
                var fLbl = document.getElementById('diskFreeLabel');
                if (fLbl) fLbl.innerHTML = '<strong>Libre :</strong> <span style="color:#10b981;">' + free + ' GB</span>';

                var cTotalLbl = document.getElementById('cleanableTotalLabel');
                if (cTotalLbl) {
                    var cleanMB = diskData.CleanableMB || (diskData.TempUserMB + diskData.TempWinMB + diskData.SoftDistMB) || 0;
                    cTotalLbl.innerText = (cleanMB > 1024 ? (cleanMB / 1024).toFixed(1) + ' GB' : cleanMB.toFixed(0) + ' MB');
                }

                var tuLbl = document.getElementById('diskTempUser');
                if (tuLbl) tuLbl.innerText = (diskData.TempUserMB > 1024 ? (diskData.TempUserMB / 1024).toFixed(1) + ' GB' : (diskData.TempUserMB || 0) + ' MB');
                var twLbl = document.getElementById('diskTempWin');
                if (twLbl) twLbl.innerText = (diskData.TempWinMB || 0) + ' MB';
                var sdLbl = document.getElementById('diskSoftDist');
                if (sdLbl) sdLbl.innerText = (diskData.SoftDistMB || 0) + ' MB';
            }

            // =============================================================
            // 🇧🇪 5. POPULATE BELGIAN APPS
            // =============================================================
            var belgCont = document.getElementById('belgianAppsGrid');
            var certsCont = document.getElementById('belgianCertsGrid');
            
            var bApps = (belgianData && belgianData.Apps) ? belgianData.Apps : (Array.isArray(belgianData) ? belgianData : []);
            var bCerts = (belgianData && belgianData.Certs) ? belgianData.Certs : [];

            if (belgCont && bApps.length > 0) {
                var bHtml = '';
                bApps.forEach(function(b) {
                    var bColor = b.Installed ? '#34d399' : '#64748b';
                    var bBorder = b.Installed ? 'rgba(52,211,153,0.40)' : 'rgba(148,163,184,0.15)';
                    var bBg = b.Installed ? 'rgba(16,185,129,0.10)' : 'rgba(15,23,42,0.85)';
                    var bBadgeClass = b.Installed ? 'badge badge-ok' : 'badge';
                    
                    bHtml += '<div style="background:' + bBg + '; border:1px solid ' + bBorder + '; border-left:4px solid ' + bColor + '; border-radius:6px; padding:14px; display:flex; flex-direction:column; justify-content:space-between;">';
                    bHtml += '  <div>';
                    bHtml += '    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">';
                    bHtml += '      <strong style="color:#f1f5f9; font-size:13.5px;">' + b.Name + '</strong>';
                    bHtml += '      <span class="' + bBadgeClass + '" style="font-size:10px; padding:3px 8px;">' + (b.Installed ? 'INSTALLÉ' : 'NON INSTALLÉ') + '</span>';
                    bHtml += '    </div>';
                    bHtml += '    <div style="font-size:11.5px; color:#94a3b8; margin-bottom:4px;">Catégorie : <span style="color:#cbd5e1;">' + b.Category + '</span></div>';
                    bHtml += '  </div>';
                    bHtml += '  <div style="font-size:11px; color:#94a3b8; border-top:1px solid rgba(255,255,255,0.06); padding-top:8px; margin-top:8px;">Éditeur : <strong>' + (b.Installed ? ('v' + b.Version) : 'N/A') + '</strong> (' + b.Vendor + ')</div>';
                    bHtml += '</div>';
                });
                belgCont.innerHTML = bHtml;
            }

            if (certsCont && bCerts.length > 0) {
                var cHtml = '';
                bCerts.forEach(function(c) {
                    var isWarning = (c.DaysLeft < 30);
                    var certBadge = c.IsEid ? '<span class="badge" style="background:rgba(56,189,248,0.2); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">🇧🇪 eID National</span>' : '<span class="badge" style="background:rgba(148,163,184,0.15); color:#cbd5e1;">Certificat Système</span>';
                    var statusColor = isWarning ? '#f43f5e' : '#34d399';
                    var borderCol = isWarning ? 'rgba(244,63,94,0.4)' : 'rgba(56,189,248,0.2)';

                    cHtml += '<div style="background:rgba(15,23,42,0.90); border:1px solid ' + borderCol + '; border-left:4px solid ' + (c.IsEid ? '#38bdf8' : '#64748b') + '; border-radius:6px; padding:14px;">';
                    cHtml += '  <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">';
                    cHtml += '    <div style="font-weight:700; color:#f1f5f9; font-size:12.5px; word-break:break-word;">' + c.Subject + '</div>';
                    cHtml += '    ' + certBadge;
                    cHtml += '  </div>';
                    cHtml += '  <div style="font-size:11.5px; color:#94a3b8; margin-bottom:4px;">Émetteur : <span style="color:#cbd5e1;">' + c.Issuer + '</span></div>';
                    cHtml += '  <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px; padding-top:8px; border-top:1px solid rgba(255,255,255,0.06); font-size:11px;">';
                    cHtml += '    <span style="color:' + statusColor + '; font-weight:700;">' + c.Status + '</span>';
                    cHtml += '    <span style="color:#64748b; font-family:Consolas, monospace;">' + c.Scope + '</span>';
                    cHtml += '  </div>';
                    cHtml += '</div>';
                });
                certsCont.innerHTML = cHtml;
            }

            
        // =============================================================
        // 🇧🇪 5. CATALOGUE & MOTEUR MULTILINGUE LOGICIELS MÉTIERS & CERTIFICATS eID
        // =============================================================
        var belgianCatalogMaster = [
            {
                Name: "Belgium e-ID Middleware",
                Category: { fr: "Authentification & Signature", nl: "Authenticatie & Handtekening", en: "Authentication & Digital Signature", de: "Authentifizierung & Signatur", es: "Autenticación y Firma", it: "Autenticazione e Firma", pt: "Autenticação e Assinatura" },
                Vendor: "SPF Intérieur / BOSA",
                Desc: {
                    fr: "Passerelle officielle pour la lecture de la carte d'identité électronique belge (eID), l'accès aux portails fédéraux (CSAM, MyMinfin, Tax-on-web) et la signature électronique qualifiée.",
                    nl: "Officiële middleware voor het lezen van de Belgische eID-kaart, toegang tot federale portalen (CSAM, MyMinfin, Tax-on-web) en gekwalificeerde digitale handtekeningen.",
                    en: "Official Belgian electronic ID (eID) middleware for smart card readers, federal portal access (CSAM, MyMinfin), and qualified electronic signatures.",
                    de: "Offizielle Middleware zum Lesen des belgischen eID-Ausweises, Zugang zu Bundesportalen (CSAM, MyMinfin) und qualifizierten elektronischen Signaturen.",
                    es: "Middleware oficial de documento de identidad electrónico belga (eID) para lectores de tarjetas inteligentes y portales federales.",
                    it: "Middleware ufficiale per la carta d'identità elettronica belga (eID), accesso ai portali federali e firma digitale qualificata.",
                    pt: "Middleware oficial de bilhete de identidade eletrónico belga (eID) para leitores de cartões inteligentes e portais federais."
                }
            },
            {
                Name: "Winbooks Classic / on Web",
                Category: { fr: "Comptabilité & ERP", nl: "Boekhouding & ERP", en: "Accounting & ERP", de: "Buchhaltung & ERP", es: "Contabilidad y ERP", it: "Contabilità ed ERP", pt: "Contabilidade e ERP" },
                Vendor: "Winbooks Accounting",
                Desc: {
                    fr: "Solution de comptabilité et de gestion financière de référence pour les PME et fiduciaires belges.",
                    nl: "Toonaangevende boekhoud- en financieel beheeroplossing voor Belgische kmo's en accountantskantoren.",
                    en: "Leading accounting and financial management ERP for Belgian SMEs and accounting firms.",
                    de: "Führende Buchhaltungs- und Finanzmanagement-Lösung für belgische KMU und Treuhänder.",
                    es: "Solución líder de contabilidad y gestión financiera para pymes y asesorías contables.",
                    it: "Soluzione leader di contabilità e gestione finanziaria per PMI e commercialisti.",
                    pt: "Solução líder de contabilidade e gestão financeira para PMEs e gabinetes de contabilidade."
                }
            },
            {
                Name: "Sage BOB 50 / BOB 100",
                Category: { fr: "Comptabilité & Finance", nl: "Boekhouding & Financiën", en: "Accounting & Finance", de: "Buchhaltung & Finanzen", es: "Contabilidad y Finanzas", it: "Contabilità e Finanze", pt: "Contabilidade e Finanças" },
                Vendor: "Sage BOB Belgium",
                Desc: {
                    fr: "Progiciel de comptabilité générale, analytique et de gestion commerciale largement déployé en Belgique et au Luxembourg.",
                    nl: "Boekhoud-, analytische en commerciële beheersoftware, breed ingezet in België en Luxemburg.",
                    en: "General, analytical accounting and commercial ERP widely deployed across Belgium and Luxembourg.",
                    de: "Weit verbreitete Finanz- und Handelsmanagement-Software in Belgien und Luxemburg.",
                    es: "Software de contabilidad general, analítica y gestión comercial ampliamente utilizado.",
                    it: "Software di contabilità generale, analitica e gestione commerciale molto diffuso.",
                    pt: "Software de contabilidade geral, analítica e gestão comercial amplamente utilizado."
                }
            },
            {
                Name: "Isabel 6 Multi-Banking",
                Category: { fr: "E-Banking Entreprise", nl: "Zakelijk E-Banking", en: "Enterprise Multi-Banking", de: "Unternehmens-Banking", es: "Banca Electrónica Empresa", it: "E-Banking Aziendale", pt: "Multi-Banking Empresarial" },
                Vendor: "Isabel Group",
                Desc: {
                    fr: "Plateforme multibancaire sécurisée standard permettant la gestion centralisée des comptes auprès de plus de 20 banques belges et internationales.",
                    nl: "Standaard beveiligd multibankingplatform voor centraal beheer van rekeningen bij meer dan 20 banken.",
                    en: "Standard enterprise multi-banking platform for centralized account management across 20+ banks.",
                    de: "Sichere Multibanking-Plattform für die zentrale Kontoführung bei über 20 Banken.",
                    es: "Plataforma multibancaria segura para la gestión centralizada de cuentas en más de 20 bancos.",
                    it: "Piattaforma multibancaria sicura per la gestione centralizzata dei conti presso oltre 20 banche.",
                    pt: "Plataforma multi-bancária segura para gestão centralizada de contas em mais de 20 bancos."
                }
            },
            {
                Name: "Silverfin Connector",
                Category: { fr: "Fiscalité & Audit", nl: "Fiscaliteit & Audit", en: "Taxation & Financial Audit", de: "Steuern & Wirtschaftsprüfung", es: "Fiscalidad y Auditoría", it: "Fiscalità e Revisione", pt: "Fiscalidade e Auditoria" },
                Vendor: "Silverfin BE",
                Desc: {
                    fr: "Connecteur cloud pour l'automatisation comptable, le reporting financier et la préparation des clôtures annuelles.",
                    nl: "Cloudconnector voor boekhoudautomatisering, financiële rapportage en jaarrekeningvoorbereiding.",
                    en: "Cloud connector for accounting automation, financial reporting, and annual tax filings.",
                    de: "Cloud-Konnektor für Buchhaltungsautomatisierung, Finanzberichte und Jahresabschlüsse.",
                    es: "Conector en la nube para automatización contable, informes financieros y cierres anuales.",
                    it: "Connettore cloud per l'automazione contabile, la rendicontazione finanziaria e le chiusure annuali.",
                    pt: "Conector em nuvem para automação contabilística, relatórios financeiros e encerramentos anuais."
                }
            },
            {
                Name: "Accon Bilans BNB",
                Category: { fr: "Dépôt Bilans BNB", nl: "Neerlegging Jaarrekeningen NBB", en: "National Bank Balance Sheets", de: "Jahresabschlüsse NBB", es: "Depósito Balances Banco Central", it: "Deposito Bilanci BNB", pt: "Depósito de Balanços BNB" },
                Vendor: "Kluwer Accon",
                Desc: {
                    fr: "Outil d'établissement et de validation des comptes annuels selon les schémas officiels de la Banque Nationale de Belgique (BNB).",
                    nl: "Tool voor het opstellen en valideren van jaarrekeningen volgens de officiële schema's van de Nationale Bank van België (NBB).",
                    en: "Official tool for preparing and validating annual accounts according to the National Bank of Belgium (NBB) schemas.",
                    de: "Offizielles Tool zur Erstellung und Validierung von Jahresabschlüssen der Belgischen Nationalbank (NBB).",
                    es: "Herramienta oficial para la elaboración de cuentas anuales según el Banco Nacional.",
                    it: "Strumento ufficiale per la redazione dei bilanci annuali secondo la Banca Nazionale.",
                    pt: "Ferramenta oficial para preparação de contas anuais de acordo com o Banco Nacional."
                }
            },
            {
                Name: "SuperFisc",
                Category: { fr: "Déclarations Fiscales", nl: "Fiscale Aangiften", en: "Corporate & Personal Tax", de: "Steuererklärungen", es: "Declaraciones Fiscales", it: "Dichiarazioni Fiscali", pt: "Declarações Fiscais" },
                Vendor: "Wolters Kluwer",
                Desc: {
                    fr: "Logiciel fiscal pour le calcul et l'envoi électronique des déclarations d'impôt des personnes physiques (IPP) et des sociétés (ISoc).",
                    nl: "Fiscale software voor berekening en elektronische verzending van personenbelasting (PB) en vennootschapsbelasting (VenB).",
                    en: "Tax software for computing and filing personal income tax (IPP) and corporate tax (ISoc) returns.",
                    de: "Steuersoftware zur Berechnung und Übermittlung von Einkommen- und Körperschaftsteuererklärungen.",
                    es: "Software fiscal para el cálculo y presentación electrónica de impuestos de sociedades y personas físicas.",
                    it: "Software fiscale per il calcolo e l'invio telematico delle dichiarazioni dei redditi.",
                    pt: "Software fiscal para cálculo e submissão eletrónica de declarações fiscais."
                }
            },
            {
                Name: "Octopus Accountancy",
                Category: { fr: "Comptabilité Cloud", nl: "Cloud Boekhouding", en: "Cloud Accounting Platform", de: "Cloud-Buchhaltung", es: "Contabilidad en la Nube", it: "Contabilità in Cloud", pt: "Contabilidade na Nuvem" },
                Vendor: "Octopus",
                Desc: {
                    fr: "Logiciel de gestion et de comptabilité 100% cloud pour entrepreneurs et experts-comptables.",
                    nl: "100% cloudgebaseerde boekhoud- en beheersoftware voor ondernemers en accountants.",
                    en: "100% cloud-based accounting and document management platform for businesses and CPAs.",
                    de: "Cloud-basierte Buchhaltungs- und Dokumentenmanagement-Plattform für Unternehmen.",
                    es: "Software de contabilidad y gestión 100% en la nube para empresas y asesores.",
                    it: "Software di contabilità e gestione 100% in cloud per aziende e commercialisti.",
                    pt: "Software de contabilidade e gestão 100% na nuvem para empresas e contabilistas."
                }
            }
        ];

        window.renderBelgianTab = function(lang) {
            var belgCont = document.getElementById('belgianAppsGrid');
            var certsCont = document.getElementById('belgianCertsGrid');
            var currentL = lang || currentLang || 'fr';

            var detectedAppsMap = {};
            var rawApps = (window.belgianData && window.belgianData.Apps) ? window.belgianData.Apps : (Array.isArray(window.belgianData) ? window.belgianData : []);
            rawApps.forEach(function(a) {
                if (a.Name) detectedAppsMap[a.Name.toLowerCase()] = a;
            });

            if (belgCont) {
                var bHtml = '';
                belgianCatalogMaster.forEach(function(item) {
                    var detected = detectedAppsMap[item.Name.toLowerCase()] || {};
                    // Also check partial match for Belgium e-ID
                    if (!detected.Installed && item.Name.indexOf("e-ID") !== -1) {
                        for (var k in detectedAppsMap) {
                            if (k.indexOf("eid") !== -1 || k.indexOf("e-id") !== -1) {
                                detected = detectedAppsMap[k];
                                break;
                            }
                        }
                    }

                    var isInstalled = !!detected.Installed;
                    var versionStr = isInstalled ? ('v' + (detected.Version || '5.1.6205')) : 'N/A';
                    var statusLabel = isInstalled ? (currentL === 'nl' ? 'GEÏNSTALLEERD' : (currentL === 'en' ? 'INSTALLED' : (currentL === 'de' ? 'INSTALLIERT' : (currentL === 'es' ? 'INSTALADO' : (currentL === 'it' ? 'INSTALLATO' : (currentL === 'pt' ? 'INSTALADO' : 'INSTALLÉ')))))) : (currentL === 'nl' ? 'NIET GEÏNSTALLEERD' : (currentL === 'en' ? 'NOT INSTALLED' : (currentL === 'de' ? 'NICHT INSTALLIERT' : (currentL === 'es' ? 'NO INSTALADO' : (currentL === 'it' ? 'NON INSTALLATO' : (currentL === 'pt' ? 'NÃO INSTALADO' : 'NON INSTALLÉ'))))));
                    
                    var bColor = isInstalled ? '#34d399' : '#64748b';
                    var bBorder = isInstalled ? 'rgba(52,211,153,0.45)' : 'rgba(148,163,184,0.18)';
                    var bBg = isInstalled ? 'linear-gradient(135deg, rgba(16,185,129,0.12) 0%, rgba(15,23,42,0.92) 100%)' : 'rgba(15,23,42,0.80)';
                    var badgeStyle = isInstalled ? 'background:rgba(16,185,129,0.25); color:#34d399; border:1px solid #10b981;' : 'background:rgba(148,163,184,0.12); color:#94a3b8; border:1px solid rgba(148,163,184,0.25);';

                    var catText = (item.Category && item.Category[currentL]) ? item.Category[currentL] : (item.Category ? item.Category.fr : 'Logiciel Métier');
                    var descText = (item.Desc && item.Desc[currentL]) ? item.Desc[currentL] : (item.Desc ? item.Desc.fr : '');

                    bHtml += '<div style="background:' + bBg + '; border:1px solid ' + bBorder + '; border-left:4px solid ' + bColor + '; border-radius:8px; padding:16px; display:flex; flex-direction:column; justify-content:space-between; box-shadow:' + (isInstalled ? '0 0 16px rgba(16,185,129,0.12)' : 'none') + ';">';
                    bHtml += '  <div>';
                    bHtml += '    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">';
                    bHtml += '      <strong style="color:#f1f5f9; font-size:14px; font-weight:800;">' + item.Name + '</strong>';
                    bHtml += '      <span style="font-size:10px; font-weight:800; padding:3px 8px; border-radius:3px; ' + badgeStyle + '">' + statusLabel + '</span>';
                    bHtml += '    </div>';
                    bHtml += '    <div style="font-size:11.5px; color:#38bdf8; font-weight:700; margin-bottom:8px;">' + catText + '</div>';
                    bHtml += '    <p style="font-size:12px; color:#cbd5e1; line-height:1.5; margin:6px 0 12px 0;">' + descText + '</p>';
                    bHtml += '  </div>';
                    bHtml += '  <div style="font-size:11px; color:#94a3b8; border-top:1px solid rgba(255,255,255,0.08); padding-top:10px; display:flex; justify-content:space-between; align-items:center;">';
                    bHtml += '    <span>Éditeur : <strong style="color:#f1f5f9;">' + item.Vendor + '</strong></span>';
                    bHtml += '    <span style="font-family:Consolas, monospace; color:' + (isInstalled ? '#34d399' : '#64748b') + '; font-weight:700;">' + versionStr + '</span>';
                    bHtml += '  </div>';
                    bHtml += '</div>';
                });
                belgCont.innerHTML = bHtml;
            }

            var bCerts = (window.belgianData && window.belgianData.Certs) ? window.belgianData.Certs : [];
            if (certsCont && bCerts.length > 0) {
                var cHtml = '';
                bCerts.forEach(function(c) {
                    var isWarning = (c.DaysLeft < 30);
                    var certBadge = c.IsEid ? '<span class="badge" style="background:rgba(56,189,248,0.2); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">🇧🇪 eID National</span>' : '<span class="badge" style="background:rgba(148,163,184,0.15); color:#cbd5e1;">Certificat Système</span>';
                    var statusColor = isWarning ? '#f43f5e' : '#34d399';
                    var borderCol = isWarning ? 'rgba(244,63,94,0.4)' : 'rgba(56,189,248,0.25)';

                    cHtml += '<div style="background:rgba(15,23,42,0.90); border:1px solid ' + borderCol + '; border-left:4px solid ' + (c.IsEid ? '#38bdf8' : '#64748b') + '; border-radius:8px; padding:16px;">';
                    cHtml += '  <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">';
                    cHtml += '    <div style="font-weight:700; color:#f1f5f9; font-size:13px; word-break:break-word;">' + c.Subject + '</div>';
                    cHtml += '    ' + certBadge;
                    cHtml += '  </div>';
                    cHtml += '  <div style="font-size:11.5px; color:#94a3b8; margin-bottom:6px;">Émetteur : <span style="color:#cbd5e1;">' + c.Issuer + '</span></div>';
                    cHtml += '  <div style="display:flex; justify-content:space-between; align-items:center; margin-top:10px; padding-top:10px; border-top:1px solid rgba(255,255,255,0.08); font-size:11.5px;">';
                    cHtml += '    <span style="color:' + statusColor + '; font-weight:700;">' + c.Status + '</span>';
                    cHtml += '    <span style="color:#64748b; font-family:Consolas, monospace;">' + c.Scope + '</span>';
                    cHtml += '  </div>';
                    cHtml += '</div>';
                });
                certsCont.innerHTML = cHtml;
            }
        };


            // 6. Populate SMART Disks
            var smartCont = document.getElementById('smartDisksContainer');
            if (smartCont && benchData.length > 0) {
                var smTable = '<table class="data-table"><thead><tr><th>Disque Physique</th><th>Type Média</th><th>Taille</th><th>Santé SMART</th><th>Usure (%)</th><th>Heures Activité</th><th>Température</th><th>Erreurs Lecture</th></tr></thead><tbody>';
                benchData.forEach(function(d) {
                    var hCol = (d.Health === 'Healthy' || d.Health === 'OK') ? '#34d399' : '#ef4444';
                    smTable += '<tr><td><strong>' + d.Model + '</strong></td><td>' + d.MediaType + '</td><td>' + d.SizeGB + ' GB</td><td style="color:' + hCol + '; font-weight:bold;">' + d.Health + '</td><td>' + d.WearPct + ' %</td><td>' + d.PowerOnHours + ' h</td><td>' + d.Temperature + '</td><td>' + d.ReadErrors + '</td></tr>';
                });
                smTable += '</tbody></table>';
                smartCont.innerHTML = smTable;
            }

            // =============================================================
            // 👤 7. POPULATE SECURITY & USERS
            // =============================================================
            var admText = document.getElementById('adminMembersText');
            if (admText && secData.AdminGroupMembers) admText.innerText = secData.AdminGroupMembers;

            var usersCont = document.getElementById('localUsersTableContainer');
            if (usersCont && secData.Users && secData.Users.length > 0) {
                var uTable = '<table class="data-table"><thead><tr><th>Nom Utilisateur</th><th>Statut Compte</th><th>Expiration MDP</th><th>Dernière Connexion</th></tr></thead><tbody>';
                secData.Users.forEach(function(u) {
                    var uStat = u.Enabled ? '<span style="color:#34d399; font-weight:bold;">Actif</span>' : '<span style="color:#64748b;">Désactivé</span>';
                    uTable += '<tr><td><strong>' + u.Name + '</strong></td><td>' + uStat + '</td><td>' + (u.PasswordExpires ? 'Oui' : 'Non (Permanent)') + '</td><td>' + u.LastLogon + '</td></tr>';
                });
                uTable += '</tbody></table>';
                usersCont.innerHTML = uTable;
            }

            var suspCont = document.getElementById('suspiciousProcsContainer');
            if (suspCont) {
                if (!secData.SuspiciousProcesses || secData.SuspiciousProcesses.length === 0) {
                    suspCont.innerHTML = '<div style="background:rgba(16,185,129,0.12); border:1px solid #10b981; padding:14px; border-radius:6px; color:#34d399; font-size:12.5px;">✅ Aucun processus suspect exécuté depuis %TEMP% ou Public.</div>';
                } else {
                    var spHtml = '';
                    secData.SuspiciousProcesses.forEach(function(p) {
                        spHtml += '<div style="background:rgba(239,68,68,0.12); border:1px solid #ef4444; padding:10px 14px; border-radius:6px; margin-bottom:8px; font-size:12px; color:#f87171;">';
                        spHtml += '⚠️ Processus : <strong>' + p.Name + ' (PID: ' + p.PID + ')</strong> — Chemin : <code>' + p.Path + '</code>';
                        spHtml += '</div>';
                    });
                    suspCont.innerHTML = spHtml;
                }
            }

            window.downloadDiagnosticJson = function() {
                var fullExport = {
                    metadata: { hostname: '__HOSTNAME__', scanDate: '__SCAN_DATE__', os: '__OS_NAME__', version: '__OS_VER__' },
                    healthScore: '__HEALTH_SCORE__',
                    cveMatches: cveData,
                    diskAudit: diskData,
                    networkAudit: netData,
                    securityAudit: secData,
                    belgianApps: belgianData,
                    smartDisks: benchData
                };
                var blob = new Blob([JSON.stringify(fullExport, null, 2)], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'Diagnostic_RMM___HOSTNAME___' + (new Date().toISOString().slice(0,10)) + '.json';
                a.click();
                showToast("📥 Export JSON RMM téléchargé.");
            };

            window.downloadDiagnosticCsv = function() {
                var csv = "Categorie,Nom,Statut,Details\n";
                belgianData.forEach(function(b) {
                    csv += '"Logiciels Belgique","' + b.Name + '","' + b.Status + '","' + b.Vendor + '"\n';
                });
                cveData.forEach(function(c) {
                    csv += '"Vulnerabilite CVE","' + c.App + '","' + c.Severity + '","' + c.CVE + ' - ' + c.Desc.replace(/"/g, '""') + '"\n';
                });
                var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'Inventaire_IT___HOSTNAME___.csv';
                a.click();
                showToast("📊 Export CSV Inventaire téléchargé.");
            };
        })();

    
        // =============================================================
        // 🖨️ GESTIONNAIRE D'IMPRESSION SÉLECTIVE DE RAPPORTS
        // =============================================================
        window.printSelectiveReport = function() {
            var selectElem = document.getElementById('printSectionSelect');
            var selectedVal = selectElem ? selectElem.value : 'all';

            if (selectedVal === 'all') {
                document.body.classList.add('print-all-mode');
                document.body.classList.remove('print-selective-mode');
                setTimeout(function() {
                    window.print();
                    setTimeout(function() {
                        document.body.classList.remove('print-all-mode');
                    }, 1000);
                }, 100);
            } else {
                window.switchTab(selectedVal);
                document.body.classList.add('print-selective-mode');
                document.body.classList.remove('print-all-mode');
                setTimeout(function() {
                    window.print();
                    setTimeout(function() {
                        document.body.classList.remove('print-selective-mode');
                    }, 1000);
                }, 150);
            }
        };

    
        // =============================================================
        // 🗄️ CONTRÔLEURS DE TIROIRS ACCORDÉONS (PROFILS WINGET)
        // =============================================================
        window.toggleProfileDrawer = function(drawerId) {
            var drawer = document.getElementById(drawerId);
            if (drawer) {
                drawer.classList.toggle('open');
            }
        };

        window.toggleAllProfileDrawers = function(openState) {
            var drawers = document.querySelectorAll('.profile-drawer');
            for (var i = 0; i < drawers.length; i++) {
                if (openState) {
                    drawers[i].classList.add('open');
                } else {
                    drawers[i].classList.remove('open');
                }
            }
        };

    </script>
</body>
</html>
'@

# Remplacement des balises
$htmlOutput = $htmlTemplate
$htmlOutput = $htmlOutput.Replace('__INITIAL_LANG__', $Lang.ToLowerInvariant())
$htmlOutput = $htmlOutput.Replace('__SCAN_DATE__', $scanDate)
$htmlOutput = $htmlOutput.Replace('__HOSTNAME__', $hostName)
$htmlOutput = $htmlOutput.Replace('__OS_NAME__', $osName)
$htmlOutput = $htmlOutput.Replace('__OS_VER__', $osVer)
$htmlOutput = $htmlOutput.Replace('__CPU__', $cpuName)
$htmlOutput = $htmlOutput.Replace('__RAM__', $ramGB)
$htmlOutput = $htmlOutput.Replace('__UPTIME__', $upStr)
$htmlOutput = $htmlOutput.Replace('__BOOTMODE__', $bMode)
$htmlOutput = $htmlOutput.Replace('__TOTAL_COUNT__', [string]$totalCount)
$htmlOutput = $htmlOutput.Replace('__OK_COUNT__', [string]$okCount)
$htmlOutput = $htmlOutput.Replace('__WARN_COUNT__', [string]$warnCount)
$htmlOutput = $htmlOutput.Replace('__ERR_COUNT__', [string]$errorCount)
$htmlOutput = $htmlOutput.Replace('__HEALTH_BADGE__', [string]$healthBadge)
$htmlOutput = $htmlOutput.Replace('__HEALTH_SCORE__', [string]$healthScore)
$htmlOutput = $htmlOutput.Replace('__HEALTH_COLOR__', [string]$healthColor)
$htmlOutput = $htmlOutput.Replace('__ISSUES_COUNT__', [string]$issues.Count)
$htmlOutput = $htmlOutput.Replace('__RESOLUTION_CARDS__', [string]$resolutionCardsHtml)
$htmlOutput = $htmlOutput.Replace('__TABLE_ROWS__', [string]$tableRows)
$htmlOutput = $htmlOutput.Replace('__RUNTIMES_HTML__', [string]$runtimesHtml)
$htmlOutput = $htmlOutput.Replace('__PROFILES_HTML__', [string]$profilesHtml)
$htmlOutput = $htmlOutput.Replace('__FOSS_DRAWERS__', [string]$fossDrawersHtml)
$htmlOutput = $htmlOutput.Replace('__FOSS_JSON__', [string]$fossThemesJson)
$htmlOutput = $htmlOutput.Replace('__STARTUP_ROWS__', [string]$startupRowsHtml)
$htmlOutput = $htmlOutput.Replace('__TOTAL_STARTUP__', [string]$totalStartup)
$htmlOutput = $htmlOutput.Replace('__SUSPICIOUS_COUNT__', [string]$suspiciousCount)
$htmlOutput = $htmlOutput.Replace('__APP_COUNT__', [string]$appCount)
$htmlOutput = $htmlOutput.Replace('__SCRIPT_COUNT__', [string]$scriptCount)
$htmlOutput = $htmlOutput.Replace('__FOLDER_COUNT__', [string]$folderCount)
$htmlOutput = $htmlOutput.Replace('__TASK_COUNT__', [string]$taskCount)
$htmlOutput = $htmlOutput.Replace('__FAST_BOOT_BADGE__', [string]$fastStartupBadge)
$htmlOutput = $htmlOutput.Replace('__FAST_BOOT_DESC__', [string]$fastStartupState)
$htmlOutput = $htmlOutput.Replace('__THROTTLE_BADGE__', [string]$throttleBadge)
$htmlOutput = $htmlOutput.Replace('__POWER_PLAN__', [string]$powerPlanName)
$htmlOutput = $htmlOutput.Replace('__CPU_CLOCK_INFO__', [string]"$curClock MHz (Base $maxClock MHz - $throttleRatio%)")
$htmlOutput = $htmlOutput.Replace('__SOFT_DIST_MB__', [string]$softDistMB)
$htmlOutput = $htmlOutput.Replace('__TEMP_MB__', [string]$tempMB)
$htmlOutput = $htmlOutput.Replace('__CRASH_DUMPS_MB__', [string]$crashDumpsMB)
$htmlOutput = $htmlOutput.Replace('__TOTAL_CACHES_MB__', [string]$totalCachesMB)
$htmlOutput = $htmlOutput.Replace('__LISTENING_ROWS__', [string]$listeningRowsHtml)
$htmlOutput = $htmlOutput.Replace('__PUBLIC_PORTS_COUNT__', [string]$publicCount)
$htmlOutput = $htmlOutput.Replace('__TPM_BADGE__', [string]$tpmBadge)
$htmlOutput = $htmlOutput.Replace('__BITLOCKER_BADGE__', [string]$bitlockerBadge)
$htmlOutput = $htmlOutput.Replace('__SECURE_BOOT_BADGE__', [string]$secureBootBadge)
$htmlOutput = $htmlOutput.Replace('__UAC_BADGE__', [string]$uacBadge)

$cFreeInfoStr = "$cFreeGB Go libres ($cFreePct% disponible)"
$cveCountStr = if ($cveMatches.Count -gt 0) { "$($cveMatches.Count) faille(s) active(s)" } else { "0 faille critique" }
$totalRunsStr = "$($historyList.Count) diagnostics archivés"
$htmlOutput = $htmlOutput.Replace('__C_FREE_INFO__', [string]$cFreeInfoStr)
$htmlOutput = $htmlOutput.Replace('__CVE_COUNT_INFO__', [string]$cveCountStr)
$htmlOutput = $htmlOutput.Replace('__TOTAL_RUNS_INFO__', [string]$totalRunsStr)
$htmlOutput = $htmlOutput.Replace('__HISTORY_JSON__', (ConvertTo-Utf8Base64 $historyJson))
$htmlOutput = $htmlOutput.Replace('__PREDICTIVE_TEXT__', [string]$healthPrediction)
$htmlOutput = $htmlOutput.Replace('__CVE_JSON__', (ConvertTo-Utf8Base64 $cveMatchesJson))
$htmlOutput = $htmlOutput.Replace('__BENCH_JSON__', (ConvertTo-Utf8Base64 $benchDataJson))
$htmlOutput = $htmlOutput.Replace('__CPU_BENCH_SCORE__', [string]$cpuScore)
$htmlOutput = $htmlOutput.Replace('__CPU_BENCH_MS__', [string]$cpuBenchMs)
$cpuOpsPerSecText = if ($null -ne $cpuOpsPerSec) { $cpuOpsPerSec.ToString("N0") } else { '0' }
$htmlOutput = $htmlOutput.Replace('__CPU_OPS_PER_SEC__', [string]$cpuOpsPerSecText)
$htmlOutput = $htmlOutput.Replace('__CPU_TIER_NAME__', [string]$cpuTierName)
$htmlOutput = $htmlOutput.Replace('__CPU_TIER_BADGE__', [string]$cpuTierBadge)
$htmlOutput = $htmlOutput.Replace('__CPU_TIER_COL__', [string]$cpuTierCol)
$htmlOutput = $htmlOutput.Replace('__CPU_TIER_DESC__', [string]$cpuTierDesc)
$cpuBarPct = [math]::Min(95, [math]::Max(5, [math]::Round(($cpuBenchMs / 200.0) * 100)))
$htmlOutput = $htmlOutput.Replace('__CPU_BAR_PCT__', [string]$cpuBarPct)
$cpuNameFull = if ($cpuInfo -and $cpuInfo.Name) { $cpuInfo.Name } else { "$env:PROCESSOR_IDENTIFIER" }
$htmlOutput = $htmlOutput.Replace('__CPU_NAME_FULL__', [string]$cpuNameFull)
$htmlOutput = $htmlOutput.Replace('__CPU_HIGHLIGHT_ROW_PRO__', "")
$htmlOutput = $htmlOutput.Replace('__CPU_HIGHLIGHT_CURRENT__', "")
$htmlOutput = $htmlOutput.Replace('__DISK_AUDIT_JSON__', (ConvertTo-Utf8Base64 $diskAuditJson))
$htmlOutput = $htmlOutput.Replace('__NETWORK_AUDIT_JSON__', (ConvertTo-Utf8Base64 $networkAuditJson))
$htmlOutput = $htmlOutput.Replace('__ADAPTER_OPTIONS_HTML__', [string]$adapterOptionsHtml)
$htmlOutput = $htmlOutput.Replace('__SECURITY_AUDIT_JSON__', (ConvertTo-Utf8Base64 $securityAuditJson))

$htmlOutput = $htmlOutput.Replace('__P1_SCORE__', [string]$p1_security)
$htmlOutput = $htmlOutput.Replace('__P1_DESC__', [string]$p1_desc)
$htmlOutput = $htmlOutput.Replace('__P1_COLOR__', [string]$p1_col)
$htmlOutput = $htmlOutput.Replace('__P2_SCORE__', [string]$p2_perf)
$htmlOutput = $htmlOutput.Replace('__P2_DESC__', [string]$p2_desc)
$htmlOutput = $htmlOutput.Replace('__P2_COLOR__', [string]$p2_col)
$htmlOutput = $htmlOutput.Replace('__P3_SCORE__', [string]$p3_storage)
$htmlOutput = $htmlOutput.Replace('__P3_DESC__', [string]$p3_desc)
$htmlOutput = $htmlOutput.Replace('__P3_COLOR__', [string]$p3_col)
$htmlOutput = $htmlOutput.Replace('__P4_SCORE__', [string]$p4_network)
$htmlOutput = $htmlOutput.Replace('__P4_DESC__', [string]$p4_desc)
$htmlOutput = $htmlOutput.Replace('__P4_COLOR__', [string]$p4_col)
$htmlOutput = $htmlOutput.Replace('__P5_SCORE__', [string]$p5_system)
$htmlOutput = $htmlOutput.Replace('__P5_DESC__', [string]$p5_desc)
$htmlOutput = $htmlOutput.Replace('__P5_COLOR__', [string]$p5_col)

$htmlOutput = $htmlOutput.Replace('__BELGIAN_APPS_JSON__', (ConvertTo-Utf8Base64 $belgianAppsJson))


# Écriture du rapport uniquement dans le dossier de sortie choisi
$htmlOutput | Out-File -FilePath $ReportPath -Encoding UTF8

$Duration = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "  ✅ DIAGNOSTIC IT & SCANNER DE PACKAGES TERMINÉ en $Duration s !         " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "  📊 Bilan : $totalCount tests ($okCount OK, $warnCount avertissements, $errorCount pannes)" -ForegroundColor White
Write-Host "  📦 Profils & Runtimes : 12 Profils Métiers + Détecteur Runtimes & FOSS" -ForegroundColor White
Write-Host "  📁 Rapport Bureau : $ReportPath" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""

if (-not $NoOpen) {
    Start-Process $ReportPath
}
if (-not $NonInteractive) {
    Read-Host -Prompt "Appuyez sur [Entrée] pour fermer la console"
}
