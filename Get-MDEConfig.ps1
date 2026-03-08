<#
    .SYNOPSIS
        Analizador de cumplimiento de Microsoft Defender for Endpoint.
    .DESCRIPTION
        Este script compara las configuraciones de MDE y muestra un reporte visual del estado de seguridad.
    .NOTES
        Autor: Ismael Morilla
        Version: 3.0 (Refactorizada)
        Fecha de creación: 10 de agosto de 2022
        Fecha modificacion: 08 de marzo de 2026
#>

# --- Configuracion de Colores ---
$HeaderColor = "Cyan"
$SuccessColor= "Green"
$WarnColor   = "Yellow"
$ErrorColor  = "Red"

function Show-Banner {
    Clear-Host
    $line = "=" * 60
    Write-Host $line -ForegroundColor $HeaderColor
    Write-Host "   DEFENDER FOR ENDPOINT - ANALIZADOR PROFESIONAL" -ForegroundColor $HeaderColor
    Write-Host "   Version: 3.1 | Autor: Ismael Morilla" -ForegroundColor $HeaderColor
    Write-Host $line -ForegroundColor $HeaderColor
    Write-Host ""
}

function Check-AdminPrivileges {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host " [!] ADVERTENCIA: Ejecutando sin privilegios de Administrador.`n" -ForegroundColor $WarnColor
    }
}

function Get-SystemSecurityInfo {
    try {
        $defenderPrefs  = Get-MpPreference
        $defenderStatus = Get-MpComputerStatus
        $dsregRaw = dsregcmd /status
        
        $dsregObj = @{
            DomainJoined  = if ($dsregRaw -match "DomainJoined\s*:\s*YES") { "YES" } else { "NO" }
            AzureADJoined = if ($dsregRaw -match "AzureADJoined\s*:\s*YES") { "YES" } else { "NO" }
        }

        return [PSCustomObject]@{
            Prefs  = $defenderPrefs
            Status = $defenderStatus
            Dsreg  = $dsregObj
        }
    } catch {
        Write-Host " [X] Error al recolectar datos: $($_.Exception.Message)" -ForegroundColor $ErrorColor
        return $null
    }
}

# --- Diccionario ASR ---
$asrPolicies = @(
    @{ ID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"; Desc = "Bloquear procesos secundarios Adobe Reader" }
    @{ ID = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"; Desc = "Bloquear scripts ofuscados" }
    @{ ID = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"; Desc = "Bloquear Win32 API en macros Office" }
    @{ ID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Desc = "Bloquear robo credenciales LSASS" }
    @{ ID = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Desc = "Bloquear ejecutables no confiables" }
    @{ ID = "d3e037e1-3eb8-44c8-a917-57927947596d"; Desc = "Bloquear JS/VBS ejecutando contenido" }
    @{ ID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"; Desc = "Bloquear ejecutables sin firma en USB" }
    @{ ID = "c1db55ab-c21a-4637-bb3f-a12568109d35"; Desc = "Proteccion avanzada contra Ransomware" }
)

function Show-EquipoInfo ($data) {
    $tipo = "Grupo de Trabajo"
    if ($data.Dsreg.DomainJoined -eq "YES" -and $data.Dsreg.AzureADJoined -eq "YES") { $tipo = "Hibrido (AD + Entra ID)" }
    elseif ($data.Dsreg.DomainJoined -eq "YES") { $tipo = "Dominio Local (AD)" }
    elseif ($data.Dsreg.AzureADJoined -eq "YES") { $tipo = "Nube (Entra ID)" }

    Write-Host " [i] INFORMACION DEL SISTEMA" -ForegroundColor $HeaderColor
    Write-Host " Hostname:      $($env:COMPUTERNAME)"
    Write-Host " ID Defender:   $($data.Prefs.ComputerID)"
    Write-Host " Tipo Registro: $tipo"
    
    $mColor = if ($data.Status.AMRunningMode -eq "Normal") { $SuccessColor } else { $WarnColor }
    Write-Host " Modo Defender: " -NoNewline; Write-Host $data.Status.AMRunningMode -ForegroundColor $mColor
    Write-Host ""
}

function Show-AntivirusTable ($data) {
    Write-Host " [+] CONFIGURACION ANTIVIRUS" -ForegroundColor $HeaderColor
    
    $rtp = if ($data.Status.RealTimeProtectionEnabled) { "ACTIVO" } else { "INACTIVO" }
    $pua = switch($data.Prefs.PUAProtection) { 1 {"Activo"}; 2 {"Auditoria"}; default {"OFF"} }
    $net = switch($data.Prefs.EnableNetworkProtection) { 1 {"Activo"}; 2 {"Auditoria"}; default {"OFF"} }

    $items = @(
        [PSCustomObject]@{ Parametro = "Proteccion Tiempo Real"; Estado = $rtp }
        [PSCustomObject]@{ Parametro = "Proteccion PUA"; Estado = $pua }
        [PSCustomObject]@{ Parametro = "Network Protection"; Estado = $net }
        [PSCustomObject]@{ Parametro = "Limite CPU Escaneo"; Estado = "$($data.Prefs.ScanAvgCPULoadFactor)%" }
    )
    $items | Format-Table -AutoSize
}

function Show-ASRRules ($data) {
    Write-Host " [!] REGLAS ASR (Surface Reduction)" -ForegroundColor $HeaderColor
    $ids = $data.Prefs.AttackSurfaceReductionRules_Ids
    $actions = $data.Prefs.AttackSurfaceReductionRules_Actions
    
    if (-not $ids) {
        Write-Host " No se detectan reglas ASR configuradas.`n" -ForegroundColor $WarnColor
        return
    }

    $res = for ($i=0; $i -lt $ids.Count; $i++) {
        $id = $ids[$i]
        $pol = $asrPolicies | Where-Object { $_.ID -eq $id }
        $desc = if ($pol) { $pol.Desc } else { "Regla ID: $id" }
        
        [PSCustomObject]@{
            Regla  = $desc
            Accion = switch ($actions[$i]) { 1 {"Bloquear"}; 2 {"Auditoria"}; 6 {"Advertir"}; default {"OFF"} }
        }
    }
    $res | Format-Table -AutoSize
}

function Show-Schedule ($data) {
    $dias = "Todos los dias","Domingo","Lunes","Martes","Miercoles","Jueves","Viernes","Sabado","Nunca"
    $tipo = switch($data.Prefs.ScanParameters) { 1 {"Rapido"}; 2 {"Completo"}; default {"No def."} }
    
    Write-Host " [o] EXAMEN PROGRAMADO" -ForegroundColor $HeaderColor
    if ($data.Prefs.ScanScheduleDay -eq 8 -or $null -eq $data.Prefs.ScanScheduleDay) {
        Write-Host " Estado: No hay examenes programados.`n" -ForegroundColor $WarnColor
    } else {
        $dia = $dias[$data.Prefs.ScanScheduleDay]
        Write-Host " Tipo: $tipo | Dia: $dia | Hora: $($data.Prefs.ScanScheduleTime.Hours):00 hs`n" -ForegroundColor $SuccessColor
    }
}

# --- EJECUCION ---
Show-Banner
Check-AdminPrivileges
$info = Get-SystemSecurityInfo

if ($info) {
    Show-EquipoInfo -data $info
    Show-AntivirusTable -data $info
    Show-Schedule -data $info
    Show-ASRRules -data $info
}

Write-Host "Analisis completo. Presione una tecla..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
