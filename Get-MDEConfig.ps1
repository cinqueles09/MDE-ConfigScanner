<#
    Autor: Ismael Morilla
    Version: 2.0
    Fecha de creacion: 10 de agosto de 2022
    Fecha modificacion: 19 de enero de 2025
    Descripcion: Este script compara las configuraciones existentes de Microsoft Defender for Endpoint y muestra las diferencias 
    con respecto a las configuraciones esperadas.
#>
function Check-AdminPrivileges {
    # Verificar si el script se esta ejecutando como administrador
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Mostrar un banner de advertencia en rojo
        $bannerColor = [System.ConsoleColor]::Red
        $resetColor = [System.ConsoleColor]::White

        $bannerMessage = "Este script NO esta siendo ejecutado con privilegios de administrador. Algunos comandos pueden no funcionar correctamente."
        $bannerLength = $bannerMessage.Length + 4  # Longitud del banner con los bordes

        # Crear el banner
        Write-Host ("*" * $bannerLength) -ForegroundColor $bannerColor
        Write-Host "* $bannerMessage *" -ForegroundColor $bannerColor
        Write-Host ("*" * $bannerLength) -ForegroundColor $bannerColor
        Write-Host ""  # Espacio en blanco
    }
}

# Funcion para recolectar informacion
function Get-SystemInfo {
    # Manejo de errores
    try {
        # Obtener preferencias de Microsoft Defender
        $defenderPreferences = Get-MpPreference
        
        # Obtener estado de Microsoft Defender
        $defenderStatus = Get-MpComputerStatus
        
        # Obtener estado de registro de dispositivo
        $dsregStatus = dsregcmd /status
	# Optimizar los datos
	# Ejemplo para analizar la salida y extraer valores especificos
	$dsregOutput = dsregcmd /status

	# Convertir la salida a una lista de lineas
	$lines = $dsregOutput -split "`n"

	# Inicializar un Hashtable para almacenar los resultados
	$dsregStatus = @{}

	# Iterar sobre las lineas y buscar las claves que te interesan
	foreach ($line in $lines) {
	    if ($line -match "DomainJoined\s*:\s*(.+)") {
	        $dsregStatus["DomainJoined"] = $matches[1].Trim()
	    }
	    elseif ($line -match "AzureADJoined\s*:\s*(.+)") {
	        $dsregStatus["AzureADJoined"] = $matches[1].Trim()
	    }
    
	}

        # Almacena la informacion en archivos
        #$defenderPreferences | Out-File -FilePath "defender.txt" -Encoding utf8
        #$defenderStatus | Out-File -FilePath "Status.txt" -Encoding utf8
        #$dsregStatus | Out-File -FilePath "result.txt" -Encoding utf8

        # Retorna las variables como un Hashtable
        return @{
            DefenderPreferences = $defenderPreferences
            DefenderStatus = $defenderStatus
            DsregStatus = $dsregStatus
        }
    } catch {
        Write-Host "Ocurrio un error al recolectar informacion: $_"
        return $null
    }
}

# Declaracion de variables ASR como un arreglo de objetos
$asrPolicies = @(
    [PSCustomObject]@{ Description = "Impedir que Adobe Reader cree procesos secundarios"; ID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" },
    [PSCustomObject]@{ Description = "Bloquear la ejecucion de scripts posiblemente ofuscados"; ID = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" },
    [PSCustomObject]@{ Description = "Bloquear las llamadas API Win32 desde macros de office"; ID = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" },
    [PSCustomObject]@{ Description = "Bloquear el robo de credenciales del subsistema de autoridad de seguridad local de Windows"; ID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" },
    [PSCustomObject]@{ Description = "Bloquear los archivos ejecutables si no cumplen un criterio de la lista de confianza, antigüedad o prevalencia"; ID = "01443614-cd74-433a-b99e-2ecdc07bfc25" },
    [PSCustomObject]@{ Description = "Impedir que JavaScript o VBScript inicien el contenido ejecutable descargado"; ID = "d3e037e1-3eb8-44c8-a917-57927947596d" },
    [PSCustomObject]@{ Description = "Impedir que la aplicacion de comunicacion de Office cree procesos secundarios"; ID = "26190899-1602-49e8-8b27-eb1d0a1ce869" },
    [PSCustomObject]@{ Description = "Impedir que todas las aplicaciones de Office creen procesos secundarios"; ID = "d4f940ab-401b-4efc-aadc-ad5f3c50688a" },
    [PSCustomObject]@{ Description = "Bloquear los procesos sin firma y que no son de confianza ejecutados desde USB"; ID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" },
    [PSCustomObject]@{ Description = "Bloquear la creacion de procesos procedente de comandos PSExec y WMI"; ID = "d1e49aac-8f56-4280-b9ba-993a6d77406c" },
    [PSCustomObject]@{ Description = "Bloquear la persistencia mediante la suscripcion de eventos WMI"; ID = "e6db77e5-3df2-4cf1-b95a-636979351e5b" },
    [PSCustomObject]@{ Description = "Impedir que las aplicaciones de Office creen contenido ejecutable"; ID = "3b576869-a4ec-4529-8536-b80a7769e899" },
    [PSCustomObject]@{ Description = "Impedir que las aplicaciones de Office inyecten codigo en otros procesos"; ID = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" },
    [PSCustomObject]@{ Description = "Usar proteccion avanzada contra ransomware"; ID = "c1db55ab-c21a-4637-bb3f-a12568109d35" },
    [PSCustomObject]@{ Description = "Bloquear contenido ejecutable del cliente de correo electronico y el correo web"; ID = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" },
    [PSCustomObject]@{ Description = "Bloquear el abuso de controladores firmados vulnerables explotados (dispositivos)"; ID = "56a863a9-875e-4185-98a7-b882c64b5ce5" }
)
# Llamar a la funcion y guardar el resultado en una variable
$systemInfo = Get-SystemInfo

# Ahora puedes acceder a las variables desde $systemInfo
$defenderPreferences = $systemInfo.DefenderPreferences
$defenderStatus = $systemInfo.DefenderStatus
$dsregStatus = $systemInfo.DsregStatus

# Opcional: Mostrar un mensaje de exito
Write-Host "Informacion recolectada con exito."

# Declaracion de funciones
Function equipo {
    # Nombre del equipo
    $hostname = hostname

    # Comprobar si la Proteccion en la red esta activada
    $red = $defenderPreferences.EnableNetworkProtection

    # Comprobar el estado de inscripcion del dispositivo
    $domainJoined = $dsregStatus["DomainJoined"]
    $azureJoined = $dsregStatus["AzureADJoined"]

    # Determinar el estado del equipo
    $estado = if ($domianJoined -eq "YES") {
        if ($AzureJoined -eq "YES" -and $DomainJoined -eq "YES") { "Equipo Hibrido" } else { "Equipo en Dominio" }
    } else {
        "Equipo en la Nube"
    }

    # Comprobar el estado de la Proteccion contra Aplicaciones Potencialmente No Deseadas (PUA)
    $PUA = $defenderPreferences.PUAProtection

    # Comprobar si Defender esta en modo pasivo o primario
    $Mode = $DefenderStatus.AMRunningMode

    # Comprobar el estado de la Proteccion en Tiempo Real
    $RealTime = $DefenderStatus.RealTimeProtectionEnabled

    # Pintar en pantalla los datos adquiridos
    Write-Host -ForegroundColor Yellow "Datos del equipo"
    Write-Host -ForegroundColor Yellow "###################################################"
    
    Write-Host "`n"
    Write-Host "ID del equipo: $($DefenderPreferences.ComputerID)"
    Write-Host "Nombre del equipo: $hostname"
    Write-Host "Inscripcion del dispositivo: $estado"
    Write-Host "`n"

    # Proteccion en la red
    switch ($red) {
        "1" { Write-Host "Proteccion en la red: " -NoNewline; Write-Host -ForegroundColor Green "Activado" }
        "2" { Write-Host "Proteccion en la red: " -NoNewline; Write-Host -ForegroundColor Yellow "Auditoria" }
        default { Write-Host "Proteccion en la red: " -NoNewline; Write-Host -ForegroundColor Red "Desactivado" }
    }

    # Proteccion PUA
    switch ($PUA) {
        "1" { Write-Host "Proteccion PUA: " -NoNewline; Write-Host -ForegroundColor Green "Activado" }
        "2" { Write-Host "Proteccion PUA: " -NoNewline; Write-Host -ForegroundColor Yellow "Auditoria" }
        default { Write-Host "Proteccion PUA: " -NoNewline; Write-Host -ForegroundColor Red "Desactivado" }
    }

    # Proteccion en tiempo real
    if ($RealTime -eq "True") {
        Write-Host "Proteccion en tiempo real: " -NoNewline; Write-Host -ForegroundColor Green "Activado`n"
    } else {
        Write-Host "Proteccion en tiempo real: " -NoNewline; Write-Host -ForegroundColor Red "Desactivado`n"
    }

    # Modo Defender
    if ($Mode -eq "Normal") {
        Write-Host "M. Defender: " -NoNewline; Write-Host -ForegroundColor Green "Activo`n"
    } else {
        Write-Host "M. Defender: " -NoNewline; Write-Host -ForegroundColor Red "Pasivo`n"
    }
}

function Amenazas {

    # Obtener la accion para LowThreatDefaultAction
    $flag = $defenderPreference.LowThreatDefaultAction

    # Solo mostrar las amenazas si el equipo recibe las politicas de defender por GPO
    if ($flag -eq "0") {
        $threatsPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\'
        
        $threatsCount = (Get-Item -Path $threatsPath | Select-Object -ExpandProperty Property).Count
        $threat = @{}

        for ($i = 1; $i -le $threatsCount; $i++) {
            $itemProperty = Get-ItemProperty -Path $threatsPath | Select-String "1"
            $item = $itemProperty[$i - 1] -split ";"
            $rul = $item[0] -split "=" | Select-Object -Last 1
            $key = $item[1] -split "=" | Select-Object -Last 1 -replace '\s+', ''

            # Asignar nivel de amenaza
            $nivel = switch ($rul) {
                "@{1" { "Amenaza Baja" }
                "1" { "Amenaza Baja" }
                "2" { "Amenaza Media" }
                "4" { "Amenaza Alta" }
                "5" { "Amenaza Grave" }
                default { "Desconocida" }
            }

            # Asignar accion segun clave
            $correccion = switch ($key) {
                "2" { "Cuarentena" }
                "3" { "Quitar" }
                "6" { "Omitir" }
                default { "Desconocida" }
            }

            $threat[$nivel] = $correccion
        }
        return $threat
    } else {
        # Asignaciones para los niveles de amenaza
        $levels = @{
            "Amenaza baja" = $defenderPreference.LowThreatDefaultAction
            "Amenaza media" = $defenderPreference.ModerateThreatDefaultAction
            "Amenaza alta" = $defenderPreference.HighThreatDefaultAction
            "Amenaza critica" = $defenderPreference.SevereThreatDefaultAction
        }

        $actions = @{
            "1" = "Limpiar"
            "2" = "Cuarentena"
            "3" = "Eliminar"
            "6" = "Permitir"
            "8" = "Usuario define"
            "10" = "Bloquear"
        }

        $threat = @{}

        foreach ($level in $levels.Keys) {
            $value = $levels[$level]

            # Validar que $value no sea null
            if ($value -and $actions.ContainsKey($value)) {
                $threat[$level] = $actions[$value]
            } else {
                $threat[$level] = "Desconocida"
            }
        }

        return $threat.GetEnumerator() | Format-Table -AutoSize
    }
}
Function Antivirus {
    # Creacion de tabla de contenido para directivas de antivirus de defender
    $Antivirus = [ordered]@{}

    # Lista de configuraciones y sus descripciones
    $configuraciones = @{
        "DisableArchiveScanning"                           = "Examen de archivos"
        "DisableEmailScanning"                             = "Examen de email"
        "DisableRealtimeMonitoring"                        = "Monitorizacion en tiempo real"
        "DisableRemovableDriveScanning"                   = "Examen unidades extraibles"
        "DisableRestorePoint"                              = "Puntos de restauracion"
        "DisableScanningMappedNetworkDrivesForFullScan"  = "Examen completo unidades de red"
        "DisableBehaviorMonitoring"                        = "Control del comportamiento"
        "DisableInboundConnectionFiltering"                = "Filtrado de conexiones entrantes"
        "DisableDatagramProcessing"                        = "Inspeccion de conexiones UDP"
        "DisableDnsOverTcpParsing"                        = "Inspeccion del trafico DNS en canal TCP"
        "DisableDnsParsing"                               = "Inspeccion del trafico DNS en canal UDP"
        "DisableBlockAtFirstSeen"                         = "Bloqueo visto por primera vez"
        "DisableCatchupFullScan"                          = "Analisis de puesta al dia completo"
        "DisableCatchupQuickScan"                         = "Analisis de puesta al dia rapido"
    }

    # Procesar cada configuracion
    foreach ($key in $configuraciones.Keys) {
        $valor = $DefenderPreferences.$Key
        
        if ($valor -eq "False") {
            $Antivirus[$configuraciones[$key]] = "Habilitado"
        } else {
            $Antivirus[$configuraciones[$key]] = "Deshabilitado"
        }
    }

    # Direcciones del analisis de archivos
    $a9 = $DefenderPreferences.RealTimeScanDirection

    switch ($a9) {
        0 { $Antivirus["Direccion analisis de los archivos"] = "Bidireccional" }
        1 { $Antivirus["Direccion analisis de los archivos"] = "Solo entrantes" }
        2 { $Antivirus["Direccion analisis de los archivos"] = "Solo salientes" }
    }

    # Configuraciones adicionales
    $a13 = $DefenderPreferences.ScanAvgCPULoadFactor
    $Antivirus["Limitacion CPU para examenes"] = "$a13 %"

    $a17 = $defenderPreference.MAPSReporting 

    switch ($a17) {
        0 { $Antivirus["Proteccion en la nube"] = "Deshabilitado" }
        1 { $Antivirus["Proteccion en la nube"] = "Membresia basica" }
        2 { $Antivirus["Proteccion en la nube"] = "Membresia avanzada" }
    }

    $a19 = $DefenderPreferences.CloudBlockLevel

    switch ($a19) {
        0 { $Antivirus["Nivel proteccion en la nube"] = "Predeterminado" }
        2 { $Antivirus["Nivel proteccion en la nube"] = "Alto" }
        4 { $Antivirus["Nivel proteccion en la nube"] = "Alto nivel de bloqueo +" }
        6 { $Antivirus["Nivel proteccion en la nube"] = "Tolerancia cero" }
    }

    $a20 = $DefenderPreferences.CloudExtendedTimeout
    $Antivirus["Tiempo extendido bloqueo archivo malicioso"] = "$a20 seg."

    $a21 = $DefenderPreferences.ScanParameters

    switch ($a21) {
        1 { $Antivirus["Tipo de analisis"] = "Rapido" }
        2 { $Antivirus["Tipo de analisis"] = "Completo" }
    }

    $a22 = $DefenderPreferences.SubmitSamplesConsent

    switch ($a22) {
        0 { $Antivirus["Consentimiento usuario"] = "Preguntar siempre" }
        1 { $Antivirus["Consentimiento usuario"] = "Enviar muestras seguras autom." }
        2 { $Antivirus["Consentimiento usuario"] = "Nunca enviar" }
        3 { $Antivirus["Consentimiento usuario"] = "Enviar todas muestras autom." }
    }

    # Mostrar la tabla de valores con los datos extraidos
    Write-Host -ForegroundColor Yellow "Antivirus"
    Write-Host -ForegroundColor Yellow "###################################################"
    $Antivirus.GetEnumerator() | Sort-Object -Property Key | Format-Table -AutoSize
}

function RuleASR {

    # Cuenta cuantas reglas en total tiene el equipo aplicada.
    $totalASR = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    $ASR_total = $totalASR.Count

    $ASR = @{}
    $ruleActions = @{
        0 = "Deshabilitado"
        1 = "Bloqueado"
        2 = "Auditoria"
        6 = "Advertencia"
    }

    # Analiza la regla ASR y la compara con el diccionario de arriba para asociarla con su enunciado y su estado.
    foreach ($index in 0..($ASR_total - 1)) {
        $rule = $totalASR[$index]
        $Accion = (Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions)[$index]

        # Verifica si la regla coincide y asigna su accion correspondiente.
        if ($rule -match "asr\d+") {
            $action = $ruleActions[$Accion]
            $ASR[$rule] = $action
        }
    }

    if ($ASR_total -gt 0) {
        Write-Host -ForegroundColor Yellow "Estados de reglas ASR"
        Write-Host -ForegroundColor Yellow "###################################################"
        $ASR.GetEnumerator() | Sort-Object -Property key | Format-Table -AutoSize
    }
}

function Get-ASRStatus {
    $actions = @("Deshabilitado", "Bloqueado", "Auditoria", "Advertencia")
    $asrActions = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
    $asrRules = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    
    # Crear un hash table para almacenar los resultados
    $ASR = @{}

    for ($i = 0; $i -lt $asrRules.Count; $i++) {
        $ruleID = $asrRules[$i]
        $actionID = $asrActions[$i]
        
        # Buscar la descripcion de la politica correspondiente
        $description = ($asrPolicies | Where-Object { $_.ID -eq $ruleID }).Description
        
        if ($description) {
            $ASR[$description] = $actions[$actionID]
        }
    }

    return $ASR
}

function RuleASR {
    $ASR = Get-ASRStatus
    
    if ($ASR.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "Estados de reglas ASR"
        Write-Host -ForegroundColor Yellow "###################################################"
        $ASR.GetEnumerator() | Sort-Object -Property key | Format-Table -AutoSize
    } else {
        Write-Host -ForegroundColor Red "No se encontraron reglas ASR aplicadas."
    }
}

function ExamenProgramado {

    # Extraer y limpiar parametros relevantes
    $TypeScan = $DefenderPreferences.ScanParameters
    $DayScan = $DefenderPreferences.ScanScheduleDay
    $ScanTime = $DefenderPreferences.ScanScheduleTime
    $HourScan = $ScanTime.Hours # Obtener solo la hora

    # Diccionario para dias de la semana
    $daysOfWeek = @(
        "todos los dias", "domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado", "nunca"
    )
    
    # Determinar el dia de la semana
    $day = if ($DayScan -ge 0 -and $DayScan -lt $daysOfWeek.Count) {
        $daysOfWeek[$DayScan]
    } else {
        "Desconocido"
    }

    # Diccionario para tipos de examen
    $typeMapping = @{
        1 = "Rapido"
        2 = "Completo"
    }
    
    # Determinar tipo de examen
    # Verificar si $TypeScan es un numero y existe en el mapeo
    if (-not [string]::IsNullOrWhiteSpace($TypeScan) -and [int]::TryParse($TypeScan, [ref]$null)) {
        $type = if ($typeMapping.ContainsKey([int]$TypeScan)) { 
            $typeMapping[[int]$TypeScan] 
        } else { 
            "Desconocido" 
        }
    } else {
        $type = "Desconocido"  # Si $TypeScan esta vacio o no es un numero valido
    }

    # Mostrar resultados
    Write-Host -ForegroundColor Yellow "Examen programado"
    Write-Host -ForegroundColor Yellow "###################################################"
    Write-Host "Existe examen" -NoNewline
    Write-Host -ForegroundColor Green " $type " -NoNewline
    Write-Host "programado para" -NoNewline
    Write-Host -ForegroundColor Green " $day " -NoNewline
    Write-Host "a las" -NoNewline
    Write-Host -ForegroundColor Green " $HourScan "`n
}

#Revision de privilegios
Check-AdminPrivileges
## Ejecucion por prioridad
Equipo
RuleASR
ExamenProgramado
Antivirus
#Amenazas
Remove-Item status.txt 
