cls

##########################

## Diccionario ASR

##########################

$v1="Impedir que Adobe Reader cree procesos secundarios"	
$asr1="7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

$v2="Bloquear la ejecución de scripts posiblemente ofuscados"	
$asr2="5beb7efe-fd9a-4556-801d-275e5ffc04cc"

$v3="Bloquear las llamadas API Win32 desde macros de office"
$asr4="92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

$v4="Bloquear el robo de credenciales del subsistema de autoridad de seguridad local de Windows"
$asr4="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

$v5="Bloquear los archivos ejecutables si no cumplen un criterio de la lista de confianza, antigüedad o prevalencia"	
$asr5="01443614-cd74-433a-b99e-2ecdc07bfc25"

$v6="Impedir que JavaScript o VBScript inicien el contenido ejecutable descargado"
$asr6="d3e037e1-3eb8-44c8-a917-57927947596d"

$v7="Impedir que la aplicación de comunicación de Office cree procesos secundarios"
$asr7="26190899-1602-49e8-8b27-eb1d0a1ce869"

$v8="Impedir que todas las aplicaciones de office creen procesos secundarios"
$asr8="d4f940ab-401b-4efc-aadc-ad5f3c50688a"

$v9="Bloquear los procesos sin firma y que no son de confianza ejecutados desde USB"
$asr9="b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

$v10="Bloquear la creación de procesos procedente de comandos PSExec y WMI"
$asr10="d1e49aac-8f56-4280-b9ba-993a6d77406c"

$v11="Bloquear la persistencia mediante la suscripción de eventos WMI"
$asr11="e6db77e5-3df2-4cf1-b95a-636979351e5b"

$v12="Impedir que las aplicaciones de office creen contenido ejecutable"
$asr12="3b576869-a4ec-4529-8536-b80a7769e899"

$v13="Impedir que las aplicaciones de office inyecten código en otros procesos"
$asr13="75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

$v14="Usar protección avanzada contra ransomware"
$asr14="c1db55ab-c21a-4637-bb3f-a12568109d35"

$v15="Bloquear contenido ejecutable del cliente de correo electrónico y el correo web"
$asr15="be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

$v16="Bloquear el abuso de controladores firmados vulnerables explotados (dispositivos)"
$asr16="56a863a9-875e-4185-98a7-b882c64b5ce5"
###################################################


Function equipo {

    Get-MpPreference > C:\defender.txt
    Get-MpComputerStatus > C:\Status.txt
    $ID = Get-Content C:\defender.txt | Select-String "ComputerID" | ForEach-Object { ([string]$_).Split(":")[1] }
    $hostname=hostname
    #Proteccion en la red
    $red = Get-Content C:\defender.txt | Select-String "EnableNetworkProtection" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($red -eq 1)
    {
        $flag="Activado"
    }
    else
    {
        $flag="Desactivado"
    }

    #Protección contra aplicaciones pontencialmente no deseadas
    $PUA= get-content C:\defender.txt | Select-String "PUAProtection" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($PUA -eq 1)
    {
        $flag1="Activado"
    }
    else
    {
        $flag1="Desactivado"
    }

    $Mode = Get-Content C:\status.txt | Select-String "AMRunningMode" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    $RealTime = Get-Content C:\status.txt | Select-String "RealTimeProtectionEnabled" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($RealTime -eq "True")
    {
        $flag2="Activado"
    }
    else
    {
        $flag2="Desactivado"
    }

    Write-host -ForegroundColor Yellow "Datos del equipo"
    Write-host -ForegroundColor Yellow "###################################################"
    
    Write-Host "`n"
    Write-Host "ID del equipo: $ID"
    Write-Host "Nombre del equipo: $hostname"
    Write-Host "`n"
    Write-Host "Proteccion en la red: $flag"
    Write-Host "Proteccion PUA: $flag1"
    Write-Host "Proteccion en tiempo real: $flag2`n"

    if ($Mode -eq "Normal")
    {
        Write-Host -ForegroundColor Green "M. Defender: Activo`n"
    }
    else 
    {
        Write-Host -ForegroundColor Red "M. Defender: Pasivo`n"
    }
}

######################################

## Estado ASR

######################################

function RuleASR {

    #Cuenta cuantas reglas en total tiene el equipo aplicada.
    Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids | measure-object -line | fl * > total.txt

    $ASR_total=Get-Content total.txt | Select-String "Lines" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    del total.txt

    $ASR = [ordered]@{}
    $head=1


    #Analiza la regla ASR y la compara con el diccionario de arriba para asociarla con su enunciado y su estado. 
    for ($i = 1; $i -le $ASR_total; $i++) {
      $rule=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids  | select -first $head | select -last 1

      if ($rule -eq $asr1) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v1"] = "$action"
      }
      elseif ($rule -eq $asr2) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v2"] = "$action"
      }
      elseif ($rule -eq $asr3) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v3"] = "$action"
      }
      elseif ($rule -eq $asr4) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v4"] = "$action"
      }  
      elseif ($rule -eq $asr5) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v5"] = "$action"
      }
      elseif ($rule -eq $asr6) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v6"] = "$action"
      }
      elseif ($rule -eq $asr7) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v7"] = "$action"
      }
      elseif ($rule -eq $asr8) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v8"] = "$action"
      }
      elseif ($rule -eq $asr9) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v9"] = "$action"
      }
      elseif ($rule -eq $asr10) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v10"] = "$action"
      }
      elseif ($rule -eq $asr11) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v11"] = "$action"
      }
      elseif ($rule -eq $asr12) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v12"] = "$action"
      }
      elseif ($rule -eq $asr13) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v13"] = "$action"
      }
      elseif ($rule -eq $asr14) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v14"] = "$action"
      }
      elseif ($rule -eq $asr15) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v15"] = "$action"
      }
      elseif ($rule -eq $asr16) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | select -first $head | select -last 1
        if ($Accion -eq 0)
        {
            $action="Deshabilitado"
        }
        elseif ($Accion -eq 1)
        {
            $action="Bloqueado"
        }
        elseif ($Accion -eq 2)
        {
            $action="Auditoria"
        }
        elseif ($Accion -eq 6)
        {
            $action="Advertencia"
        }

        $ASR["$v16"] = "$action"
      }
  
      $head++ 
    }

    

    if ($ASR_total -gt 0)
    {

        Write-host -ForegroundColor Yellow "Estados de reglas ASR"
        Write-host -ForegroundColor Yellow "###################################################"

        $ASR.GetEnumerator() | Sort-Object -Property key | Format-Table -AutoSize
    }

}

######################################
##
## Programación de examenes
##
#####################################


function exam {
    $TypeScan=Get-Content C:\defender.txt | Select-String "ScanParameters" | ForEach-Object { ([string]$_).Split(":")[1] }
    $DayScan=Get-Content C:\defender.txt | Select-String "ScanScheduleDay" | ForEach-Object { ([string]$_).Split(":")[1] }
    $HourScan=Get-Content C:\defender.txt | Select-String "ScanScheduleTime" | ForEach-Object { ([string]$_).Split(":")[1] }
    $MinuteScan=Get-Content C:\defender.txt | Select-String "ScanScheduleTime" | ForEach-Object { ([string]$_).Split(":")[2] }

    $DayScan= $DayScan -replace(" ","")
    $TypeScan= $TypeScan -replace(" ","")

    #Analizar que día de la semana es el examen

    if ($DayScan -eq 0)
    {
        $day="Todos los dias"
    }
    elseif ( $DayScan -eq 1)
    {
        $day="Domingo"
    }
    elseif ( $DayScan -eq 2)
    {
        $day="Lunes"
    }
    elseif ( $DayScan -eq 3)
    {
        $day="Martes"
    }
    elseif ( $DayScan -eq 4)
    {
        $day="Miercoles"
    }
    elseif ( $DayScan -eq 5)
    {
        $day="Jueves"
    }
    elseif ( $DayScan -eq 6)
    {
        $day="Viernes"
    }
    elseif ( $DayScan -eq  7)
    {
        $day="Sabado"
    }
    elseif ( $DayScan -eq 8)
    {
        $day="Nunca"
    }


    #Indicar tipo de examen
    if ( $TypeScan -eq 1)
    {
        $type="rapido"
    }
    elseif ($TypeScan -eq 2)
    {
        $type="completo"
    }

    Write-host -ForegroundColor Yellow "Examen programado"
    Write-host -ForegroundColor Yellow "###################################################"
    write-host "Existe examen $Type programado para $day a las $HourScan : $MinuteScan"



}

######################################
## Exlcusiones
##
######################################


$Extension= Get-Content C:\defender.txt | Select-String "ExclusionExtension" | ForEach-Object { ([string]$_).Split(":")[1] }
$IPA= Get-Content C:\defender.txt | Select-String "ExclusionIpAddress" | ForEach-Object { ([string]$_).Split(":")[1] }
$Path= Get-Content C:\defender.txt | Select-String "ExclusionPath" | ForEach-Object { ([string]$_).Split(":")[1] }
$Process= Get-Content C:\defender.txt | Select-String "ExclusionProcess" | ForEach-Object { ([string]$_).Split(":")[1] }

#######################################
##
## Antivirus
##
#######################################

Function antivirus {
   


    #Directiva de antivirus
    $Antivirus = [ordered]@{}

    $a1= get-content C:\defender.txt | Select-String "DisableArchiveScanning" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a1 -eq "False")
    {
        $Antivirus["Escaneo de archivos"] = "Habilitado"
    }
    else
    {
        $Antivirus["Escaneo de archivos"] = "Deshabilitado"
    }

    $a2= get-content C:\defender.txt | Select-String "DisableEmailScanning" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a2 -eq "False")
    {
        $Antivirus["Escaneo de email"] = "Habilitado"
    }
    else
    {
        $Antivirus["Escaneo de email"] = "Deshabilitado"
    }


    $a3= get-content C:\defender.txt | Select-String "DisableRealtimeMonitoring" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a3 -eq "False")
    {
        $Antivirus["Monitorizacion en tiempo real"] = "Habilitado"
    }
    else
    {
        $Antivirus["Monitorizacion en tiempo real"] = "Deshabilitado"
    }

    $a4= get-content C:\defender.txt | Select-String "DisableRemovableDriveScanning" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a4 -eq "False")
    {
        $Antivirus["Escaneo unidades extraibles"] = "Habilitado"
    }
    else
    {
        $Antivirus["Escaneo unidades extraibles"] = "Deshabilitado"
    }

    $a5= get-content C:\defender.txt | Select-String "DisableRestorePoint" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a5 -eq "False")
    {
        $Antivirus["Puntos de restauracion"] = "Habilitado"
    }
    else
    {
        $Antivirus["Puntos de restauracion"] = "Deshabilitado"
    }

    $a6= get-content C:\defender.txt | Select-String "DisableScanningMappedNetworkDrivesForFullScan" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a6 -eq "False")
    {
        $Antivirus["Escaneo completo unidades de red"] = "Habilitado"
    }
    else
    {
        $Antivirus["Escaneo completo unidades de red"] = "Deshabilitado"
    }

    $a7= get-content C:\defender.txt | Select-String "DisableBehaviorMonitoring" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a7 -eq "False")
    {
        $Antivirus["Control del comportamiento"] = "Habilitado"
    }
    else
    {
        $Antivirus["Control del comportamiento"] = "Deshabilitado"
    }

    $a8= get-content C:\defender.txt | Select-String "DisableInboundConnectionFiltering" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a8 -eq "False")
    {
        $Antivirus["Filtrado de conexiones entrantes"] = "Habilitado"
    }
    else
    {
        $Antivirus["Filtrado de conexiones entrantes"] = "Deshabilitado"
    }

    

    $a9= get-content C:\defender.txt | Select-String "RealTimeScanDirection" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a9 -eq 0)
    {
        $Antivirus["Direccion analisis de los archivos"] = "Bidireccional"
    }
    elseif ($a9 -eq 1)
    {
        $Antivirus["Direccion analisis de los archivos"] = "Solo entrantes"
    }
    elseif ($a9 -eq 2)
    {
        $Antivirus["Direccion analisis de los archivos"] = "Solo entrantes"
    }


    
    $a10= get-content C:\defender.txt | Select-String "DisableBlockAtFirstSeen" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a -eq "False")
    {
        $Antivirus["Bloqueo visto por primera vez"] = "Habilitado"
    }
    else
    {
        $Antivirus["Bloqueo visto por primera vez"] = "Deshabilitado"
    }



    $a11= get-content C:\defender.txt | Select-String "DisableCatchupFullScan" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a11 -eq "False")
    {
        $Antivirus["Analisis de puesta al día completo"] = "Habilitado"
    }
    else
    {
        $Antivirus["Analisis de puesta al día completo"] = "Deshabilitado"
    }



    $a12= get-content C:\defender.txt | Select-String "DisableCatchupQuickScan" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a12 -eq "False")
    {
        $Antivirus["Analisis de puesta al día rapido"] = "Habilitado"
    }
    else
    {
        $Antivirus["Analisis de puesta al día rapido"] = "Deshabilitado"
    }



    $a13= get-content C:\defender.txt | Select-String "DisableCpuThrottleOnIdleScans" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a13 -eq "False")
    {
        $Antivirus["Limitacion CPU para examenes"] = "Habilitado"
    }
    else
    {
        $Antivirus["Limitacion CPU para examenes"] = "Deshabilitado"
    }


    $a14= get-content C:\defender.txt | Select-String "DisableDatagramProcessing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a14 -eq "False")
    {
        $Antivirus["Inspeccion conexiones UDP"] = "Habilitado"
    }
    else
    {
        $Antivirus["Inspeccion conexiones UDP"] = "Deshabilitado"
    }


    $a15= get-content C:\defender.txt | Select-String "DisableDnsOverTcpParsing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a15 -eq "False")
    {
        $Antivirus["Inspeccion del trafico DNS en canal TCP"] = "Habilitado"
    }
    else
    {
        $Antivirus["Inspeccion del trafico DNS en canal TCP"] = "Deshabilitado"
    }

    $a16= get-content C:\defender.txt | Select-String "DisableDnsParsing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a15 -eq "False")
    {
        $Antivirus["Inspeccion del trafico DNS en canal UDP"] = "Habilitado"
    }
    else
    {
        $Antivirus["Inspeccion del trafico DNS en canal UDP"] = "Deshabilitado"
    }


    Write-host -ForegroundColor Yellow "Antivirus"
    Write-host -ForegroundColor Yellow "###################################################"

    $Antivirus.GetEnumerator() | Sort-Object -Property key | format-table -AutoSize

}
#######################################
##
## Mostrar los resultados
##
#######################################

function exe {
    
    equipo

    Antivirus

    RuleASR


    exam
    del C:\defender.txt 
    del C:\Status.txt

}

exe