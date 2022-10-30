# Autor: Ismael Morilla
# Versión: 1.0
# Descripcion: Comparar las configuraciones existentes de Microsoft Defender for Endpoint


# Exortación de inforamcion
Clear-Host
Get-MpPreference > defender.txt
Get-MpComputerStatus > Status.txt
dsregcmd /status > result.txt

# Declaracion de variables ASR
$v1="Impedir que Adobe Reader cree procesos secundarios"	
$asr1="7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"

$v2="Bloquear la ejecucion de scripts posiblemente ofuscados"	
$asr2="5beb7efe-fd9a-4556-801d-275e5ffc04cc"

$v3="Bloquear las llamadas API Win32 desde macros de office"
$asr3="92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"

$v4="Bloquear el robo de credenciales del subsistema de autoridad de seguridad local de Windows"
$asr4="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"

$v5="Bloquear los archivos ejecutables si no cumplen un criterio de la lista de confianza, antiguedad o prevalencia"	
$asr5="01443614-cd74-433a-b99e-2ecdc07bfc25"

$v6="Impedir que JavaScript o VBScript inicien el contenido ejecutable descargado"
$asr6="d3e037e1-3eb8-44c8-a917-57927947596d"

$v7="Impedir que la aplicacion de comunicacion de Office cree procesos secundarios"
$asr7="26190899-1602-49e8-8b27-eb1d0a1ce869"

$v8="Impedir que todas las aplicaciones de office creen procesos secundarios"
$asr8="d4f940ab-401b-4efc-aadc-ad5f3c50688a"

$v9="Bloquear los procesos sin firma y que no son de confianza ejecutados desde USB"
$asr9="b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"

$v10="Bloquear la creacion de procesos procedente de comandos PSExec y WMI"
$asr10="d1e49aac-8f56-4280-b9ba-993a6d77406c"

$v11="Bloquear la persistencia mediante la suscripcion de eventos WMI"
$asr11="e6db77e5-3df2-4cf1-b95a-636979351e5b"

$v12="Impedir que las aplicaciones de office creen contenido ejecutable"
$asr12="3b576869-a4ec-4529-8536-b80a7769e899"

$v13="Impedir que las aplicaciones de office inyecten codigo en otros procesos"
$asr13="75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"

$v14="Usar proteccion avanzada contra ransomware"
$asr14="c1db55ab-c21a-4637-bb3f-a12568109d35"

$v15="Bloquear contenido ejecutable del cliente de correo electronico y el correo web"
$asr15="be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"

$v16="Bloquear el abuso de controladores firmados vulnerables explotados (dispositivos)"
$asr16="56a863a9-875e-4185-98a7-b882c64b5ce5"

# Declaracion de funciones
Function equipo {
    #ID del equipo
        $ID = Get-Content defender.txt | Select-String "ComputerID" | ForEach-Object { ([string]$_).Split(":")[1] }
    #Hostame del equipo
        $hostname=hostname
    
    #Comprobar si la Proteccion en la red está activado
        $red = Get-Content defender.txt | Select-String "EnableNetworkProtection" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }



    #Comprobar el estado de inscripción del dispositivo
        $domian= Get-Content result.txt | select-string "DomainJoined" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }
        $Azure= Get-Content result.txt | select-string "AzureADJoined" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

        if ($domian -eq "YES")
        {
            if ($Azure -eq "YES")
            {
                $estado="Equipo Hibrido"
            }
            else 
            {
                $estado="Equipo en dominio"
            }

        }
        else
        {
            $estado="Equipo en la nube"
        }

    #Comprobar que la "Protección contra aplicaciones pontencialmente no deseadas" el estado en el que se encuentra
        $PUA= get-content defender.txt | Select-String "PUAProtection" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    #Comprobar si Defender está modo pasivo o primario
        $Mode = Get-Content status.txt | Select-String "AMRunningMode" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    #Comprobar el estado de la "protección en tiempo real"
        $RealTime = Get-Content status.txt | Select-String "RealTimeProtectionEnabled" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    #Pintar en pantalla los datos adquiridos
        Write-host -ForegroundColor Yellow "Datos del equipo"
        Write-host -ForegroundColor Yellow "###################################################"
        
        Write-Host "`n"
        Write-Host "ID del equipo: $ID"
        Write-Host "Nombre del equipo: $hostname"
        Write-Host "Inscripcion del dispositivo: $estado"
        Write-Host "`n"
       
        if ($red -eq 1)
        {
            Write-Host "Proteccion en la red: " -NoNewline; Write-Host -ForegroundColor Green "Activado"
        }
        elseif ($red -eq 2)
        {
            Write-Host "Proteccion en la red: " -NoNewline; Write-Host -ForegroundColor Yellow "Auditoria"
        }
        else 
        {
            Write-Host "Proteccion en la red: " -NoNewline; Write-Host -ForegroundColor Red "Desactivado"
        }

        
        if ($PUA -eq 1)
        {
            Write-Host "Proteccion PUA: " -NoNewline; Write-Host -ForegroundColor Green "Activado"
        }
        elseif ($PUA -eq 2)
        {
            Write-Host "Proteccion PUA: " -NoNewline; Write-Host -ForegroundColor Yellow "Auditoria"
        }
        else 
        {
            Write-Host "Proteccion PUA: " -NoNewline; Write-Host -ForegroundColor Red "Desactivado"
        }

       
        if ($RealTime -eq "True")
        {
            Write-Host "Proteccion en tiempo real: " -NoNewline; Write-Host -ForegroundColor Green "Activado"`n
        }
        else
        {
            Write-Host "Proteccion en tiempo real: " -NoNewline; Write-Host -ForegroundColor Red "Desactivado"`n
        } 


        if ($Mode -eq "Normal")
        {
            Write-Host "M. Defender: " -NoNewline; Write-Host -ForegroundColor Green "Activo"`n
        }
        else 
        {
            Write-Host "M. Defender: " -NoNewline; Write-Host -ForegroundColor Red "Pasivo"`n
        }
}

function Amenazas {

    $flag=Get-Content defender.txt | Select-String "LowThreatDefaultAction" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    # Solo mostrar las amenazas si el equipo recibe las politicas de defender por GPO
    if ($flag -eq 0)
    {

        Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\' | select-object -ExpandProperty Property | Measure-Object -line | Format-List * > total.txt
    
        $Threat_total=Get-Content total.txt | Select-String "Lines" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }
    
        Remove-Item total.txt

        if ($threat_total -ne 0)
            {
                #Creacion de la tabla de valores
                $threat = [ordered]@{}
                $linea=0

                for ($i = 1; $i -le $Threat_total; $i++) {
                        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\' | Select-String "1" >> result.txt
                        $rul=Get-Content .\result.txt | select-string "@{1" | ForEach-Object { ([string]$_).Split(";")[$linea] } | ForEach-Object { ([string]$_).Split("=")[0] } 
                        $key=Get-Content .\result.txt | select-string "@{1" | ForEach-Object { ([string]$_).Split(";")[$linea] } | ForEach-Object { ([string]$_).Split("=")[1] } | ForEach-Object { ([string]$_).Split(" ")[0] } 
                
            
    
                        if ($rul -eq "@{1")
                        {
                            $rul=1
                        } 
                        else 
                        {
                            $rul=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\' | Select-String "1" | ForEach-Object { ([string]$_).Split(";")[$linea] } | ForEach-Object { ([string]$_).Split("=")[0] } | ForEach-Object { ([string]$_).Split(" ")[1] } 
                        }
        
    
                        if ($rul -eq 1)
                        {
                            $nivel="Amenaza Baja"
                        }
                        elseif ($rul -eq 2)
                        {
                            $nivel="Amenaza Media"
                        }
                        elseif ($rul -eq 4)
                        {
                            $nivel="Amenaza Alta"
                        }
                        elseif ($rul -eq 5)
                        {
                        $nivel="Amenaza Grave"
                        }
    
    
            
    
                        if ($key -eq 2)
                        { 
                            $correccion="Cuarentena" 
                        }
                        elseif ($key -eq 3)
                        {
                            $correccion="Quitar"
                        }
                        elseif ($key -eq 6)
                        {
                            $correccion="Omitir"
                        }
        
                        $threat["$nivel"] = "$correccion"
                        $linea++              
                }
            }

        $threat
    } 

    else 
    {
        $low=Get-Content defender.txt | Select-String "LowThreatDefaultAction" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }
        $moderate=Get-Content defender.txt | Select-String "ModerateThreatDefaultAction" | ForEach-Object { ([string]$_).Split(":")[1] }| ForEach-Object { ([string]$_).Split(" ")[1] }
        $high=Get-Content defender.txt | Select-String "HighThreatDefaultAction" | ForEach-Object { ([string]$_).Split(":")[1] }| ForEach-Object { ([string]$_).Split(" ")[1] }
        $severe=Get-Content defender.txt | Select-String "SevereThreatDefaultAction" | ForEach-Object { ([string]$_).Split(":")[1] }| ForEach-Object { ([string]$_).Split(" ")[1] }
    
        $threat = [ordered]@{}
    
        if ($low -eq 1)
        {
            $amenaza="Limpiar"
        }
        elseif ($low -eq 2)
        {
            $amenaza="Cuarentena"
        }
        elseif ($low -eq 3)
        {
            $amenaza="Eliminar"
        }
        elseif ($low -eq 6)
        {
            $amenaza="Permitir"
        }
        elseif ($low -eq 8)
        {
            $amenaza="Usuario define"
        }
        elseif ($low -eq 10)
        {
            $amenaza="Bloquear"
        }
    
        $threat["Amenaza baja"] = "$amenaza"
    
        if ($moderate -eq 1)
        {
            $amenaza="Limpiar"
        }
        elseif ($moderate -eq 2)
        {
            $amenaza="Cuarentena"
        }
        elseif ($moderate -eq 3)
        {
            $amenaza="Eliminar"
        }
        elseif ($moderate -eq 6)
        {
            $amenaza="Permitir"
        }
        elseif ($moderate -eq 8)
        {
            $amenaza="Usuario define"
        }
        elseif ($moderate -eq 10)
        {
            $amenaza="Bloquear"
        }
            
    
        $threat["Amenaza media"] = "$amenaza"
    
        if ($high -eq 1)
        {
            $amenaza="Limpiar"
        }
        elseif ($high -eq 2)
        {
            $amenaza="Cuarentena"
        }
        elseif ($high -eq 3)
        {
            $amenaza="Eliminar"
        }
        elseif ($high -eq 6)
        {
            $amenaza="Permitir"
        }
        elseif ($high -eq 8)
        {
            $amenaza="Usuario define"
        }
        elseif ($high -eq 10)
        {
            $amenaza="Bloquear"
        }
    
        $threat["Amenaza alta"] = "$amenaza"
    
        if ($severe -eq 1)
        {
            $amenaza="Limpiar"
        }
        elseif ($severe -eq 2)
        {
            $amenaza="Cuarentena"
        }
        elseif ($severe -eq 3)
        {
            $amenaza="Eliminar"
        }
        elseif ($severe -eq 6)
        {
            $amenaza="Permitir"
        }
        elseif ($severe -eq 8)
        {
            $amenaza="Usuario define"
        }
        elseif ($severe -eq 10)
        {
            $amenaza="Bloquear"
        }
    
        $threat["Amenaza critica"] = "$amenaza"
    
        $threat.GetEnumerator() | format-table -AutoSize
    }
}

Function Antivirus {
   
    #Creacion de tabla de contenido para directivas de antivirus de defender
    $Antivirus = [ordered]@{}

    #Analisis de las directivas
    $a1= get-content defender.txt | Select-String "DisableArchiveScanning" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    #Examen de archivos
    if ($a1 -eq "False")
    {
        $Antivirus["Examen de archivos"] = "Habilitado"
    }
    else
    {
        $Antivirus["Examen de archivos"] = "Deshabilitado"
    }

    #Examen de email
    $a2= get-content defender.txt | Select-String "DisableEmailScanning" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a2 -eq "False")
    {
        $Antivirus["Examen de email"] = "Habilitado"
    }
    else
    {
        $Antivirus["Examen de email"] = "Deshabilitado"
    }


    #Monitorización en tiempo real
    $a3= get-content defender.txt | Select-String "DisableRealtimeMonitoring" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a3 -eq "False")
    {
        $Antivirus["Monitorizacion en tiempo real"] = "Habilitado"
    }
    else
    {
        $Antivirus["Monitorizacion en tiempo real"] = "Deshabilitado"
    }

    #Examen de unidades extraibles
    $a4= get-content defender.txt | Select-String "DisableRemovableDriveScanning" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a4 -eq "False")
    {
        $Antivirus["Examen unidades extraibles"] = "Habilitado"
    }
    else
    {
        $Antivirus["Examen unidades extraibles"] = "Deshabilitado"
    }

    # Puntos de restauración
    $a5= get-content defender.txt | Select-String "DisableRestorePoint" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a5 -eq "False")
    {
        $Antivirus["Puntos de restauracion"] = "Habilitado"
    }
    else
    {
        $Antivirus["Puntos de restauracion"] = "Deshabilitado"
    }

    #Examen completo de unidades de red
    $a6= get-content defender.txt | Select-String "DisableScanningMappedNetworkDrivesForFullScan" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a6 -eq "False")
    {
        $Antivirus["Examen completo unidades de red"] = "Habilitado"
    }
    else
    {
        $Antivirus["Examen completo unidades de red"] = "Deshabilitado"
    }

    #Control del comportamiento
    $a7= get-content defender.txt | Select-String "DisableBehaviorMonitoring" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a7 -eq "False")
    {
        $Antivirus["Control del comportamiento"] = "Habilitado"
    }
    else
    {
        $Antivirus["Control del comportamiento"] = "Deshabilitado"
    }


    #Filtrado de conexiones entrantes
    $a8= get-content defender.txt | Select-String "DisableInboundConnectionFiltering" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a8 -eq "False")
    {
        $Antivirus["Filtrado de conexiones entrantes"] = "Habilitado"
    }
    else
    {
        $Antivirus["Filtrado de conexiones entrantes"] = "Deshabilitado"
    }

    
    #Dirección del analisis de los archivos
    $a9= get-content defender.txt | Select-String "RealTimeScanDirection" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

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


    #Bloqueo visto por primera vez
    $a10= get-content defender.txt | Select-String "DisableBlockAtFirstSeen" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a10 -eq "False")
    {
        $Antivirus["Bloqueo visto por primera vez"] = "Habilitado"
    }
    else
    {
        $Antivirus["Bloqueo visto por primera vez"] = "Deshabilitado"
    }


    #Analisis completo de puesta al día
    $a11= get-content defender.txt | Select-String "DisableCatchupFullScan" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a11 -eq "False")
    {
        $Antivirus["Analisis de puesta al dia completo"] = "Habilitado"
    }
    else
    {
        $Antivirus["Analisis de puesta al dia completo"] = "Deshabilitado"
    }


    #Analisis rapido de puesta al día
    $a12= get-content defender.txt | Select-String "DisableCatchupQuickScan" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a12 -eq "False")
    {
        $Antivirus["Analisis de puesta al dia rapido"] = "Habilitado"
    }
    else
    {
        $Antivirus["Analisis de puesta al dia rapido"] = "Deshabilitado"
    }


    #Mostrar el porcentaje de limitación de CPU
    $a13= get-content defender.txt | Select-String "ScanAvgCPULoadFactor" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }
 
    $Antivirus["Limitacion CPU para examenes"] = "$a13 %"
    

    #Inspección de conexiones UDP
    $a14= get-content defender.txt | Select-String "DisableDatagramProcessing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a14 -eq "False")
    {
        $Antivirus["Inspeccion conexiones UDP"] = "Habilitado"
    }
    else
    {
        $Antivirus["Inspeccion conexiones UDP"] = "Deshabilitado"
    }


    #Inspección del trafico DNS en el canal TCP
    $a15= get-content defender.txt | Select-String "DisableDnsOverTcpParsing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a15 -eq "False")
    {
        $Antivirus["Inspeccion del trafico DNS en canal TCP"] = "Habilitado"
    }
    else
    {
        $Antivirus["Inspeccion del trafico DNS en canal TCP"] = "Deshabilitado"
    }

    #Inspección del trafico DNS en el canal UDP
    $a16= get-content defender.txt | Select-String "DisableDnsParsing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a16 -eq "False")
    {
        $Antivirus["Inspeccion del trafico DNS en canal UDP"] = "Habilitado"
    }
    else
    {
        $Antivirus["Inspeccion del trafico DNS en canal UDP"] = "Deshabilitado"
    }



    #Comprobar si la protección en la nube está activo y el nivel de protección
    $a17=Get-Content defender.txt | Select-String "MAPSReporting" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a17 -eq 0)
    {
        $Antivirus["Proteccion en la nube"] = "Deshabilitado"
    }
    elseif ($a17 -eq 1)
    {
        $Antivirus["Proteccion en la nube"] = "Membresia basica"
    }
    else
    {
        $Antivirus["Proteccion en la nube"] = "Membresia Avanzada"
    }


    # Examinar todos los archivos y datos adjuntos descargados
    $a18= get-content defender.txt | Select-String "DisableDnsParsing" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a18 -eq "False")
    {
        $Antivirus["Examen archivos y adjuntos descargados"] = "Habilitado"
    }
    else
    {
        $Antivirus["Examen archivos y adjuntos descargados"] = "Deshabilitado"
    }

    #Comprobar el nivel de proteccion en la nube
    $a19=Get-Content defender.txt | Select-String "CloudBlockLevel" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a19 -eq 0)
    {
        $Antivirus["Nivel proteccion en la nube"] = "Predeterminado"
    }
    elseif ($a19 -eq 2)
    {
        $Antivirus["Nivel proteccion en la nube"] = "Alto"
    }
    elseif ($a19 -eq 4)
    {
        $Antivirus["Nivel proteccion en la nube"] = "Alto nivel de bloqueo +"
    }
    elseif ($a19 -eq 6)
    {
        $Antivirus["Nivel proteccion en la nube"] = "Tolerancia cero"
    }


    #Tiempo extendido  para bloquear un archivo malicioso
    $a20= get-content defender.txt | Select-String "CloudExtendedTimeout" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }
 
    $Antivirus["Tiempo extendido bloqueo archivo malicioso"] = "$a20 seg."

    
    #Comprobar tipo de analisis predeterminado
    $a21=Get-Content defender.txt | Select-String "ScanParameters" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a21 -eq 1)
    {
        $Antivirus["Tipo de analisis"] = "Rapido"
    }
    elseif ($a21 -eq 2)
    {
        $Antivirus["Tipo de analisis"] = "Completo"
    }

    #Consentimiento del usuario
    $a22=Get-Content defender.txt | Select-String "SubmitSamplesConsent" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    if ($a22 -eq 0)
    {
        $Antivirus["Consentimiento usuario"] = "Preguntar siempre"
    }
    elseif ($a22 -eq 1)
    {
        $Antivirus["Consentimiento usuario"] = "Enviar muestras seguras autom."
    }
    elseif ($a22 -eq 2)
    {
        $Antivirus["Consentimiento usuario"] = "Nunca enviar"
    }
    elseif ($a22 -eq 3)
    {
        $Antivirus["Consentimiento usuario"] = "Enviar todas muestras autom."
    }

    #Mostrar la tabla de valores con los datos extraidos
    Write-host -ForegroundColor Yellow "Antivirus"
    Write-host -ForegroundColor Yellow "###################################################"
    $Antivirus.GetEnumerator() | Sort-Object -Property key | format-table -AutoSize
    
}

function RuleASR {

    #Cuenta cuantas reglas en total tiene el equipo aplicada.
    Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids | measure-object -line | Format-List * > total.txt

    $ASR_total=Get-Content total.txt | Select-String "Lines" | ForEach-Object { ([string]$_).Split(":")[1] } | ForEach-Object { ([string]$_).Split(" ")[1] }

    Remove-Item total.txt

    $ASR = [ordered]@{}
    $head=1


    #Analiza la regla ASR y la compara con el diccionario de arriba para asociarla con su enunciado y su estado. 
    for ($i = 1; $i -le $ASR_total; $i++) {
      $rule=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids  | Select-Object -first $head | Select-Object -last 1

      if ($rule -eq $asr1) 
      {
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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
        $Accion=Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions  | Select-Object -first $head | Select-Object -last 1
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

function ExamenProgramado {
    $TypeScan=Get-Content defender.txt | Select-String "ScanParameters" | ForEach-Object { ([string]$_).Split(":")[1] }
    $DayScan=Get-Content defender.txt | Select-String "ScanScheduleDay" | ForEach-Object { ([string]$_).Split(":")[1] }
    $Scan=Get-Content defender.txt | Select-String "ScanScheduleTime" 
    $HourScan= $Scan -split ' ' | ForEach-Object { ([string]$_).Split(" ")[0] } | Select-Object -last 1


    $DayScan= $DayScan -replace(" ","")
    $TypeScan= $TypeScan -replace(" ","")

    #Analizar que día de la semana es el examen

    if ($DayScan -eq 0)
    {
        $day="todos los dias"
    }
    elseif ( $DayScan -eq 1)
    {
        $day="domingo"
    }
    elseif ( $DayScan -eq 2)
    {
        $day="lunes"
    }
    elseif ( $DayScan -eq 3)
    {
        $day="martes"
    }
    elseif ( $DayScan -eq 4)
    {
        $day="miercoles"
    }
    elseif ( $DayScan -eq 5)
    {
        $day="jueves"
    }
    elseif ( $DayScan -eq 6)
    {
        $day="viernes"
    }
    elseif ( $DayScan -eq  7)
    {
        $day="sabado"
    }
    elseif ( $DayScan -eq 8)
    {
        $day="nunca"
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
    write-host "Existe examen" -NoNewline; Write-Host -ForegroundColor Green " $Type " -NoNewline; Write-Host "programado para" -NoNewline; Write-Host -ForegroundColor Green " $day " -NoNewline; Write-host "a las" -NoNewline; Write-Host -ForegroundColor Green " $HourScan "`n



}

# Ejecución de funcion en orden de prioridad
equipo
RuleASR
ExamenProgramado
Antivirus
write-host -ForegroundColor Yellow "Proteccion contra amenazas:"
Amenazas

Remove-Item defender.txt 
Remove-Item result.txt 
Remove-Item status.txt 