Set-Content -Path "dns_win.ps1" -Value @'
# =============================================================
#  Script de Configuración Automática de DNS - Windows Server
#  Versión: 1.2
#
#  USO:
#    .\dns_windows.ps1                        (pide dominio interactivamente)
#    .\dns_windows.ps1 -Domain midominio.com  (dominio como parámetro)
# =============================================================

#Requires -RunAsAdministrator

$DOMAIN = ""
$DNS_IP = ""
$ErrorActionPreference = "Continue"

# ── Funciones de log ─────────────────────────────────────────
function Log-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Log-Ok    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Log-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Log-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Print-Banner {
    Clear-Host
    $domDisplay = if ([string]::IsNullOrWhiteSpace($DOMAIN)) { "Sin configurar" } else { $DOMAIN }
    Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Administrador DNS - Windows Server         ║" -ForegroundColor Cyan
    Write-Host ("║   Dominio: " + $domDisplay.PadRight(34) + "║") -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ── Función auxiliar: configurar IP estática ─────────────────
function _Set-StaticIP {
    param($AdapterIndex, $AdapterName)

    Write-Host ""
    Log-Info "Configuración de IP estática para: $AdapterName"
    $newIP   = Read-Host "IP estática (ej: 192.168.1.100)"
    $prefix  = Read-Host "Longitud de prefijo (ej: 24)"
    $gateway = Read-Host "Gateway (ej: 192.168.1.1)"
    $dns1    = Read-Host "DNS primario (ej: 8.8.8.8)"

    if ($newIP -notmatch "^\d{1,3}(\.\d{1,3}){3}$") {
        Log-Error "Formato de IP inválido: $newIP"; return $null
    }

    try {
        Remove-NetIPAddress -InterfaceIndex $AdapterIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute     -InterfaceIndex $AdapterIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress -InterfaceIndex $AdapterIndex -IPAddress $newIP `
                         -PrefixLength $prefix -DefaultGateway $gateway | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $AdapterIndex -ServerAddresses ($dns1, "8.8.8.8")

        Log-Ok "IP estática asignada: $newIP/$prefix"
        return $newIP
    } catch {
        Log-Error "Error al configurar IP: $_"; return $null
    }
}

# ── Función auxiliar: resolver IP a usar ─────────────────────
function _Resolve-IP {
    if ($script:DNS_IP -ne "") { return }

    # Obtener todos los adaptadores activos con IPv4
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    if ($adapters.Count -eq 0) {
        Log-Error "No se encontraron adaptadores de red activos."
        return
    }

    # Mostrar todas las interfaces disponibles para que el usuario elija
    Write-Host ""
    Log-Info "Interfaces de red disponibles:"
    $i = 1
    $adapterList = @()
    foreach ($a in $adapters) {
        $ipCfg = Get-NetIPConfiguration -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue
        $ip = if ($ipCfg.IPv4Address) { $ipCfg.IPv4Address.IPAddress } else { "Sin IP" }
        $dhcpStatus = (Get-NetIPInterface -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
        $tipo = if ($dhcpStatus -eq "Disabled") { "Estática" } else { "DHCP" }
        Write-Host "  $i) $($a.Name) | IP: $ip | $tipo" -ForegroundColor White
        $adapterList += $a
        $i++
    }

    Write-Host ""
    $sel = Read-Host "Selecciona la interfaz de red interna [1-$($adapterList.Count)]"
    $idx = [int]$sel - 1

    if ($idx -lt 0 -or $idx -ge $adapterList.Count) {
        Log-Error "Selección inválida. Usando primera interfaz."
        $idx = 0
    }

    $adapter  = $adapterList[$idx]
    $ipCfg    = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
    $currentIP = if ($ipCfg.IPv4Address) { $ipCfg.IPv4Address.IPAddress } else { "" }
    $dhcp     = (Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4).Dhcp

    if ($dhcp -eq "Disabled") {
        Log-Ok "IP estática detectada en $($adapter.Name): $currentIP"
        Write-Host ""
        $cambiar = Read-Host "¿Deseas modificar la IP, gateway o DNS de esta interfaz? (s/n)"
        if ($cambiar -match "^[Ss]$") {
            $result = _Set-StaticIP -AdapterIndex $adapter.InterfaceIndex -AdapterName $adapter.Name
            if ($result) { $script:DNS_IP = $result }
            else         { $script:DNS_IP = $currentIP }
        } else {
            $script:DNS_IP = $currentIP
            Log-Ok "Usando IP estática actual: $currentIP"
        }
    } else {
        Log-Warn "IP dinámica (DHCP) en $($adapter.Name): $currentIP"
        $resp = Read-Host "¿Configurar IP estática ahora? (s/n)"
        if ($resp -match "^[Ss]$") {
            $result = _Set-StaticIP -AdapterIndex $adapter.InterfaceIndex -AdapterName $adapter.Name
            if ($result) { $script:DNS_IP = $result }
            else         { $script:DNS_IP = $currentIP }
        } else {
            $script:DNS_IP = $currentIP
            Log-Warn "Usando IP dinámica: $currentIP"
        }
    }
}


# ── Función auxiliar: pedir y validar dominio ────────────────
function _Resolver-Dominio {
    if (-not [string]::IsNullOrWhiteSpace($script:DOMAIN)) { return $true }

    Write-Host ""
    $d = Read-Host "Ingresa el dominio a configurar (ej: reprobados.com)"
    if ([string]::IsNullOrWhiteSpace($d)) {
        $d = "reprobados.com"
        Log-Warn "No se ingresó dominio. Usando valor por defecto: $d"
    }

    if ($d -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$") {
        Log-Error "Formato de dominio inválido: $d"
        return $false
    }

    $script:DOMAIN = $d
    Log-Ok "Dominio configurado: $($script:DOMAIN)"
    return $true
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 1 — Instalación Idempotente
# ════════════════════════════════════════════════════════════
function Opcion-Instalacion {
    Write-Host "`n── [ 1 ] Instalación Idempotente ──────────────────" -ForegroundColor White

    _Resolve-IP

    Log-Info "Verificando si el rol DNS ya está instalado..."

    $feature = Get-WindowsFeature -Name DNS

    if ($feature.Installed) {
        Log-Ok "Rol DNS ya instalado. No se reinstalará (idempotente)."

        $svc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

        if (-not $svc) {
            Log-Error "El servicio DNS no fue encontrado en el sistema."
            return
        }

        if ($svc.Status -eq "Running") {
            Log-Ok "Servicio DNS ya en ejecución."
            return
        }

        Log-Info "Configurando inicio automático del servicio DNS..."
        Set-Service DNS -StartupType Automatic

        Log-Info "Intentando iniciar el servicio DNS..."
        try {
            Start-Service DNS -ErrorAction Stop
            Start-Sleep -Seconds 3

            $svcCheck = Get-Service -Name "DNS"
            if ($svcCheck.Status -eq "Running") {
                Log-Ok "Servicio DNS iniciado correctamente."
            } else {
                Log-Error "El servicio no quedó en estado Running. Estado actual: $($svcCheck.Status)"
                Log-Warn "Revisa el Visor de Eventos: eventvwr.msc -> Registros de Windows -> Sistema"
            }
        } catch {
            Log-Error "No se pudo iniciar el servicio DNS: $_"
            Log-Warn "Posibles causas:"
            Log-Warn "  1) El rol DNS requiere reiniciar el servidor tras la instalación."
            Log-Warn "  2) Conflicto con otro servicio en el puerto 53."
            Log-Warn "Verifica con: Get-EventLog -LogName System -Source DNS -Newest 5"
        }
        return
    }

    Log-Info "Instalando rol DNS Server con herramientas de administración..."
    try {
        Install-WindowsFeature DNS -IncludeManagementTools | Out-Null
        Set-Service DNS -StartupType Automatic
        Start-Service DNS
        Log-Ok "Rol DNS instalado e iniciado correctamente."
    } catch {
        Log-Error "Error al instalar el rol DNS: $_"
    }
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 2 — Configuración de Zona DNS
# ════════════════════════════════════════════════════════════
function Opcion-Zona {
    Write-Host "`n── [ 2 ] Configuración de Zona DNS ────────────────" -ForegroundColor White
    if (-not (_Resolver-Dominio)) { return }


    # ── Verificar que el servicio DNS esté activo ─────────
    Log-Info "Verificando que el servicio DNS esté activo..."
    $svc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

    if (-not $svc) {
        Log-Error "Servicio DNS no encontrado. Ejecuta primero la Opción 1 (Instalación)."
        return
    }

    if ($svc.Status -ne "Running") {
        # Verificar si el servicio está deshabilitado y reactivarlo
        $startType = (Get-Service DNS).StartType
        if ($startType -eq "Disabled") {
            Log-Warn "Servicio DNS deshabilitado. Reactivando..."
            Set-Service DNS -StartupType Automatic
            Log-Ok "Tipo de inicio restaurado a Automático."
        }

        Log-Warn "Servicio DNS detenido. Iniciando..."
        try {
            Start-Service DNS -ErrorAction Stop
            Start-Sleep -Seconds 3

            $check = Get-Service -Name "DNS"
            if ($check.Status -eq "Running") {
                Log-Ok "Servicio DNS iniciado correctamente."
            } else {
                Log-Error "El servicio no quedó en estado Running. Estado: $($check.Status)"
                Log-Warn "Intenta reiniciar el servidor con: Restart-Computer"
                return
            }
        } catch {
            Log-Error "No se pudo iniciar el servicio DNS: $_"
            Log-Warn "Intenta reiniciar el servidor con: Restart-Computer"
            return
        }
    } else {
        Log-Ok "Servicio DNS en ejecución."
    }

    _Resolve-IP

    Log-Info "Verificando si la zona $DOMAIN ya existe..."

    $zona = Get-DnsServerZone -Name $DOMAIN -ErrorAction SilentlyContinue
    if ($zona) {
        Log-Warn "Zona $DOMAIN ya existe. Se eliminará y recreará."
        Remove-DnsServerZone -Name $DOMAIN -Force -Confirm:$false
        Log-Ok "Zona anterior eliminada."
    }

    try {
        Log-Info "Creando zona primaria: $DOMAIN..."
        Add-DnsServerPrimaryZone -Name $DOMAIN -ZoneFile "${DOMAIN}.dns" -DynamicUpdate None
        Start-Sleep -Seconds 2
        Log-Ok "Zona primaria '$DOMAIN' creada correctamente."
    } catch {
        Log-Error "Error al crear zona: $_"
        Log-Warn "Asegúrate de haber ejecutado la Opción 1 (Instalación) primero."
    }
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 3 — Configuración de Dominio DNS (Registros)
# ════════════════════════════════════════════════════════════
function Opcion-Dominio {
    Write-Host "`n── [ 3 ] Configuración de Dominio DNS ─────────────" -ForegroundColor White

    # ── Solicitar dominio si no está configurado ──────────
    if ([string]::IsNullOrWhiteSpace($script:DOMAIN)) {
        $input = Read-Host "Ingresa el dominio a configurar (ej: reprobados.com)"
        if ([string]::IsNullOrWhiteSpace($input)) {
            $input = "reprobados.com"
            Log-Warn "No se ingresó dominio. Usando valor por defecto: $input"
        }
        if ($input -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$") {
            Log-Error "Formato de dominio inválido: $input"
            return
        }
        $script:DOMAIN = $input
        Log-Ok "Dominio configurado: $($script:DOMAIN)"
    } else {
        Log-Info "Dominio activo: $($script:DOMAIN)"
        $cambiar = Read-Host "¿Deseas usar otro dominio? (s/n)"
        if ($cambiar -match "^[Ss]$") {
            $input = Read-Host "Nuevo dominio"
            if ($input -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$") {
                Log-Error "Formato de dominio inválido: $input"
                return
            }
            $script:DOMAIN = $input
            Log-Ok "Dominio actualizado: $($script:DOMAIN)"
        }
    }

    $zona = Get-DnsServerZone -Name $DOMAIN -ErrorAction SilentlyContinue
    if (-not $zona) {
        Log-Error "Zona $DOMAIN no encontrada."
        Log-Warn "Ejecuta primero la Opción 2 (Configuración de Zona DNS)."
        return
    }

    _Resolve-IP

    # ── Registro A para dominio raíz (@) ─────────────────
    $existeA = Get-DnsServerResourceRecord -ZoneName $DOMAIN -Name "@" -RRType A -ErrorAction SilentlyContinue
    if ($existeA) {
        Log-Warn "Registro A raíz ya existe. Eliminando para recrear..."
        Remove-DnsServerResourceRecord -ZoneName $DOMAIN -Name "@" -RRType A -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    try {
        Add-DnsServerResourceRecordA -ZoneName $DOMAIN -Name "@" -IPv4Address $script:DNS_IP -TimeToLive (New-TimeSpan -Hours 1)
        Log-Ok "Registro A: $DOMAIN → $($script:DNS_IP)"
    } catch {
        Log-Error "Error al crear registro A raíz: $_"
    }

    # ── Registro A para www ───────────────────────────────
    $existeWWW = Get-DnsServerResourceRecord -ZoneName $DOMAIN -Name "www" -RRType A -ErrorAction SilentlyContinue
    if ($existeWWW) {
        Log-Warn "Registro A www ya existe. Eliminando para recrear..."
        Remove-DnsServerResourceRecord -ZoneName $DOMAIN -Name "www" -RRType A -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    try {
        Add-DnsServerResourceRecordA -ZoneName $DOMAIN -Name "www" -IPv4Address $script:DNS_IP -TimeToLive (New-TimeSpan -Hours 1)
        Log-Ok "Registro A: www.$DOMAIN → $($script:DNS_IP)"
    } catch {
        Log-Error "Error al crear registro A www: $_"
    }

    # ── Mostrar registros actuales ────────────────────────
    Write-Host ""
    Log-Info "Registros actuales en la zona $DOMAIN :"
    Get-DnsServerResourceRecord -ZoneName $DOMAIN | Format-Table -AutoSize
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 4 — Dar de Baja DNS
# ════════════════════════════════════════════════════════════
function Opcion-Baja {
    Write-Host "`n── [ 4 ] Dar de Baja DNS ──────────────────────────" -ForegroundColor White

    if (-not (_Resolver-Dominio)) { return }

    $conf = Read-Host "¿Confirmas dar de baja el DNS para $DOMAIN? (s/n)"
    if ($conf -notmatch "^[Ss]$") {
        Log-Warn "Operación cancelada."; return
    }

    # Eliminar zona
    $zona = Get-DnsServerZone -Name $DOMAIN -ErrorAction SilentlyContinue
    if ($zona) {
        Remove-DnsServerZone -Name $DOMAIN -Force -Confirm:$false
        Log-Ok "Zona $DOMAIN eliminada."
    } else {
        Log-Warn "Zona $DOMAIN no encontrada (ya eliminada)."
    }

    # Detener servicio DNS
    $svc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Stop-Service DNS -Force
        Set-Service DNS -StartupType Disabled
        Log-Ok "Servicio DNS detenido y deshabilitado."
    } else {
        Log-Warn "El servicio DNS ya estaba detenido."
    }

    $script:DNS_IP = ""
    Log-Ok "DNS dado de baja correctamente."

    Write-Host ""
    $uninstall = Read-Host "¿Desinstalar el rol DNS de Windows Server? (s/n)"
    if ($uninstall -match "^[Ss]$") {
        try {
            Remove-WindowsFeature DNS -IncludeManagementTools | Out-Null
            Log-Ok "Rol DNS desinstalado del sistema."
        } catch {
            Log-Error "Error al desinstalar el rol: $_"
        }
    }
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 5 — Consultar DNS
# ════════════════════════════════════════════════════════════
function Opcion-Consultar {
    Write-Host "`n── [ 5 ] Consultar DNS ────────────────────────────" -ForegroundColor White

    # Estado del servicio
    if (-not (_Resolver-Dominio)) { return }
    _Resolve-IP

    Write-Host ""
    Log-Info "Estado del servicio DNS:"
    $svc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  Nombre  : $($svc.Name)" -ForegroundColor Gray
        Write-Host "  Estado  : $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq "Running") {"Green"} else {"Red"})
        Write-Host "  Inicio  : $($svc.StartType)" -ForegroundColor Gray
    } else {
        Log-Warn "Servicio DNS no encontrado."
    }

    $srvDNS = Read-Host "`nServidor DNS a consultar (Enter para 127.0.0.1)"
    if ([string]::IsNullOrWhiteSpace($srvDNS)) { $srvDNS = "127.0.0.1" }

    Write-Host ""
    Write-Host "─── Resolución: $DOMAIN ──────────────────────────────" -ForegroundColor Cyan
    nslookup $DOMAIN $srvDNS

    Write-Host ""
    Write-Host "─── Resolución: www.$DOMAIN ──────────────────────────" -ForegroundColor Cyan
    nslookup "www.$DOMAIN" $srvDNS

    Write-Host ""
    Write-Host "─── Ping: www.$DOMAIN ────────────────────────────────" -ForegroundColor Cyan
    ping -n 2 "www.$DOMAIN"

    Write-Host ""
    Log-Info "Registros activos en zona $DOMAIN :"
    $zona = Get-DnsServerZone -Name $DOMAIN -ErrorAction SilentlyContinue
    if ($zona) {
        Get-DnsServerResourceRecord -ZoneName $DOMAIN | Format-Table -AutoSize
    } else {
        Log-Warn "Zona $DOMAIN no encontrada o DNS no activo."
    }
}

# ════════════════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ════════════════════════════════════════════════════════════
function Menu-Principal {
    while ($true) {
        Print-Banner
        Write-Host "  1) Instalación Idempotente"      -ForegroundColor White
        Write-Host "  2) Configuración de Zona DNS"     -ForegroundColor White
        Write-Host "  3) Configuración de Dominio DNS"  -ForegroundColor White
        Write-Host "  4) Dar de Baja DNS"               -ForegroundColor White
        Write-Host "  5) Consultar DNS"                 -ForegroundColor White
        Write-Host "  0) Salir"                         -ForegroundColor White
        Write-Host ""

        $opt = Read-Host "Selecciona una opción [0-5]"

        switch ($opt) {
            "1" { Opcion-Instalacion }
            "2" { Opcion-Zona        }
            "3" { Opcion-Dominio     }
            "4" { Opcion-Baja        }
            "5" { Opcion-Consultar   }
            "0" { Write-Host "`nSaliendo...`n" -ForegroundColor Green; exit 0 }
            default { Log-Warn "Opción inválida. Intenta de nuevo." }
        }

        Write-Host ""
        Read-Host "Presiona Enter para volver al menú"
    }
}

# ── Punto de entrada ──────────────────────────────────────────
Menu-Principal
'@
