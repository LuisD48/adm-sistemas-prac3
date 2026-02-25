#!/bin/bash
# =============================================================
#  Script de Configuración Automática de DNS - BIND9
#  Sistema Operativo: OpenSUSE (Leap / Tumbleweed)
#  Dominio: reprobados.com
#  Versión: 1.2
# =============================================================

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DOMAIN="reprobados.com"
ZONE_FILE="/var/lib/named/${DOMAIN}.zone"
NAMED_CONF="/etc/named.conf"
NAMED_CONF_LOCAL="/etc/named.d/${DOMAIN}.conf"
DNS_IP=""

# ── Funciones de log ─────────────────────────────────────────
log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Verificar root ────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo su o sudo bash)."
        exit 1
    fi
}


# ── Función auxiliar: configurar IP estática (wicked) ────────
_configurar_ip_estatica() {
    local IFACE=$1

    echo -ne "IP estática (ej: 192.168.1.100): "; read -r NEW_IP
    echo -ne "Máscara en bits (ej: 24):         "; read -r PREFIX
    echo -ne "Gateway (ej: 192.168.1.1):        "; read -r GATEWAY
    echo -ne "DNS primario (ej: 8.8.8.8):       "; read -r DNS1

    if ! [[ "$NEW_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Formato de IP inválido: $NEW_IP"; return 1
    fi

    local CFG_FILE="/etc/sysconfig/network/ifcfg-${IFACE}"
    local ROUTE_FILE="/etc/sysconfig/network/ifroute-${IFACE}"
    local DNS_FILE="/etc/sysconfig/network/config"

    log_info "Escribiendo configuración en ${CFG_FILE}..."

    cat > "$CFG_FILE" <<EOF
BOOTPROTO='static'
STARTMODE='auto'
IPADDR='${NEW_IP}'
PREFIXLEN='${PREFIX}'
EOF

    # Ruta por defecto
    echo "default ${GATEWAY} - -" > "$ROUTE_FILE"

    # DNS en /etc/sysconfig/network/config
    if grep -q "^NETCONFIG_DNS_STATIC_SERVERS" "$DNS_FILE" 2>/dev/null; then
        sed -i "s|^NETCONFIG_DNS_STATIC_SERVERS=.*|NETCONFIG_DNS_STATIC_SERVERS='${DNS1} 8.8.8.8'|" "$DNS_FILE"
    else
        echo "NETCONFIG_DNS_STATIC_SERVERS='${DNS1} 8.8.8.8'" >> "$DNS_FILE"
    fi

    # Aplicar configuración
    wicked ifdown "$IFACE" &>/dev/null
    wicked ifup "$IFACE"
    netconfig update -f &>/dev/null

    if [[ $? -eq 0 ]]; then
        log_ok "IP estática aplicada: ${NEW_IP}/${PREFIX}"
        DNS_IP="$NEW_IP"
    else
        log_error "Error al aplicar configuración de red."
        return 1
    fi
}

# ── Función auxiliar: resolver IP a usar ─────────────────────
_resolver_ip() {
    if [[ -n "$DNS_IP" ]]; then return; fi

    local DETECTED
    DETECTED=$(hostname -I | awk '{print $1}')
    local IFACE
    IFACE=$(ip route get 1 2>/dev/null | awk '{print $5; exit}')
    local CFG_FILE="/etc/sysconfig/network/ifcfg-${IFACE}"

    log_info "Interfaz activa: ${IFACE} | IP detectada: ${DETECTED}"

    # En OpenSUSE, BOOTPROTO='static' indica IP fija
    local IS_STATIC=false
    if [[ -f "$CFG_FILE" ]] && grep -q "BOOTPROTO='static'\|BOOTPROTO=static" "$CFG_FILE" 2>/dev/null; then
        IS_STATIC=true
    fi

    if $IS_STATIC; then
        log_ok "IP estática detectada: ${DETECTED}"
        DNS_IP="$DETECTED"
    else
        log_warn "IP dinámica o sin configuración estática detectada."
        echo -ne "¿Configurar IP estática ahora? (s/n): "; read -r REPLY
        if [[ "$REPLY" =~ ^[Ss]$ ]]; then
            _configurar_ip_estatica "$IFACE"
        else
            DNS_IP="$DETECTED"
            log_warn "Usando IP actual: ${DNS_IP}"
        fi
    fi
}

# ── Función auxiliar: asegurar include en named.conf ─────────
_asegurar_include_named() {
    # OpenSUSE incluye archivos desde /etc/named.d/ — asegurar que esté declarado
    if ! grep -q "named.d" "$NAMED_CONF" 2>/dev/null; then
        echo "" >> "$NAMED_CONF"
        echo "include \"/etc/named.d/${DOMAIN}.conf\";" >> "$NAMED_CONF"
        log_ok "Include agregado en $NAMED_CONF"
    elif ! grep -q "${DOMAIN}.conf" "$NAMED_CONF" 2>/dev/null; then
        echo "include \"/etc/named.d/${DOMAIN}.conf\";" >> "$NAMED_CONF"
        log_ok "Include de zona agregado en $NAMED_CONF"
    else
        log_info "Include de zona ya presente en named.conf."
    fi
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 1 — Instalación Idempotente
# ════════════════════════════════════════════════════════════
opcion_instalacion() {
    echo -e "\n${BOLD}── [ 1 ] Instalación Idempotente ──────────────────${NC}"

    _resolver_ip

    log_info "Verificando si BIND ya está instalado..."

    # En OpenSUSE el paquete es 'bind' y el servicio es 'named'
    if systemctl is-active --quiet named; then
        log_ok "BIND (named) ya está en ejecución. No se reinstalará (idempotente)."
        return
    fi

    if rpm -q bind &>/dev/null; then
        log_warn "BIND instalado pero detenido. Iniciando servicio..."
        systemctl start named
        systemctl enable named &>/dev/null
        log_ok "Servicio named iniciado."
        return
    fi

    log_info "Instalando bind y bind-utils con zypper..."
    zypper --non-interactive install bind bind-utils

    if [[ $? -ne 0 ]]; then
        log_error "Error durante la instalación de BIND."
        return
    fi

    # Crear directorio para zonas si no existe
    mkdir -p /var/lib/named
    mkdir -p /etc/named.d

    # Asignar permisos correctos
    chown named:named /var/lib/named
    chmod 750 /var/lib/named

    systemctl enable named &>/dev/null
    systemctl start named
    log_ok "BIND instalado e iniciado correctamente."
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 2 — Configuración de Zona DNS
# ════════════════════════════════════════════════════════════
opcion_zona() {
    echo -e "\n${BOLD}── [ 2 ] Configuración de Zona DNS ────────────────${NC}"

    _resolver_ip

    # Asegurar que existe el directorio para configuraciones de zona
    mkdir -p /etc/named.d

    log_info "Configurando zona en: ${NAMED_CONF_LOCAL}..."

    # Reescribir el archivo de zona con idempotencia
    cat > "$NAMED_CONF_LOCAL" <<EOF
// Zona directa ${DOMAIN} — generada automáticamente por script
zone "${DOMAIN}" IN {
    type master;
    file "${ZONE_FILE}";
    allow-query { any; };
    allow-update { none; };
};
EOF

    log_ok "Archivo de zona declarado: ${NAMED_CONF_LOCAL}"

    # Asegurar que named.conf incluye este archivo
    _asegurar_include_named

    # Generar archivo de zona base (SOA + NS)
    log_info "Generando archivo de zona base: ${ZONE_FILE}..."
    local SERIAL
    SERIAL=$(date +%Y%m%d01)

    mkdir -p /var/lib/named

    cat > "$ZONE_FILE" <<EOF
\$TTL    86400
@       IN      SOA     ns1.${DOMAIN}. admin.${DOMAIN}. (
                         ${SERIAL}  ; Serial
                         3600       ; Refresh
                         900        ; Retry
                         604800     ; Expire
                         86400 )    ; Negative Cache TTL

; Servidor de nombres
@       IN      NS      ns1.${DOMAIN}.
ns1     IN      A       ${DNS_IP}
EOF

    chown named:named "$ZONE_FILE" 2>/dev/null
    chmod 640 "$ZONE_FILE"
    log_ok "Archivo de zona base creado: ${ZONE_FILE}"

    # Validar sintaxis
    log_info "Validando con named-checkconf..."
    named-checkconf "$NAMED_CONF" && log_ok "named-checkconf: OK" || { log_error "Error en named.conf"; return; }

    log_info "Validando con named-checkzone..."
    named-checkzone "$DOMAIN" "$ZONE_FILE" && log_ok "named-checkzone: OK" || { log_error "Error en archivo de zona."; return; }

    systemctl restart named && log_ok "Servicio named reiniciado." || log_error "Error al reiniciar named."
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 3 — Configuración de Dominio DNS (Registros)
# ════════════════════════════════════════════════════════════
opcion_dominio() {
    echo -e "\n${BOLD}── [ 3 ] Configuración de Dominio DNS ─────────────${NC}"

    if [[ ! -f "$ZONE_FILE" ]]; then
        log_error "Archivo de zona no encontrado: ${ZONE_FILE}"
        log_warn "Ejecuta primero la Opción 2 (Configuración de Zona DNS)."
        return
    fi

    _resolver_ip

    log_info "Agregando registros DNS para ${DOMAIN}..."

    # Eliminar registros previos de @ y www para evitar duplicados
    sed -i "/^@[[:space:]]*IN[[:space:]]*A/d" "$ZONE_FILE"
    sed -i "/^www[[:space:]]*IN[[:space:]]*A/d" "$ZONE_FILE"
    sed -i "/^www[[:space:]]*IN[[:space:]]*CNAME/d" "$ZONE_FILE"

    # Agregar registro A para dominio raíz
    echo "@       IN      A       ${DNS_IP}" >> "$ZONE_FILE"
    log_ok "Registro A: ${DOMAIN} → ${DNS_IP}"

    # Agregar registro CNAME para www → dominio raíz
    echo "www     IN      CNAME   ${DOMAIN}." >> "$ZONE_FILE"
    log_ok "Registro CNAME: www.${DOMAIN} → ${DOMAIN}"

    # Actualizar Serial
    local SERIAL
    SERIAL=$(date +%Y%m%d01)
    sed -i "s/[0-9]\{10\}[[:space:]]*; Serial/${SERIAL}  ; Serial/" "$ZONE_FILE"
    log_ok "Serial actualizado: ${SERIAL}"

    echo ""
    echo -e "${CYAN}Contenido final del archivo de zona:${NC}"
    echo "─────────────────────────────────────────────"
    cat "$ZONE_FILE"
    echo "─────────────────────────────────────────────"
    echo ""

    log_info "Revalidando zona..."
    named-checkzone "$DOMAIN" "$ZONE_FILE" && log_ok "Zona válida." || { log_error "Error en zona."; return; }

    systemctl restart named && log_ok "Servicio named reiniciado con nuevos registros." || log_error "Error al reiniciar named."
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 4 — Dar de Baja DNS
# ════════════════════════════════════════════════════════════
opcion_baja() {
    echo -e "\n${BOLD}── [ 4 ] Dar de Baja DNS ──────────────────────────${NC}"

    echo -ne "${YELLOW}¿Confirmas dar de baja el DNS para ${DOMAIN}? (s/n): ${NC}"
    read -r CONF
    if [[ ! "$CONF" =~ ^[Ss]$ ]]; then
        log_warn "Operación cancelada."; return
    fi

    # Detener y deshabilitar servicio named
    log_info "Deteniendo servicio named..."
    systemctl stop named    && log_ok "Servicio named detenido."    || log_warn "Servicio ya detenido."
    systemctl disable named &>/dev/null && log_ok "named deshabilitado del arranque."

    # Eliminar archivo de configuración de zona
    if [[ -f "$NAMED_CONF_LOCAL" ]]; then
        rm -f "$NAMED_CONF_LOCAL"
        log_ok "Configuración de zona eliminada: ${NAMED_CONF_LOCAL}"
    else
        log_warn "Archivo ${NAMED_CONF_LOCAL} no encontrado."
    fi

    # Eliminar include de named.conf si existe
    if grep -q "${DOMAIN}.conf" "$NAMED_CONF" 2>/dev/null; then
        sed -i "/${DOMAIN}.conf/d" "$NAMED_CONF"
        log_ok "Include de zona eliminado de named.conf."
    fi

    # Eliminar archivo de zona
    if [[ -f "$ZONE_FILE" ]]; then
        rm -f "$ZONE_FILE"
        log_ok "Archivo de zona eliminado: ${ZONE_FILE}"
    else
        log_warn "Archivo de zona no encontrado (ya eliminado)."
    fi

    DNS_IP=""
    log_ok "DNS dado de baja correctamente."

    echo ""
    echo -ne "¿Desinstalar BIND completamente del sistema? (s/n): "; read -r UNINSTALL
    if [[ "$UNINSTALL" =~ ^[Ss]$ ]]; then
        zypper --non-interactive remove bind bind-utils
        log_ok "BIND desinstalado del sistema."
    fi
}

# ════════════════════════════════════════════════════════════
#  OPCIÓN 5 — Consultar DNS
# ════════════════════════════════════════════════════════════
opcion_consultar() {
    echo -e "\n${BOLD}── [ 5 ] Consultar DNS ────────────────────────────${NC}"

    # Verificar que bind-utils esté instalado (provee nslookup y dig)
    if ! command -v nslookup &>/dev/null; then
        log_warn "nslookup no encontrado. Instalando bind-utils..."
        zypper --non-interactive install bind-utils &>/dev/null
    fi

    echo ""
    log_info "Estado del servicio named:"
    systemctl status named --no-pager | head -12
    echo ""

    echo -ne "Servidor DNS a consultar (Enter para 127.0.0.1): "; read -r SRV_DNS
    SRV_DNS="${SRV_DNS:-127.0.0.1}"

    echo ""
    echo -e "${CYAN}─── nslookup ${DOMAIN} ${SRV_DNS} ────────────────────${NC}"
    nslookup "${DOMAIN}" "${SRV_DNS}"

    echo ""
    echo -e "${CYAN}─── nslookup www.${DOMAIN} ${SRV_DNS} ───────────────${NC}"
    nslookup "www.${DOMAIN}" "${SRV_DNS}"

    echo ""
    echo -e "${CYAN}─── dig ${DOMAIN} @${SRV_DNS} ───────────────────────${NC}"
    dig "${DOMAIN}" @"${SRV_DNS}" +short

    echo ""
    echo -e "${CYAN}─── ping -c 2 www.${DOMAIN} ────────────────────────${NC}"
    ping -c 2 "www.${DOMAIN}" 2>&1 || log_warn "Ping bloqueado o dominio sin resolución."

    echo ""
    echo -e "${CYAN}─── Registros activos en zona: ${DOMAIN} ────────────${NC}"
    if [[ -f "$ZONE_FILE" ]]; then
        cat "$ZONE_FILE"
    else
        log_warn "Archivo de zona no encontrado: ${ZONE_FILE}"
    fi
}

# ════════════════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ════════════════════════════════════════════════════════════
menu_principal() {
    while true; do
            clear
		echo -e "${CYAN}${BOLD}"
		echo ""
		echo "   Administrador DNS OpenSUSE	    "
		echo ""
		echo -e "${NC}"
        echo -e "  ${BOLD}1)${NC} Instalación Idempotente"
        echo -e "  ${BOLD}2)${NC} Configuración de Zona DNS"
        echo -e "  ${BOLD}3)${NC} Configuración de Dominio DNS"
        echo -e "  ${BOLD}4)${NC} Dar de Baja DNS"
        echo -e "  ${BOLD}5)${NC} Consultar DNS"
        echo -e "  ${BOLD}0)${NC} Salir"
        echo ""
        echo -ne "Selecciona una opción [0-5]: "; read -r OPT

        case $OPT in
            1) opcion_instalacion ;;
            2) opcion_zona        ;;
            3) opcion_dominio     ;;
            4) opcion_baja        ;;
            5) opcion_consultar   ;;
            0) echo -e "\n${GREEN}Saliendo...${NC}\n"; exit 0 ;;
            *) log_warn "Opción inválida. Intenta de nuevo." ;;
        esac

        echo ""
        echo -ne "Presiona Enter para volver al menú..."; read -r
    done
}

# ── Punto de entrada ──────────────────────────────────────────
check_root
menu_principal