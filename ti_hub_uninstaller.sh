#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Desinstalación v1.0.3 (ACTUALIZADO)
# Limpieza completa del sistema con opciones de backup
# Compatible con: Script de instalación v1.0.3
# https://github.com/juanpadiaz 
# =============================================================================

set -euo pipefail

# Colores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Constantes del sistema
readonly SCRIPT_VERSION="1.0.3-updated"
readonly INSTALL_USER="ti-hub"
readonly INSTALL_DIR="/opt/threat-intel-hub"
readonly CONFIG_DIR="/etc/threat-intel-hub"
readonly LOG_DIR="/var/log/threat-intel-hub"
readonly DATA_DIR="/var/lib/threat-intel-hub"
readonly BACKUP_DIR="/tmp/ti-hub-backup-$(date +%Y%m%d_%H%M%S)"

# Variables de configuración
KEEP_LOGS="false"
KEEP_DATABASE="false"
CREATE_BACKUP="true"
FORCE_REMOVE="false"
DB_PASSWORD=""

# Funciones de logging
log_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${RED}"
    echo "================================================================"
    echo "   THREAT INTEL HUB v${SCRIPT_VERSION} - DESINSTALADOR ACTUALIZADO"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Este script removerá completamente el sistema${NC}"
    echo -e "${GREEN}✅  ACTUALIZADO: Compatible con instalación v1.0.3-fixed${NC}"
    echo
    echo "Componentes que serán eliminados:"
    echo "   • Servicios systemd (corregidos)"
    echo "   • Usuario y grupo del sistema ($INSTALL_USER)"
    echo "   • Directorios de instalación"
    echo "   • Base de datos (opcional) - tablas actualizadas"
    echo "   • Logs del sistema (opcional)"
    echo "   • Archivos de configuración"
    echo "   • Comandos administrativos corregidos"
    echo "   • Scripts Python actualizados"
    echo
    echo "Opciones de backup disponibles:"
    echo "   • Configuración y datos críticos"
    echo "   • Logs históricos"
    echo "   • Export de base de datos con nuevas tablas"
    echo "   • Scripts corregidos"
    echo
    read -p "¿Continuar con la desinstalación? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Desinstalación cancelada."
        exit 0
    fi
    echo
}

# Detectar instalación existente (ACTUALIZADO)
detect_installation() {
    log_header "DETECCIÓN DE INSTALACIÓN (ACTUALIZADA)"
    
    local found_components=()
    
    # Verificar servicios systemd
    if systemctl list-unit-files | grep -q "threat-intel-hub"; then
        found_components+=("Servicios systemd")
        
        # Verificar si son la versión corregida
        if [[ -f "/etc/systemd/system/threat-intel-hub.service" ]]; then
            if grep -q "StandardOutput=journal" "/etc/systemd/system/threat-intel-hub.service"; then
                found_components+=("Servicios systemd (versión corregida)")
            fi
        fi
    fi
    
    # Verificar directorios
    [[ -d "$INSTALL_DIR" ]] && found_components+=("Directorio de instalación")
    [[ -d "$CONFIG_DIR" ]] && found_components+=("Configuración")
    [[ -d "$LOG_DIR" ]] && found_components+=("Logs")
    [[ -d "$DATA_DIR" ]] && found_components+=("Datos")
    
    # Verificar scripts actualizados
    if [[ -f "$DATA_DIR/scripts/ti_hub_monitor.py" ]]; then
        if grep -q "CORREGIDO" "$DATA_DIR/scripts/ti_hub_monitor.py"; then
            found_components+=("Scripts Python (versión corregida)")
        else
            found_components+=("Scripts Python (versión original)")
        fi
    fi
    
    # Verificar comandos administrativos actualizados
    if [[ -f "/usr/local/bin/ti-hub-status" ]]; then
        if grep -q "vía API" "/usr/local/bin/ti-hub-status"; then
            found_components+=("Comandos administrativos (versión corregida)")
        else
            found_components+=("Comandos administrativos (versión original)")
        fi
    fi
    
    # Verificar usuario
    if id "$INSTALL_USER" &>/dev/null; then
        found_components+=("Usuario del sistema")
    fi
    
    # Verificar base de datos con tablas actualizadas
    local db_exists=false
    if command -v mysql &>/dev/null || command -v mariadb &>/dev/null; then
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="sudo mysql -u root"
        fi
        
        if [[ -n "$mysql_cmd" ]] && $mysql_cmd -e "SHOW DATABASES;" 2>/dev/null | grep -q "ti_hub"; then
            found_components+=("Base de datos")
            
            # Verificar si tiene las tablas actualizadas
            if $mysql_cmd -e "USE ti_hub; SHOW TABLES LIKE 'threat_alerts';" 2>/dev/null | grep -q "threat_alerts"; then
                found_components+=("Base de datos (esquema v1.0.3)")
            else
                found_components+=("Base de datos (esquema anterior)")
            fi
            db_exists=true
        fi
    fi
    
    if [[ ${#found_components[@]} -eq 0 ]]; then
        log_error "No se encontró una instalación de Threat Intel Hub"
        exit 1
    fi
    
    log_info "Componentes encontrados:"
    for component in "${found_components[@]}"; do
        echo "   • $component"
    done
    
    echo
    return 0
}

# Configurar opciones de desinstalación
configure_uninstall_options() {
    log_header "OPCIONES DE DESINSTALACIÓN"
    
    echo "Configure las opciones de desinstalación:"
    echo
    
    # Backup
    read -p "¿Crear backup antes de desinstalar? (Y/n): " create_backup
    CREATE_BACKUP=$([[ $create_backup =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    if [[ "$CREATE_BACKUP" == "true" ]]; then
        echo "  📦 Backup será creado en: $BACKUP_DIR"
        echo "     Incluirá: scripts corregidos, configuración actualizada, BD con nuevas tablas"
    fi
    
    echo
    
    # Logs
    read -p "¿Preservar logs históricos? (y/N): " keep_logs
    KEEP_LOGS=$([[ $keep_logs =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    # Base de datos
    read -p "¿Preservar base de datos? (y/N): " keep_db
    KEEP_DATABASE=$([[ $keep_db =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    if [[ "$KEEP_DATABASE" == "false" ]]; then
        log_warn "La base de datos 'ti_hub' (con esquema v1.0.3) será eliminada completamente"
        read -p "¿Está seguro? (y/N): " confirm_db
        if [[ ! $confirm_db =~ ^[Yy]$ ]]; then
            KEEP_DATABASE="true"
            log_info "Base de datos será preservada"
        fi
    fi
    
    echo
    
    # Forzar eliminación
    read -p "¿Forzar eliminación de archivos protegidos? (y/N): " force_remove
    FORCE_REMOVE=$([[ $force_remove =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    echo
    log_info "Configuración de desinstalación:"
    echo "   • Crear backup: $([[ "$CREATE_BACKUP" == "true" ]] && echo "✅ Sí" || echo "❌ No")"
    echo "   • Preservar logs: $([[ "$KEEP_LOGS" == "true" ]] && echo "✅ Sí" || echo "❌ No")"
    echo "   • Preservar BD: $([[ "$KEEP_DATABASE" == "true" ]] && echo "✅ Sí" || echo "❌ No")"
    echo "   • Forzar eliminación: $([[ "$FORCE_REMOVE" == "true" ]] && echo "✅ Sí" || echo "❌ No")"
    echo
}

# Crear backup (ACTUALIZADO)
create_backup() {
    if [[ "$CREATE_BACKUP" != "true" ]]; then
        return
    fi
    
    log_step "Creando backup del sistema (ACTUALIZADO)..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup de configuración
    if [[ -d "$CONFIG_DIR" ]]; then
        log_info "Respaldando configuración..."
        cp -r "$CONFIG_DIR" "$BACKUP_DIR/config" 2>/dev/null || true
        
        # Extraer contraseña de BD del config
        if [[ -f "$CONFIG_DIR/config.ini" ]]; then
            DB_PASSWORD=$(grep "^password" "$CONFIG_DIR/config.ini" | cut -d'=' -f2 | xargs 2>/dev/null || echo "")
        fi
    fi
    
    # Backup de datos críticos (ACTUALIZADO)
    if [[ -d "$DATA_DIR" ]]; then
        log_info "Respaldando datos críticos (versión actualizada)..."
        mkdir -p "$BACKUP_DIR/data"
        
        # Scripts corregidos (IMPORTANTE)
        if [[ -d "$DATA_DIR/scripts" ]]; then
            mkdir -p "$BACKUP_DIR/data/scripts_corrected"
            cp -r "$DATA_DIR/scripts"/* "$BACKUP_DIR/data/scripts_corrected/" 2>/dev/null || true
            
            # Marcar como scripts corregidos
            echo "# Scripts corregidos de Threat Intel Hub v1.0.3" > "$BACKUP_DIR/data/scripts_corrected/README.txt"
            echo "# Fecha backup: $(date)" >> "$BACKUP_DIR/data/scripts_corrected/README.txt"
            echo "# Incluye correcciones aplicadas durante troubleshooting" >> "$BACKUP_DIR/data/scripts_corrected/README.txt"
        fi
        
        # Reglas personalizadas
        [[ -d "$DATA_DIR/rules" ]] && cp -r "$DATA_DIR/rules" "$BACKUP_DIR/data/" 2>/dev/null || true
        
        # Exports recientes
        if [[ -d "$DATA_DIR/api_exports" ]]; then
            mkdir -p "$BACKUP_DIR/data/recent_exports"
            find "$DATA_DIR/api_exports" -mtime -7 -type f -exec cp {} "$BACKUP_DIR/data/recent_exports/" \; 2>/dev/null || true
        fi
        
        # Reportes recientes
        if [[ -d "$DATA_DIR/reports" ]]; then
            mkdir -p "$BACKUP_DIR/data/recent_reports"
            find "$DATA_DIR/reports" -mtime -30 -type f -exec cp {} "$BACKUP_DIR/data/recent_reports/" \; 2>/dev/null || true
        fi
        
        # Configuraciones de webhook y API
        [[ -d "$DATA_DIR/webhooks" ]] && cp -r "$DATA_DIR/webhooks" "$BACKUP_DIR/data/" 2>/dev/null || true
        [[ -d "$DATA_DIR/campaigns" ]] && cp -r "$DATA_DIR/campaigns" "$BACKUP_DIR/data/" 2>/dev/null || true
    fi
    
    # Backup de comandos administrativos corregidos
    log_info "Respaldando comandos administrativos corregidos..."
    mkdir -p "$BACKUP_DIR/admin_commands"
    
    local admin_commands=(
        "/usr/local/bin/ti-hub-status"
        "/usr/local/bin/ti-hub-admin"
    )
    
    for cmd in "${admin_commands[@]}"; do
        if [[ -f "$cmd" ]]; then
            cp "$cmd" "$BACKUP_DIR/admin_commands/" 2>/dev/null || true
        fi
    done
    
    # Backup de servicios systemd corregidos
    log_info "Respaldando servicios systemd corregidos..."
    mkdir -p "$BACKUP_DIR/systemd_services"
    
    local services=(
        "/etc/systemd/system/threat-intel-hub.service"
        "/etc/systemd/system/threat-intel-hub-api.service"
    )
    
    for service in "${services[@]}"; do
        if [[ -f "$service" ]]; then
            cp "$service" "$BACKUP_DIR/systemd_services/" 2>/dev/null || true
        fi
    done
    
    # Backup de logs (últimos 7 días)
    if [[ -d "$LOG_DIR" ]]; then
        log_info "Respaldando logs recientes..."
        mkdir -p "$BACKUP_DIR/logs"
        find "$LOG_DIR" -name "*.log" -mtime -7 -exec cp {} "$BACKUP_DIR/logs/" \; 2>/dev/null || true
    fi
    
    # Backup de base de datos (ACTUALIZADO con nuevas tablas)
    if command -v mysqldump &>/dev/null && [[ -n "$DB_PASSWORD" ]]; then
        log_info "Respaldando base de datos (esquema v1.0.3)..."
        
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
            mysqldump -u root ti_hub > "$BACKUP_DIR/ti_hub_database_v103.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con root sin contraseña"
            }
        elif mysql -u ti_hub_user -p"$DB_PASSWORD" -e "SELECT 1;" &>/dev/null 2>&1; then
            mysqldump -u ti_hub_user -p"$DB_PASSWORD" ti_hub > "$BACKUP_DIR/ti_hub_database_v103.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con usuario ti_hub"
            }
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            sudo mysqldump -u root ti_hub > "$BACKUP_DIR/ti_hub_database_v103.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con sudo"
            }
        fi
        
        # Crear backup específico de nuevas tablas v1.0.3
        if [[ -f "$BACKUP_DIR/ti_hub_database_v103.sql" ]]; then
            log_info "Creando backup específico de tablas v1.0.3..."
            mysql -u root ti_hub -e "SELECT * FROM threat_alerts;" > "$BACKUP_DIR/threat_alerts_data.csv" 2>/dev/null || true
            mysql -u root ti_hub -e "SELECT * FROM system_config;" > "$BACKUP_DIR/system_config_data.csv" 2>/dev/null || true
        fi
    fi
    
    # Crear manifest del backup (ACTUALIZADO)
    cat > "$BACKUP_DIR/backup_manifest.txt" << EOF
# Threat Intel Hub - Backup Manifest (ACTUALIZADO)
# Created: $(date)
# Version: $SCRIPT_VERSION
# Hostname: $(hostname)
# Installation: v1.0.3-fixed compatible

BACKUP_DATE=$(date +%Y-%m-%d_%H:%M:%S)
ORIGINAL_INSTALLATION_DIR=$INSTALL_DIR
ORIGINAL_CONFIG_DIR=$CONFIG_DIR
ORIGINAL_DATA_DIR=$DATA_DIR
ORIGINAL_LOG_DIR=$LOG_DIR
DATABASE_USER=ti_hub_user
DATABASE_NAME=ti_hub
DATABASE_SCHEMA=v1.0.3

# Special Files Backed Up:
CORRECTED_SCRIPTS=data/scripts_corrected/
ADMIN_COMMANDS=admin_commands/
SYSTEMD_SERVICES=systemd_services/
DATABASE_V103=ti_hub_database_v103.sql
THREAT_ALERTS_DATA=threat_alerts_data.csv
SYSTEM_CONFIG_DATA=system_config_data.csv

# Restore Instructions (Updated):
# 1. Install Threat Intel Hub v1.0.3-fixed
# 2. Stop services: systemctl stop threat-intel-hub threat-intel-hub-api
# 3. Restore config: cp -r config/* $CONFIG_DIR/
# 4. Restore corrected scripts: cp -r data/scripts_corrected/* $DATA_DIR/scripts/
# 5. Restore admin commands: cp admin_commands/* /usr/local/bin/
# 6. Restore systemd services: cp systemd_services/* /etc/systemd/system/
# 7. Restore database: mysql -u root ti_hub < ti_hub_database_v103.sql
# 8. Fix permissions: chown -R ti-hub:ti-hub $DATA_DIR $LOG_DIR
# 9. Reload systemd: systemctl daemon-reload
# 10. Start services: systemctl start threat-intel-hub threat-intel-hub-api

# Notes:
# - This backup includes all corrections from troubleshooting session
# - Scripts are the corrected versions with improved error handling
# - Admin commands use API-based health checks (more stable)
# - Database includes v1.0.3 schema with threat_alerts and system_config tables
EOF
    
    # Comprimir backup
    if command -v tar &>/dev/null; then
        log_info "Comprimiendo backup..."
        cd "$(dirname "$BACKUP_DIR")"
        tar -czf "${BACKUP_DIR}.tar.gz" "$(basename "$BACKUP_DIR")" 2>/dev/null || {
            log_warn "No se pudo comprimir el backup"
        }
        
        if [[ -f "${BACKUP_DIR}.tar.gz" ]]; then
            rm -rf "$BACKUP_DIR"
            log_success "Backup creado: ${BACKUP_DIR}.tar.gz"
        else
            log_success "Backup creado: $BACKUP_DIR"
        fi
    else
        log_success "Backup creado: $BACKUP_DIR"
    fi
}

# Detener servicios (ACTUALIZADO)
stop_services() {
    log_step "Deteniendo servicios (versión actualizada)..."
    
    local services=("threat-intel-hub" "threat-intel-hub-api")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "Deteniendo $service..."
            systemctl stop "$service" 2>/dev/null || log_warn "No se pudo detener $service"
            
            # Esperar a que se detenga completamente
            local timeout=10
            while systemctl is-active --quiet "$service" 2>/dev/null && [ $timeout -gt 0 ]; do
                sleep 1
                ((timeout--))
            done
            
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_warn "$service sigue activo, forzando detención..."
                systemctl kill "$service" 2>/dev/null || true
            fi
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_info "Deshabilitando $service..."
            systemctl disable "$service" 2>/dev/null || log_warn "No se pudo deshabilitar $service"
        fi
    done
    
    log_success "Servicios detenidos"
}

# Eliminar servicios systemd (ACTUALIZADO)
remove_systemd_services() {
    log_step "Eliminando servicios systemd (versión actualizada)..."
    
    local service_files=(
        "/etc/systemd/system/threat-intel-hub.service"
        "/etc/systemd/system/threat-intel-hub-api.service"
    )
    
    for service_file in "${service_files[@]}"; do
        if [[ -f "$service_file" ]]; then
            log_info "Eliminando $(basename "$service_file")..."
            
            # Verificar si es la versión corregida
            if grep -q "StandardOutput=journal" "$service_file" 2>/dev/null; then
                log_info "  (Detectada versión corregida)"
            fi
            
            rm -f "$service_file"
        fi
    done
    
    # Limpiar configuraciones systemd adicionales
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    
    log_success "Servicios systemd eliminados"
}

# Eliminar base de datos (ACTUALIZADO)
remove_database() {
    if [[ "$KEEP_DATABASE" == "true" ]]; then
        log_info "Preservando base de datos según configuración"
        return
    fi
    
    log_step "Eliminando base de datos (esquema v1.0.3)..."
    
    local mysql_cmd=""
    if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="mysql -u root"
    elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="sudo mysql -u root"
    else
        log_warn "No se pudo conectar a MySQL/MariaDB para eliminar la BD"
        return
    fi
    
    # Verificar si existe la BD
    if $mysql_cmd -e "SHOW DATABASES;" 2>/dev/null | grep -q "ti_hub"; then
        # Mostrar información sobre las tablas antes de eliminar
        log_info "Analizando base de datos antes de eliminar..."
        
        local table_count=$($mysql_cmd -e "USE ti_hub; SHOW TABLES;" 2>/dev/null | wc -l)
        log_info "Tablas encontradas: $((table_count - 1))"
        
        # Verificar tablas específicas v1.0.3
        local v103_tables=0
        if $mysql_cmd -e "USE ti_hub; SHOW TABLES LIKE 'threat_alerts';" 2>/dev/null | grep -q "threat_alerts"; then
            ((v103_tables++))
            log_info "  • threat_alerts (v1.0.3) encontrada"
        fi
        
        if $mysql_cmd -e "USE ti_hub; SHOW TABLES LIKE 'system_config';" 2>/dev/null | grep -q "system_config"; then
            ((v103_tables++))
            log_info "  • system_config (v1.0.3) encontrada"
        fi
        
        if [ $v103_tables -gt 0 ]; then
            log_info "Esquema v1.0.3 detectado ($v103_tables tablas específicas)"
        fi
        
        log_info "Eliminando base de datos 'ti_hub'..."
        $mysql_cmd -e "DROP DATABASE IF EXISTS ti_hub;" 2>/dev/null || {
            log_warn "No se pudo eliminar la base de datos"
        }
    fi
    
    # Eliminar usuario
    if $mysql_cmd -e "SELECT User FROM mysql.user WHERE User = 'ti_hub_user';" 2>/dev/null | grep -q "ti_hub_user"; then
        log_info "Eliminando usuario 'ti_hub_user'..."
        $mysql_cmd -e "DROP USER IF EXISTS 'ti_hub_user'@'localhost';" 2>/dev/null || {
            log_warn "No se pudo eliminar el usuario de BD"
        }
        $mysql_cmd -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    fi
    
    log_success "Base de datos eliminada"
}

# Eliminar directorios (ACTUALIZADO)
remove_directories() {
    log_step "Eliminando directorios del sistema..."
    
    local directories=("$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR")
    
    # Manejar logs según configuración
    if [[ "$KEEP_LOGS" == "true" ]]; then
        log_info "Preservando logs en $LOG_DIR"
        # Crear archivo de información
        if [[ -d "$LOG_DIR" ]]; then
            cat > "$LOG_DIR/UNINSTALLED_$(date +%Y%m%d_%H%M%S).txt" << EOF
Threat Intel Hub v1.0.3 (ACTUALIZADO) fue desinstalado el $(date)
Los logs fueron preservados según configuración del usuario.

Información de la instalación eliminada:
- Versión: v1.0.3 con correcciones aplicadas
- Scripts: Versión corregida con manejo de errores mejorado
- Comandos admin: Versión corregida con verificación vía API
- Base de datos: Esquema v1.0.3 con tablas actualizadas

Para eliminar logs manualmente: sudo rm -rf $LOG_DIR
EOF
        fi
    else
        directories+=("$LOG_DIR")
    fi
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Eliminando $dir..."
            
            # Verificar contenido específico antes de eliminar
            if [[ "$dir" == "$DATA_DIR/scripts" ]] && [[ -f "$DATA_DIR/scripts/ti_hub_monitor.py" ]]; then
                if grep -q "CORREGIDO" "$DATA_DIR/scripts/ti_hub_monitor.py" 2>/dev/null; then
                    log_info "  (Eliminando scripts corregidos)"
                fi
            fi
            
            if [[ "$FORCE_REMOVE" == "true" ]]; then
                rm -rf "$dir" 2>/dev/null || {
                    log_warn "No se pudo eliminar $dir (puede requerir permisos administrativos)"
                }
            else
                # Eliminar con más cuidado
                if [[ -w "$dir" ]] || [[ "$dir" == "$INSTALL_DIR"* ]] || [[ "$dir" == "$DATA_DIR"* ]]; then
                    rm -rf "$dir" 2>/dev/null || {
                        log_warn "No se pudo eliminar $dir completamente"
                    }
                else
                    log_warn "Saltando $dir (protegido por permisos)"
                fi
            fi
        fi
    done
    
    log_success "Directorios eliminados"
}

# Eliminar usuario del sistema
remove_system_user() {
    log_step "Eliminando usuario del sistema..."
    
    if id "$INSTALL_USER" &>/dev/null; then
        log_info "Eliminando usuario '$INSTALL_USER'..."
        
        # Matar procesos del usuario
        if pgrep -u "$INSTALL_USER" >/dev/null 2>&1; then
            log_info "Terminando procesos del usuario..."
            pkill -u "$INSTALL_USER" 2>/dev/null || true
            sleep 2
            pkill -9 -u "$INSTALL_USER" 2>/dev/null || true
        fi
        
        # Eliminar usuario y grupo
        userdel "$INSTALL_USER" 2>/dev/null || log_warn "No se pudo eliminar el usuario"
        groupdel "$INSTALL_USER" 2>/dev/null || log_warn "No se pudo eliminar el grupo"
        
        log_success "Usuario del sistema eliminado"
    else
        log_info "Usuario '$INSTALL_USER' no existe"
    fi
}

# Limpiar configuraciones adicionales (ACTUALIZADO)
cleanup_additional_configs() {
    log_step "Limpiando configuraciones adicionales (actualizada)..."
    
    # Logrotate
    local logrotate_file="/etc/logrotate.d/threat-intel-hub"
    if [[ -f "$logrotate_file" ]]; then
        log_info "Eliminando configuración de logrotate..."
        rm -f "$logrotate_file"
    fi
    
    # Comandos administrativos actualizados
    local admin_commands=(
        "/usr/local/bin/ti-hub-status"
        "/usr/local/bin/ti-hub-admin"
    )
    
    for cmd in "${admin_commands[@]}"; do
        if [[ -f "$cmd" ]]; then
            # Verificar si es la versión corregida
            if grep -q "vía API" "$cmd" 2>/dev/null; then
                log_info "Eliminando comando administrativo corregido: $(basename "$cmd")"
            else
                log_info "Eliminando comando administrativo: $(basename "$cmd")"
            fi
            rm -f "$cmd"
        fi
    done
    
    # Nginx config (si existe)
    local nginx_configs=(
        "/etc/nginx/sites-available/threat-intel-hub"
        "/etc/nginx/sites-enabled/threat-intel-hub"
    )
    
    for config in "${nginx_configs[@]}"; do
        if [[ -f "$config" ]]; then
            log_info "Eliminando configuración nginx: $config"
            rm -f "$config"
        fi
    done
    
    # Recargar nginx si está activo
    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
    fi
    
    # Crontabs (si existen)
    if crontab -u root -l 2>/dev/null | grep -q "threat-intel-hub"; then
        log_info "Eliminando entradas de crontab..."
        (crontab -u root -l 2>/dev/null | grep -v "threat-intel-hub") | crontab -u root - || true
    fi
    
    # Limpiar cache de systemd
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed 2>/dev/null || true
    
    log_success "Configuraciones adicionales limpiadas"
}

# Verificar limpieza (ACTUALIZADO)
verify_cleanup() {
    log_step "Verificando limpieza del sistema (actualizada)..."
    
    local remaining_items=()
    
    # Verificar servicios
    if systemctl list-unit-files | grep -q "threat-intel-hub"; then
        remaining_items+=("Servicios systemd")
    fi
    
    # Verificar directorios
    [[ -d "$INSTALL_DIR" ]] && remaining_items+=("$INSTALL_DIR")
    [[ -d "$CONFIG_DIR" ]] && remaining_items+=("$CONFIG_DIR")
    [[ -d "$DATA_DIR" ]] && remaining_items+=("$DATA_DIR")
    
    if [[ "$KEEP_LOGS" == "false" ]] && [[ -d "$LOG_DIR" ]]; then
        remaining_items+=("$LOG_DIR")
    fi
    
    # Verificar usuario
    if id "$INSTALL_USER" &>/dev/null; then
        remaining_items+=("Usuario $INSTALL_USER")
    fi
    
    # Verificar comandos administrativos
    if [[ -f "/usr/local/bin/ti-hub-status" ]] || [[ -f "/usr/local/bin/ti-hub-admin" ]]; then
        remaining_items+=("Comandos administrativos")
    fi
    
    # Verificar base de datos
    if [[ "$KEEP_DATABASE" == "false" ]] && command -v mysql &>/dev/null; then
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="sudo mysql -u root"
        fi
        
        if [[ -n "$mysql_cmd" ]] && $mysql_cmd -e "SHOW DATABASES;" 2>/dev/null | grep -q "ti_hub"; then
            remaining_items+=("Base de datos ti_hub")
        fi
    fi
    
    if [[ ${#remaining_items[@]} -eq 0 ]]; then
        log_success "✅ Sistema completamente limpio"
    else
        log_warn "⚠️  Elementos que requieren atención manual:"
        for item in "${remaining_items[@]}"; do
            echo "     • $item"
        done
    fi
}

# Mostrar resumen final (ACTUALIZADO)
show_final_summary() {
    log_header "DESINSTALACIÓN COMPLETADA (ACTUALIZADA)"
    
    echo -e "${GREEN}✅ Threat Intel Hub v${SCRIPT_VERSION} ha sido desinstalado${NC}"
    echo
    
    echo "📋 RESUMEN DE ACCIONES:"
    echo "   • Servicios systemd: Eliminados (versión corregida)"
    echo "   • Usuario del sistema: Eliminado"
    echo "   • Directorios: Eliminados"
    echo "   • Scripts corregidos: Eliminados"
    echo "   • Comandos admin actualizados: Eliminados"
    echo "   • Base de datos: $([[ "$KEEP_DATABASE" == "true" ]] && echo "Preservada (esquema v1.0.3)" || echo "Eliminada (esquema v1.0.3)")"
    echo "   • Logs históricos: $([[ "$KEEP_LOGS" == "true" ]] && echo "Preservados en $LOG_DIR" || echo "Eliminados")"
    echo
    
    if [[ "$CREATE_BACKUP" == "true" ]]; then
        if [[ -f "${BACKUP_DIR}.tar.gz" ]]; then
            echo "📦 BACKUP CREADO (ACTUALIZADO):"
            echo "   • Archivo: ${BACKUP_DIR}.tar.gz"
            echo "   • Tamaño: $(du -sh "${BACKUP_DIR}.tar.gz" 2>/dev/null | cut -f1 || echo "N/A")"
            echo "   • Contenido especial:"
            echo "     - Scripts corregidos (data/scripts_corrected/)"
            echo "     - Comandos admin actualizados (admin_commands/)"
            echo "     - Servicios systemd corregidos (systemd_services/)"
            echo "     - Base de datos v1.0.3 (ti_hub_database_v103.sql)"
        elif [[ -d "$BACKUP_DIR" ]]; then
            echo "📦 BACKUP CREADO (ACTUALIZADO):"
            echo "   • Directorio: $BACKUP_DIR"
            echo "   • Tamaño: $(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1 || echo "N/A")"
        fi
        echo "   • Manifest: Incluido con instrucciones de restauración actualizadas"
        echo "   • Compatible con: Instalación v1.0.3-fixed"
    fi
    
    echo
    if [[ "$KEEP_LOGS" == "true" ]]; then
        echo "📝 LOGS PRESERVADOS:"
        echo "   • Ubicación: $LOG_DIR"
        echo "   • Información de versión incluida"
        echo "   • Para eliminar manualmente: sudo rm -rf $LOG_DIR"
    fi
    
    if [[ "$KEEP_DATABASE" == "true" ]]; then
        echo "🗄️ BASE DE DATOS PRESERVADA (ESQUEMA v1.0.3):"
        echo "   • Nombre: ti_hub"
        echo "   • Usuario: ti_hub_user"
        echo "   • Esquema: v1.0.3 (incluye threat_alerts, system_config)"
        echo "   • Para eliminar manualmente:"
        echo "     - mysql -u root -e \"DROP DATABASE ti_hub;\""
        echo "     - mysql -u root -e \"DROP USER 'ti_hub_user'@'localhost';\""
    fi
    
    echo
    echo -e "${BLUE}Para reinstalar el sistema (versión corregida):${NC}"
    echo -e "${CYAN}  sudo bash threat-intel-hub-installer-v103-fixed.sh${NC}"
    echo
    echo -e "${BLUE}Para restaurar desde backup:${NC}"
    echo -e "${CYAN}  1. Extraer backup: tar -xzf ${BACKUP_DIR##*/}.tar.gz${NC}"
    echo -e "${CYAN}  2. Seguir instrucciones en backup_manifest.txt${NC}"
    echo
    echo -e "${YELLOW}¡Gracias por usar Threat Intel Hub!${NC}"
}

# Cleanup function
cleanup() {
    # Limpiar archivos temporales si existen
    rm -f /tmp/ti-hub-uninstall-*.tmp 2>/dev/null || true
}
trap cleanup EXIT

# Función principal
main() {
    # Verificar permisos
    if [[ $EUID -ne 0 ]]; then
        log_error "Debe ejecutarse como root: sudo bash uninstall.sh"
        exit 1
    fi
    
    show_welcome_banner
    detect_installation
    configure_uninstall_options
    
    echo
    log_warn "⚠️  ÚLTIMA CONFIRMACIÓN (VERSIÓN ACTUALIZADA)"
    echo "Esta acción es IRREVERSIBLE y eliminará:"
    echo "   • Todos los servicios y configuraciones (versión corregida)"
    echo "   • Usuario del sistema y directorios"
    echo "   • Scripts corregidos con mejoras aplicadas"
    echo "   • Comandos administrativos actualizados"
    if [[ "$KEEP_DATABASE" == "false" ]]; then
        echo "   • Base de datos completa (esquema v1.0.3)"
    fi
    if [[ "$KEEP_LOGS" == "false" ]]; then
        echo "   • Todos los logs históricos"
    fi
    echo
    
    read -p "Escriba 'DESINSTALAR' para confirmar: " confirmation
    if [[ "$confirmation" != "DESINSTALAR" ]]; then
        echo "Desinstalación cancelada."
        exit 0
    fi
    
    echo
    log_info "🚀 Iniciando desinstalación (versión actualizada)..."
    
    # Proceso de desinstalación
    create_backup
    stop_services
    remove_systemd_services
    remove_database
    remove_directories
    remove_system_user
    cleanup_additional_configs
    verify_cleanup
    show_final_summary
    
    echo
    log_success "🎉 Desinstalación completada exitosamente"
}

# Ejecutar función principal
main "$@"