#!/bin/bash

# =============================================================================
# ti_hub_uninstaller.sh - Script de Desinstalación v1.0.3
# Threat Intel Hub - Limpieza completa del sistema con opciones de backup
# Compatible con: ti_hub_installer.sh v1.0.3
# Autor: Juan Pablo Díaz Ezcurdia
# Versión: 1.0.3 - Actionable Intelligence Platform
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
readonly SCRIPT_VERSION="1.0.3"
readonly SCRIPT_NAME="ti_hub_uninstaller.sh"
readonly INSTALLER_NAME="ti_hub_installer.sh"
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
    echo "🎯================================================================🎯"
    echo "   THREAT INTEL HUB v${SCRIPT_VERSION} - DESINSTALADOR"
    echo "   Script: ${SCRIPT_NAME}"
    echo "🎯================================================================🎯"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Este script removerá completamente el sistema${NC}"
    echo -e "${GREEN}✅  COMPATIBLE: Con instalación de ${INSTALLER_NAME} v${SCRIPT_VERSION}${NC}"
    echo
    echo "Componentes que serán eliminados:"
    echo "   • 🔧 Servicios systemd (threat-intel-hub, threat-intel-hub-api)"
    echo "   • 👤 Usuario y grupo del sistema ($INSTALL_USER)"
    echo "   • 📁 Directorios de instalación completos"
    echo "   • 🗄️  Base de datos ti_hub (opcional)"
    echo "   • 📝 Logs del sistema (opcional)"
    echo "   • ⚙️  Archivos de configuración"
    echo "   • 🛠️  Comandos administrativos (ti-hub-status, ti-hub-admin)"
    echo "   • 🐍 Entorno Python y dependencias"
    echo
    echo "Opciones de backup disponibles:"
    echo "   • 📦 Configuración y datos críticos"
    echo "   • 📋 Logs históricos"
    echo "   • 💾 Export completo de base de datos v1.0.3"
    echo "   • 🔄 Scripts y comandos para reinstalación"
    echo
    read -p "¿Continuar con la desinstalación? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Desinstalación cancelada."
        exit 0
    fi
    echo
}

# Detectar instalación existente
detect_installation() {
    log_header "DETECCIÓN DE INSTALACIÓN THREAT INTEL HUB v${SCRIPT_VERSION}"
    
    local found_components=()
    
    # Verificar servicios systemd
    if systemctl list-unit-files | grep -q "threat-intel-hub"; then
        found_components+=("Servicios systemd")
    fi
    
    # Verificar directorios
    [[ -d "$INSTALL_DIR" ]] && found_components+=("Directorio de instalación")
    [[ -d "$CONFIG_DIR" ]] && found_components+=("Configuración")
    [[ -d "$LOG_DIR" ]] && found_components+=("Logs")
    [[ -d "$DATA_DIR" ]] && found_components+=("Datos")
    
    # Verificar comandos administrativos
    [[ -f "/usr/local/bin/ti-hub-status" ]] && found_components+=("Comando ti-hub-status")
    [[ -f "/usr/local/bin/ti-hub-admin" ]] && found_components+=("Comando ti-hub-admin")
    
    # Verificar usuario
    if id "$INSTALL_USER" &>/dev/null; then
        found_components+=("Usuario del sistema")
    fi
    
    # Verificar base de datos
    local db_exists=false
    if command -v mysql &>/dev/null || command -v mariadb &>/dev/null; then
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="sudo mysql -u root"
        fi
        
        if [[ -n "$mysql_cmd" ]] && $mysql_cmd -e "SHOW DATABASES;" 2>/dev/null | grep -q "ti_hub"; then
            found_components+=("Base de datos ti_hub")
            db_exists=true
        fi
    fi
    
    if [[ ${#found_components[@]} -eq 0 ]]; then
        log_error "No se encontró una instalación de Threat Intel Hub v${SCRIPT_VERSION}"
        log_info "Si desea instalar el sistema, ejecute: sudo bash ${INSTALLER_NAME}"
        exit 1
    fi
    
    log_info "Componentes encontrados:"
    for component in "${found_components[@]}"; do
        echo "   ✅ $component"
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
        echo "     Incluirá: configuración, scripts, BD, comandos admin"
    fi
    
    echo
    
    # Logs
    read -p "¿Preservar logs históricos? (y/N): " keep_logs
    KEEP_LOGS=$([[ $keep_logs =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    # Base de datos
    read -p "¿Preservar base de datos ti_hub? (y/N): " keep_db
    KEEP_DATABASE=$([[ $keep_db =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    if [[ "$KEEP_DATABASE" == "false" ]]; then
        log_warn "La base de datos 'ti_hub' será eliminada completamente"
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

# Crear backup
create_backup() {
    if [[ "$CREATE_BACKUP" != "true" ]]; then
        return
    fi
    
    log_step "Creando backup del sistema v${SCRIPT_VERSION}..."
    
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
    
    # Backup de datos críticos
    if [[ -d "$DATA_DIR" ]]; then
        log_info "Respaldando datos críticos..."
        mkdir -p "$BACKUP_DIR/data"
        
        # Scripts
        [[ -d "$DATA_DIR/scripts" ]] && cp -r "$DATA_DIR/scripts" "$BACKUP_DIR/data/" 2>/dev/null || true
        
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
        
        # Configuraciones de webhook
        [[ -d "$DATA_DIR/webhooks" ]] && cp -r "$DATA_DIR/webhooks" "$BACKUP_DIR/data/" 2>/dev/null || true
        [[ -d "$DATA_DIR/campaigns" ]] && cp -r "$DATA_DIR/campaigns" "$BACKUP_DIR/data/" 2>/dev/null || true
    fi
    
    # Backup de comandos administrativos
    log_info "Respaldando comandos administrativos..."
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
    
    # Backup de servicios systemd
    log_info "Respaldando servicios systemd..."
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
    
    # Backup de base de datos
    if command -v mysqldump &>/dev/null && [[ -n "$DB_PASSWORD" ]]; then
        log_info "Respaldando base de datos v${SCRIPT_VERSION}..."
        
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
            mysqldump -u root ti_hub > "$BACKUP_DIR/ti_hub_database_v${SCRIPT_VERSION}.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con root sin contraseña"
            }
        elif mysql -u ti_hub_user -p"$DB_PASSWORD" -e "SELECT 1;" &>/dev/null 2>&1; then
            mysqldump -u ti_hub_user -p"$DB_PASSWORD" ti_hub > "$BACKUP_DIR/ti_hub_database_v${SCRIPT_VERSION}.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con usuario ti_hub"
            }
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            sudo mysqldump -u root ti_hub > "$BACKUP_DIR/ti_hub_database_v${SCRIPT_VERSION}.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con sudo"
            }
        fi
    fi
    
    # Crear manifest del backup
    cat > "$BACKUP_DIR/backup_manifest.txt" << EOF
# Threat Intel Hub - Backup Manifest
# Created: $(date)
# Version: $SCRIPT_VERSION
# Script: $SCRIPT_NAME
# Hostname: $(hostname)

BACKUP_DATE=$(date +%Y-%m-%d_%H:%M:%S)
ORIGINAL_INSTALLATION_DIR=$INSTALL_DIR
ORIGINAL_CONFIG_DIR=$CONFIG_DIR
ORIGINAL_DATA_DIR=$DATA_DIR
ORIGINAL_LOG_DIR=$LOG_DIR
DATABASE_USER=ti_hub_user
DATABASE_NAME=ti_hub
DATABASE_VERSION=$SCRIPT_VERSION

# Restore Instructions:
# 1. Install Threat Intel Hub: sudo bash $INSTALLER_NAME
# 2. Stop services: systemctl stop threat-intel-hub threat-intel-hub-api
# 3. Restore config: cp -r config/* $CONFIG_DIR/
# 4. Restore data: cp -r data/* $DATA_DIR/
# 5. Restore admin commands: cp admin_commands/* /usr/local/bin/
# 6. Restore systemd services: cp systemd_services/* /etc/systemd/system/
# 7. Restore database: mysql -u root ti_hub < ti_hub_database_v${SCRIPT_VERSION}.sql
# 8. Fix permissions: chown -R ti-hub:ti-hub $DATA_DIR $LOG_DIR
# 9. Reload systemd: systemctl daemon-reload
# 10. Start services: systemctl start threat-intel-hub threat-intel-hub-api
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

# Detener servicios
stop_services() {
    log_step "Deteniendo servicios de Threat Intel Hub..."
    
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

# Eliminar servicios systemd
remove_systemd_services() {
    log_step "Eliminando servicios systemd..."
    
    local service_files=(
        "/etc/systemd/system/threat-intel-hub.service"
        "/etc/systemd/system/threat-intel-hub-api.service"
    )
    
    for service_file in "${service_files[@]}"; do
        if [[ -f "$service_file" ]]; then
            log_info "Eliminando $(basename "$service_file")..."
            rm -f "$service_file"
        fi
    done
    
    # Limpiar configuraciones systemd
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    
    log_success "Servicios systemd eliminados"
}

# Eliminar base de datos
remove_database() {
    if [[ "$KEEP_DATABASE" == "true" ]]; then
        log_info "Preservando base de datos según configuración"
        return
    fi
    
    log_step "Eliminando base de datos ti_hub..."
    
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

# Eliminar directorios
remove_directories() {
    log_step "Eliminando directorios del sistema..."
    
    local directories=("$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR")
    
    # Manejar logs según configuración
    if [[ "$KEEP_LOGS" == "true" ]]; then
        log_info "Preservando logs en $LOG_DIR"
        # Crear archivo de información
        if [[ -d "$LOG_DIR" ]]; then
            cat > "$LOG_DIR/UNINSTALLED_$(date +%Y%m%d_%H%M%S).txt" << EOF
Threat Intel Hub v$SCRIPT_VERSION fue desinstalado el $(date)
Script utilizado: $SCRIPT_NAME
Los logs fueron preservados según configuración del usuario.

Para eliminar logs manualmente: sudo rm -rf $LOG_DIR
Para reinstalar: sudo bash $INSTALLER_NAME
EOF
        fi
    else
        directories+=("$LOG_DIR")
    fi
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Eliminando $dir..."
            
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

# Limpiar configuraciones adicionales
cleanup_additional_configs() {
    log_step "Limpiando configuraciones adicionales..."
    
    # Logrotate
    local logrotate_file="/etc/logrotate.d/threat-intel-hub"
    if [[ -f "$logrotate_file" ]]; then
        log_info "Eliminando configuración de logrotate..."
        rm -f "$logrotate_file"
    fi
    
    # Comandos administrativos
    local admin_commands=(
        "/usr/local/bin/ti-hub-status"
        "/usr/local/bin/ti-hub-admin"
    )
    
    for cmd in "${admin_commands[@]}"; do
        if [[ -f "$cmd" ]]; then
            log_info "Eliminando comando administrativo: $(basename "$cmd")"
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

# Verificar limpieza
verify_cleanup() {
    log_step "Verificando limpieza del sistema..."
    
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

# Mostrar resumen final
show_final_summary() {
    log_header "DESINSTALACIÓN COMPLETADA v${SCRIPT_VERSION}"
    
    echo -e "${GREEN}✅ Threat Intel Hub v${SCRIPT_VERSION} ha sido desinstalado${NC}"
    echo -e "${GREEN}✅ Script utilizado: ${SCRIPT_NAME}${NC}"
    echo
    
    echo "📋 RESUMEN DE ACCIONES:"
    echo "   • Servicios systemd: Eliminados"
    echo "   • Usuario del sistema: Eliminado"
    echo "   • Directorios: Eliminados"
    echo "   • Comandos administrativos: Eliminados"
    echo "   • Base de datos: $([[ "$KEEP_DATABASE" == "true" ]] && echo "Preservada" || echo "Eliminada")"
    echo "   • Logs históricos: $([[ "$KEEP_LOGS" == "true" ]] && echo "Preservados en $LOG_DIR" || echo "Eliminados")"
    echo
    
    if [[ "$CREATE_BACKUP" == "true" ]]; then
        if [[ -f "${BACKUP_DIR}.tar.gz" ]]; then
            echo "📦 BACKUP CREADO:"
            echo "   • Archivo: ${BACKUP_DIR}.tar.gz"
            echo "   • Tamaño: $(du -sh "${BACKUP_DIR}.tar.gz" 2>/dev/null | cut -f1 || echo "N/A")"
        elif [[ -d "$BACKUP_DIR" ]]; then
            echo "📦 BACKUP CREADO:"
            echo "   • Directorio: $BACKUP_DIR"
            echo "   • Tamaño: $(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1 || echo "N/A")"
        fi
        echo "   • Manifest: Incluido con instrucciones de restauración"
    fi
    
    echo
    if [[ "$KEEP_LOGS" == "true" ]]; then
        echo "📝 LOGS PRESERVADOS:"
        echo "   • Ubicación: $LOG_DIR"
        echo "   • Para eliminar manualmente: sudo rm -rf $LOG_DIR"
    fi
    
    if [[ "$KEEP_DATABASE" == "true" ]]; then
        echo "🗄️  BASE DE DATOS PRESERVADA:"
        echo "   • Nombre: ti_hub"
        echo "   • Usuario: ti_hub_user"
        echo "   • Para eliminar manualmente:"
        echo "     - mysql -u root -e \"DROP DATABASE ti_hub;\""
        echo "     - mysql -u root -e \"DROP USER 'ti_hub_user'@'localhost';\""
    fi
    
    echo
    echo -e "${BLUE}Para reinstalar el sistema:${NC}"
    echo -e "${CYAN}  sudo bash ${INSTALLER_NAME}${NC}"
    echo
    echo -e "${YELLOW}¡Gracias por usar Threat Intel Hub v${SCRIPT_VERSION}!${NC}"
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
        log_error "Debe ejecutarse como root: sudo bash ${SCRIPT_NAME}"
        exit 1
    fi
    
    show_welcome_banner
    detect_installation
    configure_uninstall_options
    
    echo
    log_warn "⚠️  ÚLTIMA CONFIRMACIÓN"
    echo "Esta acción es IRREVERSIBLE y eliminará:"
    echo "   • Todos los servicios y configuraciones"
    echo "   • Usuario del sistema y directorios"
    echo "   • Comandos administrativos (ti-hub-status, ti-hub-admin)"
    if [[ "$KEEP_DATABASE" == "false" ]]; then
        echo "   • Base de datos completa"
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
    log_info "🚀 Iniciando desinstalación con ${SCRIPT_NAME}..."
    
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