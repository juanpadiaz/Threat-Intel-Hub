#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Desinstalación v1.0.3
# Limpieza completa del sistema con opciones de backup
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
readonly SCRIPT_VERSION="1.0.3"
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
    echo "     THREAT INTEL HUB v${SCRIPT_VERSION} - DESINSTALADOR"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Este script removerá completamente el sistema${NC}"
    echo
    echo "Componentes que serán eliminados:"
    echo "   • Servicios systemd"
    echo "   • Usuario y grupo del sistema ($INSTALL_USER)"
    echo "   • Directorios de instalación"
    echo "   • Base de datos (opcional)"
    echo "   • Logs del sistema (opcional)"
    echo "   • Archivos de configuración"
    echo
    echo "Opciones de backup disponibles:"
    echo "   • Configuración y datos críticos"
    echo "   • Logs históricos"
    echo "   • Export de base de datos"
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
    log_header "DETECCIÓN DE INSTALACIÓN"
    
    local found_components=()
    
    # Verificar servicios
    if systemctl list-unit-files | grep -q "threat-intel-hub"; then
        found_components+=("Servicios systemd")
    fi
    
    # Verificar directorios
    [[ -d "$INSTALL_DIR" ]] && found_components+=("Directorio de instalación")
    [[ -d "$CONFIG_DIR" ]] && found_components+=("Configuración")
    [[ -d "$LOG_DIR" ]] && found_components+=("Logs")
    [[ -d "$DATA_DIR" ]] && found_components+=("Datos")
    
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
            found_components+=("Base de datos")
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
    fi
    
    echo
    
    # Logs
    read -p "¿Preservar logs históricos? (y/N): " keep_logs
    KEEP_LOGS=$([[ $keep_logs =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    # Base de datos
    read -p "¿Preservar base de datos? (y/N): " keep_db
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
    
    log_step "Creando backup del sistema..."
    
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
        
        # Scripts y configuraciones personalizadas
        [[ -d "$DATA_DIR/scripts" ]] && cp -r "$DATA_DIR/scripts" "$BACKUP_DIR/data/" 2>/dev/null || true
        
        # Reglas personalizadas
        [[ -d "$DATA_DIR/rules" ]] && cp -r "$DATA_DIR/rules" "$BACKUP_DIR/data/" 2>/dev/null || true
        
        # Exports recientes
        if [[ -d "$DATA_DIR/api_exports" ]]; then
            find "$DATA_DIR/api_exports" -mtime -7 -type f -exec cp {} "$BACKUP_DIR/data/recent_exports/" \; 2>/dev/null || true
        fi
        
        # Reportes recientes
        if [[ -d "$DATA_DIR/reports" ]]; then
            find "$DATA_DIR/reports" -mtime -30 -type f -exec cp {} "$BACKUP_DIR/data/recent_reports/" \; 2>/dev/null || true
        fi
    fi
    
    # Backup de logs (últimos 7 días)
    if [[ -d "$LOG_DIR" ]]; then
        log_info "Respaldando logs recientes..."
        mkdir -p "$BACKUP_DIR/logs"
        find "$LOG_DIR" -name "*.log" -mtime -7 -exec cp {} "$BACKUP_DIR/logs/" \; 2>/dev/null || true
    fi
    
    # Backup de base de datos
    if command -v mysqldump &>/dev/null && [[ -n "$DB_PASSWORD" ]]; then
        log_info "Respaldando base de datos..."
        
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
            mysqldump -u root ti_hub > "$BACKUP_DIR/ti_hub_database.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con root sin contraseña"
            }
        elif mysql -u ti_hub_user -p"$DB_PASSWORD" -e "SELECT 1;" &>/dev/null 2>&1; then
            mysqldump -u ti_hub_user -p"$DB_PASSWORD" ti_hub > "$BACKUP_DIR/ti_hub_database.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con usuario ti_hub"
            }
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            sudo mysqldump -u root ti_hub > "$BACKUP_DIR/ti_hub_database.sql" 2>/dev/null || {
                log_warn "No se pudo hacer backup de la BD con sudo"
            }
        fi
    fi
    
    # Crear manifest del backup
    cat > "$BACKUP_DIR/backup_manifest.txt" << EOF
# Threat Intel Hub - Backup Manifest
# Created: $(date)
# Version: $SCRIPT_VERSION
# Hostname: $(hostname)

BACKUP_DATE=$(date +%Y-%m-%d_%H:%M:%S)
ORIGINAL_INSTALLATION_DIR=$INSTALL_DIR
ORIGINAL_CONFIG_DIR=$CONFIG_DIR
ORIGINAL_DATA_DIR=$DATA_DIR
ORIGINAL_LOG_DIR=$LOG_DIR
DATABASE_USER=ti_hub_user
DATABASE_NAME=ti_hub

# Restore Instructions:
# 1. Install Threat Intel Hub v$SCRIPT_VERSION
# 2. Stop services: systemctl stop threat-intel-hub threat-intel-hub-api
# 3. Restore config: cp -r config/* $CONFIG_DIR/
# 4. Restore data: cp -r data/* $DATA_DIR/
# 5. Restore database: mysql -u root ti_hub < ti_hub_database.sql
# 6. Fix permissions: chown -R ti-hub:ti-hub $DATA_DIR $LOG_DIR
# 7. Start services: systemctl start threat-intel-hub threat-intel-hub-api
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
    log_step "Deteniendo servicios..."
    
    local services=("threat-intel-hub" "threat-intel-hub-api")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "Deteniendo $service..."
            systemctl stop "$service" 2>/dev/null || log_warn "No se pudo detener $service"
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
    
    systemctl daemon-reload
    log_success "Servicios systemd eliminados"
}

# Eliminar base de datos
remove_database() {
    if [[ "$KEEP_DATABASE" == "true" ]]; then
        log_info "Preservando base de datos según configuración"
        return
    fi
    
    log_step "Eliminando base de datos..."
    
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
Threat Intel Hub fue desinstalado el $(date)
Los logs fueron preservados según configuración del usuario.
Para eliminarlos manualmente: sudo rm -rf $LOG_DIR
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
    log_header "DESINSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}✅ Threat Intel Hub v${SCRIPT_VERSION} ha sido desinstalado${NC}"
    echo
    
    echo "📋 RESUMEN DE ACCIONES:"
    echo "   • Servicios systemd: Eliminados"
    echo "   • Usuario del sistema: Eliminado"
    echo "   • Directorios: Eliminados"
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
    echo -e "${BLUE}Para reinstalar el sistema, ejecute el instalador nuevamente:${NC}"
    echo -e "${CYAN}  sudo bash threat-intel-hub-installer-v103.sh${NC}"
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
    log_warn "⚠️  ÚLTIMA CONFIRMACIÓN"
    echo "Esta acción es IRREVERSIBLE y eliminará:"
    echo "   • Todos los servicios y configuraciones"
    echo "   • Usuario del sistema y directorios"
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
    log_info "🚀 Iniciando desinstalación..."
    
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