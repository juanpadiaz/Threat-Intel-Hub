#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Desinstalación v1.0.2
# https://github.com/juanpadiaz
# Compatible con: Ubuntu 20.04+ LTS
# Elimina completamente Threat Intel Hub y sus componentes
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
readonly SCRIPT_VERSION="1.0.2"
readonly INSTALL_USER="ti-hub"
readonly INSTALL_DIR="/opt/threat-intel-hub"
readonly CONFIG_DIR="/etc/threat-intel-hub"
readonly LOG_DIR="/var/log/threat-intel-hub"
readonly DATA_DIR="/var/lib/threat-intel-hub"
readonly SERVICE_NAME="threat-intel-hub"
readonly DB_NAME="ti_hub"
readonly DB_USER="ti_hub_user"

# Variables de control
REMOVE_DATABASE="false"
REMOVE_MARIADB="false"
BACKUP_DATABASE="false"
BACKUP_DIR=""
FORCE_REMOVAL="false"
PRESERVE_LOGS="false"

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
show_uninstall_banner() {
    clear
    echo -e "${RED}"
    echo "================================================================"
    echo "     THREAT INTEL HUB UNINSTALLER v${SCRIPT_VERSION}"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Este script eliminará Threat Intel Hub${NC}"
    echo
    echo "Se eliminarán los siguientes componentes:"
    echo "   • Servicio systemd"
    echo "   • Usuario y grupo del sistema (${INSTALL_USER})"
    echo "   • Directorios de instalación"
    echo "   • Archivos de configuración"
    echo "   • Entorno Python virtual"
    echo "   • Reglas de logrotate"
    echo
    echo "Componentes opcionales:"
    echo "   • Base de datos ${DB_NAME} (opcional)"
    echo "   • Logs del sistema (opcional)"
    echo "   • MariaDB/MySQL (solo si no hay otras BD)"
    echo
}

# Verificar prerrequisitos
check_prerequisites() {
    log_step "Verificando prerrequisitos..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root: sudo bash uninstall.sh"
        exit 1
    fi
    
    if [[ ! -d "$INSTALL_DIR" ]] && [[ ! -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        log_warn "No se detectó instalación de Threat Intel Hub"
        read -p "¿Continuar de todos modos? (y/N): " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            echo "Desinstalación cancelada."
            exit 0
        fi
    fi
    
    log_success "Prerrequisitos verificados"
}

# Detectar componentes instalados
detect_components() {
    log_step "Detectando componentes instalados..."
    
    local components_found=0
    
    # Verificar servicio
    if systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
        log_info "Servicio systemd detectado: ${SERVICE_NAME}"
        ((components_found++))
    fi
    
    # Verificar directorios
    if [[ -d "$INSTALL_DIR" ]]; then
        log_info "Directorio de instalación detectado: $INSTALL_DIR"
        ((components_found++))
    fi
    
    if [[ -d "$CONFIG_DIR" ]]; then
        log_info "Directorio de configuración detectado: $CONFIG_DIR"
        ((components_found++))
    fi
    
    if [[ -d "$DATA_DIR" ]]; then
        log_info "Directorio de datos detectado: $DATA_DIR"
        local data_size=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)
        log_info "Tamaño de datos: ${data_size:-desconocido}"
        ((components_found++))
    fi
    
    if [[ -d "$LOG_DIR" ]]; then
        log_info "Directorio de logs detectado: $LOG_DIR"
        local log_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
        log_info "Tamaño de logs: ${log_size:-desconocido}"
        ((components_found++))
    fi
    
    # Verificar usuario
    if id "$INSTALL_USER" &>/dev/null; then
        log_info "Usuario del sistema detectado: $INSTALL_USER"
        ((components_found++))
    fi
    
    # Verificar base de datos
    if command -v mysql &>/dev/null; then
        if mysql -e "SHOW DATABASES;" 2>/dev/null | grep -q "$DB_NAME"; then
            log_info "Base de datos detectada: $DB_NAME"
            
            # Obtener tamaño de la base de datos
            local db_size=$(mysql -e "
                SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'DB Size (MB)'
                FROM information_schema.tables 
                WHERE table_schema='$DB_NAME';" 2>/dev/null | tail -1)
            
            if [[ -n "$db_size" ]] && [[ "$db_size" != "NULL" ]]; then
                log_info "Tamaño de base de datos: ${db_size} MB"
            fi
            
            ((components_found++))
        fi
    fi
    
    # Verificar logrotate
    if [[ -f "/etc/logrotate.d/threat-intel-hub" ]]; then
        log_info "Configuración de logrotate detectada"
        ((components_found++))
    fi
    
    if [[ $components_found -eq 0 ]]; then
        log_warn "No se encontraron componentes de Threat Intel Hub instalados"
        echo "Es posible que el sistema ya haya sido desinstalado."
        exit 0
    else
        log_success "$components_found componentes detectados"
    fi
}

# Opciones de desinstalación
configure_uninstall_options() {
    log_header "OPCIONES DE DESINSTALACIÓN"
    
    echo "Configure las opciones de desinstalación:"
    echo
    
    # Base de datos
    if command -v mysql &>/dev/null && mysql -e "SHOW DATABASES;" 2>/dev/null | grep -q "$DB_NAME"; then
        echo -e "${YELLOW}BASE DE DATOS:${NC}"
        echo "Se detectó la base de datos '$DB_NAME'"
        
        read -p "¿Crear backup de la base de datos antes de eliminar? (Y/n): " backup_db
        if [[ ! $backup_db =~ ^[Nn]$ ]]; then
            BACKUP_DATABASE="true"
            BACKUP_DIR="/tmp/threat-intel-hub-backup-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$BACKUP_DIR"
            log_info "Los backups se guardarán en: $BACKUP_DIR"
        fi
        
        echo
        read -p "¿Eliminar la base de datos '$DB_NAME'? (y/N): " remove_db
        if [[ $remove_db =~ ^[Yy]$ ]]; then
            REMOVE_DATABASE="true"
            log_warn "La base de datos será eliminada"
        else
            log_info "La base de datos se preservará"
        fi
    fi
    
    # Logs
    echo
    if [[ -d "$LOG_DIR" ]]; then
        echo -e "${YELLOW}LOGS:${NC}"
        local log_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
        echo "Tamaño actual de logs: ${log_size:-desconocido}"
        
        read -p "¿Preservar los logs del sistema? (y/N): " preserve_logs
        if [[ $preserve_logs =~ ^[Yy]$ ]]; then
            PRESERVE_LOGS="true"
            if [[ "$BACKUP_DATABASE" == "true" ]]; then
                log_info "Los logs se moverán a: $BACKUP_DIR"
            else
                BACKUP_DIR="/tmp/threat-intel-hub-logs-$(date +%Y%m%d-%H%M%S)"
                mkdir -p "$BACKUP_DIR"
                log_info "Los logs se moverán a: $BACKUP_DIR"
            fi
        fi
    fi
    
    # MariaDB/MySQL
    echo
    if command -v mysql &>/dev/null; then
        # Verificar si hay otras bases de datos
        local other_dbs=$(mysql -e "SHOW DATABASES;" 2>/dev/null | grep -v -E "Database|information_schema|mysql|performance_schema|sys|$DB_NAME" | wc -l)
        
        if [[ $other_dbs -eq 0 ]]; then
            echo -e "${YELLOW}MARIADB/MYSQL:${NC}"
            echo "No se detectaron otras bases de datos en el sistema."
            read -p "¿Desinstalar MariaDB/MySQL completamente? (y/N): " remove_mariadb
            if [[ $remove_mariadb =~ ^[Yy]$ ]]; then
                REMOVE_MARIADB="true"
                log_warn "MariaDB/MySQL será desinstalado completamente"
            fi
        else
            log_info "Se detectaron $other_dbs bases de datos adicionales. MariaDB/MySQL se preservará."
        fi
    fi
    
    echo
    echo -e "${YELLOW}CONFIRMACIÓN FINAL:${NC}"
    echo "Se eliminarán los siguientes componentes:"
    echo "   ✓ Servicio systemd"
    echo "   ✓ Directorios de instalación"
    echo "   ✓ Usuario del sistema"
    echo "   ✓ Archivos de configuración"
    [[ "$REMOVE_DATABASE" == "true" ]] && echo "   ✓ Base de datos $DB_NAME"
    [[ "$PRESERVE_LOGS" != "true" ]] && echo "   ✓ Logs del sistema"
    [[ "$REMOVE_MARIADB" == "true" ]] && echo "   ✓ MariaDB/MySQL"
    
    echo
    read -p "¿Confirmar desinstalación? (yes/NO): " confirm_uninstall
    if [[ "$confirm_uninstall" != "yes" ]]; then
        echo "Desinstalación cancelada."
        exit 0
    fi
}

# Detener servicio
stop_service() {
    log_step "Deteniendo servicio..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME" || log_warn "Error deteniendo servicio"
        log_success "Servicio detenido"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME" || log_warn "Error deshabilitando servicio"
        log_success "Servicio deshabilitado"
    fi
    
    # Eliminar archivo de servicio
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        log_success "Archivo de servicio eliminado"
    fi
}

# Backup de base de datos
backup_database() {
    if [[ "$BACKUP_DATABASE" != "true" ]]; then
        return
    fi
    
    log_step "Creando backup de base de datos..."
    
    local backup_file="$BACKUP_DIR/${DB_NAME}_backup_$(date +%Y%m%d_%H%M%S).sql"
    
    if mysqldump "$DB_NAME" > "$backup_file" 2>/dev/null; then
        # Comprimir backup
        gzip "$backup_file"
        log_success "Backup creado: ${backup_file}.gz"
        
        # Crear archivo con información de restauración
        cat > "$BACKUP_DIR/RESTORE_INFO.txt" << EOF
================================================
Threat Intel Hub - Información de Restauración
================================================

Fecha de backup: $(date)
Base de datos: $DB_NAME

Para restaurar la base de datos:

1. Descomprimir el backup:
   gunzip ${backup_file}.gz

2. Crear la base de datos:
   mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"

3. Restaurar los datos:
   mysql $DB_NAME < $(basename $backup_file)

4. Recrear usuario (con nueva contraseña):
   mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY 'NUEVA_CONTRASEÑA';"
   mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
   mysql -e "FLUSH PRIVILEGES;"

================================================
EOF
        log_info "Información de restauración guardada en: $BACKUP_DIR/RESTORE_INFO.txt"
    else
        log_error "Error creando backup de base de datos"
        read -p "¿Continuar sin backup? (y/N): " continue_without_backup
        if [[ ! $continue_without_backup =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Preservar logs
preserve_logs() {
    if [[ "$PRESERVE_LOGS" != "true" ]] || [[ ! -d "$LOG_DIR" ]]; then
        return
    fi
    
    log_step "Preservando logs..."
    
    if [[ -n "$BACKUP_DIR" ]]; then
        cp -r "$LOG_DIR" "$BACKUP_DIR/logs"
        log_success "Logs copiados a: $BACKUP_DIR/logs"
        
        # Crear índice de logs
        cat > "$BACKUP_DIR/logs/LOG_INDEX.txt" << EOF
================================================
Threat Intel Hub - Índice de Logs
================================================

Fecha de preservación: $(date)
Ubicación original: $LOG_DIR

Archivos de log preservados:
EOF
        
        find "$BACKUP_DIR/logs" -type f -name "*.log*" -exec basename {} \; >> "$BACKUP_DIR/logs/LOG_INDEX.txt"
        
        echo "================================================" >> "$BACKUP_DIR/logs/LOG_INDEX.txt"
    fi
}

# Eliminar base de datos
remove_database() {
    if [[ "$REMOVE_DATABASE" != "true" ]]; then
        log_info "Base de datos preservada: $DB_NAME"
        return
    fi
    
    log_step "Eliminando base de datos..."
    
    # Eliminar base de datos
    if mysql -e "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null; then
        log_success "Base de datos eliminada: $DB_NAME"
    else
        log_warn "No se pudo eliminar la base de datos"
    fi
    
    # Eliminar usuario
    if mysql -e "DROP USER IF EXISTS '$DB_USER'@'localhost';" 2>/dev/null; then
        log_success "Usuario de base de datos eliminado: $DB_USER"
    else
        log_warn "No se pudo eliminar el usuario de base de datos"
    fi
    
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
}

# Eliminar directorios
remove_directories() {
    log_step "Eliminando directorios..."
    
    # Lista de directorios a eliminar
    local directories=(
        "$INSTALL_DIR"
        "$CONFIG_DIR"
        "$DATA_DIR"
    )
    
    # Agregar directorio de logs si no se preservan
    if [[ "$PRESERVE_LOGS" != "true" ]]; then
        directories+=("$LOG_DIR")
    fi
    
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            log_success "Directorio eliminado: $dir"
        fi
    done
}

# Eliminar usuario del sistema
remove_system_user() {
    log_step "Eliminando usuario del sistema..."
    
    # Matar procesos del usuario si existen
    if id "$INSTALL_USER" &>/dev/null; then
        pkill -u "$INSTALL_USER" 2>/dev/null || true
        sleep 2
        
        # Eliminar usuario
        if userdel "$INSTALL_USER" 2>/dev/null; then
            log_success "Usuario eliminado: $INSTALL_USER"
        else
            log_warn "No se pudo eliminar el usuario"
        fi
    fi
    
    # Eliminar grupo si existe
    if getent group "$INSTALL_USER" >/dev/null 2>&1; then
        if groupdel "$INSTALL_USER" 2>/dev/null; then
            log_success "Grupo eliminado: $INSTALL_USER"
        else
            log_warn "No se pudo eliminar el grupo"
        fi
    fi
}

# Eliminar configuración de logrotate
remove_logrotate() {
    log_step "Eliminando configuración de logrotate..."
    
    if [[ -f "/etc/logrotate.d/threat-intel-hub" ]]; then
        rm -f "/etc/logrotate.d/threat-intel-hub"
        log_success "Configuración de logrotate eliminada"
    fi
}

# Eliminar MariaDB/MySQL
remove_mariadb() {
    if [[ "$REMOVE_MARIADB" != "true" ]]; then
        return
    fi
    
    log_step "Desinstalando MariaDB/MySQL..."
    
    log_warn "Esta acción eliminará MariaDB/MySQL completamente del sistema"
    
    # Detener servicio
    systemctl stop mariadb 2>/dev/null || systemctl stop mysql 2>/dev/null || true
    systemctl disable mariadb 2>/dev/null || systemctl disable mysql 2>/dev/null || true
    
    # Desinstalar paquetes
    apt-get remove --purge -y mariadb-server mariadb-client mysql-server mysql-client 2>/dev/null || true
    apt-get autoremove -y
    apt-get autoclean
    
    # Eliminar directorios de datos
    rm -rf /var/lib/mysql
    rm -rf /etc/mysql
    rm -rf /var/log/mysql
    
    log_success "MariaDB/MySQL desinstalado completamente"
}

# Limpieza final
final_cleanup() {
    log_step "Realizando limpieza final..."
    
    # Eliminar archivos temporales
    rm -f /tmp/ti-hub-*.tmp 2>/dev/null || true
    rm -f /tmp/ti_hub_* 2>/dev/null || true
    
    # Recargar systemd
    systemctl daemon-reload
    
    log_success "Limpieza final completada"
}

# Resumen de desinstalación
show_uninstall_summary() {
    log_header "RESUMEN DE DESINSTALACIÓN"
    
    echo -e "${GREEN}✅ Desinstalación completada${NC}"
    echo
    
    echo "Componentes eliminados:"
    echo "   ✓ Servicio systemd"
    echo "   ✓ Directorios de instalación"
    echo "   ✓ Usuario y grupo del sistema"
    echo "   ✓ Archivos de configuración"
    echo "   ✓ Entorno Python virtual"
    echo "   ✓ Configuración de logrotate"
    
    if [[ "$REMOVE_DATABASE" == "true" ]]; then
        echo "   ✓ Base de datos $DB_NAME"
    else
        echo "   ⚠️  Base de datos preservada: $DB_NAME"
    fi
    
    if [[ "$PRESERVE_LOGS" == "true" ]]; then
        echo "   ⚠️  Logs preservados en: $BACKUP_DIR/logs"
    else
        echo "   ✓ Logs del sistema"
    fi
    
    if [[ "$REMOVE_MARIADB" == "true" ]]; then
        echo "   ✓ MariaDB/MySQL"
    fi
    
    echo
    
    if [[ "$BACKUP_DATABASE" == "true" ]] || [[ "$PRESERVE_LOGS" == "true" ]]; then
        echo -e "${YELLOW}BACKUPS Y ARCHIVOS PRESERVADOS:${NC}"
        if [[ -n "$BACKUP_DIR" ]] && [[ -d "$BACKUP_DIR" ]]; then
            echo "   Ubicación: $BACKUP_DIR"
            echo
            echo "   Contenido:"
            if [[ "$BACKUP_DATABASE" == "true" ]]; then
                echo "   • Backup de base de datos (.sql.gz)"
                echo "   • Instrucciones de restauración (RESTORE_INFO.txt)"
            fi
            if [[ "$PRESERVE_LOGS" == "true" ]]; then
                echo "   • Logs del sistema (/logs)"
                echo "   • Índice de logs (LOG_INDEX.txt)"
            fi
            echo
            echo -e "${YELLOW}⚠️  IMPORTANTE:${NC}"
            echo "   Guarde estos archivos en un lugar seguro si desea conservarlos."
            echo "   Ubicación temporal: $BACKUP_DIR"
        fi
    fi
    
    echo
    echo "Componentes que pueden requerir limpieza manual:"
    echo "   • Paquetes Python del sistema (si fueron instalados globalmente)"
    echo "   • Configuraciones de firewall específicas"
    echo "   • Entradas en crontab (si se agregaron manualmente)"
    
    if [[ "$REMOVE_DATABASE" != "true" ]] && command -v mysql &>/dev/null; then
        echo
        echo -e "${YELLOW}Base de datos preservada:${NC}"
        echo "   La base de datos '$DB_NAME' no fue eliminada."
        echo "   Para eliminarla manualmente:"
        echo "   mysql -e \"DROP DATABASE IF EXISTS $DB_NAME;\""
        echo "   mysql -e \"DROP USER IF EXISTS '$DB_USER'@'localhost';\""
    fi
    
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     THREAT INTEL HUB DESINSTALADO EXITOSAMENTE           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Función principal
main() {
    show_uninstall_banner
    
    read -p "¿Desea continuar con la desinstalación? (yes/NO): " initial_confirm
    if [[ "$initial_confirm" != "yes" ]]; then
        echo "Desinstalación cancelada."
        exit 0
    fi
    
    check_prerequisites
    detect_components
    configure_uninstall_options
    
    log_header "EJECUTANDO DESINSTALACIÓN"
    
    # Ejecutar pasos de desinstalación
    stop_service
    backup_database
    preserve_logs
    remove_database
    remove_directories
    remove_system_user
    remove_logrotate
    remove_mariadb
    final_cleanup
    
    show_uninstall_summary
}

# Manejo de errores
trap 'log_error "Error durante la desinstalación. Código de salida: $?"' ERR

# Ejecutar función principal
main