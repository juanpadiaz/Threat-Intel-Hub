#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Instalación v1.0.5 ENTERPRISE
# PARTE 1: Instalador principal y configuración base
# Compatible con: Ubuntu 20.04+ LTS / Debian 10+ 
# Versión: 1.0.5-COMPLETE
# Fecha: Enero 2025
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
readonly SCRIPT_VERSION="1.0.5-COMPLETE"
readonly INSTALL_USER="ti-hub"
readonly INSTALL_DIR="/opt/threat-intel-hub"
readonly CONFIG_DIR="/etc/threat-intel-hub"
readonly LOG_DIR="/var/log/threat-intel-hub"
readonly DATA_DIR="/var/lib/threat-intel-hub"
readonly VENV_DIR="$INSTALL_DIR/venv"
readonly REPORTS_DIR="$DATA_DIR/reports"

# Variables de configuración
DB_HOST="localhost"
DB_PORT="3306"
DB_NAME="ti_hub"
DB_USER="ti_hub_user"
DB_PASSWORD=""
DB_ROOT_PASSWORD=""

# Variables de detección
WAZUH_DETECTED="false"
WAZUH_MANAGER_URL=""
WAZUH_INDEXER_URL=""
WAZUH_USER=""
WAZUH_PASSWORD=""

# Configuración de triggers
KEV_ENABLED="true"
KEV_CHECK_MINUTES="30"
EPSS_ENABLED="true"
EPSS_SPIKE_THRESHOLD="0.2"
EPSS_CHECK_HOURS="4"
MISP_PRIORITY="true"

# API Keys
NVD_API_KEY=""
OTX_API_KEY=""
MISP_URL=""
MISP_API_KEY=""
VT_API_KEY=""

# Email configuration
EMAIL_ENABLED="false"
SMTP_SERVER=""
SMTP_PORT=""
SENDER_EMAIL=""
SENDER_PASSWORD=""
RECIPIENT_EMAIL=""
USE_TLS="true"

# Advisory configuration
ADVISORY_ENABLED="false"
ADVISORY_SCHEDULE="daily"
ADVISORY_TIMES=""

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
    cat << "BANNER"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     ████████╗██╗      ██╗  ██╗██╗   ██╗██████╗     ██╗   ██╗ ╭─╮ ╭─╮   ║
║     ╚══██╔══╝██║      ██║  ██║██║   ██║██╔══██╗    ██║   ██║ │ │ │ │   ║
║        ██║   ██║█████╗███████║██║   ██║██████╔╝    ██║   ██║ │ │ │ │   ║
║        ██║   ██║╚════╝██╔══██║██║   ██║██╔══██╗    ╚██╗ ██╔╝ │ │ │ │   ║
║        ██║   ██║      ██║  ██║╚██████╔╝██████╔╝     ╚████╔╝  ╰─╯•╰─╯   ║
║        ╚═╝   ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═════╝       ╚═══╝      5      ║
║                                                                          ║
║          THREAT INTELLIGENCE HUB - ENTERPRISE EDITION v1.0.5            ║
║                     Actionable Intelligence Platform                    ║
║                      with MDR Advisory Generator                        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
BANNER
    
    echo -e "${CYAN}Versión: ${SCRIPT_VERSION}${NC}"
    echo -e "${CYAN}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo
    echo -e "${GREEN}Características de esta versión ENTERPRISE:${NC}"
    echo "  ✅ Generador de MDR Threat Advisories"
    echo "  ✅ Comando ti-hub-advisory-gen"
    echo "  ✅ Todos los comandos administrativos"
    echo "  ✅ Automatización con cron configurable"
    echo "  ✅ Fix completo para OTX SDK"
    echo "  ✅ Módulo OTX alternativo si falla PyPI"
    echo "  ✅ Base de datos con esquema v1.0.3"
    echo "  ✅ Detección automática de Wazuh"
    echo
    read -p "¿Desea continuar con la instalación? (s/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        echo "Instalación cancelada."
        exit 0
    fi
}

# Verificar requisitos
check_requirements() {
    log_header "VERIFICACIÓN DE REQUISITOS"
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        exit 1
    fi
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        log_info "Sistema detectado: $OS $VER"
        
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            log_warn "Sistema no probado. Se recomienda Ubuntu 20.04+ o Debian 10+"
            read -p "¿Continuar de todos modos? (s/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Ss]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_info "Python version: $PYTHON_VERSION"
    
    if ! command -v mysql &> /dev/null; then
        log_error "MariaDB/MySQL no está instalado"
        echo "Por favor instale MariaDB primero:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install mariadb-server mariadb-client"
        exit 1
    fi
    
    log_success "Todos los requisitos cumplidos"
}

# Instalar dependencias del sistema
install_dependencies() {
    log_header "INSTALACIÓN DE DEPENDENCIAS"
    
    log_step "Actualizando repositorios..."
    apt-get update -qq
    
    log_step "Instalando paquetes necesarios..."
    
    PACKAGES=(
        python3-pip
        python3-venv
        python3-dev
        build-essential
        libssl-dev
        libffi-dev
        libmysqlclient-dev
        git
        curl
        wget
        jq
        cron
        logrotate
    )
    
    for package in "${PACKAGES[@]}"; do
        if dpkg -l | grep -q "^ii  $package"; then
            log_info "$package ya instalado"
        else
            log_step "Instalando $package..."
            apt-get install -y $package
        fi
    done
    
    log_success "Dependencias instaladas"
}

# Detectar Wazuh
detect_wazuh() {
    log_header "DETECCIÓN DE WAZUH"
    
    if systemctl list-units --all | grep -q "wazuh-manager"; then
        log_info "Wazuh Manager detectado"
        WAZUH_DETECTED="true"
        
        if [[ -f /var/ossec/etc/ossec.conf ]]; then
            log_info "Configuración de Wazuh encontrada"
            read -p "¿Configurar integración con Wazuh? (S/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                read -p "URL del Wazuh Manager [https://localhost:55000]: " WAZUH_MANAGER_URL
                WAZUH_MANAGER_URL="${WAZUH_MANAGER_URL:-https://localhost:55000}"
                
                read -p "URL del Wazuh Indexer [https://localhost:9200]: " WAZUH_INDEXER_URL
                WAZUH_INDEXER_URL="${WAZUH_INDEXER_URL:-https://localhost:9200}"
                
                read -p "Usuario de Wazuh [admin]: " WAZUH_USER
                WAZUH_USER="${WAZUH_USER:-admin}"
                
                read -s -p "Contraseña de Wazuh: " WAZUH_PASSWORD
                echo
            fi
        fi
    else
        log_info "Wazuh no detectado en este sistema"
    fi
}

# Configuración interactiva
interactive_configuration() {
    log_header "CONFIGURACIÓN INTERACTIVA"
    
    echo
    echo "=== Configuración de Triggers ==="
    
    read -p "¿Habilitar monitoreo KEV? (S/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        KEV_ENABLED="false"
    else
        read -p "Intervalo de verificación KEV en minutos [30]: " KEV_CHECK_MINUTES
        KEV_CHECK_MINUTES="${KEV_CHECK_MINUTES:-30}"
    fi
    
    read -p "¿Habilitar monitoreo EPSS? (S/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        EPSS_ENABLED="false"
    else
        read -p "Umbral de spike EPSS [0.2]: " EPSS_SPIKE_THRESHOLD
        EPSS_SPIKE_THRESHOLD="${EPSS_SPIKE_THRESHOLD:-0.2}"
        read -p "Intervalo de verificación EPSS en horas [4]: " EPSS_CHECK_HOURS
        EPSS_CHECK_HOURS="${EPSS_CHECK_HOURS:-4}"
    fi
    
    echo
    echo "=== Configuración de APIs (opcional) ==="
    echo "Puede dejar en blanco si no tiene las API keys"
    
    read -p "NVD API Key (mejora rate limits): " NVD_API_KEY
    read -p "AlienVault OTX API Key: " OTX_API_KEY
    
    read -p "¿Configurar MISP? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        read -p "MISP URL: " MISP_URL
        if [[ -n "$MISP_URL" ]]; then
            read -p "MISP API Key: " MISP_API_KEY
        fi
    fi
    
    read -p "VirusTotal API Key (opcional): " VT_API_KEY
    
    echo
    echo "=== Configuración de Email y Advisories ==="
    read -p "¿Configurar notificaciones por email y MDR Advisories? (s/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        EMAIL_ENABLED="true"
        
        echo "Servidor SMTP:"
        echo "  1) Gmail (smtp.gmail.com)"
        echo "  2) Outlook (smtp-mail.outlook.com)"
        echo "  3) Yahoo (smtp.mail.yahoo.com)"
        echo "  4) Otro"
        read -p "Seleccione [1-4]: " smtp_choice
        
        case $smtp_choice in
            1)
                SMTP_SERVER="smtp.gmail.com"
                SMTP_PORT="587"
                USE_TLS="true"
                echo "NOTA: Para Gmail, necesita generar una App Password"
                echo "      https://myaccount.google.com/apppasswords"
                ;;
            2)
                SMTP_SERVER="smtp-mail.outlook.com"
                SMTP_PORT="587"
                USE_TLS="true"
                ;;
            3)
                SMTP_SERVER="smtp.mail.yahoo.com"
                SMTP_PORT="587"
                USE_TLS="true"
                ;;
            4)
                read -p "Servidor SMTP: " SMTP_SERVER
                read -p "Puerto SMTP [587]: " SMTP_PORT
                SMTP_PORT="${SMTP_PORT:-587}"
                read -p "¿Usar TLS? (S/n): " -n 1 -r
                echo
                USE_TLS=$([[ $REPLY =~ ^[Nn]$ ]] && echo "false" || echo "true")
                ;;
        esac
        
        read -p "Email remitente: " SENDER_EMAIL
        read -s -p "Contraseña del remitente: " SENDER_PASSWORD
        echo
        read -p "Email(s) destinatario(s) (separados por coma): " RECIPIENT_EMAIL
        
        echo
        echo "=== Configuración de MDR Threat Advisories Automáticos ==="
        read -p "¿Habilitar generación automática de advisories? (s/N): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            ADVISORY_ENABLED="true"
            
            echo "Frecuencia de generación:"
            echo "  1) Una vez al día (8:00 AM)"
            echo "  2) Dos veces al día (8:00 AM y 4:00 PM)"
            echo "  3) Tres veces al día (8:00 AM, 2:00 PM, 8:00 PM)"
            echo "  4) Personalizado"
            read -p "Seleccione [1-4]: " freq_choice
            
            case $freq_choice in
                1)
                    ADVISORY_SCHEDULE="daily"
                    ADVISORY_TIMES="0 8 * * *"
                    ;;
                2)
                    ADVISORY_SCHEDULE="twice"
                    ADVISORY_TIMES="0 8,16 * * *"
                    ;;
                3)
                    ADVISORY_SCHEDULE="thrice"
                    ADVISORY_TIMES="0 8,14,20 * * *"
                    ;;
                4)
                    echo "Ingrese la expresión cron (formato: minuto hora * * *)"
                    read -p "Ejemplo: '0 9,17 * * *' para 9AM y 5PM: " ADVISORY_TIMES
                    ADVISORY_SCHEDULE="custom"
                    ;;
            esac
            
            log_info "Advisories configurados: $ADVISORY_SCHEDULE"
        fi
    fi
}

# Configurar Base de Datos
setup_database() {
    log_header "CONFIGURACIÓN DE BASE DE DATOS v1.0.3"
    
    if [[ -z "$DB_PASSWORD" ]]; then
        DB_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        log_info "Contraseña generada para usuario de BD"
    fi
    
    log_step "Creando base de datos y usuario..."
    
    mysql -u root ${DB_ROOT_PASSWORD:+-p"$DB_ROOT_PASSWORD"} << EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
USE ${DB_NAME};
EOF
    
    log_step "Creando esquema de base de datos v1.0.3..."
    
    mysql -u root ${DB_ROOT_PASSWORD:+-p"$DB_ROOT_PASSWORD"} $DB_NAME << 'EOF'
-- Tabla principal de vulnerabilidades
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    published_date DATETIME,
    last_modified DATETIME,
    description TEXT,
    cvss_v3_score DECIMAL(3,1),
    cvss_severity ENUM('NONE','LOW','MEDIUM','HIGH','CRITICAL'),
    cvss_vector VARCHAR(100),
    cpe_list JSON,
    reference_urls JSON,
    epss_score DECIMAL(6,5),
    epss_percentile DECIMAL(6,5),
    epss_date DATE,
    kev_status BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    threat_score DECIMAL(4,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (cvss_severity),
    INDEX idx_epss_score (epss_score),
    INDEX idx_kev_status (kev_status),
    INDEX idx_threat_score (threat_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de vulnerabilidades KEV
CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    vendor_project VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name VARCHAR(255),
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve_id (cve_id),
    INDEX idx_date_added (date_added),
    INDEX idx_ransomware (known_ransomware)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de IoCs
CREATE TABLE IF NOT EXISTS threat_iocs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ioc_type ENUM('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','file_path','registry','mutex') NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    source VARCHAR(100),
    threat_type VARCHAR(100),
    confidence_score DECIMAL(3,2),
    first_seen DATETIME,
    last_seen DATETIME,
    times_seen INT DEFAULT 1,
    tags JSON,
    related_cves JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_ioc (ioc_type, ioc_value),
    INDEX idx_type (ioc_type),
    INDEX idx_value (ioc_value),
    INDEX idx_active (is_active),
    INDEX idx_confidence (confidence_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de correlaciones CVE-IoC
CREATE TABLE IF NOT EXISTS cve_ioc_correlations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    ioc_id INT NOT NULL,
    correlation_type ENUM('direct','indirect','potential') DEFAULT 'potential',
    confidence DECIMAL(3,2),
    source VARCHAR(100),
    evidence JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES threat_iocs(id) ON DELETE CASCADE,
    INDEX idx_cve (cve_id),
    INDEX idx_ioc (ioc_id),
    INDEX idx_correlation (correlation_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de campañas
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    campaign_name VARCHAR(255) NOT NULL,
    actor_name VARCHAR(255),
    description TEXT,
    first_seen DATE,
    last_seen DATE,
    targeted_sectors JSON,
    targeted_countries JSON,
    ttps JSON,
    associated_cves JSON,
    associated_iocs JSON,
    confidence_level ENUM('LOW','MEDIUM','HIGH','CONFIRMED'),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (campaign_name),
    INDEX idx_actor (actor_name),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de correlaciones con Wazuh
CREATE TABLE IF NOT EXISTS wazuh_correlations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(100),
    rule_id VARCHAR(20),
    agent_id VARCHAR(10),
    agent_name VARCHAR(255),
    cve_list JSON,
    ioc_matches JSON,
    correlation_type ENUM('cve_match','ioc_match','behavior_match','combined'),
    confidence_score DECIMAL(3,2),
    detection_timestamp DATETIME,
    raw_log TEXT,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (correlation_type),
    INDEX idx_agent (agent_id),
    INDEX idx_timestamp (detection_timestamp),
    INDEX idx_resolved (is_resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de alertas generadas
CREATE TABLE IF NOT EXISTS threat_alerts (
    id VARCHAR(36) PRIMARY KEY,
    alert_type ENUM('kev_addition','epss_spike','ioc_detection','campaign_active','wazuh_correlation','manual') NOT NULL,
    priority ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    cve_list JSON,
    ioc_list JSON,
    affected_systems JSON,
    recommended_actions JSON,
    alert_data JSON,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at DATETIME,
    distribution_status ENUM('pending','sent','failed') DEFAULT 'pending',
    distribution_log JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (alert_type),
    INDEX idx_priority (priority),
    INDEX idx_status (distribution_status),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    config_type ENUM('string','integer','boolean','json') DEFAULT 'string',
    category VARCHAR(50),
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_key (config_key),
    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insertar configuración inicial
INSERT INTO system_config (config_key, config_value, category, description) VALUES
('db_version', '1.0.3', 'system', 'Database schema version'),
('last_kev_check', NULL, 'triggers', 'Last KEV check timestamp'),
('last_epss_check', NULL, 'triggers', 'Last EPSS check timestamp'),
('last_correlation_run', NULL, 'correlation', 'Last correlation run timestamp')
ON DUPLICATE KEY UPDATE config_value=VALUES(config_value);
EOF
    
    TABLES_COUNT=$(mysql -u root ${DB_ROOT_PASSWORD:+-p"$DB_ROOT_PASSWORD"} -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_NAME';")
    
    if [[ $TABLES_COUNT -eq 8 ]]; then
        log_success "Base de datos creada correctamente"
    else
        log_error "Error al crear la base de datos"
        exit 1
    fi
}

# Crear usuario del sistema
create_system_user() {
    log_header "CONFIGURACIÓN DE USUARIO DEL SISTEMA"
    
    if id "$INSTALL_USER" &>/dev/null; then
        log_info "Usuario $INSTALL_USER ya existe"
    else
        log_step "Creando usuario $INSTALL_USER..."
        useradd -r -s /bin/bash -d /home/$INSTALL_USER -m $INSTALL_USER
        log_success "Usuario creado"
    fi
    
    log_step "Creando estructura de directorios..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"/{scripts,reports,campaigns,rules,api_exports,webhooks,blocklists,templates}
    mkdir -p "$DATA_DIR"/rules/{snort,yara,sigma,wazuh}
    mkdir -p "$INSTALL_DIR"/lib/otx_alternative
    
    chown -R $INSTALL_USER:$INSTALL_USER "$INSTALL_DIR"
    chown -R $INSTALL_USER:$INSTALL_USER "$DATA_DIR"
    chown -R $INSTALL_USER:$INSTALL_USER "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    log_success "Estructura de directorios creada"
}

# DESCARGAR Y EJECUTAR PARTE 2
download_and_run_part2() {
    log_header "DESCARGANDO SEGUNDA PARTE DEL INSTALADOR"
    
    log_step "La parte 2 contiene los comandos administrativos y scripts..."
    echo "Por favor, descargue la parte 2 del instalador y ejecútela después de este script."
    echo
    echo "Puede continuar con: sudo bash ti_hub_installer_v1.0.5_part2.sh"
    echo
    
    # Guardar variables para la parte 2
    cat > /tmp/ti_hub_install_vars.sh << EOF
#!/bin/bash
export INSTALL_USER="$INSTALL_USER"
export INSTALL_DIR="$INSTALL_DIR"
export CONFIG_DIR="$CONFIG_DIR"
export LOG_DIR="$LOG_DIR"
export DATA_DIR="$DATA_DIR"
export VENV_DIR="$VENV_DIR"
export REPORTS_DIR="$REPORTS_DIR"
export DB_HOST="$DB_HOST"
export DB_PORT="$DB_PORT"
export DB_NAME="$DB_NAME"
export DB_USER="$DB_USER"
export DB_PASSWORD="$DB_PASSWORD"
export EMAIL_ENABLED="$EMAIL_ENABLED"
export ADVISORY_ENABLED="$ADVISORY_ENABLED"
export ADVISORY_SCHEDULE="$ADVISORY_SCHEDULE"
export ADVISORY_TIMES="$ADVISORY_TIMES"
export NVD_API_KEY="$NVD_API_KEY"
export OTX_API_KEY="$OTX_API_KEY"
export SMTP_SERVER="$SMTP_SERVER"
export SMTP_PORT="$SMTP_PORT"
export SENDER_EMAIL="$SENDER_EMAIL"
export SENDER_PASSWORD="$SENDER_PASSWORD"
export RECIPIENT_EMAIL="$RECIPIENT_EMAIL"
export USE_TLS="$USE_TLS"
EOF
    
    log_success "Variables guardadas en /tmp/ti_hub_install_vars.sh"
}

# Función principal (parte 1)
main() {
    show_welcome_banner
    check_requirements
    install_dependencies
    detect_wazuh
    interactive_configuration
    setup_database
    create_system_user
    download_and_run_part2
}

# Ejecutar instalador parte 1
main "$@"
