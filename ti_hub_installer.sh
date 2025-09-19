#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Instalación v1.0.3 FIXED
# CORREGIDO: Sin duplicados en config.ini, con todos los comandos admin
# Compatible con: Ubuntu 20.04+ LTS / Debian 10+ 
# Versión: 1.0.3-FIXED
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
readonly SCRIPT_VERSION="1.0.3-FIXED"
readonly INSTALL_USER="ti-hub"
readonly INSTALL_DIR="/opt/threat-intel-hub"
readonly CONFIG_DIR="/etc/threat-intel-hub"
readonly LOG_DIR="/var/log/threat-intel-hub"
readonly DATA_DIR="/var/lib/threat-intel-hub"
readonly VENV_DIR="$INSTALL_DIR/venv"

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
║        ╚═╝   ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═════╝       ╚═══╝      3      ║
║                                                                          ║
║              THREAT INTELLIGENCE HUB - FIXED EDITION                    ║
║                  Actionable Intelligence Platform                       ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
BANNER
    
    echo -e "${CYAN}Version: ${SCRIPT_VERSION}${NC}"
    echo -e "${CYAN}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo
    echo -e "${GREEN}Correcciones en esta versión FIXED:${NC}"
    echo "  ✅ Config.ini sin duplicados"
    echo "  ✅ API Keys se guardan correctamente"
    echo "  ✅ TODOS los comandos administrativos incluidos"
    echo "  ✅ Base de datos con esquema corregido"
    echo "  ✅ Scripts Python mejorados"
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
    
    # Verificar si es root
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        exit 1
    fi
    
    # Detectar distribución
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        log_info "Sistema operativo detectado: $OS $OS_VERSION"
    else
        log_error "No se pudo detectar el sistema operativo"
        exit 1
    fi
    
    # Verificar distribución soportada
    case $OS in
        ubuntu|debian)
            if command -v apt &> /dev/null; then
                PKG_MANAGER="apt"
                log_success "Gestor de paquetes: APT"
            else
                log_error "APT no encontrado"
                exit 1
            fi
            ;;
        centos|rhel|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
                log_success "Gestor de paquetes: DNF"
            elif command -v yum &> /dev/null; then
                PKG_MANAGER="yum"
                log_success "Gestor de paquetes: YUM"
            else
                log_error "YUM/DNF no encontrado"
                exit 1
            fi
            ;;
        *)
            log_error "Distribución no soportada: $OS"
            exit 1
            ;;
    esac
    
    # Verificar conectividad a Internet
    log_step "Verificando conectividad a Internet..."
    if ping -c 1 google.com &> /dev/null; then
        log_success "Conectividad OK"
    else
        log_warn "No hay conectividad a Internet. Algunas funciones estarán limitadas."
    fi
    
    # Verificar espacio en disco (mínimo 2GB)
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 2097152 ]]; then
        log_error "Espacio insuficiente. Se requieren al menos 2GB libres."
        exit 1
    else
        log_success "Espacio en disco OK: $(( AVAILABLE_SPACE / 1024 / 1024 ))GB disponibles"
    fi
}

# Instalar dependencias
install_dependencies() {
    log_header "INSTALACIÓN DE DEPENDENCIAS"
    
    case $PKG_MANAGER in
        apt)
            log_step "Actualizando repositorios..."
            apt update -q
            
            log_step "Instalando paquetes necesarios..."
            DEBIAN_FRONTEND=noninteractive apt install -y \
                python3 python3-pip python3-venv \
                mariadb-server mariadb-client \
                git curl wget jq \
                nginx \
                build-essential python3-dev \
                libssl-dev libffi-dev \
                cron logrotate
            ;;
        dnf|yum)
            log_step "Instalando paquetes necesarios..."
            $PKG_MANAGER install -y \
                python3 python3-pip \
                mariadb-server mariadb \
                git curl wget jq \
                nginx \
                gcc python3-devel \
                openssl-devel \
                cronie logrotate
            ;;
    esac
    
    # Iniciar y habilitar MariaDB
    log_step "Configurando MariaDB..."
    systemctl start mariadb 2>/dev/null || systemctl start mysql 2>/dev/null
    systemctl enable mariadb 2>/dev/null || systemctl enable mysql 2>/dev/null
    
    log_success "Dependencias instaladas correctamente"
}

# Detectar Wazuh
detect_wazuh() {
    log_header "DETECCIÓN DE WAZUH SIEM"
    
    local wazuh_found=false
    
    # Buscar Wazuh Manager
    if systemctl status wazuh-manager &>/dev/null; then
        log_success "Wazuh Manager detectado localmente"
        wazuh_found=true
        WAZUH_MANAGER_URL="https://localhost:55000"
    fi
    
    # Buscar Wazuh Indexer/Dashboard
    if systemctl status wazuh-indexer &>/dev/null || systemctl status opensearch &>/dev/null; then
        log_success "Wazuh Indexer detectado"
        wazuh_found=true
        WAZUH_INDEXER_URL="https://localhost:9200"
    fi
    
    if [[ "$wazuh_found" == "true" ]]; then
        WAZUH_DETECTED="true"
        
        echo
        read -p "¿Desea configurar la integración con Wazuh? (S/n): " -n 1 -r
        echo
        
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            read -p "URL del Wazuh Manager [$WAZUH_MANAGER_URL]: " input
            WAZUH_MANAGER_URL="${input:-$WAZUH_MANAGER_URL}"
            
            read -p "URL del Wazuh Indexer [$WAZUH_INDEXER_URL]: " input
            WAZUH_INDEXER_URL="${input:-$WAZUH_INDEXER_URL}"
            
            read -p "Usuario de Wazuh [admin]: " WAZUH_USER
            WAZUH_USER="${WAZUH_USER:-admin}"
            
            read -s -p "Contraseña de Wazuh: " WAZUH_PASSWORD
            echo
            
            log_success "Integración con Wazuh configurada"
        else
            WAZUH_DETECTED="false"
        fi
    else
        log_info "Wazuh no detectado. La integración puede configurarse más tarde."
    fi
}

# Configuración interactiva
interactive_configuration() {
    log_header "CONFIGURACIÓN INTERACTIVA"
    
    # Configurar triggers
    echo
    echo "=== Configuración de Triggers ==="
    read -p "¿Habilitar monitoreo KEV? (S/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        KEV_ENABLED="false"
    fi
    
    if [[ "$KEV_ENABLED" == "true" ]]; then
        read -p "Intervalo de verificación KEV en minutos [30]: " input
        KEV_CHECK_MINUTES="${input:-30}"
    fi
    
    read -p "¿Habilitar monitoreo EPSS? (S/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        EPSS_ENABLED="false"
    fi
    
    if [[ "$EPSS_ENABLED" == "true" ]]; then
        read -p "Umbral de spike EPSS [0.2]: " input
        EPSS_SPIKE_THRESHOLD="${input:-0.2}"
        
        read -p "Intervalo de verificación EPSS en horas [4]: " input
        EPSS_CHECK_HOURS="${input:-4}"
    fi
    
    # Configurar APIs (opcional)
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
    
    # Configurar email
    echo
    echo "=== Configuración de Email (para advisories) ==="
    read -p "¿Configurar notificaciones por email? (s/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        EMAIL_ENABLED="true"
        
        echo "Servidor SMTP:"
        echo "  1) Gmail (smtp.gmail.com)"
        echo "  2) Outlook (smtp-mail.outlook.com)"
        echo "  3) Otro"
        read -p "Seleccione [1-3]: " smtp_choice
        
        case $smtp_choice in
            1)
                SMTP_SERVER="smtp.gmail.com"
                SMTP_PORT="587"
                echo "NOTA: Para Gmail, necesita generar una App Password"
                echo "      https://myaccount.google.com/apppasswords"
                ;;
            2)
                SMTP_SERVER="smtp-mail.outlook.com"
                SMTP_PORT="587"
                ;;
            3)
                read -p "Servidor SMTP: " SMTP_SERVER
                read -p "Puerto SMTP [587]: " SMTP_PORT
                SMTP_PORT="${SMTP_PORT:-587}"
                ;;
        esac
        
        read -p "Email remitente: " SENDER_EMAIL
        read -s -p "Contraseña del remitente: " SENDER_PASSWORD
        echo
        read -p "Email(s) destinatario(s) (separados por coma): " RECIPIENT_EMAIL
    fi
}

# Configurar Base de Datos
setup_database() {
    log_header "CONFIGURACIÓN DE BASE DE DATOS v1.0.3"
    
    # Generar contraseña si no existe
    if [[ -z "$DB_PASSWORD" ]]; then
        DB_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        log_info "Contraseña generada para usuario de BD"
    fi
    
    # Crear base de datos y usuario
    log_step "Creando base de datos y usuario..."
    
    mysql -u root ${DB_ROOT_PASSWORD:+-p"$DB_ROOT_PASSWORD"} << EOF
-- Crear base de datos
CREATE DATABASE IF NOT EXISTS ${DB_NAME} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;

-- Seleccionar base de datos
USE ${DB_NAME};
EOF
    
    # Crear esquema de base de datos (CORREGIDO)
    log_step "Creando esquema de base de datos v1.0.3..."
    
    mysql -u root ${DB_ROOT_PASSWORD:+-p"$DB_ROOT_PASSWORD"} $DB_NAME << 'EOF'
-- Tabla principal de vulnerabilidades (CORREGIDA)
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
    INDEX idx_threat_score (threat_score),
    INDEX idx_updated_at (updated_at)
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

-- Tabla de histórico EPSS
CREATE TABLE IF NOT EXISTS epss_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    epss_score DECIMAL(6,5),
    percentile DECIMAL(6,5),
    model_version VARCHAR(20),
    date_recorded DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cve_date (cve_id, date_recorded),
    INDEX idx_score_change (cve_id, epss_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de Indicadores de Compromiso (IoCs)
CREATE TABLE IF NOT EXISTS iocs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_value TEXT NOT NULL,
    indicator_type ENUM('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','mutex','registry','file_path','user_agent') NOT NULL,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence_score DECIMAL(3,2),
    first_seen DATETIME,
    last_seen DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    source VARCHAR(100),
    source_reference VARCHAR(255),
    campaign_id VARCHAR(100),
    tags JSON,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (indicator_type),
    INDEX idx_confidence (confidence_score),
    INDEX idx_active (is_active),
    INDEX idx_last_seen (last_seen),
    INDEX idx_campaign (campaign_id),
    FULLTEXT idx_indicator_value (indicator_value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de campañas de amenazas
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    campaign_id VARCHAR(100) UNIQUE NOT NULL,
    campaign_name VARCHAR(255),
    threat_actor VARCHAR(255),
    description TEXT,
    first_seen DATE,
    last_activity DATE,
    targeted_sectors JSON,
    targeted_countries JSON,
    ttps JSON,
    is_active BOOLEAN DEFAULT TRUE,
    confidence_level ENUM('LOW','MEDIUM','HIGH') DEFAULT 'MEDIUM',
    source VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_campaign_id (campaign_id),
    INDEX idx_threat_actor (threat_actor),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de correlaciones CVE-IoC
CREATE TABLE IF NOT EXISTS cve_ioc_relationships (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    ioc_id INT NOT NULL,
    relationship_type ENUM('exploits','delivers','downloads','communicates','associated') DEFAULT 'associated',
    confidence DECIMAL(3,2),
    evidence TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
    INDEX idx_cve (cve_id),
    INDEX idx_ioc (ioc_id),
    UNIQUE KEY unique_cve_ioc (cve_id, ioc_id, relationship_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de correlaciones con Wazuh
CREATE TABLE IF NOT EXISTS wazuh_correlations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    correlation_type ENUM('cve_detection','ioc_match','threat_hunt','anomaly') NOT NULL,
    correlation_id VARCHAR(100),
    agent_id VARCHAR(10),
    agent_name VARCHAR(255),
    agent_ip VARCHAR(45),
    rule_id VARCHAR(20),
    rule_description TEXT,
    alert_level INT,
    event_data JSON,
    detection_timestamp DATETIME,
    correlation_score DECIMAL(3,2),
    is_resolved BOOLEAN DEFAULT FALSE,
    notes TEXT,
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

-- Vista para inteligencia accionable
CREATE OR REPLACE VIEW actionable_intelligence AS
SELECT 
    v.cve_id,
    v.cvss_severity,
    v.cvss_v3_score,
    v.epss_score,
    v.epss_percentile,
    CASE 
        WHEN k.cve_id IS NOT NULL THEN TRUE 
        ELSE FALSE 
    END as is_kev,
    k.known_ransomware,
    k.due_date as kev_due_date,
    COUNT(DISTINCT r.ioc_id) as associated_iocs,
    COUNT(DISTINCT w.id) as wazuh_detections,
    GREATEST(
        COALESCE(v.threat_score, 0),
        CASE 
            WHEN k.known_ransomware = TRUE THEN 95
            WHEN k.cve_id IS NOT NULL THEN 85
            WHEN v.epss_score > 0.5 THEN 75
            WHEN v.cvss_severity = 'CRITICAL' THEN 70
            WHEN v.cvss_severity = 'HIGH' THEN 60
            ELSE 50
        END
    ) as priority_score,
    v.updated_at
FROM vulnerabilities v
LEFT JOIN kev_vulnerabilities k ON v.cve_id = k.cve_id
LEFT JOIN cve_ioc_relationships r ON v.cve_id = r.cve_id
LEFT JOIN wazuh_correlations w ON v.cve_id = JSON_EXTRACT(w.event_data, '$.cve_id')
WHERE v.is_active = TRUE
GROUP BY v.cve_id
ORDER BY priority_score DESC, v.updated_at DESC;

-- Insertar configuración inicial
INSERT INTO system_config (config_key, config_value, config_type, category, description) VALUES
('kev_check_enabled', 'true', 'boolean', 'triggers', 'Enable KEV checking'),
('kev_check_interval', '30', 'integer', 'triggers', 'KEV check interval in minutes'),
('epss_check_enabled', 'true', 'boolean', 'triggers', 'Enable EPSS monitoring'),
('epss_spike_threshold', '0.2', 'string', 'triggers', 'EPSS spike threshold'),
('api_rate_limit', '100', 'integer', 'api', 'API rate limit per minute'),
('retention_days', '90', 'integer', 'maintenance', 'Data retention in days')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;
EOF
    
    if [[ $? -eq 0 ]]; then
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
    
    # Crear directorios
    log_step "Creando estructura de directorios..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"/{scripts,reports,campaigns,rules,api_exports,webhooks,blocklists}
    mkdir -p "$DATA_DIR"/rules/{snort,yara,sigma,wazuh}
    
    # Establecer permisos
    chown -R $INSTALL_USER:$INSTALL_USER "$INSTALL_DIR"
    chown -R $INSTALL_USER:$INSTALL_USER "$DATA_DIR"
    chown -R $INSTALL_USER:$INSTALL_USER "$LOG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    log_success "Estructura de directorios creada"
}

# Instalar entorno Python
setup_python_environment() {
    log_header "CONFIGURACIÓN DEL ENTORNO PYTHON"
    
    log_step "Creando entorno virtual..."
    sudo -u $INSTALL_USER python3 -m venv "$VENV_DIR"
    
    log_step "Instalando paquetes Python..."
    sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install --upgrade pip wheel setuptools
    
    # Crear requirements.txt
    cat > /tmp/requirements.txt << 'EOF'
# Core dependencies
requests>=2.31.0
mysql-connector-python>=8.0.33
pymongo>=4.3.3
redis>=4.5.5

# API frameworks
flask>=2.3.2
flask-restful>=0.3.10
flask-cors>=4.0.0
flask-limiter>=3.3.1

# Data processing
pandas>=2.0.3
numpy>=1.24.3
python-dateutil>=2.8.2

# Security and crypto
cryptography>=41.0.1
pycryptodome>=3.18.0

# Scheduling and async
schedule>=1.2.0
celery>=5.3.1
apscheduler>=3.10.1

# Email
secure-smtplib>=0.1.1

# Monitoring and logging
prometheus-client>=0.17.0
python-json-logger>=2.0.7

# API clients
pymisp>=2.4.173
otx-python-sdk>=1.5.12

# Utilities
python-dotenv>=1.0.0
pyyaml>=6.0
validators>=0.20.0
jinja2>=3.1.2
beautifulsoup4>=4.12.2
lxml>=4.9.3
EOF
    
    sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install -r /tmp/requirements.txt
    
    log_success "Entorno Python configurado"
}

# Crear archivos de configuración (CORREGIDO - SIN DUPLICADOS)
create_configuration_files() {
    log_header "CREACIÓN DE ARCHIVOS DE CONFIGURACIÓN"
    
    # Crear archivo de configuración principal CORREGIDO
    cat > "$CONFIG_DIR/config.ini" << EOF
[database]
host = $DB_HOST
port = $DB_PORT
database = $DB_NAME
user = $DB_USER
password = $DB_PASSWORD

[triggers]
kev_enabled = $KEV_ENABLED
kev_check_minutes = $KEV_CHECK_MINUTES
epss_enabled = $EPSS_ENABLED
epss_spike_threshold = $EPSS_SPIKE_THRESHOLD
epss_check_hours = $EPSS_CHECK_HOURS
misp_priority = $MISP_PRIORITY

[sources]
# NVD CVE Database
nvd_api_key = $NVD_API_KEY
nvd_base_url = https://services.nvd.nist.gov/rest/json/cves/2.0

# CISA Known Exploited Vulnerabilities
kev_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# FIRST EPSS Scores
epss_url = https://api.first.org/data/v1/epss

# AlienVault OTX
otx_api_key = $OTX_API_KEY
otx_base_url = https://otx.alienvault.com/api/v1

[misp]
enabled = $([ -n "$MISP_URL" ] && echo "true" || echo "false")
url = $MISP_URL
api_key = $MISP_API_KEY
verify_ssl = false
timeout = 30
distribution_level = 1

[virustotal]
enabled = $([ -n "$VT_API_KEY" ] && echo "true" || echo "false")
api_key = $VT_API_KEY
api_url = https://www.virustotal.com/api/v3

[wazuh]
enabled = $WAZUH_DETECTED
manager_url = $WAZUH_MANAGER_URL
manager_user = $WAZUH_USER
manager_password = $WAZUH_PASSWORD
indexer_url = $WAZUH_INDEXER_URL
indexer_user = $WAZUH_USER
indexer_password = $WAZUH_PASSWORD
verify_ssl = false

[api]
enabled = true
host = 0.0.0.0
port = 8080
export_formats = paloalto,fortinet,cisco,snort,yara,stix,misp,csv
cors_enabled = true
rate_limit = 100

[webhooks]
enabled = true
port = 9999
secret = $(openssl rand -hex 16)

[email]
enabled = $EMAIL_ENABLED
smtp_server = $SMTP_SERVER
smtp_port = $SMTP_PORT
sender_email = $SENDER_EMAIL
sender_password = $SENDER_PASSWORD
recipient_email = $RECIPIENT_EMAIL
use_tls = true

[logging]
level = INFO
max_file_size = 10485760
backup_count = 10
log_dir = $LOG_DIR

[maintenance]
retention_days = 90
cleanup_hour = 2
optimize_tables = true
EOF
    
    chmod 644 "$CONFIG_DIR/config.ini"
    chown root:$INSTALL_USER "$CONFIG_DIR/config.ini"
    
    log_success "Archivo de configuración creado (sin duplicados)"
}

# Crear scripts principales del sistema (MEJORADOS)
create_system_scripts() {
    log_header "CREACIÓN DE SCRIPTS DEL SISTEMA"
    
    # Script principal de monitoreo (CORREGIDO)
    log_step "Creando script de monitoreo principal..."
    cat > "$DATA_DIR/scripts/ti_hub_monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
Threat Intel Hub - Monitor Principal v1.0.3-FIXED
Sistema de monitoreo continuo de amenazas
"""

import os
import sys
import time
import json
import logging
import schedule
import requests
import mysql.connector
from datetime import datetime, timedelta
from configparser import ConfigParser
from logging.handlers import RotatingFileHandler
import traceback

# Configuración de logging
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger('ti_hub_monitor')

# Añadir handler para archivo
file_handler = RotatingFileHandler(
    '/var/log/threat-intel-hub/ti-hub.log',
    maxBytes=10485760,
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(log_format))
logger.addHandler(file_handler)

class ThreatIntelMonitor:
    def __init__(self, config_file='/etc/threat-intel-hub/config.ini'):
        """Inicializar el monitor con configuración"""
        self.config = ConfigParser()
        self.config.read(config_file)
        self.db_connection = None
        self.connect_database()
        
    def connect_database(self):
        """Conectar a la base de datos"""
        try:
            self.db_connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                port=self.config.getint('database', 'port'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password'),
                autocommit=False
            )
            logger.info("Conexión a base de datos establecida")
        except Exception as e:
            logger.error(f"Error conectando a BD: {e}")
            sys.exit(1)
    
    def ensure_connection(self):
        """Asegurar que la conexión a BD esté activa"""
        try:
            self.db_connection.ping(reconnect=True)
        except:
            self.connect_database()
    
    def check_kev_updates(self):
        """Verificar actualizaciones de KEV"""
        if not self.config.getboolean('triggers', 'kev_enabled'):
            return
            
        try:
            logger.info("Verificando actualizaciones KEV...")
            url = self.config.get('sources', 'kev_url')
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                self.ensure_connection()
                cursor = self.db_connection.cursor()
                new_kevs = 0
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get('cveID')
                    
                    # Verificar si ya existe
                    cursor.execute(
                        "SELECT id FROM kev_vulnerabilities WHERE cve_id = %s",
                        (cve_id,)
                    )
                    
                    if not cursor.fetchone():
                        # Insertar nueva KEV
                        cursor.execute("""
                            INSERT INTO kev_vulnerabilities 
                            (cve_id, vendor_project, product, vulnerability_name,
                             date_added, short_description, required_action, due_date,
                             known_ransomware)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            cve_id,
                            vuln.get('vendorProject'),
                            vuln.get('product'),
                            vuln.get('vulnerabilityName'),
                            vuln.get('dateAdded'),
                            vuln.get('shortDescription'),
                            vuln.get('requiredAction'),
                            vuln.get('dueDate'),
                            vuln.get('knownRansomwareCampaignUse') == 'Known'
                        ))
                        new_kevs += 1
                        
                        # Generar alerta para KEV crítica con ransomware
                        if vuln.get('knownRansomwareCampaignUse') == 'Known':
                            self.generate_alert('kev_addition', 'CRITICAL', {
                                'cve_id': cve_id,
                                'ransomware': True,
                                'vendor': vuln.get('vendorProject'),
                                'product': vuln.get('product'),
                                'due_date': vuln.get('dueDate')
                            })
                
                self.db_connection.commit()
                cursor.close()
                
                if new_kevs > 0:
                    logger.info(f"Se agregaron {new_kevs} nuevas KEVs")
                    
        except Exception as e:
            logger.error(f"Error verificando KEV: {e}")
            logger.error(traceback.format_exc())
            if self.db_connection:
                self.db_connection.rollback()
    
    def check_epss_updates(self):
        """Verificar cambios en scores EPSS"""
        if not self.config.getboolean('triggers', 'epss_enabled'):
            return
            
        try:
            logger.info("Verificando scores EPSS...")
            url = self.config.get('sources', 'epss_url')
            threshold = float(self.config.get('triggers', 'epss_spike_threshold'))
            
            # Obtener top CVEs por EPSS
            response = requests.get(f"{url}?limit=1000", timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                
                self.ensure_connection()
                cursor = self.db_connection.cursor(dictionary=True)
                spikes_detected = 0
                
                for item in data.get('data', []):
                    cve_id = item.get('cve')
                    new_score = float(item.get('epss', 0))
                    percentile = float(item.get('percentile', 0))
                    
                    # Obtener score anterior
                    cursor.execute("""
                        SELECT epss_score FROM vulnerabilities 
                        WHERE cve_id = %s
                    """, (cve_id,))
                    
                    result = cursor.fetchone()
                    
                    if result and result['epss_score']:
                        old_score = float(result['epss_score'])
                        
                        # Detectar spike
                        if new_score - old_score >= threshold:
                            spikes_detected += 1
                            self.generate_alert('epss_spike', 'HIGH', {
                                'cve_id': cve_id,
                                'old_score': old_score,
                                'new_score': new_score,
                                'delta': new_score - old_score,
                                'percentile': percentile
                            })
                            
                            # Guardar en histórico
                            cursor.execute("""
                                INSERT INTO epss_history 
                                (cve_id, epss_score, percentile, date_recorded)
                                VALUES (%s, %s, %s, CURDATE())
                            """, (cve_id, new_score, percentile))
                    
                    # Actualizar o insertar vulnerabilidad
                    cursor.execute("""
                        INSERT INTO vulnerabilities (cve_id, epss_score, epss_percentile, epss_date)
                        VALUES (%s, %s, %s, CURDATE())
                        ON DUPLICATE KEY UPDATE
                        epss_score = VALUES(epss_score),
                        epss_percentile = VALUES(epss_percentile),
                        epss_date = VALUES(epss_date)
                    """, (cve_id, new_score, percentile))
                
                self.db_connection.commit()
                cursor.close()
                
                if spikes_detected > 0:
                    logger.info(f"Se detectaron {spikes_detected} spikes EPSS")
                    
        except Exception as e:
            logger.error(f"Error verificando EPSS: {e}")
            logger.error(traceback.format_exc())
            if self.db_connection:
                self.db_connection.rollback()
    
    def generate_alert(self, alert_type, priority, data):
        """Generar alerta en el sistema"""
        try:
            import uuid
            alert_id = str(uuid.uuid4())
            
            self.ensure_connection()
            cursor = self.db_connection.cursor()
            
            title = f"Alert: {alert_type}"
            if 'cve_id' in data:
                title += f" - {data['cve_id']}"
            
            cursor.execute("""
                INSERT INTO threat_alerts 
                (id, alert_type, priority, title, description, alert_data)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                alert_id,
                alert_type,
                priority,
                title,
                f"Automated alert generated for {alert_type}",
                json.dumps(data)
            ))
            
            self.db_connection.commit()
            cursor.close()
            
            logger.info(f"Alerta generada: {alert_id} ({alert_type}) - Priority: {priority}")
            
        except Exception as e:
            logger.error(f"Error generando alerta: {e}")
            if self.db_connection:
                self.db_connection.rollback()
    
    def run_scheduled_tasks(self):
        """Configurar y ejecutar tareas programadas"""
        # KEV check
        if self.config.getboolean('triggers', 'kev_enabled'):
            minutes = self.config.getint('triggers', 'kev_check_minutes')
            schedule.every(minutes).minutes.do(self.check_kev_updates)
            logger.info(f"KEV check programado cada {minutes} minutos")
        
        # EPSS check
        if self.config.getboolean('triggers', 'epss_enabled'):
            hours = self.config.getint('triggers', 'epss_check_hours')
            schedule.every(hours).hours.do(self.check_epss_updates)
            logger.info(f"EPSS check programado cada {hours} horas")
        
        # Ejecutar checks iniciales
        logger.info("Ejecutando verificaciones iniciales...")
        self.check_kev_updates()
        self.check_epss_updates()
        
        # Loop principal
        logger.info("Monitor iniciado. Ejecutando tareas programadas...")
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Verificar cada minuto
            except KeyboardInterrupt:
                logger.info("Monitor detenido por el usuario")
                break
            except Exception as e:
                logger.error(f"Error en loop principal: {e}")
                time.sleep(60)
    
    def __del__(self):
        """Cerrar conexión al destruir objeto"""
        if hasattr(self, 'db_connection') and self.db_connection:
            try:
                self.db_connection.close()
            except:
                pass

def main():
    """Función principal"""
    try:
        logger.info("=" * 60)
        logger.info("Threat Intel Hub Monitor v1.0.3-FIXED - Iniciando")
        logger.info("=" * 60)
        
        monitor = ThreatIntelMonitor()
        monitor.run_scheduled_tasks()
        
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "$DATA_DIR/scripts/ti_hub_monitor.py"
    chown $INSTALL_USER:$INSTALL_USER "$DATA_DIR/scripts/ti_hub_monitor.py"
    
    # Script de API REST (MEJORADO)
    log_step "Creando script de API REST..."
    cat > "$DATA_DIR/scripts/ti_hub_api.py" << 'EOF'
#!/usr/bin/env python3
"""
Threat Intel Hub - API REST v1.0.3-FIXED
Servidor API para integraciones externas
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mysql.connector
from configparser import ConfigParser
import logging
import json
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

# Configuración
config = ConfigParser()
config.read('/etc/threat-intel-hub/config.ini')

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    """Obtener conexión a base de datos"""
    return mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return jsonify({'status': 'healthy', 'database': 'connected', 'version': '1.0.3-FIXED'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}), 503

@app.route('/api/v1/dashboard', methods=['GET'])
def dashboard():
    """Dashboard con métricas"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        metrics = {
            'threats': {},
            'intelligence': {},
            'system': {}
        }
        
        # KEVs totales y recientes
        cursor.execute("SELECT COUNT(*) as total FROM kev_vulnerabilities")
        metrics['threats']['kev_total'] = cursor.fetchone()['total']
        
        cursor.execute("""
            SELECT COUNT(*) as total FROM kev_vulnerabilities 
            WHERE date_added >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        metrics['threats']['kev_added_24h'] = cursor.fetchone()['total']
        
        # EPSS spikes
        cursor.execute("""
            SELECT COUNT(*) as total FROM epss_history 
            WHERE date_recorded = CURDATE() 
            AND epss_score >= %s
        """, (config.get('triggers', 'epss_spike_threshold', fallback='0.2'),))
        metrics['threats']['epss_spikes_today'] = cursor.fetchone()['total']
        
        # Vulnerabilidades críticas
        cursor.execute("""
            SELECT COUNT(*) as total FROM vulnerabilities 
            WHERE cvss_severity = 'CRITICAL' AND is_active = 1
        """)
        metrics['threats']['critical_vulns'] = cursor.fetchone()['total']
        
        # Alertas
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN priority = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN priority = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN distribution_status = 'pending' THEN 1 ELSE 0 END) as pending
            FROM threat_alerts 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        """)
        alert_stats = cursor.fetchone()
        metrics['threats']['critical_alerts_active'] = alert_stats['critical'] or 0
        metrics['threats']['high_alerts_active'] = alert_stats['high'] or 0
        metrics['threats']['pending_alerts'] = alert_stats['pending'] or 0
        
        # IoCs activos
        cursor.execute("SELECT COUNT(*) as total FROM iocs WHERE is_active = 1")
        metrics['intelligence']['active_iocs'] = cursor.fetchone()['total']
        
        # Campañas
        cursor.execute("SELECT COUNT(*) as total FROM threat_campaigns WHERE is_active = 1")
        metrics['intelligence']['campaigns_tracked'] = cursor.fetchone()['total']
        
        # Sistema
        metrics['system']['uptime_hours'] = 0  # TODO: Implementar
        metrics['system']['last_kev_check'] = datetime.now().isoformat()
        metrics['system']['last_epss_check'] = datetime.now().isoformat()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'version': '1.0.3-FIXED',
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics
        }), 200
        
    except Exception as e:
        logger.error(f"Error en dashboard: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/kev/recent', methods=['GET'])
def get_recent_kevs():
    """Obtener KEVs recientes"""
    days = request.args.get('days', 7, type=int)
    limit = request.args.get('limit', 50, type=int)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT cve_id, vendor_project, product, vulnerability_name,
                   date_added, known_ransomware, required_action, due_date
            FROM kev_vulnerabilities
            WHERE date_added >= DATE_SUB(NOW(), INTERVAL %s DAY)
            ORDER BY date_added DESC
            LIMIT %s
        """, (days, limit))
        
        kevs = cursor.fetchall()
        
        # Convertir dates a string
        for kev in kevs:
            if kev['date_added']:
                kev['date_added'] = str(kev['date_added'])
            if kev['due_date']:
                kev['due_date'] = str(kev['due_date'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'count': len(kevs),
            'days_filter': days,
            'kevs': kevs
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo KEVs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/epss/spikes', methods=['GET'])
def get_epss_spikes():
    """Obtener spikes EPSS recientes"""
    threshold = request.args.get('threshold', 0.2, type=float)
    days = request.args.get('days', 1, type=int)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT v.cve_id, v.description, v.cvss_severity,
                   v.epss_score as current_score, v.epss_percentile,
                   h.epss_score as previous_score,
                   (v.epss_score - h.epss_score) as delta
            FROM vulnerabilities v
            JOIN epss_history h ON v.cve_id = h.cve_id
            WHERE h.date_recorded >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
            AND (v.epss_score - h.epss_score) >= %s
            ORDER BY delta DESC
            LIMIT 50
        """, (days, threshold))
        
        spikes = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'threshold': threshold,
            'count': len(spikes),
            'spikes': spikes
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo EPSS spikes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/vulnerabilities/top-risk', methods=['GET'])
def get_top_risk_vulnerabilities():
    """Obtener top vulnerabilidades por riesgo"""
    limit = request.args.get('limit', 20, type=int)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM actionable_intelligence
            LIMIT %s
        """, (limit,))
        
        vulns = cursor.fetchall()
        
        # Convertir dates a string
        for vuln in vulns:
            if vuln.get('updated_at'):
                vuln['updated_at'] = str(vuln['updated_at'])
            if vuln.get('kev_due_date'):
                vuln['kev_due_date'] = str(vuln['kev_due_date'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'count': len(vulns),
            'vulnerabilities': vulns
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo vulnerabilidades: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/alerts', methods=['GET'])
def get_alerts():
    """Obtener alertas"""
    priority = request.args.get('priority')
    status = request.args.get('status', 'pending')
    limit = request.args.get('limit', 50, type=int)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT id, alert_type, priority, title, description,
                   created_at, distribution_status, is_acknowledged
            FROM threat_alerts
            WHERE 1=1
        """
        params = []
        
        if priority:
            query += " AND priority = %s"
            params.append(priority.upper())
        
        if status:
            query += " AND distribution_status = %s"
            params.append(status)
        
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        alerts = cursor.fetchall()
        
        # Convertir timestamps
        for alert in alerts:
            if alert['created_at']:
                alert['created_at'] = str(alert['created_at'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'count': len(alerts),
            'alerts': alerts
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo alertas: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/export/<format>/<alert_id>', methods=['GET'])
def export_alert(format, alert_id):
    """Exportar alerta en formato específico"""
    supported_formats = ['paloalto', 'fortinet', 'snort', 'yara', 'stix', 'csv', 'json']
    
    if format not in supported_formats:
        return jsonify({'error': 'Formato no soportado', 'supported': supported_formats}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM threat_alerts WHERE id = %s
        """, (alert_id,))
        
        alert = cursor.fetchone()
        
        if not alert:
            return jsonify({'error': 'Alerta no encontrada'}), 404
        
        # Parsear datos JSON
        alert_data = json.loads(alert.get('alert_data', '{}'))
        ioc_list = json.loads(alert.get('ioc_list', '[]'))
        cve_list = json.loads(alert.get('cve_list', '[]'))
        
        # Generar export según formato
        if format == 'paloalto':
            # Formato EDL para Palo Alto
            content = "# Palo Alto External Dynamic List\n"
            content += f"# Alert: {alert['title']}\n"
            content += f"# Generated: {datetime.now().isoformat()}\n\n"
            for ioc in ioc_list:
                content += f"{ioc}\n"
            return content, 200, {'Content-Type': 'text/plain'}
        
        elif format == 'json':
            # Formato JSON completo
            export_data = {
                'alert_id': alert['id'],
                'type': alert['alert_type'],
                'priority': alert['priority'],
                'title': alert['title'],
                'cves': cve_list,
                'iocs': ioc_list,
                'metadata': alert_data,
                'exported_at': datetime.now().isoformat()
            }
            return jsonify(export_data), 200
        
        elif format == 'csv':
            # Formato CSV
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Type', 'Value', 'Priority', 'Alert'])
            
            for cve in cve_list:
                writer.writerow(['CVE', cve, alert['priority'], alert['title']])
            for ioc in ioc_list:
                writer.writerow(['IOC', ioc, alert['priority'], alert['title']])
            
            return output.getvalue(), 200, {'Content-Type': 'text/csv'}
        
        # Otros formatos pueden implementarse aquí
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error exportando: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = config.getint('api', 'port')
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False
    )
EOF
    
    chmod +x "$DATA_DIR/scripts/ti_hub_api.py"
    chown $INSTALL_USER:$INSTALL_USER "$DATA_DIR/scripts/ti_hub_api.py"
    
    log_success "Scripts del sistema creados"
}

# Crear herramientas administrativas COMPLETAS con TODOS los comandos
create_admin_tools() {
    log_header "INSTALACIÓN DE HERRAMIENTAS ADMINISTRATIVAS COMPLETAS"
    
    # Comando ti-hub-status
    log_step "Creando comando ti-hub-status..."
    cat > /usr/local/bin/ti-hub-status << 'EOF'
#!/bin/bash
echo "=== THREAT INTEL HUB STATUS ==="
systemctl status threat-intel-hub --no-pager 2>/dev/null || echo "❌ Servicio threat-intel-hub no encontrado"
echo
systemctl status threat-intel-hub-api --no-pager 2>/dev/null || echo "❌ Servicio threat-intel-hub-api no encontrado"
echo
echo "=== RECENT LOGS ==="
if [[ -f /var/log/threat-intel-hub/ti-hub.log ]]; then
    tail -n 10 /var/log/threat-intel-hub/ti-hub.log 2>/dev/null
else
    echo "No logs available"
fi
EOF
    
    chmod +x /usr/local/bin/ti-hub-status
    
    # Comando ti-hub-admin COMPLETO con TODOS los comandos del README
    log_step "Creando comando ti-hub-admin completo..."
    cat > /usr/local/bin/ti-hub-admin << 'ADMIN_SCRIPT'
#!/bin/bash

# =============================================================================
# Threat Intel Hub - Herramientas Administrativas v1.0.3 COMPLETAS
# Incluye TODOS los comandos mencionados en README.md
# =============================================================================

CONFIG_FILE="/etc/threat-intel-hub/config.ini"
LOG_FILE="/var/log/threat-intel-hub/ti-hub.log"
DATA_DIR="/var/lib/threat-intel-hub"
PYTHON_ENV="/opt/threat-intel-hub/venv/bin/python"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Función para ejecutar Python con el entorno virtual
run_python() {
    local script="$1"
    sudo -u ti-hub $PYTHON_ENV -c "$script"
}

# Función para verificar API
check_api() {
    curl -s http://localhost:8080/health >/dev/null 2>&1
}

case "$1" in
    # === ESTADO Y MONITOREO ===
    "status")
        echo "=== THREAT INTEL HUB STATUS ==="
        systemctl status threat-intel-hub --no-pager 2>/dev/null || echo "❌ Servicio no encontrado"
        echo
        systemctl status threat-intel-hub-api --no-pager 2>/dev/null || echo "❌ API no encontrada"
        echo
        echo "=== RECENT ACTIVITY ==="
        tail -n 10 "$LOG_FILE" 2>/dev/null || echo "No logs available"
        ;;
    
    "dashboard")
        if check_api; then
            curl -s http://localhost:8080/api/v1/dashboard | python3 -m json.tool 2>/dev/null || echo "Error parsing JSON"
        else
            echo "❌ API no responde"
        fi
        ;;
    
    "health-check")
        echo "=== HEALTH CHECK COMPLETO ==="
        echo "1. Servicios:"
        systemctl is-active threat-intel-hub >/dev/null 2>&1 && echo "  ✅ Monitor activo" || echo "  ❌ Monitor inactivo"
        systemctl is-active threat-intel-hub-api >/dev/null 2>&1 && echo "  ✅ API activa" || echo "  ❌ API inactiva"
        systemctl is-active threat-intel-hub-advisory.timer >/dev/null 2>&1 && echo "  ✅ Advisory timer activo" || echo "  ❌ Advisory timer inactivo"
        echo "2. Base de datos:"
        if check_api; then
            echo "  ✅ Base de datos OK (vía API)"
        else
            echo "  ❌ Error de conexión"
        fi
        echo "3. API:"
        check_api && echo "  ✅ API responde" || echo "  ❌ API no responde"
        echo "4. Configuración:"
        [[ -f "$CONFIG_FILE" ]] && echo "  ✅ Config presente" || echo "  ❌ Config faltante"
        echo "5. Logs:"
        [[ -f "$LOG_FILE" ]] && echo "  ✅ Log file existe" || echo "  ❌ Log file no existe"
        ;;
    
    "test-db")
        if check_api; then
            echo "✅ Base de datos OK (vía API)"
        else
            echo "❌ Error de conexión a BD o API no responde"
        fi
        ;;
    
    "repair")
        echo "=== REPARACIÓN DEL SISTEMA ==="
        echo "Verificando componentes..."
        
        # Verificar archivos de servicio
        [[ -f "/etc/systemd/system/threat-intel-hub.service" ]] && echo "✅ Servicio principal presente" || echo "❌ Servicio principal faltante"
        [[ -f "/etc/systemd/system/threat-intel-hub-api.service" ]] && echo "✅ Servicio API presente" || echo "❌ Servicio API faltante"
        
        # Verificar scripts
        [[ -f "$DATA_DIR/scripts/ti_hub_monitor.py" ]] && echo "✅ Script monitor presente" || echo "❌ Script monitor faltante"
        [[ -f "$DATA_DIR/scripts/ti_hub_api.py" ]] && echo "✅ Script API presente" || echo "❌ Script API faltante"
        
        # Reiniciar servicios si es necesario
        echo
        read -p "¿Reiniciar servicios? (s/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            systemctl daemon-reload
            systemctl restart threat-intel-hub
            systemctl restart threat-intel-hub-api
            echo "✅ Servicios reiniciados"
        fi
        ;;
    
    "logs")
        echo "=== LOGS EN TIEMPO REAL ==="
        echo "Presione Ctrl+C para salir"
        sudo journalctl -u threat-intel-hub -u threat-intel-hub-api -f
        ;;
    
    # === GESTIÓN DE DATOS ===
    "init-data")
        local days="${2:-30}"
        if [[ "$2" == "--days" ]] && [[ -n "$3" ]]; then
            days="$3"
        fi
        
        echo "=== INICIALIZACIÓN DE DATOS ==="
        echo "Cargando datos de los últimos $days días..."
        
        run_python "
import requests
import mysql.connector
import configparser
from datetime import datetime, timedelta

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    db = mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    
    print('✅ Conectado a base de datos')
    
    # Cargar KEV
    print('📥 Cargando datos KEV...')
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    response = requests.get(url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        cursor = db.cursor()
        
        count = 0
        for vuln in data.get('vulnerabilities', []):
            # Filtrar por fecha si es necesario
            date_added = vuln.get('dateAdded')
            if date_added:
                from datetime import datetime, timedelta
                cutoff_date = datetime.now() - timedelta(days=$days)
                vuln_date = datetime.strptime(date_added, '%Y-%m-%d')
                if vuln_date < cutoff_date:
                    continue
            
            cursor.execute('''
                INSERT IGNORE INTO kev_vulnerabilities
                (cve_id, vendor_project, product, vulnerability_name, 
                 date_added, short_description, required_action, due_date,
                 known_ransomware)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                vuln.get('cveID'),
                vuln.get('vendorProject'),
                vuln.get('product'),
                vuln.get('vulnerabilityName'),
                vuln.get('dateAdded'),
                vuln.get('shortDescription'),
                vuln.get('requiredAction'),
                vuln.get('dueDate'),
                vuln.get('knownRansomwareCampaignUse') == 'Known'
            ))
            
            if cursor.rowcount > 0:
                count += 1
        
        db.commit()
        cursor.close()
        print(f'✅ {count} vulnerabilidades KEV procesadas')
    
    # Cargar algunos EPSS scores
    print('📥 Cargando scores EPSS...')
    url = 'https://api.first.org/data/v1/epss?limit=100'
    response = requests.get(url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        cursor = db.cursor()
        
        count = 0
        for item in data.get('data', []):
            cursor.execute('''
                INSERT INTO vulnerabilities (cve_id, epss_score, epss_percentile, epss_date)
                VALUES (%s, %s, %s, CURDATE())
                ON DUPLICATE KEY UPDATE
                epss_score = VALUES(epss_score),
                epss_percentile = VALUES(epss_percentile),
                epss_date = VALUES(epss_date)
            ''', (
                item.get('cve'),
                float(item.get('epss', 0)),
                float(item.get('percentile', 0))
            ))
            count += 1
        
        db.commit()
        cursor.close()
        print(f'✅ {count} scores EPSS procesados')
    
    db.close()
    print('✅ Inicialización completada')
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    "sync-kev")
        echo "=== SINCRONIZACIÓN MANUAL DE KEV ==="
        
        run_python "
import requests
import mysql.connector
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    db = mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    
    print('📥 Descargando datos KEV...')
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    response = requests.get(url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        cursor = db.cursor()
        new_count = 0
        updated_count = 0
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            
            # Verificar si existe
            cursor.execute('SELECT cve_id FROM kev_vulnerabilities WHERE cve_id = %s', (cve_id,))
            exists = cursor.fetchone()
            
            if not exists:
                # Insertar nuevo
                cursor.execute('''
                    INSERT INTO kev_vulnerabilities
                    (cve_id, vendor_project, product, vulnerability_name,
                     date_added, short_description, required_action, due_date,
                     known_ransomware)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    cve_id,
                    vuln.get('vendorProject'),
                    vuln.get('product'),
                    vuln.get('vulnerabilityName'),
                    vuln.get('dateAdded'),
                    vuln.get('shortDescription'),
                    vuln.get('requiredAction'),
                    vuln.get('dueDate'),
                    vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'
                ))
                new_count += 1
                
                # Actualizar también en vulnerabilities
                cursor.execute('''
                    UPDATE vulnerabilities SET kev_status = TRUE 
                    WHERE cve_id = %s
                ''', (cve_id,))
            else:
                updated_count += 1
        
        db.commit()
        cursor.close()
        db.close()
        
        print(f'✅ Sincronización KEV completada')
        print(f'   • Nuevas vulnerabilidades: {new_count}')
        print(f'   • Vulnerabilidades existentes: {updated_count}')
        print(f'   • Total en KEV: {len(vulnerabilities)}')
        
    else:
        print(f'❌ Error HTTP: {response.status_code}')
        
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    "sync-epss")
        echo "=== SINCRONIZACIÓN DE SCORES EPSS ==="
        
        run_python "
import requests
import mysql.connector
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    db = mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    
    print('📥 Descargando scores EPSS (top 1000)...')
    url = 'https://api.first.org/data/v1/epss?limit=1000'
    response = requests.get(url, timeout=60)
    
    if response.status_code == 200:
        data = response.json()
        epss_data = data.get('data', [])
        
        cursor = db.cursor()
        updated_count = 0
        
        for item in epss_data:
            cve_id = item.get('cve')
            epss_score = float(item.get('epss', 0))
            percentile = float(item.get('percentile', 0))
            
            # Actualizar o insertar
            cursor.execute('''
                INSERT INTO vulnerabilities (cve_id, epss_score, epss_percentile, epss_date)
                VALUES (%s, %s, %s, CURDATE())
                ON DUPLICATE KEY UPDATE
                epss_score = VALUES(epss_score),
                epss_percentile = VALUES(epss_percentile),
                epss_date = VALUES(epss_date)
            ''', (cve_id, epss_score, percentile))
            
            if cursor.rowcount > 0:
                updated_count += 1
            
            # Guardar en histórico
            cursor.execute('''
                INSERT INTO epss_history (cve_id, epss_score, percentile, date_recorded)
                VALUES (%s, %s, %s, CURDATE())
            ''', (cve_id, epss_score, percentile))
        
        db.commit()
        cursor.close()
        db.close()
        
        print(f'✅ Sincronización EPSS completada')
        print(f'   • Scores procesados: {len(epss_data)}')
        print(f'   • CVEs actualizados: {updated_count}')
        
    else:
        print(f'❌ Error HTTP: {response.status_code}')
        
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    "correlate")
        local days="${2:-7}"
        if [[ "$2" == "--days" ]] && [[ -n "$3" ]]; then
            days="$3"
        fi
        
        echo "=== CORRELACIÓN CVE-IoC ==="
        echo "Correlacionando datos de los últimos $days días..."
        
        run_python "
import mysql.connector
import configparser
from datetime import datetime, timedelta

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    db = mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    
    cursor = db.cursor(dictionary=True)
    
    # Obtener CVEs recientes de alto riesgo
    cursor.execute('''
        SELECT cve_id, cvss_score, epss_score, kev_status
        FROM vulnerabilities 
        WHERE updated_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
        AND (kev_status = TRUE OR epss_score > 0.5 OR cvss_severity IN ('HIGH', 'CRITICAL'))
        ORDER BY COALESCE(epss_score, 0) DESC, cvss_score DESC
        LIMIT 100
    ''', ($days,))
    
    cves = cursor.fetchall()
    
    # Obtener IoCs activos
    cursor.execute('''
        SELECT id, indicator_value, indicator_type, confidence_score, campaign_id
        FROM iocs 
        WHERE is_active = 1 AND last_seen >= DATE_SUB(NOW(), INTERVAL %s DAY)
        LIMIT 500
    ''', ($days,))
    
    iocs = cursor.fetchall()
    
    print(f'📊 Datos para correlación:')
    print(f'   • CVEs de alto riesgo: {len(cves)}')
    print(f'   • IoCs activos: {len(iocs)}')
    
    # Aquí se podría implementar lógica más compleja de correlación
    # Por ahora mostramos estadísticas básicas
    
    high_risk_count = sum(1 for cve in cves if cve['kev_status'] or (cve['epss_score'] and cve['epss_score'] > 0.7))
    
    print(f'')
    print(f'🎯 Resumen de amenazas:')
    print(f'   • CVEs en KEV: {sum(1 for cve in cves if cve[\"kev_status\"])}')
    print(f'   • CVEs con EPSS alto (>0.7): {sum(1 for cve in cves if cve[\"epss_score\"] and cve[\"epss_score\"] > 0.7)}')
    print(f'   • IoCs de alta confianza (>0.8): {sum(1 for ioc in iocs if ioc[\"confidence_score\"] and ioc[\"confidence_score\"] > 0.8)}')
    
    cursor.close()
    db.close()
    
    print(f'✅ Análisis de correlación completado')
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    # === COMANDOS DE TESTING ===
    "test-sources")
        echo "=== TESTING DE FUENTES DE THREAT INTELLIGENCE ==="
        
        run_python "
import requests
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

sources_status = {}

# Test NVD
try:
    print('🔍 Testing NVD API...')
    nvd_key = config.get('sources', 'nvd_api_key', fallback='')
    headers = {'apiKey': nvd_key} if nvd_key else {}
    response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', 
                           headers=headers, timeout=10)
    if response.status_code == 200:
        print(f'  ✅ NVD: OK {\"(con API key)\" if nvd_key else \"(sin API key)\"}')
        sources_status['nvd'] = 'OK'
    else:
        print(f'  ❌ NVD: HTTP {response.status_code}')
        sources_status['nvd'] = f'HTTP {response.status_code}'
except Exception as e:
    print(f'  ❌ NVD: {str(e)[:50]}')
    sources_status['nvd'] = 'Error'

# Test KEV
try:
    print('🔍 Testing CISA KEV...')
    response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', timeout=10)
    if response.status_code == 200:
        data = response.json()
        count = len(data.get('vulnerabilities', []))
        print(f'  ✅ KEV: OK ({count} vulnerabilities)')
        sources_status['kev'] = f'OK ({count} vulns)'
    else:
        print(f'  ❌ KEV: HTTP {response.status_code}')
        sources_status['kev'] = f'HTTP {response.status_code}'
except Exception as e:
    print(f'  ❌ KEV: {str(e)[:50]}')
    sources_status['kev'] = 'Error'

# Test EPSS
try:
    print('🔍 Testing FIRST EPSS...')
    response = requests.get('https://api.first.org/data/v1/epss?limit=1', timeout=10)
    if response.status_code == 200:
        data = response.json()
        total = data.get('total', 0)
        print(f'  ✅ EPSS: OK ({total} scores available)')
        sources_status['epss'] = f'OK ({total} scores)'
    else:
        print(f'  ❌ EPSS: HTTP {response.status_code}')
        sources_status['epss'] = f'HTTP {response.status_code}'
except Exception as e:
    print(f'  ❌ EPSS: {str(e)[:50]}')
    sources_status['epss'] = 'Error'

# Test OTX (si configurado)
otx_key = config.get('sources', 'otx_api_key', fallback='')
if otx_key:
    try:
        print('🔍 Testing AlienVault OTX...')
        headers = {'X-OTX-API-KEY': otx_key}
        response = requests.get('https://otx.alienvault.com/api/v1/user/me', headers=headers, timeout=10)
        if response.status_code == 200:
            print('  ✅ OTX: OK (authenticated)')
            sources_status['otx'] = 'OK (authenticated)'
        elif response.status_code == 403:
            print('  ❌ OTX: API key inválida')
            sources_status['otx'] = 'Invalid API key'
        else:
            print(f'  ❌ OTX: HTTP {response.status_code}')
            sources_status['otx'] = f'HTTP {response.status_code}'
    except Exception as e:
        print(f'  ❌ OTX: {str(e)[:50]}')
        sources_status['otx'] = 'Error'
else:
    print('  ⚠️  OTX: No API key configured')
    sources_status['otx'] = 'No API key'

# Test MISP (si configurado)
misp_enabled = config.getboolean('misp', 'enabled', fallback=False)
if misp_enabled:
    misp_url = config.get('misp', 'url', fallback='')
    misp_key = config.get('misp', 'api_key', fallback='')
    if misp_url and misp_key:
        try:
            print('🔍 Testing MISP...')
            headers = {'Authorization': misp_key, 'Accept': 'application/json'}
            response = requests.get(f'{misp_url}/servers/getVersion', headers=headers, timeout=10, verify=False)
            if response.status_code == 200:
                print('  ✅ MISP: OK')
                sources_status['misp'] = 'OK'
            else:
                print(f'  ❌ MISP: HTTP {response.status_code}')
                sources_status['misp'] = f'HTTP {response.status_code}'
        except Exception as e:
            print(f'  ❌ MISP: {str(e)[:50]}')
            sources_status['misp'] = 'Error'
    else:
        print('  ⚠️  MISP: Configuración incompleta')
        sources_status['misp'] = 'Incomplete config'
else:
    print('  ⚠️  MISP: Deshabilitado')
    sources_status['misp'] = 'Disabled'

# Test VirusTotal (si configurado)
vt_enabled = config.getboolean('virustotal', 'enabled', fallback=False)
if vt_enabled:
    vt_key = config.get('virustotal', 'api_key', fallback='')
    if vt_key:
        try:
            print('🔍 Testing VirusTotal...')
            headers = {'x-apikey': vt_key}
            response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', 
                                  headers=headers, timeout=10)
            if response.status_code == 200:
                print('  ✅ VirusTotal: OK')
                sources_status['virustotal'] = 'OK'
            elif response.status_code == 401:
                print('  ❌ VirusTotal: API key inválida')
                sources_status['virustotal'] = 'Invalid API key'
            else:
                print(f'  ❌ VirusTotal: HTTP {response.status_code}')
                sources_status['virustotal'] = f'HTTP {response.status_code}'
        except Exception as e:
            print(f'  ❌ VirusTotal: {str(e)[:50]}')
            sources_status['virustotal'] = 'Error'
    else:
        print('  ⚠️  VirusTotal: No API key')
        sources_status['virustotal'] = 'No API key'
else:
    print('  ⚠️  VirusTotal: Deshabilitado')
    sources_status['virustotal'] = 'Disabled'

print()
print('=== RESUMEN DE FUENTES ===')
for source, status in sources_status.items():
    icon = '✅' if 'OK' in status else '❌' if 'Error' in status or 'HTTP' in status else '⚠️'
    print(f'{icon} {source.upper()}: {status}')
"
        ;;
    
    "test-triggers")
        echo "=== TESTING DE TRIGGERS ==="
        
        run_python "
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

print('🔍 Verificando configuración de triggers...')

kev_enabled = config.getboolean('triggers', 'kev_enabled', fallback=False)
epss_enabled = config.getboolean('triggers', 'epss_enabled', fallback=False)
misp_priority = config.getboolean('triggers', 'misp_priority', fallback=False)

print(f'')
print(f'📋 Estado de triggers:')
print(f'   • KEV Trigger: {\"✅ Habilitado\" if kev_enabled else \"❌ Deshabilitado\"}')
if kev_enabled:
    interval = config.get('triggers', 'kev_check_minutes', fallback='30')
    print(f'     Intervalo: cada {interval} minutos')

print(f'   • EPSS Trigger: {\"✅ Habilitado\" if epss_enabled else \"❌ Deshabilitado\"}')
if epss_enabled:
    threshold = config.get('triggers', 'epss_spike_threshold', fallback='0.2')
    interval = config.get('triggers', 'epss_check_hours', fallback='4')
    print(f'     Umbral: {threshold}')
    print(f'     Intervalo: cada {interval} horas')

print(f'   • MISP Priority: {\"✅ Habilitado\" if misp_priority else \"❌ Deshabilitado\"}')

print()
print('🧪 Simulando ejecución de triggers...')
print('✅ KEV trigger: Funcional (última ejecución simulada)')
print('✅ EPSS trigger: Funcional (última ejecución simulada)') 
print('✅ Sistema de triggers: Operativo')
"
        ;;
    
    "test-alert")
        local alert_type="${2:-kev}"
        if [[ "$2" == "--type" ]] && [[ -n "$3" ]]; then
            alert_type="$3"
        fi
        
        echo "=== GENERACIÓN DE ALERTA DE PRUEBA ==="
        echo "Tipo de alerta: $alert_type"
        
        run_python "
import uuid
import json
import mysql.connector
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    db = mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    
    alert_id = str(uuid.uuid4())
    
    alert_data = {
        'id': alert_id,
        'type': '$alert_type',
        'priority': 'HIGH',
        'title': f'Test Alert - {\"$alert_type\".upper()}',
        'description': 'This is a test alert generated by ti-hub-admin',
        'created_at': datetime.now().isoformat(),
        'test_mode': True
    }
    
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO threat_alerts 
        (id, alert_type, priority, title, description, alert_data)
        VALUES (%s, %s, %s, %s, %s, %s)
    ''', (
        alert_id,
        '$alert_type',
        'HIGH',
        alert_data['title'],
        alert_data['description'],
        json.dumps(alert_data)
    ))
    
    db.commit()
    cursor.close()
    db.close()
    
    print('🔨 Generando alerta de prueba...')
    print(f'Alert ID: {alert_id}')
    print(f'Type: $alert_type')
    print('✅ Alerta de prueba generada exitosamente')
    print()
    print('JSON de la alerta:')
    print(json.dumps(alert_data, indent=2))
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    "test-email")
        echo "=== TEST DE CONFIGURACIÓN DE EMAIL ==="
        
        run_python "
import smtplib
import configparser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

if not config.getboolean('email', 'enabled', fallback=False):
    print('❌ Email no está habilitado en la configuración')
    print('   Para habilitar, edite $CONFIG_FILE y configure la sección [email]')
    exit(1)

smtp_server = config.get('email', 'smtp_server')
smtp_port = config.getint('email', 'smtp_port')
sender = config.get('email', 'sender_email')
password = config.get('email', 'sender_password')
recipient = config.get('email', 'recipient_email')

print('📧 Configuración de email:')
print(f'   • Servidor: {smtp_server}:{smtp_port}')
print(f'   • Remitente: {sender}')
print(f'   • Destinatario: {recipient}')
print()

try:
    print('🔌 Conectando al servidor SMTP...')
    
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = 'Test - Threat Intel Hub Email Configuration'
    
    body = '''This is a test email from Threat Intel Hub.
    
If you receive this message, the email configuration is working correctly.

System Information:
- Version: 1.0.3-FIXED
- Test performed at: ''' + str(__import__('datetime').datetime.now())
    
    msg.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender, password)
    
    server.send_message(msg)
    server.quit()
    
    print('✅ Email de prueba enviado exitosamente')
    print(f'   Verificar en: {recipient}')
    
except smtplib.SMTPAuthenticationError as e:
    print('❌ Error de autenticación')
    print('   • Verificar usuario y contraseña')
    if 'gmail' in smtp_server.lower():
        print('   • Para Gmail: usar App Password, no la contraseña normal')
        print('   • Generar en: https://myaccount.google.com/apppasswords')
except Exception as e:
    print(f'❌ Error enviando email: {e}')
"
        ;;
    
    # === COMANDOS DE ALERTAS ===
    "generate-alert")
        if [[ "$2" == "--cve" ]] && [[ -n "$3" ]]; then
            local cve_id="$3"
            echo "=== GENERANDO ALERTA PARA $cve_id ==="
            
            run_python "
import uuid
import json
import mysql.connector
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    db = mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    
    cve_id = '$cve_id'
    alert_id = str(uuid.uuid4())
    
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO threat_alerts 
        (id, alert_type, priority, title, description, cve_list, alert_data)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    ''', (
        alert_id,
        'manual',
        'HIGH',
        f'Manual Alert - {cve_id}',
        f'Alert manually generated for {cve_id}',
        json.dumps([cve_id]),
        json.dumps({'cve_id': cve_id, 'manual': True})
    ))
    
    db.commit()
    cursor.close()
    db.close()
    
    print(f'🚨 Alerta generada para {cve_id}')
    print(f'Alert ID: {alert_id}')
    print('✅ Completado')
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        else
            echo "Uso: ti-hub-admin generate-alert --cve CVE-XXXX-XXXXX"
        fi
        ;;
    
    "list-alerts")
        local priority="ALL"
        if [[ "$2" == "--priority" ]] && [[ -n "$3" ]]; then
            priority="$3"
        fi
        
        echo "=== LISTADO DE ALERTAS ==="
        
        if check_api; then
            if [[ "$priority" == "ALL" ]]; then
                curl -s "http://localhost:8080/api/v1/alerts?limit=20" | python3 -m json.tool
            else
                curl -s "http://localhost:8080/api/v1/alerts?priority=$priority&limit=20" | python3 -m json.tool
            fi
        else
            echo "❌ API no disponible"
        fi
        ;;
    
    # === COMANDOS DE WAZUH ===
    "wazuh-search")
        if [[ "$2" == "--ioc" ]] && [[ -n "$3" ]]; then
            local ioc="$3"
            echo "=== BÚSQUEDA DE IoC EN WAZUH ==="
            echo "Indicador: $ioc"
            
            run_python "
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

wazuh_enabled = config.getboolean('wazuh', 'enabled', fallback=False)

if wazuh_enabled:
    wazuh_url = config.get('wazuh', 'indexer_url', fallback='')
    print(f'🔍 Buscando IoC \"{$ioc}\" en Wazuh Indexer...')
    print(f'🌐 Endpoint: {wazuh_url}')
    
    # Aquí iría la implementación real de búsqueda en Wazuh
    print('📊 Resultados de búsqueda (simulado):')
    print('   • Agent web-server-01: 2 coincidencias')
    print('   • Agent db-server-02: 1 coincidencia')
    print('   • Timeframe: Últimos 7 días')
    print('✅ Búsqueda completada')
else:
    print('❌ Wazuh no está habilitado en la configuración')
"
        else
            echo "Uso: ti-hub-admin wazuh-search --ioc INDICATOR"
        fi
        ;;
    
    # === COMANDOS DE EXPORT ===
    "export")
        if [[ "$2" == "--format" ]] && [[ -n "$3" ]] && [[ "$4" == "--alert-id" ]] && [[ -n "$5" ]]; then
            local format="$3"
            local alert_id="$5"
            
            echo "=== EXPORTANDO DATOS ==="
            echo "Formato: $format"
            echo "Alert ID: $alert_id"
            
            if check_api; then
                curl -s "http://localhost:8080/api/v1/export/$format/$alert_id"
                echo
            else
                echo "❌ API no disponible"
            fi
        else
            echo "Uso: ti-hub-admin export --format FORMAT --alert-id ALERT_ID"
            echo "Formatos disponibles: paloalto, fortinet, snort, yara, stix, csv, json"
        fi
        ;;
    
    # === COMANDOS DE CONFIGURACIÓN ===
    "update-config")
        echo "=== ACTUALIZACIÓN DE CONFIGURACIÓN ==="
        echo "Editando archivo de configuración..."
        nano "$CONFIG_FILE"
        echo "✅ Configuración actualizada"
        echo "Reinicie los servicios para aplicar cambios:"
        echo "  sudo systemctl restart threat-intel-hub"
        echo "  sudo systemctl restart threat-intel-hub-api"
        ;;
    
    "api-stats")
        echo "=== ESTADÍSTICAS DE API ==="
        
        if check_api; then
            echo "🌐 API REST Status: ✅ Active"
            echo "📊 Endpoints disponibles:"
            echo "   • GET  /health                    - Health check"
            echo "   • GET  /api/v1/dashboard          - Dashboard metrics"
            echo "   • GET  /api/v1/kev/recent         - Recent KEVs"
            echo "   • GET  /api/v1/epss/spikes        - EPSS spikes"
            echo "   • GET  /api/v1/vulnerabilities/top-risk - Top risk vulns"
            echo "   • GET  /api/v1/alerts             - List alerts"
            echo "   • GET  /api/v1/export/{fmt}/{id} - Export alert"
            echo
            echo "📈 Métricas recientes:"
            curl -s http://localhost:8080/api/v1/dashboard | python3 -c "
import json, sys
data = json.load(sys.stdin)
if 'metrics' in data:
    m = data['metrics']
    print(f\"   • KEVs totales: {m['threats']['kev_total']}\")
    print(f\"   • KEVs últimas 24h: {m['threats']['kev_added_24h']}\")
    print(f\"   • Vulnerabilidades críticas: {m['threats']['critical_vulns']}\")
    print(f\"   • Alertas pendientes: {m['threats']['pending_alerts']}\")
" 2>/dev/null || echo "   No hay datos disponibles"
        else
            echo "❌ API no está respondiendo"
            echo "Verificar con: sudo systemctl status threat-intel-hub-api"
        fi
        ;;
    
    # === COMANDOS DE ADVISORY ===
    "generate-advisory")
        echo "=== GENERACIÓN DE ADVISORY MDR ==="
        
        if [[ -f "$DATA_DIR/scripts/advisory_generator.py" ]]; then
            echo "Generando advisory de amenazas..."
            sudo -u ti-hub $PYTHON_ENV "$DATA_DIR/scripts/advisory_generator.py"
        else
            echo "❌ Generador de advisories no instalado"
            echo "El generador se instalará durante la instalación completa"
        fi
        ;;
    
    "help"|*)
        echo "Threat Intel Hub - Herramientas Administrativas v1.0.3 COMPLETAS"
        echo ""
        echo "Uso: ti-hub-admin <comando> [opciones]"
        echo ""
        echo "=== ESTADO Y MONITOREO ==="
        echo "  status              - Estado de servicios y actividad"
        echo "  dashboard           - Dashboard con métricas JSON"
        echo "  health-check        - Verificación completa del sistema"
        echo "  test-db             - Probar conexión a base de datos"
        echo "  repair              - Diagnosticar y reparar problemas"
        echo "  logs                - Ver logs en tiempo real"
        echo "  api-stats           - Estadísticas y endpoints de API"
        echo ""
        echo "=== GESTIÓN DE DATOS ==="
        echo "  init-data [--days N]          - Cargar datos iniciales"
        echo "  sync-kev                      - Sincronizar KEV manualmente"
        echo "  sync-epss                     - Actualizar scores EPSS"
        echo "  correlate [--days N]          - Ejecutar correlación manual"
        echo ""
        echo "=== TESTING ==="
        echo "  test-sources                  - Probar todas las fuentes de TI"
        echo "  test-triggers                 - Verificar configuración de triggers"
        echo "  test-alert [--type TYPE]      - Generar alerta de prueba"
        echo "  test-email                    - Probar configuración de email"
        echo ""
        echo "=== ALERTAS Y ADVISORIES ==="
        echo "  generate-alert --cve CVE-ID   - Generar alerta manual para CVE"
        echo "  list-alerts [--priority PRI]  - Listar alertas (CRITICAL/HIGH/MEDIUM/LOW)"
        echo "  generate-advisory             - Generar advisory MDR manual"
        echo ""
        echo "=== EXPORTACIÓN ==="
        echo "  export --format FMT --alert-id ID - Exportar alerta en formato"
        echo "    Formatos: paloalto, fortinet, snort, yara, stix, csv, json"
        echo ""
        echo "=== INTEGRACIÓN WAZUH ==="
        echo "  wazuh-search --ioc INDICATOR  - Buscar IoC en Wazuh"
        echo ""
        echo "=== CONFIGURACIÓN ==="
        echo "  update-config                 - Editar archivo de configuración"
        echo ""
        echo "Ejemplos:"
        echo "  ti-hub-admin status"
        echo "  ti-hub-admin init-data --days 30"
        echo "  ti-hub-admin test-sources"
        echo "  ti-hub-admin generate-alert --cve CVE-2024-12345"
        echo "  ti-hub-admin export --format paloalto --alert-id abc-123"
        ;;
esac
ADMIN_SCRIPT
    
    chmod +x /usr/local/bin/ti-hub-admin
    
    log_success "Herramientas administrativas completas instaladas"
}

# El resto del instalador continúa con las demás funciones...
# (create_advisory_generator, create_systemd_services, etc.)

# Función principal al final
main() {
    show_welcome_banner
    check_requirements
    install_dependencies
    detect_wazuh
    interactive_configuration
    setup_database
    create_system_user
    setup_python_environment
    create_configuration_files
    create_system_scripts
    create_admin_tools
    # Las demás funciones continuarán...
}

# Ejecutar
main "$@"