#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Instalación v1.0.3
# Compatible con: Ubuntu 20.04+ LTS
# Enfoque: Inteligencia Accionable basada en KEV/EPSS/IoCs
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
readonly SUPPORTED_UBUNTU="20.04"
readonly INSTALL_USER="ti-hub"
readonly INSTALL_DIR="/opt/threat-intel-hub"
readonly CONFIG_DIR="/etc/threat-intel-hub"
readonly LOG_DIR="/var/log/threat-intel-hub"
readonly DATA_DIR="/var/lib/threat-intel-hub"

# Variables globales
DB_PASSWORD=""
API_KEY=""
SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"
SENDER_EMAIL=""
SENDER_PASSWORD=""
RECIPIENT_EMAIL=""
MONITOR_INTERVAL="1"  # Reducido a 1 hora para detección más rápida
CURRENT_USER="${SUDO_USER:-$USER}"

# Variables para características
HAS_WAZUH="false"
OTX_API_KEY=""
MISP_URL=""
MISP_API_KEY=""
MISP_VERIFY_SSL="true"
MISP_ORG="Mi Organización"
MISP_WEBHOOK_ENABLED="false"
VT_API_KEY=""
WAZUH_URL=""
WAZUH_USER=""
WAZUH_PASSWORD=""
WAZUH_INDEXER_URL=""
WAZUH_INDEXER_USER=""
WAZUH_INDEXER_PASSWORD=""
WAZUH_VERIFY_SSL="true"

# Nuevas variables v1.0.3
ENABLE_KEV_TRIGGER="true"
ENABLE_EPSS_TRIGGER="true"
ENABLE_MISP_TRIGGER="true"
ENABLE_IOC_FEEDS="true"
EPSS_SPIKE_THRESHOLD="0.2"
KEV_CHECK_INTERVAL="30"  # minutos
IOC_EXPORT_FORMATS="paloalto,fortinet,snort,yara,stix"
API_PORT="8080"
ENABLE_WEBHOOKS="false"

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

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Limpiando archivos temporales..."
    rm -f /tmp/ti-hub-*.tmp /tmp/setup_database.sh /tmp/ti_hub_* /tmp/test_email.py /tmp/ti_hub_setup.sql 2>/dev/null || true
}
trap cleanup EXIT

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${PURPLE}"
    echo "================================================================"
    echo "     THREAT INTEL HUB v${SCRIPT_VERSION} - ACTIONABLE INTELLIGENCE"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${GREEN}Versión: ${SCRIPT_VERSION} - Inteligencia de Amenazas Accionable${NC}"
    echo
    echo "🎯 NUEVO EN v1.0.3:"
    echo "   ✨ Triggers basados en KEV/EPSS/MISP"
    echo "   ✨ Generación automática de listas de bloqueo"
    echo "   ✨ APIs para EDR/Firewall/WAF"
    echo "   ✨ Detección de spikes en EPSS"
    echo "   ✨ Webhooks para eventos en tiempo real"
    echo
    echo "Este instalador configurará:"
    echo "   ✅ Monitor de KEV con alertas inmediatas"
    echo "   ✅ Detección de cambios críticos en EPSS"
    echo "   ✅ Procesamiento prioritario de IoCs de MISP/OTX"
    echo "   ✅ APIs de integración para plataformas de seguridad"
    echo "   ✅ Sistema de alertas contextualizadas"
    echo "   ✅ Generación de reglas (YARA/Snort/Sigma)"
    echo
    echo "Integraciones opcionales:"
    echo "   • Wazuh SIEM (correlación en tiempo real)"
    echo "   • AlienVault OTX (threat intelligence)"
    echo "   • MISP (plataforma de intercambio)"
    echo "   • VirusTotal (enriquecimiento)"
    echo
    read -p "¿Continuar con la instalación de Threat Intel Hub v${SCRIPT_VERSION}? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Instalación cancelada."
        exit 0
    fi
    echo
}

# Detección de Wazuh
detect_wazuh() {
    log_header "DETECCIÓN DE WAZUH SIEM"
    
    echo "Wazuh permite correlacionar IoCs con eventos de seguridad en tiempo real."
    echo
    read -p "¿Tiene Wazuh instalado en su infraestructura? (y/N): " has_wazuh
    
    if [[ $has_wazuh =~ ^[Yy]$ ]]; then
        HAS_WAZUH="true"
        log_info "Wazuh detectado - Se habilitará la correlación en tiempo real"
        echo
        echo "Capacidades habilitadas con Wazuh:"
        echo "   • Búsqueda de IoCs en logs históricos"
        echo "   • Correlación CVE-IoC con eventos de seguridad"
        echo "   • Generación de reglas Wazuh personalizadas"
        echo "   • Detección de compromisos activos"
        echo "   • Priorización basada en detecciones reales"
        echo
        read -p "Presione Enter para continuar..."
    else
        HAS_WAZUH="false"
        log_info "Sin Wazuh - El sistema funcionará en modo standalone"
        echo
    fi
}

# Generar contraseña segura
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
}

# Validar email
validate_email() {
    local email="$1"
    if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Verificar prerrequisitos
check_prerequisites() {
    log_step "Verificando prerrequisitos..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Debe ejecutarse como root: sudo bash install.sh"
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    if ! timeout 5 ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "Sin conectividad a internet"
        exit 1
    fi
    
    # Verificar versión de Ubuntu
    if command -v lsb_release &> /dev/null; then
        local ubuntu_version=$(lsb_release -rs)
        log_info "Ubuntu version: $ubuntu_version"
    fi
    
    # Verificar espacio en disco
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 2097152 ]; then  # 2GB en KB
        log_warn "Espacio en disco limitado. Se recomienda al menos 2GB libres"
    fi
    
    log_success "Prerrequisitos verificados"
}

# Instalar dependencias
install_dependencies() {
    log_step "Instalando dependencias..."
    
    # Detectar base de datos existente
    local db_exists=false
    local db_type=""
    
    if command -v mysql &>/dev/null; then
        if mysql --version | grep -qi mariadb; then
            db_exists=true
            db_type="MariaDB"
        else
            db_exists=true
            db_type="MySQL"
        fi
    fi
    
    if [ "$db_exists" = true ]; then
        log_info "$db_type ya está instalado"
    else
        log_info "Instalando MariaDB"
    fi
    
    local packages=(
        "python3-pip" "python3-venv" "python3-dev" "build-essential"
        "curl" "wget" "git" "logrotate" "systemd" "jq" "uuid-runtime"
        "libssl-dev" "libffi-dev" "libxml2-dev" "libxslt1-dev"
        "htop" "net-tools" "unzip" "nginx"  # nginx para webhooks
    )
    
    if [ "$db_exists" = false ]; then
        packages+=("mariadb-server")
    fi
    
    apt update -qq
    DEBIAN_FRONTEND=noninteractive apt install -y "${packages[@]}"
    
    if [ "$db_exists" = false ]; then
        systemctl enable mariadb
        systemctl start mariadb
    fi
    
    log_success "Dependencias instaladas"
}

# Crear usuario del sistema
create_system_user() {
    log_step "Creando usuario del sistema..."
    
    if ! getent group "$INSTALL_USER" >/dev/null 2>&1; then
        groupadd "$INSTALL_USER"
        log_info "Grupo $INSTALL_USER creado"
    fi
    
    if ! id "$INSTALL_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -g "$INSTALL_USER" -c "Threat Intel Hub Service User" "$INSTALL_USER"
        log_info "Usuario $INSTALL_USER creado"
    fi
    
    if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        usermod -a -G "$INSTALL_USER" "$CURRENT_USER"
        log_info "Usuario $CURRENT_USER agregado al grupo $INSTALL_USER"
    fi
    
    log_success "Usuario del sistema configurado"
}

# Crear directorios
create_directories() {
    log_step "Creando estructura de directorios..."
    
    local directories=(
        "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
        "$DATA_DIR/scripts" "$DATA_DIR/backups" "$DATA_DIR/cache"
        "$DATA_DIR/reports" "$DATA_DIR/ioc_feeds" "$DATA_DIR/threat_intel"
        "$DATA_DIR/rules" "$DATA_DIR/rules/yara" "$DATA_DIR/rules/snort"
        "$DATA_DIR/rules/sigma" "$DATA_DIR/blocklists" "$DATA_DIR/webhooks"
        "$DATA_DIR/api_exports" "$DATA_DIR/campaigns"
        "$INSTALL_DIR/modules" "$INSTALL_DIR/templates" "$INSTALL_DIR/schemas"
        "$INSTALL_DIR/connectors" "$INSTALL_DIR/processors" "$INSTALL_DIR/exporters"
        "$LOG_DIR/threat_intel" "$LOG_DIR/triggers" "$LOG_DIR/api"
    )
    
    if [[ "$HAS_WAZUH" == "true" ]]; then
        directories+=(
            "$DATA_DIR/wazuh_data"
            "$DATA_DIR/rules/wazuh"
            "$LOG_DIR/wazuh"
        )
    fi
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        case "$dir" in
            "$CONFIG_DIR")
                chown root:"$INSTALL_USER" "$dir"
                chmod 750 "$dir"
                ;;
            *)
                chown "$INSTALL_USER:$INSTALL_USER" "$dir"
                chmod 755 "$dir"
                ;;
        esac
    done
    
    log_success "Estructura de directorios creada"
}

# Configurar Python
setup_python() {
    log_step "Configurando entorno Python..."
    
    cd "$INSTALL_DIR"
    
    sudo -u "$INSTALL_USER" python3 -m venv venv
    
    cat > requirements.txt << 'EOF'
# Core dependencies
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
tabulate>=0.9.0
python-dateutil>=2.8.2
colorama>=0.4.6

# Web framework for API and webhooks
flask>=2.3.0
flask-restful>=0.3.10
flask-cors>=4.0.0
gunicorn>=21.2.0

# Threat Intelligence
pymisp>=2.4.170
stix2>=3.0.1
taxii2-client>=2.3.0
yara-python>=4.3.0
plyara>=2.1.1

# Data processing
lxml>=4.9.2
beautifulsoup4>=4.12.0
pandas>=1.5.0
numpy>=1.24.0

# Networking
urllib3>=2.0.0
certifi>=2023.5.7
python-whois>=0.8.0
netaddr>=0.9.0

# Validation
jsonschema>=4.17.0
marshmallow>=3.19.0
validators>=0.20.0

# Utilities
click>=8.1.0
tqdm>=4.65.0
cachetools>=5.3.0
rich>=13.3.0
watchdog>=3.0.0
EOF
    
    sudo -u "$INSTALL_USER" bash -c "
        source venv/bin/activate
        pip install --upgrade pip -q
        pip install -r requirements.txt -q
    "
    
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    log_success "Entorno Python configurado"
}

# Configurar base de datos con nuevas tablas v1.0.3
setup_database() {
    log_step "Configurando base de datos v1.0.3..."
    
    DB_PASSWORD=$(generate_password)
    
    log_info "Configurando base de datos ti_hub..."
    
    # Probar autenticación
    local mysql_cmd=""
    if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="mysql -u root"
    elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="sudo mysql -u root"
    else
        log_error "No se pudo autenticar con MySQL/MariaDB"
        exit 1
    fi
    
    # Crear script SQL
    cat > /tmp/ti_hub_setup.sql << SQLEOF
-- Eliminar usuario existente si existe
DROP USER IF EXISTS 'ti_hub_user'@'localhost';

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS ti_hub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario nuevo
CREATE USER 'ti_hub_user'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON ti_hub.* TO 'ti_hub_user'@'localhost';

-- Aplicar cambios
FLUSH PRIVILEGES;

-- Usar la base de datos
USE ti_hub;

-- Tabla principal de vulnerabilidades
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    published_date DATETIME,
    last_modified DATETIME,
    cvss_score DECIMAL(3,1),
    cvss_severity VARCHAR(20),
    description TEXT,
    reference_urls TEXT,
    affected_products TEXT,
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,4),
    epss_date DATE,
    epss_delta DECIMAL(5,4) DEFAULT 0,  -- v1.0.3: cambio en EPSS
    composite_risk_score DECIMAL(5,2),
    threat_score DECIMAL(5,2) DEFAULT 0,  -- v1.0.3: score basado en inteligencia
    affected_systems INT DEFAULT 0,
    kev_status BOOLEAN DEFAULT FALSE,  -- v1.0.3: marcador rápido KEV
    has_active_iocs BOOLEAN DEFAULT FALSE,  -- v1.0.3: tiene IoCs activos
    last_ioc_seen TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (cvss_severity),
    INDEX idx_epss_score (epss_score),
    INDEX idx_epss_delta (epss_delta),
    INDEX idx_kev_status (kev_status),
    INDEX idx_has_iocs (has_active_iocs),
    INDEX idx_threat_score (threat_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla KEV (Known Exploited Vulnerabilities)
CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
    cve_id VARCHAR(20) PRIMARY KEY,
    vendor_project VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name TEXT,
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware BOOLEAN DEFAULT FALSE,
    notes TEXT,
    threat_level ENUM('CRITICAL', 'HIGH', 'MEDIUM') DEFAULT 'HIGH',
    ioc_count INT DEFAULT 0,  -- v1.0.3: contador de IoCs asociados
    first_ioc_date TIMESTAMP NULL,  -- v1.0.3: primer IoC detectado
    alert_sent BOOLEAN DEFAULT FALSE,  -- v1.0.3: alerta ya enviada
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_date_added (date_added),
    INDEX idx_ransomware (known_ransomware),
    INDEX idx_alert_sent (alert_sent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de IoCs mejorada
CREATE TABLE IF NOT EXISTS iocs (
    id VARCHAR(36) PRIMARY KEY,
    indicator_value VARCHAR(2048) NOT NULL,
    indicator_type ENUM(
        'ip_address', 'domain', 'url', 'file_hash_md5', 
        'file_hash_sha1', 'file_hash_sha256', 'file_hash_sha512',
        'email_address', 'mutex', 'registry_key', 'filename',
        'user_agent', 'certificate_fingerprint', 'ja3_hash'
    ) NOT NULL,
    confidence_score DECIMAL(3,2) DEFAULT 0.50,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_feed VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_whitelisted BOOLEAN DEFAULT FALSE,  -- v1.0.3: whitelist
    kill_chain_phase VARCHAR(100),
    malware_family VARCHAR(255),
    campaign_name VARCHAR(255),
    threat_actor VARCHAR(255),
    description TEXT,
    tags JSON,  -- v1.0.3: tags flexibles
    metadata JSON,  -- v1.0.3: metadata adicional
    detection_count INT DEFAULT 0,
    last_detection TIMESTAMP NULL,
    export_count INT DEFAULT 0,  -- v1.0.3: veces exportado
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_ioc (indicator_value, indicator_type),
    INDEX idx_indicator_type (indicator_type),
    INDEX idx_confidence (confidence_score),
    INDEX idx_campaign (campaign_name),
    INDEX idx_threat_actor (threat_actor),
    INDEX idx_active (is_active),
    INDEX idx_whitelisted (is_whitelisted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Nueva tabla v1.0.3: Alertas de amenazas
CREATE TABLE IF NOT EXISTS threat_alerts (
    id VARCHAR(36) PRIMARY KEY,
    alert_type ENUM('kev_addition', 'epss_spike', 'campaign_active', 'ioc_wave', 'ransomware_detected'),
    trigger_source VARCHAR(50),
    priority ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
    title VARCHAR(500),
    description TEXT,
    campaign_id VARCHAR(36),
    cve_list JSON,
    ioc_bundle JSON,
    affected_products JSON,
    recommended_actions JSON,
    integration_urls JSON,
    distribution_status ENUM('pending', 'sent', 'failed', 'acknowledged'),
    acknowledged_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP NULL,
    acknowledged_at TIMESTAMP NULL,
    INDEX idx_alert_type (alert_type),
    INDEX idx_priority (priority),
    INDEX idx_created (created_at),
    INDEX idx_status (distribution_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Nueva tabla v1.0.3: Exportaciones de IoCs
CREATE TABLE IF NOT EXISTS ioc_exports (
    id VARCHAR(36) PRIMARY KEY,
    export_format ENUM('paloalto', 'fortinet', 'cisco', 'checkpoint', 'snort', 'yara', 'stix', 'misp', 'csv', 'json'),
    campaign_id VARCHAR(36),
    alert_id VARCHAR(36),
    ioc_count INT,
    file_path VARCHAR(500),
    download_url VARCHAR(500),
    download_count INT DEFAULT 0,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    INDEX idx_format (export_format),
    INDEX idx_campaign (campaign_id),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Nueva tabla v1.0.3: Historial de cambios EPSS
CREATE TABLE IF NOT EXISTS epss_changes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    old_score DECIMAL(5,4),
    new_score DECIMAL(5,4),
    score_delta DECIMAL(5,4),
    old_percentile DECIMAL(5,4),
    new_percentile DECIMAL(5,4),
    percentile_delta DECIMAL(5,4),
    change_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_triggered BOOLEAN DEFAULT FALSE,
    INDEX idx_cve (cve_id),
    INDEX idx_delta (score_delta),
    INDEX idx_detected (change_detected)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Nueva tabla v1.0.3: Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255),
    url VARCHAR(500),
    secret VARCHAR(255),
    event_types JSON,
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered TIMESTAMP NULL,
    trigger_count INT DEFAULT 0,
    error_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de campañas mejorada
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id VARCHAR(36) PRIMARY KEY,
    campaign_name VARCHAR(255) NOT NULL UNIQUE,
    threat_actor VARCHAR(255),
    first_activity DATE,
    last_activity DATE,
    target_sectors JSON,
    target_regions JSON,
    attack_vectors JSON,
    motivation ENUM('financial', 'espionage', 'disruption', 'unknown'),
    sophistication_level ENUM('low', 'medium', 'high', 'advanced'),
    description TEXT,
    threat_references JSON,
    mitre_attack_tactics JSON,
    associated_malware JSON,
    ioc_count INT DEFAULT 0,
    cve_count INT DEFAULT 0,
    detection_count INT DEFAULT 0,  -- v1.0.3
    status ENUM('active', 'dormant', 'inactive') DEFAULT 'active',  -- v1.0.3
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_threat_actor (threat_actor),
    INDEX idx_last_activity (last_activity),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de relación CVE-IoC
CREATE TABLE IF NOT EXISTS cve_ioc_relationships (
    id VARCHAR(36) PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    ioc_id VARCHAR(36) NOT NULL,
    relationship_type ENUM(
        'exploits_vulnerability', 'targets_vulnerability', 
        'associated_malware', 'exploitation_tool',
        'post_exploitation', 'reconnaissance',
        'lateral_movement', 'persistence'
    ) NOT NULL,
    confidence_score DECIMAL(3,2) DEFAULT 0.50,
    source VARCHAR(255),
    first_observed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_observed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    context_description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_cve_ioc (cve_id, ioc_id, relationship_type),
    INDEX idx_cve_id (cve_id),
    INDEX idx_ioc_id (ioc_id),
    INDEX idx_relationship (relationship_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQLEOF

    # Agregar tablas de Wazuh si está habilitado
    if [[ "$HAS_WAZUH" == "true" ]]; then
        cat >> /tmp/ti_hub_setup.sql << 'SQLEOF'

-- Tabla de correlaciones Wazuh
CREATE TABLE IF NOT EXISTS wazuh_correlations (
    id VARCHAR(36) PRIMARY KEY,
    correlation_type ENUM('cve', 'ioc', 'campaign'),
    target_id VARCHAR(50) NOT NULL,
    agent_id VARCHAR(10),
    agent_name VARCHAR(255),
    rule_id VARCHAR(10),
    rule_description TEXT,
    timestamp TIMESTAMP,
    correlation_data JSON,
    confidence_score DECIMAL(3,2) DEFAULT 0.50,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type_target (correlation_type, target_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_agent (agent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQLEOF
    fi

    # Agregar resto de tablas
    cat >> /tmp/ti_hub_setup.sql << 'SQLEOF'

-- Tablas de sistema
CREATE TABLE IF NOT EXISTS monitoring_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    kev_additions INT DEFAULT 0,
    epss_spikes INT DEFAULT 0,
    new_iocs INT DEFAULT 0,
    alerts_generated INT DEFAULT 0,
    exports_created INT DEFAULT 0,
    webhooks_triggered INT DEFAULT 0,
    status VARCHAR(50),
    message TEXT,
    execution_time_seconds DECIMAL(8,2),
    INDEX idx_timestamp (timestamp),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Vista para dashboard de inteligencia accionable
CREATE OR REPLACE VIEW actionable_intelligence AS
SELECT 
    v.cve_id,
    v.cvss_score,
    v.cvss_severity,
    v.epss_score,
    v.epss_delta,
    v.threat_score,
    k.date_added as kev_date,
    k.known_ransomware,
    k.due_date,
    COUNT(DISTINCT i.id) as active_iocs,
    COUNT(DISTINCT tc.id) as campaigns,
    MAX(ta.priority) as alert_priority,
    CASE 
        WHEN k.cve_id IS NOT NULL THEN 'CRITICAL'
        WHEN v.epss_delta > 0.2 THEN 'HIGH'
        WHEN COUNT(DISTINCT i.id) > 10 THEN 'HIGH'
        WHEN v.epss_score > 0.5 THEN 'MEDIUM'
        ELSE 'LOW'
    END as action_priority
FROM vulnerabilities v
LEFT JOIN kev_vulnerabilities k ON v.cve_id = k.cve_id
LEFT JOIN cve_ioc_relationships cir ON v.cve_id = cir.cve_id
LEFT JOIN iocs i ON cir.ioc_id = i.id AND i.is_active = TRUE
LEFT JOIN threat_campaigns tc ON i.campaign_name = tc.campaign_name
LEFT JOIN threat_alerts ta ON JSON_CONTAINS(ta.cve_list, JSON_QUOTE(v.cve_id))
WHERE v.published_date >= DATE_SUB(NOW(), INTERVAL 90 DAY)
GROUP BY v.cve_id
HAVING action_priority IN ('CRITICAL', 'HIGH', 'MEDIUM')
ORDER BY action_priority DESC, v.threat_score DESC;

-- Insertar configuración inicial
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('installation_date', NOW(), 'Fecha de instalación'),
('database_version', '1.0.3', 'Versión del esquema de base de datos'),
('platform_version', '1.0.3', 'Versión de la plataforma'),
('kev_trigger_enabled', 'true', 'Trigger basado en KEV habilitado'),
('epss_trigger_enabled', 'true', 'Trigger basado en EPSS habilitado'),
('epss_spike_threshold', '0.2', 'Umbral de cambio EPSS para alertas'),
('ioc_retention_days', '90', 'Días de retención de IoCs'),
('export_formats', 'paloalto,fortinet,snort,yara,stix', 'Formatos de exportación habilitados'),
('webhook_enabled', 'false', 'Webhooks habilitados'),
('api_port', '8080', 'Puerto de la API REST');
SQLEOF
    
    # Ejecutar script
    $mysql_cmd < /tmp/ti_hub_setup.sql || {
        log_error "Error ejecutando comandos SQL"
        rm -f /tmp/ti_hub_setup.sql
        exit 1
    }
    
    rm -f /tmp/ti_hub_setup.sql
    
    log_success "Base de datos v1.0.3 configurada correctamente"
}

# Configurar características de inteligencia accionable
configure_actionable_intelligence() {
    log_header "CONFIGURACIÓN DE INTELIGENCIA ACCIONABLE"
    
    echo "El sistema v1.0.3 prioriza alertas basadas en amenazas activas."
    echo
    
    echo -e "${YELLOW}TRIGGERS DE ALERTAS:${NC}"
    echo
    
    read -p "¿Habilitar alertas por nuevas entradas KEV? (Y/n): " enable_kev
    ENABLE_KEV_TRIGGER=$([[ $enable_kev =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    read -p "¿Habilitar alertas por cambios significativos en EPSS? (Y/n): " enable_epss
    ENABLE_EPSS_TRIGGER=$([[ $enable_epss =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    if [[ "$ENABLE_EPSS_TRIGGER" == "true" ]]; then
        read -p "Umbral de cambio EPSS para alertas (0.1-0.5) [0.2]: " epss_threshold
        EPSS_SPIKE_THRESHOLD=${epss_threshold:-0.2}
    fi
    
    read -p "¿Habilitar procesamiento prioritario de eventos MISP? (Y/n): " enable_misp
    ENABLE_MISP_TRIGGER=$([[ $enable_misp =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    echo
    echo -e "${YELLOW}EXPORTACIÓN DE IoCs:${NC}"
    echo
    echo "Formatos disponibles para listas de bloqueo:"
    echo "  • Palo Alto EDL"
    echo "  • Fortinet Threat Feed"
    echo "  • Snort/Suricata Rules"
    echo "  • YARA Rules"
    echo "  • STIX 2.1 Bundle"
    echo
    
    read -p "¿Habilitar generación automática de feeds? (Y/n): " enable_feeds
    ENABLE_IOC_FEEDS=$([[ $enable_feeds =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    echo
    echo -e "${YELLOW}WEBHOOKS:${NC}"
    echo
    read -p "¿Habilitar webhooks para eventos en tiempo real? (y/N): " enable_webhooks
    ENABLE_WEBHOOKS=$([[ $enable_webhooks =~ ^[Yy]$ ]] && echo "true" || echo "false")
    
    if [[ "$ENABLE_WEBHOOKS" == "true" ]]; then
        read -p "Puerto para webhooks [9999]: " webhook_port
        WEBHOOK_PORT=${webhook_port:-9999}
    fi
    
    log_success "Inteligencia accionable configurada"
}

# Configuración de API Key NVD
configure_api_key() {
    log_header "CONFIGURACIÓN DE API KEY NVD"
    
    echo "API Key de NVD (recomendado para enriquecimiento de CVEs):"
    echo "   • Sin API key: 5 requests/30 segundos"
    echo "   • Con API key: 50 requests/30 segundos"
    echo "   • Obtener en: https://nvd.nist.gov/developers/request-an-api-key"
    echo
    
    read -p "¿Configurar API key ahora? (y/N): " configure_api
    if [[ $configure_api =~ ^[Yy]$ ]]; then
        read -p "Ingrese su API key de NVD: " API_KEY
        if [[ -n "$API_KEY" ]]; then
            log_success "API key de NVD configurada"
        fi
    else
        API_KEY=""
        log_info "API key omitida"
    fi
}

# Configuración de email
configure_email() {
    log_header "CONFIGURACIÓN DE NOTIFICACIONES"
    
    echo "Las notificaciones incluirán IoCs listos para bloquear."
    echo
    
    read -p "¿Configurar notificaciones por email? (Y/n): " configure_mail
    if [[ ! $configure_mail =~ ^[Nn]$ ]]; then
        
        echo
        echo "SERVIDOR SMTP:"
        read -p "Servidor SMTP [smtp.gmail.com]: " smtp_input
        SMTP_SERVER=${smtp_input:-smtp.gmail.com}
        
        read -p "Puerto SMTP [587]: " port_input
        SMTP_PORT=${port_input:-587}
        
        echo
        while true; do
            read -p "Email remitente: " SENDER_EMAIL
            if validate_email "$SENDER_EMAIL"; then
                break
            else
                echo "Email inválido"
            fi
        done
        
        read -s -p "Contraseña del remitente: " SENDER_PASSWORD
        echo
        
        echo
        while true; do
            read -p "Email(s) destinatario(s) (separados por comas): " recipient_input
            
            if [[ -z "$recipient_input" ]]; then
                echo "Debe ingresar al menos un email"
                continue
            fi
            
            IFS=',' read -ra emails <<< "$recipient_input"
            valid_emails=()
            
            for email in "${emails[@]}"; do
                email=$(echo "$email" | xargs)
                if validate_email "$email"; then
                    valid_emails+=("$email")
                fi
            done
            
            if [ ${#valid_emails[@]} -gt 0 ]; then
                RECIPIENT_EMAIL=$(IFS=','; echo "${valid_emails[*]}")
                echo "Emails configurados: $RECIPIENT_EMAIL"
                break
            fi
        done
        
        log_success "Notificaciones configuradas"
    else
        log_info "Notificaciones omitidas"
    fi
}

# Configuración de Wazuh (si está habilitado)
configure_wazuh_integration() {
    if [[ "$HAS_WAZUH" != "true" ]]; then
        return
    fi
    
    log_header "CONFIGURACIÓN DE WAZUH"
    
    echo "Configure los detalles de conexión con Wazuh:"
    echo
    
    while true; do
        read -p "URL del Wazuh Manager (ej: https://wazuh.local:55000): " WAZUH_URL
        if [[ $WAZUH_URL =~ ^https?:// ]]; then
            break
        else
            echo "URL inválida"
        fi
    done
    
    read -p "Usuario Wazuh API [wazuh]: " wazuh_user
    WAZUH_USER=${wazuh_user:-"wazuh"}
    
    read -s -p "Contraseña Wazuh API: " WAZUH_PASSWORD
    echo
    
    echo
    read -p "URL Wazuh Indexer (ej: https://wazuh-indexer.local:9200): " WAZUH_INDEXER_URL
    
    if [[ -n "$WAZUH_INDEXER_URL" ]]; then
        read -p "Usuario Indexer [admin]: " wazuh_indexer_user
        WAZUH_INDEXER_USER=${wazuh_indexer_user:-"admin"}
        read -s -p "Contraseña Indexer: " WAZUH_INDEXER_PASSWORD
        echo
    fi
    
    read -p "¿Verificar certificado SSL? (Y/n): " wazuh_verify_ssl
    WAZUH_VERIFY_SSL=$([[ $wazuh_verify_ssl =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    log_success "Wazuh configurado"
}

# Configuración de fuentes de Threat Intelligence
configure_threat_sources() {
    log_header "CONFIGURACIÓN DE FUENTES DE INTELIGENCIA"
    
    echo "Configure las fuentes de IoCs y threat intelligence:"
    echo
    
    # AlienVault OTX
    echo "ALIENVAULT OTX:"
    echo "   API gratuita en: https://otx.alienvault.com/api"
    read -p "API Key de OTX (opcional): " OTX_API_KEY
    
    # MISP
    echo
    echo "MISP:"
    read -p "¿Configurar MISP? (y/N): " configure_misp
    if [[ $configure_misp =~ ^[Yy]$ ]]; then
        while true; do
            read -p "URL de MISP: " MISP_URL
            if [[ $MISP_URL =~ ^https?:// ]]; then
                break
            fi
        done
        
        read -p "API Key de MISP: " MISP_API_KEY
        
        read -p "¿Habilitar webhook de MISP? (y/N): " misp_webhook
        MISP_WEBHOOK_ENABLED=$([[ $misp_webhook =~ ^[Yy]$ ]] && echo "true" || echo "false")
    fi
    
    # VirusTotal
    echo
    echo "VIRUSTOTAL:"
    echo "   API gratuita en: https://www.virustotal.com/gui/my-apikey"
    read -p "API Key de VirusTotal (opcional): " VT_API_KEY
    
    log_success "Fuentes configuradas"
}

# Crear archivo de configuración
create_config_file() {
    log_step "Creando archivo de configuración..."
    
    cat > "$CONFIG_DIR/config.ini" << CONFEOF
# =============================================================================
# Threat Intel Hub Configuration v1.0.3
# Actionable Intelligence Platform
# =============================================================================

[database]
host = localhost
port = 3306
database = ti_hub
user = ti_hub_user
password = ${DB_PASSWORD}

[triggers]
kev_enabled = ${ENABLE_KEV_TRIGGER}
epss_enabled = ${ENABLE_EPSS_TRIGGER}
epss_spike_threshold = ${EPSS_SPIKE_THRESHOLD}
misp_priority = ${ENABLE_MISP_TRIGGER}
check_interval_minutes = ${KEV_CHECK_INTERVAL}

[monitoring]
main_interval_hours = ${MONITOR_INTERVAL}
kev_check_minutes = 30
epss_check_hours = 4
ioc_correlation_minutes = 15

[nvd]
api_key = ${API_KEY}
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0

[email]
smtp_server = ${SMTP_SERVER}
smtp_port = ${SMTP_PORT}
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_email = ${RECIPIENT_EMAIL}

[api]
enabled = true
host = 0.0.0.0
port = ${API_PORT}
export_formats = ${IOC_EXPORT_FORMATS}
cors_enabled = true

[webhooks]
enabled = ${ENABLE_WEBHOOKS}
port = ${WEBHOOK_PORT:-9999}
secret = $(generate_password)

[otx]
api_key = ${OTX_API_KEY}
base_url = https://otx.alienvault.com/api/v1
enable = $([ -n "${OTX_API_KEY}" ] && echo "true" || echo "false")

[misp]
url = ${MISP_URL}
api_key = ${MISP_API_KEY}
verify_ssl = ${MISP_VERIFY_SSL}
webhook_enabled = ${MISP_WEBHOOK_ENABLED}
enable = $([ -n "${MISP_API_KEY}" ] && echo "true" || echo "false")

[virustotal]
api_key = ${VT_API_KEY}
base_url = https://www.virustotal.com/api/v3
enable = $([ -n "${VT_API_KEY}" ] && echo "true" || echo "false")

[wazuh]
enabled = ${HAS_WAZUH}
manager_url = ${WAZUH_URL}
manager_user = ${WAZUH_USER}
manager_password = ${WAZUH_PASSWORD}
indexer_url = ${WAZUH_INDEXER_URL}
indexer_user = ${WAZUH_INDEXER_USER}
indexer_password = ${WAZUH_INDEXER_PASSWORD}
verify_ssl = ${WAZUH_VERIFY_SSL}

[logging]
level = INFO
file = /var/log/threat-intel-hub/ti-hub.log
max_size = 10485760
backup_count = 5
CONFEOF
    
    chmod 640 "$CONFIG_DIR/config.ini"
    chown root:"$INSTALL_USER" "$CONFIG_DIR/config.ini"
    
    log_success "Archivo de configuración creado"
}

# Crear script principal v1.0.3
create_main_monitor_script() {
    log_step "Creando monitor principal v1.0.3..."
    
    cat > "$DATA_DIR/scripts/ti_hub_monitor.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Threat Intel Hub v1.0.3 - Monitor Principal
Enfoque: Inteligencia Accionable basada en KEV/EPSS/IoCs
"""

import sys
import os
import json
import time
import logging
import configparser
import mysql.connector
import requests
import schedule
import smtplib
import uuid
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional, Any
from pathlib import Path

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/threat-intel-hub/ti-hub.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ThreatIntelHub-v1.0.3')

class ActionableIntelligence:
    """Monitor de Inteligencia Accionable v1.0.3"""
    
    def __init__(self, config_file='/etc/threat-intel-hub/config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.db = None
        self.init_database()
        
        # Contadores
        self.stats = {
            'kev_additions': 0,
            'epss_spikes': 0,
            'new_iocs': 0,
            'alerts_generated': 0,
            'exports_created': 0
        }
    
    def init_database(self):
        """Inicializar conexión a base de datos"""
        try:
            self.db = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                port=self.config.getint('database', 'port'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password')
            )
            logger.info("✅ Base de datos conectada")
        except Exception as e:
            logger.error(f"❌ Error conectando a base de datos: {e}")
            sys.exit(1)
    
    def check_kev_additions(self):
        """Monitorear nuevas entradas en KEV - TRIGGER PRINCIPAL"""
        if not self.config.getboolean('triggers', 'kev_enabled', fallback=True):
            return
        
        logger.info("🎯 Verificando nuevas entradas KEV...")
        
        try:
            # Obtener KEV actual
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                cursor = self.db.cursor(dictionary=True)
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get('cveID')
                    
                    # Verificar si es nuevo
                    check_query = "SELECT alert_sent FROM kev_vulnerabilities WHERE cve_id = %s"
                    cursor.execute(check_query, (cve_id,))
                    existing = cursor.fetchone()
                    
                    if not existing:
                        # Nueva entrada KEV - GENERAR ALERTA INMEDIATA
                        logger.warning(f"🚨 NUEVA KEV DETECTADA: {cve_id}")
                        
                        # Insertar en BD
                        insert_query = """
                            INSERT INTO kev_vulnerabilities
                            (cve_id, vendor_project, product, vulnerability_name,
                             date_added, short_description, required_action, due_date,
                             known_ransomware, notes)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            title = f"⚡ EPSS SPIKE: {cve_id} ({old_score:.3f} → {new_score:.3f})"
            
            description = f"""
            Cambio significativo en probabilidad de explotación:
            
            CVE: {cve_id}
            Score anterior: {old_score:.3f}
            Score nuevo: {new_score:.3f}
            Delta: +{new_score - old_score:.3f}
            
            Este cambio indica mayor actividad de explotación.
            IoCs asociados: {len(iocs)}
            """
            
            cursor.execute(query, (
                alert_id,
                'epss_spike',
                'EPSS Monitor',
                'HIGH',
                title,
                description,
                json.dumps([cve_id]),
                json.dumps(ioc_bundle),
                json.dumps(integration_urls),
                'pending'
            ))
            
            self.db.commit()
            cursor.close()
            
            self.send_alert_notification(alert_id)
            self.stats['alerts_generated'] += 1
            
        except Exception as e:
            logger.error(f"Error creando alerta EPSS: {e}")
    
    def prepare_ioc_bundle(self, iocs):
        """Preparar bundle de IoCs para exportación"""
        bundle = {
            'ips': [],
            'domains': [],
            'urls': [],
            'file_hashes': {},
            'emails': []
        }
        
        for ioc in iocs:
            value = ioc.get('indicator_value', '')
            ioc_type = ioc.get('indicator_type', '')
            
            if ioc_type == 'ip_address':
                bundle['ips'].append(value)
            elif ioc_type == 'domain':
                bundle['domains'].append(value)
            elif ioc_type == 'url':
                bundle['urls'].append(value)
            elif 'file_hash' in ioc_type:
                hash_type = ioc_type.replace('file_hash_', '')
                if hash_type not in bundle['file_hashes']:
                    bundle['file_hashes'][hash_type] = []
                bundle['file_hashes'][hash_type].append(value)
            elif ioc_type == 'email_address':
                bundle['emails'].append(value)
        
        return bundle
    
    def generate_integration_urls(self, alert_id, cve_id):
        """Generar URLs para integración con plataformas de seguridad"""
        base_url = f"http://localhost:{self.config.get('api', 'port', fallback='8080')}/api/v1"
        
        urls = {
            'paloalto_edl': f"{base_url}/export/paloalto/{alert_id}",
            'fortinet_feed': f"{base_url}/export/fortinet/{alert_id}",
            'cisco_list': f"{base_url}/export/cisco/{alert_id}",
            'snort_rules': f"{base_url}/export/snort/{alert_id}",
            'yara_rules': f"{base_url}/export/yara/{alert_id}",
            'stix_bundle': f"{base_url}/export/stix/{alert_id}",
            'json_full': f"{base_url}/export/json/{alert_id}"
        }
        
        return urls
    
    def generate_ioc_exports(self, alert_id, iocs):
        """Generar archivos de exportación en diferentes formatos"""
        try:
            formats = self.config.get('api', 'export_formats', fallback='').split(',')
            
            for fmt in formats:
                fmt = fmt.strip()
                if fmt == 'paloalto':
                    self.export_paloalto_edl(alert_id, iocs)
                elif fmt == 'fortinet':
                    self.export_fortinet_feed(alert_id, iocs)
                elif fmt == 'snort':
                    self.export_snort_rules(alert_id, iocs)
                elif fmt == 'yara':
                    self.export_yara_rules(alert_id, iocs)
                elif fmt == 'stix':
                    self.export_stix_bundle(alert_id, iocs)
                
                self.stats['exports_created'] += 1
            
        except Exception as e:
            logger.error(f"Error generando exports: {e}")
    
    def export_paloalto_edl(self, alert_id, iocs):
        """Exportar External Dynamic List para Palo Alto"""
        try:
            file_path = f"/var/lib/threat-intel-hub/api_exports/paloalto_{alert_id}.txt"
            
            with open(file_path, 'w') as f:
                # IPs y dominios en formato EDL
                for ioc in iocs:
                    if ioc['indicator_type'] in ['ip_address', 'domain']:
                        f.write(f"{ioc['indicator_value']}\n")
            
            # Registrar exportación
            self.register_export(alert_id, 'paloalto', file_path, len(iocs))
            
        except Exception as e:
            logger.error(f"Error exportando EDL: {e}")
    
    def export_snort_rules(self, alert_id, iocs):
        """Generar reglas Snort/Suricata"""
        try:
            file_path = f"/var/lib/threat-intel-hub/rules/snort/sid_{alert_id}.rules"
            sid_base = 9000000  # SID base para reglas custom
            
            with open(file_path, 'w') as f:
                f.write(f"# Threat Intel Hub - Alert {alert_id}\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                
                for idx, ioc in enumerate(iocs):
                    if ioc['indicator_type'] == 'ip_address':
                        rule = f'alert ip any any -> {ioc["indicator_value"]} any (msg:"TI-Hub: Malicious IP detected"; sid:{sid_base + idx}; rev:1;)\n'
                        f.write(rule)
                    elif ioc['indicator_type'] == 'domain':
                        rule = f'alert dns any any -> any any (msg:"TI-Hub: Malicious domain {ioc["indicator_value"]}"; content:"{ioc["indicator_value"]}"; sid:{sid_base + idx + 1000}; rev:1;)\n'
                        f.write(rule)
            
            self.register_export(alert_id, 'snort', file_path, len(iocs))
            
        except Exception as e:
            logger.error(f"Error exportando reglas Snort: {e}")
    
    def register_export(self, alert_id, format_type, file_path, ioc_count):
        """Registrar exportación en base de datos"""
        try:
            cursor = self.db.cursor()
            
            export_id = str(uuid.uuid4())
            download_url = f"/api/v1/download/{export_id}"
            
            query = """
                INSERT INTO ioc_exports
                (id, export_format, alert_id, ioc_count, file_path, download_url)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(query, (
                export_id, format_type, alert_id, ioc_count, file_path, download_url
            ))
            
            self.db.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error registrando export: {e}")
    
    def send_alert_notification(self, alert_id):
        """Enviar notificación de alerta por email"""
        if not self.config.get('email', 'sender_email'):
            return
        
        try:
            cursor = self.db.cursor(dictionary=True)
            
            # Obtener detalles de la alerta
            query = """
                SELECT * FROM threat_alerts WHERE id = %s
            """
            cursor.execute(query, (alert_id,))
            alert = cursor.fetchone()
            
            if not alert:
                return
            
            # Preparar email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 {alert['title']}"
            msg['From'] = self.config.get('email', 'sender_email')
            msg['To'] = self.config.get('email', 'recipient_email')
            
            # Contenido HTML
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #d32f2f;">{alert['title']}</h2>
                <pre>{alert['description']}</pre>
                
                <h3>IoCs para Bloqueo Inmediato:</h3>
                <div style="background: #f5f5f5; padding: 10px; font-family: monospace;">
                    {self.format_iocs_for_email(json.loads(alert['ioc_bundle']))}
                </div>
                
                <h3>Enlaces de Integración:</h3>
                <ul>
            """
            
            urls = json.loads(alert['integration_urls'])
            for platform, url in urls.items():
                html_content += f'<li><a href="{url}">{platform.replace("_", " ").title()}</a></li>'
            
            html_content += """
                </ul>
                <p style="color: #666; font-size: 12px;">
                    Generado por Threat Intel Hub v1.0.3<br>
                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </body>
            </html>
            """
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Enviar
            with smtplib.SMTP(self.config.get('email', 'smtp_server'), 
                             self.config.getint('email', 'smtp_port')) as server:
                server.starttls()
                server.login(
                    self.config.get('email', 'sender_email'),
                    self.config.get('email', 'sender_password')
                )
                
                recipients = self.config.get('email', 'recipient_email').split(',')
                server.send_message(msg, to_addrs=recipients)
            
            # Marcar como enviado
            update_query = """
                UPDATE threat_alerts 
                SET distribution_status = 'sent', sent_at = NOW()
                WHERE id = %s
            """
            cursor.execute(update_query, (alert_id,))
            self.db.commit()
            
            cursor.close()
            
            logger.info(f"✅ Notificación enviada para alerta {alert_id}")
            
        except Exception as e:
            logger.error(f"Error enviando notificación: {e}")
    
    def format_iocs_for_email(self, ioc_bundle):
        """Formatear IoCs para email"""
        lines = []
        
        if ioc_bundle.get('ips'):
            lines.append("IPs:")
            for ip in ioc_bundle['ips'][:10]:
                lines.append(f"  {ip}")
        
        if ioc_bundle.get('domains'):
            lines.append("\nDominios:")
            for domain in ioc_bundle['domains'][:10]:
                lines.append(f"  {domain}")
        
        if ioc_bundle.get('file_hashes'):
            lines.append("\nHashes:")
            for hash_type, hashes in ioc_bundle['file_hashes'].items():
                for hash_val in hashes[:5]:
                    lines.append(f"  {hash_type}: {hash_val}")
        
        return '\n'.join(lines)
    
    def run_monitoring_cycle(self):
        """Ejecutar ciclo de monitoreo principal"""
        logger.info("="*60)
        logger.info("🎯 THREAT INTEL HUB v1.0.3 - Ciclo de Monitoreo")
        logger.info("="*60)
        
        start_time = time.time()
        
        # Reiniciar estadísticas
        self.stats = {
            'kev_additions': 0,
            'epss_spikes': 0,
            'new_iocs': 0,
            'alerts_generated': 0,
            'exports_created': 0
        }
        
        # Ejecutar verificaciones prioritarias
        self.check_kev_additions()  # Prioridad 1: KEV
        self.check_epss_spikes()    # Prioridad 2: EPSS
        
        # Registrar actividad
        self.log_monitoring()
        
        elapsed_time = time.time() - start_time
        
        logger.info("="*60)
        logger.info(f"📊 Resumen del ciclo:")
        logger.info(f"   • Nuevas KEV: {self.stats['kev_additions']}")
        logger.info(f"   • EPSS Spikes: {self.stats['epss_spikes']}")
        logger.info(f"   • Alertas generadas: {self.stats['alerts_generated']}")
        logger.info(f"   • Exports creados: {self.stats['exports_created']}")
        logger.info(f"   • Tiempo: {elapsed_time:.2f} segundos")
        logger.info("="*60)
    
    def log_monitoring(self):
        """Registrar actividad de monitoreo"""
        try:
            cursor = self.db.cursor()
            
            query = """
                INSERT INTO monitoring_logs
                (kev_additions, epss_spikes, alerts_generated, exports_created, status)
                VALUES (%s, %s, %s, %s, 'completed')
            """
            
            cursor.execute(query, (
                self.stats['kev_additions'],
                self.stats['epss_spikes'],
                self.stats['alerts_generated'],
                self.stats['exports_created']
            ))
            
            self.db.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error registrando monitoreo: {e}")
    
    def run_scheduler(self):
        """Ejecutar scheduler con intervalos optimizados"""
        
        # Ejecutar inmediatamente
        self.run_monitoring_cycle()
        
        # Programar verificaciones
        schedule.every(30).minutes.do(self.check_kev_additions)  # KEV cada 30 min
        schedule.every(4).hours.do(self.check_epss_spikes)      # EPSS cada 4 horas
        
        logger.info("⏰ Scheduler configurado:")
        logger.info("   • KEV: cada 30 minutos")
        logger.info("   • EPSS: cada 4 horas")
        
        while True:
            schedule.run_pending()
            time.sleep(60)

def main():
    """Función principal"""
    try:
        monitor = ActionableIntelligence()
        monitor.run_scheduler()
    except KeyboardInterrupt:
        logger.info("\n🛑 Monitor detenido por el usuario")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
PYEOF
    
    chmod +x "$DATA_DIR/scripts/ti_hub_monitor.py"
    chown "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR/scripts/ti_hub_monitor.py"
    
    log_success "Monitor principal v1.0.3 creado"
}

# Crear API REST
create_api_service() {
    log_step "Creando servicio API REST..."
    
    cat > "$DATA_DIR/scripts/ti_hub_api.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Threat Intel Hub v1.0.3 - API REST
Endpoints para integración con plataformas de seguridad
"""

from flask import Flask, jsonify, send_file, request
from flask_restful import Api, Resource
from flask_cors import CORS
import mysql.connector
import configparser
import json
import os
from pathlib import Path

app = Flask(__name__)
CORS(app)
api = Api(app)

# Cargar configuración
config = configparser.ConfigParser()
config.read('/etc/threat-intel-hub/config.ini')

class DatabaseConnection:
    @staticmethod
    def get_connection():
        return mysql.connector.connect(
            host=config.get('database', 'host'),
            port=config.getint('database', 'port'),
            database=config.get('database', 'database'),
            user=config.get('database', 'user'),
            password=config.get('database', 'password')
        )

class ExportResource(Resource):
    def get(self, format_type, alert_id):
        """Obtener export en formato específico"""
        try:
            conn = DatabaseConnection.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Obtener información del export
            query = """
                SELECT file_path FROM ioc_exports 
                WHERE alert_id = %s AND export_format = %s
                ORDER BY created_at DESC LIMIT 1
            """
            cursor.execute(query, (alert_id, format_type))
            result = cursor.fetchone()
            
            cursor.close()
            conn.close()
            
            if result and os.path.exists(result['file_path']):
                return send_file(result['file_path'], as_attachment=True)
            else:
                # Generar dinámicamente si no existe
                return self.generate_export(format_type, alert_id)
                
        except Exception as e:
            return {'error': str(e)}, 500
    
    def generate_export(self, format_type, alert_id):
        """Generar export dinámicamente"""
        try:
            conn = DatabaseConnection.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Obtener IoCs de la alerta
            query = """
                SELECT ioc_bundle FROM threat_alerts WHERE id = %s
            """
            cursor.execute(query, (alert_id,))
            result = cursor.fetchone()
            
            if not result:
                return {'error': 'Alert not found'}, 404
            
            ioc_bundle = json.loads(result['ioc_bundle'])
            
            # Generar según formato
            if format_type == 'json':
                return jsonify(ioc_bundle)
            elif format_type == 'paloalto':
                return self.format_paloalto(ioc_bundle)
            elif format_type == 'fortinet':
                return self.format_fortinet(ioc_bundle)
            else:
                return {'error': 'Format not supported'}, 400
                
        except Exception as e:
            return {'error': str(e)}, 500
    
    def format_paloalto(self, ioc_bundle):
        """Formato Palo Alto EDL"""
        lines = []
        for ip in ioc_bundle.get('ips', []):
            lines.append(ip)
        for domain in ioc_bundle.get('domains', []):
            lines.append(domain)
        
        return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}
    
    def format_fortinet(self, ioc_bundle):
        """Formato Fortinet Threat Feed"""
        feed = {
            'name': 'ThreatIntelHub',
            'type': 'threat_feed',
            'entries': []
        }
        
        for ip in ioc_bundle.get('ips', []):
            feed['entries'].append({'type': 'ip', 'value': ip})
        for domain in ioc_bundle.get('domains', []):
            feed['entries'].append({'type': 'domain', 'value': domain})
        
        return jsonify(feed)

class AlertsResource(Resource):
    def get(self):
        """Obtener alertas recientes"""
        try:
            conn = DatabaseConnection.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT id, alert_type, priority, title, created_at
                FROM threat_alerts
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                ORDER BY created_at DESC
                LIMIT 100
            """
            cursor.execute(query)
            alerts = cursor.fetchall()
            
            # Convertir datetime a string
            for alert in alerts:
                alert['created_at'] = str(alert['created_at'])
            
            cursor.close()
            conn.close()
            
            return jsonify(alerts)
            
        except Exception as e:
            return {'error': str(e)}, 500

class DashboardResource(Resource):
    def get(self):
        """Obtener estadísticas para dashboard"""
        try:
            conn = DatabaseConnection.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            stats = {}
            
            # KEV activas
            cursor.execute("SELECT COUNT(*) as count FROM kev_vulnerabilities")
            stats['kev_total'] = cursor.fetchone()['count']
            
            # Alertas últimas 24h
            cursor.execute("""
                SELECT COUNT(*) as count FROM threat_alerts 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            stats['alerts_24h'] = cursor.fetchone()['count']
            
            # IoCs activos
            cursor.execute("SELECT COUNT(*) as count FROM iocs WHERE is_active = TRUE")
            stats['active_iocs'] = cursor.fetchone()['count']
            
            cursor.close()
            conn.close()
            
            return jsonify(stats)
            
        except Exception as e:
            return {'error': str(e)}, 500

# Registrar endpoints
api.add_resource(ExportResource, '/api/v1/export/<string:format_type>/<string:alert_id>')
api.add_resource(AlertsResource, '/api/v1/alerts')
api.add_resource(DashboardResource, '/api/v1/dashboard')

# Health check
@app.route('/health')
def health_check():
    return {'status': 'healthy', 'version': '1.0.3'}

if __name__ == '__main__':
    port = config.getint('api', 'port', fallback=8080)
    app.run(host='0.0.0.0', port=port, debug=False)
PYEOF
    
    chmod +x "$DATA_DIR/scripts/ti_hub_api.py"
    chown "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR/scripts/ti_hub_api.py"
    
    log_success "API REST creada"
}

# Crear servicio systemd
create_systemd_service() {
    log_step "Creando servicios systemd..."
    
    # Servicio principal del monitor
    cat > /etc/systemd/system/threat-intel-hub.service << 'SVCEOF'
[Unit]
Description=Threat Intel Hub v1.0.3 - Monitor Principal
After=network.target mysql.service mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=ti-hub
Group=ti-hub
WorkingDirectory=/opt/threat-intel-hub
Environment="PATH=/opt/threat-intel-hub/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/threat-intel-hub/venv/bin/python /var/lib/threat-intel-hub/scripts/ti_hub_monitor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
    
    # Servicio API
    cat > /etc/systemd/system/threat-intel-hub-api.service << 'APISVCEOF'
[Unit]
Description=Threat Intel Hub v1.0.3 - API REST
After=network.target threat-intel-hub.service
Wants=network-online.target

[Service]
Type=simple
User=ti-hub
Group=ti-hub
WorkingDirectory=/opt/threat-intel-hub
Environment="PATH=/opt/threat-intel-hub/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/threat-intel-hub/venv/bin/python /var/lib/threat-intel-hub/scripts/ti_hub_api.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
APISVCEOF
    
    systemctl daemon-reload
    systemctl enable threat-intel-hub.service
    systemctl enable threat-intel-hub-api.service
    
    log_success "Servicios systemd creados"
}

# Configurar logrotate
setup_logrotate() {
    log_step "Configurando rotación de logs..."
    
    cat > /etc/logrotate.d/threat-intel-hub << 'LOGEOF'
/var/log/threat-intel-hub/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ti-hub ti-hub
    sharedscripts
    postrotate
        systemctl reload threat-intel-hub 2>/dev/null || true
    endscript
}
LOGEOF
    
    log_success "Rotación de logs configurada"
}

# Resumen de instalación
show_summary() {
    log_header "INSTALACIÓN COMPLETADA - v${SCRIPT_VERSION}"
    
    echo -e "${GREEN}✅ Threat Intel Hub v${SCRIPT_VERSION} instalado exitosamente${NC}"
    echo
    echo "📋 INFORMACIÓN DEL SISTEMA:"
    echo "   • Versión: ${SCRIPT_VERSION} - Inteligencia Accionable"
    echo "   • Usuario: ${INSTALL_USER}"
    echo "   • Config: ${CONFIG_DIR}/config.ini"
    echo "   • Logs: ${LOG_DIR}"
    echo
    echo "🔐 BASE DE DATOS:"
    echo "   • Database: ti_hub"
    echo "   • Usuario: ti_hub_user"
    echo "   • Password: ${DB_PASSWORD}"
    echo -e "   ${YELLOW}⚠️ GUARDE ESTA CONTRASEÑA${NC}"
    echo
    
    echo "🎯 CARACTERÍSTICAS v1.0.3:"
    echo "   • KEV Trigger: $([[ "$ENABLE_KEV_TRIGGER" == "true" ]] && echo "✅ Activo" || echo "❌ Inactivo")"
    echo "   • EPSS Trigger: $([[ "$ENABLE_EPSS_TRIGGER" == "true" ]] && echo "✅ Activo" || echo "❌ Inactivo")"
    echo "   • EPSS Threshold: ${EPSS_SPIKE_THRESHOLD}"
    echo "   • IoC Feeds: $([[ "$ENABLE_IOC_FEEDS" == "true" ]] && echo "✅ Activo" || echo "❌ Inactivo")"
    echo
    
    if [[ "$HAS_WAZUH" == "true" ]]; then
        echo "🛡️ WAZUH:"
        echo "   • Estado: ✅ Integrado"
        if [[ -n "$WAZUH_URL" ]]; then
            echo "   • Manager: ${WAZUH_URL}"
        fi
    fi
    
    echo
    echo "🌐 API REST:"
    echo "   • Puerto: ${API_PORT}"
    echo "   • Endpoints:"
    echo "     - GET /api/v1/alerts"
    echo "     - GET /api/v1/dashboard"
    echo "     - GET /api/v1/export/{format}/{alert_id}"
    echo
    
    echo "📧 NOTIFICACIONES:"
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "   • Email: ✅ Configurado"
        echo "   • Destinatarios: ${RECIPIENT_EMAIL}"
    else
        echo "   • Email: ❌ No configurado"
    fi
    echo
    
    echo -e "${CYAN}🎮 COMANDOS:${NC}"
    echo -e "   • Iniciar monitor: ${GREEN}sudo systemctl start threat-intel-hub${NC}"
    echo -e "   • Iniciar API: ${GREEN}sudo systemctl start threat-intel-hub-api${NC}"
    echo -e "   • Ver logs: ${PURPLE}sudo journalctl -u threat-intel-hub -f${NC}"
    echo -e "   • Estado: ${BLUE}sudo systemctl status threat-intel-hub${NC}"
    echo
    
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    THREAT INTEL HUB v1.0.3 - READY FOR ACTION!           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
}

# Función principal
main() {
    show_welcome_banner
    check_prerequisites
    detect_wazuh
    install_dependencies
    create_system_user
    create_directories
    setup_python
    setup_database
    configure_actionable_intelligence
    configure_api_key
    configure_email
    
    if [[ "$HAS_WAZUH" == "true" ]]; then
        configure_wazuh_integration
    fi
    
    configure_threat_sources
    create_config_file
    create_main_monitor_script
    create_api_service
    create_systemd_service
    setup_logrotate
    show_summary
    
    echo
    read -p "¿Iniciar servicios ahora? (Y/n): " start_now
    if [[ ! $start_now =~ ^[Nn]$ ]]; then
        systemctl start threat-intel-hub
        systemctl start threat-intel-hub-api
        sleep 3
        echo
        systemctl status threat-intel-hub --no-pager
        echo
        systemctl status threat-intel-hub-api --no-pager
    fi
}

# Ejecutar
mains, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """
                        cursor.execute(insert_query, (
                            cve_id,
                            vuln.get('vendorProject'),
                            vuln.get('product'),
                            vuln.get('vulnerabilityName'),
                            vuln.get('dateAdded'),
                            vuln.get('shortDescription'),
                            vuln.get('requiredAction'),
                            vuln.get('dueDate'),
                            vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known',
                            vuln.get('notes')
                        ))
                        
                        # Buscar IoCs inmediatamente
                        iocs = self.search_iocs_for_cve(cve_id)
                        
                        # Crear alerta accionable
                        self.create_kev_alert(cve_id, vuln, iocs)
                        
                        self.stats['kev_additions'] += 1
                    
                    elif not existing['alert_sent']:
                        # KEV existente pero sin alerta enviada
                        iocs = self.search_iocs_for_cve(cve_id)
                        if iocs:
                            self.create_kev_alert(cve_id, vuln, iocs)
                
                self.db.commit()
                cursor.close()
                
                if self.stats['kev_additions'] > 0:
                    logger.info(f"✅ {self.stats['kev_additions']} nuevas KEV procesadas")
                
        except Exception as e:
            logger.error(f"❌ Error verificando KEV: {e}")
    
    def check_epss_spikes(self):
        """Detectar cambios significativos en EPSS"""
        if not self.config.getboolean('triggers', 'epss_enabled', fallback=True):
            return
        
        logger.info("📈 Verificando spikes en EPSS...")
        threshold = self.config.getfloat('triggers', 'epss_spike_threshold', fallback=0.2)
        
        try:
            # Obtener datos EPSS
            url = "https://api.first.org/data/v1/epss"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                cursor = self.db.cursor(dictionary=True)
                
                for item in data.get('data', [])[:1000]:  # Limitar a top 1000
                    cve_id = item.get('cve')
                    new_score = float(item.get('epss', 0))
                    new_percentile = float(item.get('percentile', 0))
                    
                    # Obtener score anterior
                    query = "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE cve_id = %s"
                    cursor.execute(query, (cve_id,))
                    old_data = cursor.fetchone()
                    
                    if old_data:
                        old_score = float(old_data['epss_score'] or 0)
                        delta = new_score - old_score
                        
                        if delta >= threshold:
                            # SPIKE DETECTADO
                            logger.warning(f"📊 EPSS SPIKE: {cve_id} ({old_score:.3f} → {new_score:.3f})")
                            
                            # Registrar cambio
                            change_query = """
                                INSERT INTO epss_changes
                                (cve_id, old_score, new_score, score_delta,
                                 old_percentile, new_percentile, percentile_delta, alert_triggered)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE)
                            """
                            cursor.execute(change_query, (
                                cve_id, old_score, new_score, delta,
                                old_data['epss_percentile'], new_percentile,
                                new_percentile - float(old_data['epss_percentile'] or 0)
                            ))
                            
                            # Buscar IoCs
                            iocs = self.search_iocs_for_cve(cve_id)
                            
                            # Crear alerta
                            self.create_epss_alert(cve_id, old_score, new_score, iocs)
                            
                            self.stats['epss_spikes'] += 1
                        
                        # Actualizar score
                        update_query = """
                            UPDATE vulnerabilities 
                            SET epss_score = %s, epss_percentile = %s, 
                                epss_delta = %s, epss_date = CURDATE()
                            WHERE cve_id = %s
                        """
                        cursor.execute(update_query, (new_score, new_percentile, delta, cve_id))
                
                self.db.commit()
                cursor.close()
                
                if self.stats['epss_spikes'] > 0:
                    logger.info(f"⚡ {self.stats['epss_spikes']} spikes EPSS detectados")
                
        except Exception as e:
            logger.error(f"❌ Error verificando EPSS: {e}")
    
    def search_iocs_for_cve(self, cve_id):
        """Buscar IoCs asociados a un CVE"""
        iocs = []
        
        try:
            cursor = self.db.cursor(dictionary=True)
            
            # Buscar en relaciones existentes
            query = """
                SELECT DISTINCT i.*
                FROM iocs i
                JOIN cve_ioc_relationships cir ON i.id = cir.ioc_id
                WHERE cir.cve_id = %s AND i.is_active = TRUE
                ORDER BY i.confidence_score DESC
                LIMIT 100
            """
            cursor.execute(query, (cve_id,))
            iocs = cursor.fetchall()
            
            # Si no hay IoCs locales, buscar en fuentes externas
            if not iocs and self.config.get('otx', 'api_key'):
                iocs.extend(self.search_otx_for_cve(cve_id))
            
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error buscando IoCs para {cve_id}: {e}")
        
        return iocs
    
    def search_otx_for_cve(self, cve_id):
        """Buscar IoCs en AlienVault OTX"""
        iocs = []
        
        try:
            api_key = self.config.get('otx', 'api_key')
            if not api_key:
                return iocs
            
            headers = {'X-OTX-API-KEY': api_key}
            url = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general"
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extraer pulsos relacionados
                for pulse in data.get('pulse_info', {}).get('pulses', []):
                    pulse_id = pulse.get('id')
                    
                    # Obtener indicadores del pulso
                    ind_url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators"
                    ind_response = requests.get(ind_url, headers=headers, timeout=30)
                    
                    if ind_response.status_code == 200:
                        indicators = ind_response.json().get('results', [])
                        
                        for ind in indicators[:20]:  # Limitar a 20 por pulso
                            iocs.append({
                                'indicator_value': ind.get('indicator'),
                                'indicator_type': self.map_otx_type(ind.get('type')),
                                'source_feed': 'AlienVault OTX',
                                'confidence_score': 0.7,
                                'description': ind.get('title', '')
                            })
                            
        except Exception as e:
            logger.error(f"Error buscando en OTX: {e}")
        
        return iocs
    
    def map_otx_type(self, otx_type):
        """Mapear tipos de OTX a tipos internos"""
        mapping = {
            'IPv4': 'ip_address',
            'domain': 'domain',
            'URL': 'url',
            'FileHash-MD5': 'file_hash_md5',
            'FileHash-SHA1': 'file_hash_sha1',
            'FileHash-SHA256': 'file_hash_sha256'
        }
        return mapping.get(otx_type, 'unknown')
    
    def create_kev_alert(self, cve_id, kev_data, iocs):
        """Crear alerta para nueva KEV"""
        try:
            alert_id = str(uuid.uuid4())
            
            # Preparar bundle de IoCs
            ioc_bundle = self.prepare_ioc_bundle(iocs)
            
            # Generar URLs de integración
            integration_urls = self.generate_integration_urls(alert_id, cve_id)
            
            # Crear alerta
            cursor = self.db.cursor()
            
            query = """
                INSERT INTO threat_alerts
                (id, alert_type, trigger_source, priority, title, description,
                 cve_list, ioc_bundle, integration_urls, distribution_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            title = f"🚨 KEV CRÍTICO: {cve_id} - {kev_data.get('vulnerabilityName', 'Unknown')}"
            
            description = f"""
            Vulnerabilidad activamente explotada detectada:
            
            CVE: {cve_id}
            Producto: {kev_data.get('product')}
            Vendor: {kev_data.get('vendorProject')}
            Descripción: {kev_data.get('shortDescription')}
            Acción requerida: {kev_data.get('requiredAction')}
            Fecha límite: {kev_data.get('dueDate')}
            Ransomware: {'SÍ' if kev_data.get('knownRansomwareCampaignUse') == 'Known' else 'NO'}
            
            IoCs detectados: {len(iocs)}
            """
            
            cursor.execute(query, (
                alert_id,
                'kev_addition',
                'CISA KEV',
                'CRITICAL',
                title,
                description,
                json.dumps([cve_id]),
                json.dumps(ioc_bundle),
                json.dumps(integration_urls),
                'pending'
            ))
            
            # Marcar KEV como alertado
            update_query = "UPDATE kev_vulnerabilities SET alert_sent = TRUE WHERE cve_id = %s"
            cursor.execute(update_query, (cve_id,))
            
            self.db.commit()
            cursor.close()
            
            # Enviar notificación
            self.send_alert_notification(alert_id)
            
            # Generar exports
            if self.config.getboolean('api', 'enabled', fallback=True):
                self.generate_ioc_exports(alert_id, iocs)
            
            self.stats['alerts_generated'] += 1
            
            logger.info(f"✅ Alerta KEV creada: {alert_id}")
            
        except Exception as e:
            logger.error(f"Error creando alerta KEV: {e}")
    
    def create_epss_alert(self, cve_id, old_score, new_score, iocs):
        """Crear alerta para spike EPSS"""
        try:
            alert_id = str(uuid.uuid4())
            
            ioc_bundle = self.prepare_ioc_bundle(iocs)
            integration_urls = self.generate_integration_urls(alert_id, cve_id)
            
            cursor = self.db.cursor()
            
            query = """
                INSERT INTO threat_alerts
                (id, alert_type, trigger_source, priority, title, description,
                 cve_list, ioc_bundle, integration_urls, distribution_status)
                VALUES (%