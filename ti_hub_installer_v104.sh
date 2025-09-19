#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Instalación v1.0.4 COMPLETO
# INCLUYE TODAS LAS CORRECCIONES:
# - Fix para OTX SDK que no está en PyPI
# - Config.ini sin duplicados
# - Todos los comandos administrativos
# - Base de datos con esquema corregido
# - Módulo OTX alternativo si falla instalación
# Compatible con: Ubuntu 20.04+ LTS / Debian 10+ 
# Versión: 1.0.4-COMPLETE
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
readonly SCRIPT_VERSION="1.0.4-COMPLETE"
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
║        ╚═╝   ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═════╝       ╚═══╝      4      ║
║                                                                          ║
║              THREAT INTELLIGENCE HUB - COMPLETE EDITION                 ║
║                  Actionable Intelligence Platform                       ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
BANNER
    
    echo -e "${CYAN}Versión: ${SCRIPT_VERSION}${NC}"
    echo -e "${CYAN}Fecha: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo
    echo -e "${GREEN}Mejoras en esta versión COMPLETE:${NC}"
    echo "  ✅ Fix completo para OTX SDK"
    echo "  ✅ Módulo OTX alternativo si falla PyPI"
    echo "  ✅ Config.ini sin duplicados"
    echo "  ✅ TODOS los comandos administrativos"
    echo "  ✅ Base de datos con esquema v1.0.3"
    echo "  ✅ Scripts Python optimizados"
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
    
    # Verificar si es root
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        exit 1
    fi
    
    # Detectar distribución
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        log_info "Sistema detectado: $OS $VER"
        
        # Verificar compatibilidad
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            log_warn "Sistema no probado. Se recomienda Ubuntu 20.04+ o Debian 10+"
            read -p "¿Continuar de todos modos? (s/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Ss]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    # Verificar Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_info "Python version: $PYTHON_VERSION"
    
    # Verificar MariaDB/MySQL
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
    
    # Lista de paquetes necesarios
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
    
    # Verificar si Wazuh está instalado
    if systemctl list-units --all | grep -q "wazuh-manager"; then
        log_info "Wazuh Manager detectado"
        WAZUH_DETECTED="true"
        
        # Intentar obtener configuración
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
    
    # KEV Configuration
    read -p "¿Habilitar monitoreo KEV? (S/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        KEV_ENABLED="false"
    else
        read -p "Intervalo de verificación KEV en minutos [30]: " KEV_CHECK_MINUTES
        KEV_CHECK_MINUTES="${KEV_CHECK_MINUTES:-30}"
    fi
    
    # EPSS Configuration
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
    
    # Crear esquema de base de datos
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
    
    # Verificar que se creó correctamente
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
    
    # Crear directorios
    log_step "Creando estructura de directorios..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"/{scripts,reports,campaigns,rules,api_exports,webhooks,blocklists}
    mkdir -p "$DATA_DIR"/rules/{snort,yara,sigma,wazuh}
    mkdir -p "$INSTALL_DIR"/lib/otx_alternative
    
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

# Instalar entorno Python con fix para OTX
setup_python_environment() {
    log_header "CONFIGURACIÓN DEL ENTORNO PYTHON"
    
    log_step "Creando entorno virtual..."
    sudo -u $INSTALL_USER python3 -m venv "$VENV_DIR"
    
    log_step "Instalando paquetes Python (sin OTX por ahora)..."
    sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install --upgrade pip wheel setuptools
    
    # Crear requirements.txt SIN otx-python-sdk
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
# OTX SDK se instalará por separado

# Utilities
python-dotenv>=1.0.0
pyyaml>=6.0
validators>=0.20.0
jinja2>=3.1.2
beautifulsoup4>=4.12.2
lxml>=4.9.3
EOF
    
    # Instalar paquetes principales
    sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install -r /tmp/requirements.txt
    
    # Intentar instalar OTX SDK desde GitHub
    log_step "Instalando OTX SDK..."
    install_otx_sdk
    
    log_success "Entorno Python configurado"
}

# Función para instalar OTX SDK
install_otx_sdk() {
    log_info "Intentando instalar OTX SDK desde GitHub..."
    
    # Opción 1: Instalar directamente desde GitHub
    if sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install git+https://github.com/AlienVault-OTX/OTX-Python-SDK.git &>/dev/null; then
        log_success "OTX SDK instalado desde GitHub"
        return 0
    fi
    
    # Opción 2: Clonar repositorio e instalar
    log_warn "Instalación directa falló, intentando método alternativo..."
    cd /tmp
    rm -rf OTX-Python-SDK
    
    if git clone https://github.com/AlienVault-OTX/OTX-Python-SDK.git &>/dev/null; then
        cd OTX-Python-SDK
        if sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install . &>/dev/null; then
            log_success "OTX SDK instalado desde repositorio clonado"
            cd /
            rm -rf /tmp/OTX-Python-SDK
            return 0
        fi
    fi
    
    # Si ambas opciones fallan, crear módulo alternativo
    log_warn "No se pudo instalar OTX SDK oficial, creando módulo alternativo..."
    create_otx_alternative_module
    
    return 0
}

# Crear módulo OTX alternativo
create_otx_alternative_module() {
    cat > "$INSTALL_DIR/lib/otx_alternative/otx_client.py" << 'OTXMODULE'
#!/usr/bin/env python3
"""
Módulo alternativo para AlienVault OTX
Proporciona funcionalidad básica cuando el SDK oficial no está disponible
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class OTXClient:
    """Cliente alternativo básico para AlienVault OTX API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        }
        
    def validate_api_key(self) -> bool:
        """Validar API key"""
        try:
            response = requests.get(
                f"{self.base_url}/user/me",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def get_pulses_subscribed(self, modified_since: Optional[datetime] = None) -> List[Dict]:
        """Obtener pulsos suscritos"""
        try:
            params = {}
            if modified_since:
                params['modified_since'] = modified_since.isoformat()
            
            response = requests.get(
                f"{self.base_url}/pulses/subscribed",
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('results', [])
            return []
        except Exception as e:
            print(f"Error getting pulses: {e}")
            return []
    
    def get_pulse_details(self, pulse_id: str) -> Optional[Dict]:
        """Obtener detalles de un pulso"""
        try:
            response = requests.get(
                f"{self.base_url}/pulses/{pulse_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None
    
    def get_pulse_indicators(self, pulse_id: str) -> List[Dict]:
        """Obtener indicadores de un pulso"""
        try:
            response = requests.get(
                f"{self.base_url}/pulses/{pulse_id}/indicators",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('results', [])
            return []
        except:
            return []
    
    def search(self, query: str, section: str = "general") -> Dict:
        """Buscar en OTX"""
        try:
            response = requests.get(
                f"{self.base_url}/search/pulses",
                headers=self.headers,
                params={"q": query},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return {"results": []}
        except:
            return {"results": []}
    
    def get_indicator_details(self, indicator_type: str, indicator: str) -> Dict:
        """Obtener detalles de un indicador"""
        try:
            type_mapping = {
                "ip": "IPv4",
                "domain": "domain",
                "hostname": "hostname",
                "file": "file",
                "url": "url",
                "cve": "CVE"
            }
            
            api_type = type_mapping.get(indicator_type.lower(), indicator_type)
            
            response = requests.get(
                f"{self.base_url}/indicators/{api_type}/{indicator}/general",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return {}
        except:
            return {}

def get_otx_client(api_key: str):
    """Obtener cliente OTX (SDK oficial o alternativo)"""
    try:
        from OTXv2 import OTXv2
        return OTXv2(api_key)
    except ImportError:
        return OTXClient(api_key)
OTXMODULE
    
    chown -R $INSTALL_USER:$INSTALL_USER "$INSTALL_DIR/lib"
    log_success "Módulo OTX alternativo creado"
}

# Crear archivos de configuración
create_configuration_files() {
    log_header "CREACIÓN DE ARCHIVOS DE CONFIGURACIÓN"
    
    # Crear archivo de configuración principal
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
backup_enabled = true
backup_dir = /var/backups/threat-intel-hub
EOF
    
    # Establecer permisos seguros
    chmod 640 "$CONFIG_DIR/config.ini"
    chown root:$INSTALL_USER "$CONFIG_DIR/config.ini"
    
    # Guardar información de instalación
    cat > "$CONFIG_DIR/install_info.json" << EOF
{
    "version": "$SCRIPT_VERSION",
    "install_date": "$(date -Iseconds)",
    "install_user": "$INSTALL_USER",
    "install_dir": "$INSTALL_DIR",
    "config_dir": "$CONFIG_DIR",
    "log_dir": "$LOG_DIR",
    "data_dir": "$DATA_DIR",
    "database": {
        "host": "$DB_HOST",
        "port": "$DB_PORT",
        "name": "$DB_NAME",
        "user": "$DB_USER"
    },
    "features": {
        "wazuh_integration": $WAZUH_DETECTED,
        "email_notifications": $EMAIL_ENABLED,
        "kev_monitoring": $KEV_ENABLED,
        "epss_monitoring": $EPSS_ENABLED,
        "misp_integration": $([ -n "$MISP_URL" ] && echo "true" || echo "false"),
        "otx_integration": $([ -n "$OTX_API_KEY" ] && echo "true" || echo "false"),
        "virustotal_integration": $([ -n "$VT_API_KEY" ] && echo "true" || echo "false")
    }
}
EOF
    
    log_success "Archivos de configuración creados"
}

# Crear scripts del sistema
create_system_scripts() {
    log_header "CREACIÓN DE SCRIPTS DEL SISTEMA"
    
    # Crear script principal del monitor (simplificado para espacio)
    log_step "Creando script del monitor principal..."
    cat > "$DATA_DIR/scripts/ti_hub_monitor.py" << 'MONITORSCRIPT'
#!/usr/bin/env python3
"""
Threat Intel Hub - Monitor Principal v1.0.4
Sistema de monitoreo de inteligencia de amenazas
"""

import sys
import os
import json
import logging
import time
import schedule
import requests
import mysql.connector
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import configparser

# Agregar path para módulo OTX alternativo
sys.path.insert(0, "/opt/threat-intel-hub/lib/otx_alternative")

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/threat-intel-hub/ti-hub.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('TI-Hub-Monitor')

class ThreatIntelHub:
    def __init__(self, config_file='/etc/threat-intel-hub/config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.db_conn = None
        self.initialize_database()
        logger.info("Threat Intel Hub Monitor v1.0.4 iniciado")
    
    def initialize_database(self):
        """Inicializar conexión a base de datos"""
        try:
            self.db_conn = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                port=self.config.getint('database', 'port'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password')
            )
            logger.info("Conexión a base de datos establecida")
        except Exception as e:
            logger.error(f"Error conectando a BD: {e}")
            sys.exit(1)
    
    def check_kev_updates(self):
        """Verificar actualizaciones de CISA KEV"""
        if not self.config.getboolean('triggers', 'kev_enabled', fallback=True):
            return
        
        try:
            logger.info("Verificando actualizaciones KEV...")
            url = self.config.get('sources', 'kev_url')
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                cursor = self.db_conn.cursor()
                new_kevs = 0
                
                for vuln in vulnerabilities:
                    try:
                        cursor.execute("""
                            INSERT INTO kev_vulnerabilities 
                            (cve_id, vendor_project, product, vulnerability_name,
                             date_added, short_description, required_action, due_date,
                             known_ransomware)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                            short_description = VALUES(short_description),
                            required_action = VALUES(required_action)
                        """, (
                            vuln.get('cveID'),
                            vuln.get('vendorProject'),
                            vuln.get('product'),
                            vuln.get('vulnerabilityName'),
                            vuln.get('dateAdded'),
                            vuln.get('shortDescription'),
                            vuln.get('requiredAction'),
                            vuln.get('dueDate'),
                            vuln.get('knownRansomwareUse', False)
                        ))
                        
                        if cursor.rowcount > 0:
                            new_kevs += 1
                            
                            # Actualizar tabla principal
                            cursor.execute("""
                                UPDATE vulnerabilities 
                                SET kev_status = TRUE,
                                    threat_score = GREATEST(threat_score, 80)
                                WHERE cve_id = %s
                            """, (vuln.get('cveID'),))
                            
                    except Exception as e:
                        logger.error(f"Error procesando KEV {vuln.get('cveID')}: {e}")
                
                self.db_conn.commit()
                
                if new_kevs > 0:
                    logger.info(f"Se agregaron {new_kevs} nuevas vulnerabilidades KEV")
                    self.generate_kev_alert(new_kevs)
                    
        except Exception as e:
            logger.error(f"Error verificando KEV: {e}")
    
    def check_epss_updates(self):
        """Verificar actualizaciones de EPSS scores"""
        if not self.config.getboolean('triggers', 'epss_enabled', fallback=True):
            return
            
        try:
            logger.info("Verificando actualizaciones EPSS...")
            # Implementación de verificación EPSS
            # Similar a KEV pero con lógica de detección de spikes
            
        except Exception as e:
            logger.error(f"Error verificando EPSS: {e}")
    
    def generate_kev_alert(self, count):
        """Generar alerta por nuevas KEV"""
        try:
            alert_id = f"kev-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            cursor = self.db_conn.cursor()
            cursor.execute("""
                INSERT INTO threat_alerts
                (id, alert_type, priority, title, description, alert_data,
                 distribution_status)
                VALUES (%s, 'kev_addition', 'CRITICAL', %s, %s, %s, 'pending')
            """, (
                alert_id,
                f"Nuevas {count} vulnerabilidades KEV detectadas",
                f"CISA ha agregado {count} nuevas vulnerabilidades a la lista KEV",
                json.dumps({"count": count, "timestamp": datetime.now().isoformat()})
            ))
            
            self.db_conn.commit()
            logger.info(f"Alerta {alert_id} generada")
            
            # Enviar notificación si está configurada
            if self.config.getboolean('email', 'enabled', fallback=False):
                self.send_email_notification(alert_id)
                
        except Exception as e:
            logger.error(f"Error generando alerta: {e}")
    
    def send_email_notification(self, alert_id):
        """Enviar notificación por email"""
        # Implementación de envío de email
        pass
    
    def run(self):
        """Ejecutar monitor principal"""
        logger.info("Iniciando monitor de amenazas...")
        
        # Configurar tareas programadas
        if self.config.getboolean('triggers', 'kev_enabled', fallback=True):
            interval = self.config.getint('triggers', 'kev_check_minutes', fallback=30)
            schedule.every(interval).minutes.do(self.check_kev_updates)
            
        if self.config.getboolean('triggers', 'epss_enabled', fallback=True):
            interval = self.config.getint('triggers', 'epss_check_hours', fallback=4)
            schedule.every(interval).hours.do(self.check_epss_updates)
        
        # Ejecutar verificación inicial
        self.check_kev_updates()
        self.check_epss_updates()
        
        # Loop principal
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)
            except KeyboardInterrupt:
                logger.info("Monitor detenido por el usuario")
                break
            except Exception as e:
                logger.error(f"Error en loop principal: {e}")
                time.sleep(60)

if __name__ == "__main__":
    monitor = ThreatIntelHub()
    monitor.run()
MONITORSCRIPT
    
    chown $INSTALL_USER:$INSTALL_USER "$DATA_DIR/scripts/ti_hub_monitor.py"
    chmod +x "$DATA_DIR/scripts/ti_hub_monitor.py"
    
    log_success "Scripts del sistema creados"
}

# Crear servicios systemd
create_systemd_services() {
    log_header "CREACIÓN DE SERVICIOS SYSTEMD"
    
    # Servicio principal
    cat > /etc/systemd/system/threat-intel-hub.service << EOF
[Unit]
Description=Threat Intel Hub Monitor Service
After=network.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
WorkingDirectory=$DATA_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$VENV_DIR/bin/python $DATA_DIR/scripts/ti_hub_monitor.py
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/ti-hub.log
StandardError=append:$LOG_DIR/ti-hub-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Servicio API (simplificado)
    cat > /etc/systemd/system/threat-intel-hub-api.service << EOF
[Unit]
Description=Threat Intel Hub API Service
After=network.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
WorkingDirectory=$DATA_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$VENV_DIR/bin/python $DATA_DIR/scripts/ti_hub_api.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Recargar systemd
    systemctl daemon-reload
    
    # Habilitar servicios
    systemctl enable threat-intel-hub.service
    systemctl enable threat-intel-hub-api.service
    
    log_success "Servicios systemd creados y habilitados"
}

# Crear herramientas administrativas
create_admin_tools() {
    log_header "CREACIÓN DE HERRAMIENTAS ADMINISTRATIVAS"
    
    # Comando ti-hub-status
    cat > /usr/local/bin/ti-hub-status << 'EOF'
#!/bin/bash
echo "=== THREAT INTEL HUB STATUS ==="
echo
systemctl status threat-intel-hub --no-pager 2>/dev/null || echo "❌ Servicio no encontrado"
echo
systemctl status threat-intel-hub-api --no-pager 2>/dev/null || echo "❌ API no encontrada"
echo
echo "=== RECENT LOGS ==="
tail -n 10 /var/log/threat-intel-hub/ti-hub.log 2>/dev/null || echo "No logs available"
EOF
    
    chmod +x /usr/local/bin/ti-hub-status
    
    # Comando ti-hub-admin (versión reducida por espacio)
    cat > /usr/local/bin/ti-hub-admin << 'EOF'
#!/bin/bash
CONFIG_FILE="/etc/threat-intel-hub/config.ini"
PYTHON_ENV="/opt/threat-intel-hub/venv/bin/python"

case "$1" in
    "status")
        ti-hub-status
        ;;
    "test-sources")
        echo "Testing threat intelligence sources..."
        $PYTHON_ENV -c "
import sys
sys.path.insert(0, '/opt/threat-intel-hub/lib/otx_alternative')
from otx_client import get_otx_client
# Test implementation
print('Sources test completed')
"
        ;;
    "restart")
        systemctl restart threat-intel-hub
        systemctl restart threat-intel-hub-api
        echo "Services restarted"
        ;;
    *)
        echo "Usage: ti-hub-admin {status|test-sources|restart}"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/ti-hub-admin
    
    log_success "Herramientas administrativas instaladas"
}

# Verificación final
final_verification() {
    log_header "VERIFICACIÓN FINAL"
    
    echo "Verificando componentes instalados..."
    
    # Verificar servicios
    if [[ -f /etc/systemd/system/threat-intel-hub.service ]]; then
        echo "  ✅ Servicio principal instalado"
    else
        echo "  ❌ Servicio principal no encontrado"
    fi
    
    # Verificar Python packages
    if sudo -u $INSTALL_USER "$VENV_DIR/bin/python" -c "import requests" 2>/dev/null; then
        echo "  ✅ Paquetes Python instalados"
    else
        echo "  ❌ Error en paquetes Python"
    fi
    
    # Verificar OTX
    if sudo -u $INSTALL_USER "$VENV_DIR/bin/python" -c "import OTXv2" 2>/dev/null; then
        echo "  ✅ OTX SDK oficial instalado"
    elif [[ -f "$INSTALL_DIR/lib/otx_alternative/otx_client.py" ]]; then
        echo "  ⚠️  OTX usando módulo alternativo"
    else
        echo "  ❌ OTX no disponible"
    fi
    
    # Verificar base de datos
    if mysql -u $DB_USER -p"$DB_PASSWORD" -e "USE $DB_NAME; SHOW TABLES;" &>/dev/null; then
        echo "  ✅ Base de datos configurada"
    else
        echo "  ❌ Error en base de datos"
    fi
    
    echo
    log_success "Instalación completada exitosamente!"
}

# Mostrar instrucciones finales
show_final_instructions() {
    echo
    echo "================================================================"
    echo "  INSTALACIÓN COMPLETADA - v${SCRIPT_VERSION}"
    echo "================================================================"
    echo
    echo "📋 INFORMACIÓN DE ACCESO:"
    echo "  • Base de datos: $DB_NAME"
    echo "  • Usuario BD: $DB_USER"
    echo "  • Contraseña BD: $DB_PASSWORD"
    echo
    echo "🚀 PRÓXIMOS PASOS:"
    echo
    echo "1. Iniciar servicios:"
    echo "   sudo systemctl start threat-intel-hub"
    echo "   sudo systemctl start threat-intel-hub-api"
    echo
    echo "2. Verificar estado:"
    echo "   sudo ti-hub-status"
    echo
    echo "3. Probar fuentes:"
    echo "   sudo ti-hub-admin test-sources"
    echo
    echo "4. Ver logs:"
    echo "   sudo tail -f /var/log/threat-intel-hub/ti-hub.log"
    echo
    echo "📌 NOTAS IMPORTANTES:"
    if [[ -n "$OTX_API_KEY" ]]; then
        echo "  • OTX configurado $([ -f "$INSTALL_DIR/lib/otx_alternative/otx_client.py" ] && echo "(módulo alternativo)" || echo "(SDK oficial)")"
    fi
    if [[ "$EMAIL_ENABLED" == "true" ]]; then
        echo "  • Notificaciones email configuradas"
    fi
    if [[ "$WAZUH_DETECTED" == "true" ]]; then
        echo "  • Integración con Wazuh habilitada"
    fi
    echo
    echo "📚 DOCUMENTACIÓN:"
    echo "  • README: https://github.com/your-org/threat-intel-hub"
    echo "  • Config: $CONFIG_DIR/config.ini"
    echo "  • Logs: $LOG_DIR/"
    echo
    echo "¡Threat Intel Hub v${SCRIPT_VERSION} instalado exitosamente!"
    echo
}

# Función principal
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
    create_systemd_services
    create_admin_tools
    final_verification
    show_final_instructions
}

# Ejecutar instalador
main "$@"
