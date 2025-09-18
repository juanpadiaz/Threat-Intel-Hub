#!/bin/bash

# =============================================================================
# THREAT INTEL HUB - INSTALADOR v1.0.3
# Sistema de Inteligencia de Amenazas Accionable
# Compatible con Ubuntu 20.04+ LTS
# https://github.com/juanpadiaz/Threat-Intel-Hub
# =============================================================================

set -euo pipefail

# Versión del instalador
readonly SCRIPT_VERSION="1.0.3"
readonly SCRIPT_DATE="2025-01-17"

# Colores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Directorios y configuración
readonly INSTALL_DIR="/opt/threat-intel-hub"
readonly CONFIG_DIR="/etc/threat-intel-hub"
readonly LOG_DIR="/var/log/threat-intel-hub"
readonly DATA_DIR="/var/lib/threat-intel-hub"
readonly INSTALL_USER="ti-hub"

# Variables de configuración
DB_NAME="ti_hub"
DB_USER="ti_hub_user"
DB_PASSWORD=""
SMTP_SERVER=""
SMTP_PORT=""
SMTP_USER=""
SMTP_PASSWORD=""
RECIPIENT_EMAIL=""
NVD_API_KEY=""
OTX_API_KEY=""
MISP_URL=""
MISP_API_KEY=""
WAZUH_ENABLED="false"
WAZUH_MANAGER_URL=""
WAZUH_USER=""
WAZUH_PASSWORD=""

# Funciones de logging
log_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}"
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗       ║
║     ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝       ║
║        ██║   ███████║██████╔╝█████╗  ███████║   ██║          ║
║        ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║          ║
║        ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║          ║
║        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝          ║
║                                                                ║
║              ██╗███╗   ██╗████████╗███████╗██╗               ║
║              ██║████╗  ██║╚══██╔══╝██╔════╝██║               ║
║              ██║██╔██╗ ██║   ██║   █████╗  ██║               ║
║              ██║██║╚██╗██║   ██║   ██╔══╝  ██║               ║
║              ██║██║ ╚████║   ██║   ███████╗███████╗           ║
║              ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝           ║
║                                                                ║
║                    ██╗  ██╗██╗   ██╗██████╗                   ║
║                    ██║  ██║██║   ██║██╔══██╗                  ║
║                    ███████║██║   ██║██████╔╝                  ║
║                    ██╔══██║██║   ██║██╔══██╗                  ║
║                    ██║  ██║╚██████╔╝██████╔╝                  ║
║                    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝                   ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${GREEN}    🎯 Actionable Threat Intelligence Platform${NC}"
    echo -e "${BLUE}    Version $SCRIPT_VERSION - $(date +%Y)${NC}"
    echo
    echo -e "${YELLOW}Características principales:${NC}"
    echo "  ✅ Correlación CVE-IoC-SIEM en tiempo real"
    echo "  ✅ Triggers inteligentes (KEV, EPSS, MISP)"
    echo "  ✅ APIs REST para integración automatizada"
    echo "  ✅ Export multi-formato para EDR/Firewall/WAF"
    echo "  ✅ Integración con Wazuh SIEM"
    echo
}

# Verificar requisitos del sistema
check_system_requirements() {
    log_header "VERIFICACIÓN DE REQUISITOS DEL SISTEMA"
    
    local errors=0
    
    # Verificar sistema operativo
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            log_success "Sistema operativo: $PRETTY_NAME"
        else
            log_warn "Sistema no es Ubuntu, pueden haber incompatibilidades"
        fi
    fi
    
    # Verificar privilegios root
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        exit 1
    fi
    
    # Verificar memoria
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [[ $mem_total -lt 2000000 ]]; then
        log_warn "Memoria RAM menor a 2GB, se recomienda 4GB o más"
    else
        log_success "Memoria RAM: $(($mem_total / 1024 / 1024))GB"
    fi
    
    # Verificar espacio en disco
    local disk_free=$(df / | tail -1 | awk '{print $4}')
    if [[ $disk_free -lt 2000000 ]]; then
        log_warn "Espacio en disco menor a 2GB"
        ((errors++))
    else
        log_success "Espacio disponible: $(($disk_free / 1024 / 1024))GB"
    fi
    
    # Verificar Python 3
    if ! command -v python3 &>/dev/null; then
        log_error "Python 3 no está instalado"
        ((errors++))
    else
        local python_version=$(python3 --version 2>&1 | awk '{print $2}')
        log_success "Python: $python_version"
    fi
    
    # Verificar conectividad a Internet
    if ! ping -c 1 google.com &>/dev/null; then
        log_warn "Sin conectividad a Internet - requerido para APIs"
    else
        log_success "Conectividad a Internet: OK"
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_error "Requisitos no cumplidos. Corrija los errores antes de continuar."
        exit 1
    fi
    
    echo
}

# Instalar dependencias del sistema
install_system_dependencies() {
    log_header "INSTALACIÓN DE DEPENDENCIAS DEL SISTEMA"
    
    log_step "Actualizando repositorios..."
    apt-get update -qq
    
    log_step "Instalando paquetes esenciales..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        mariadb-server \
        mariadb-client \
        curl \
        wget \
        git \
        jq \
        cron \
        logrotate \
        openssl \
        net-tools \
        software-properties-common \
        build-essential \
        python3-dev \
        libssl-dev \
        libffi-dev \
        libmariadb-dev \
        pkg-config \
        2>/dev/null || {
        log_error "Error instalando dependencias"
        exit 1
    }
    
    log_success "Dependencias del sistema instaladas"
    echo
}

# Configurar base de datos
setup_database() {
    log_header "CONFIGURACIÓN DE BASE DE DATOS v1.0.3"
    
    # Iniciar MariaDB
    systemctl start mariadb
    systemctl enable mariadb
    
    # Generar contraseña segura
    DB_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    log_step "Creando base de datos y usuario..."
    
    mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null || true
    mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    log_step "Creando esquema de base de datos v1.0.3..."
    
    # CORRECCIÓN: Usar backticks para la columna 'references' que es palabra reservada
    mysql $DB_NAME << 'EOF'
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
    `references` JSON,
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
);

-- Tabla de vulnerabilidades KEV
CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    vendor_project VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name VARCHAR(500),
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve (cve_id),
    INDEX idx_date_added (date_added),
    INDEX idx_ransomware (known_ransomware)
);

-- Tabla de IoCs
CREATE TABLE IF NOT EXISTS iocs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_value VARCHAR(500) NOT NULL,
    indicator_type ENUM('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','mutex','registry','file_path','user_agent') NOT NULL,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence_score DECIMAL(3,2),
    first_seen DATETIME,
    last_seen DATETIME,
    source VARCHAR(100),
    campaign_id INT,
    campaign_name VARCHAR(255),
    tags JSON,
    is_active BOOLEAN DEFAULT TRUE,
    false_positive BOOLEAN DEFAULT FALSE,
    whitelist BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_indicator (indicator_value, indicator_type),
    INDEX idx_type (indicator_type),
    INDEX idx_campaign (campaign_id),
    INDEX idx_active (is_active),
    INDEX idx_confidence (confidence_score)
);

-- Tabla de correlaciones CVE-IoC
CREATE TABLE IF NOT EXISTS cve_ioc_relationships (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    ioc_id INT NOT NULL,
    relationship_type ENUM('exploits_vulnerability','associated_malware','exploitation_tool','post_exploitation','c2_infrastructure') NOT NULL,
    confidence DECIMAL(3,2),
    evidence TEXT,
    source VARCHAR(100),
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
    INDEX idx_cve (cve_id),
    INDEX idx_ioc (ioc_id),
    INDEX idx_relationship (relationship_type)
);

-- Tabla de campañas
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    campaign_name VARCHAR(255) NOT NULL,
    threat_actor VARCHAR(255),
    description TEXT,
    first_seen DATE,
    last_seen DATE,
    targeted_sectors JSON,
    targeted_countries JSON,
    ttps JSON,
    attribution_confidence ENUM('LOW','MEDIUM','HIGH'),
    is_active BOOLEAN DEFAULT TRUE,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    mitre_attack_ids JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_actor (threat_actor),
    INDEX idx_active (is_active),
    INDEX idx_severity (severity)
);

-- Tabla de detecciones Wazuh
CREATE TABLE IF NOT EXISTS wazuh_correlations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    correlation_type ENUM('cve_detection','ioc_match','suspicious_activity') NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    agent_id VARCHAR(10),
    agent_name VARCHAR(255),
    agent_ip VARCHAR(45),
    rule_id VARCHAR(20),
    rule_description TEXT,
    alert_level INT,
    detection_time DATETIME,
    raw_log TEXT,
    confidence_score DECIMAL(3,2),
    false_positive BOOLEAN DEFAULT FALSE,
    investigated BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type_target (correlation_type, target_id),
    INDEX idx_agent (agent_id),
    INDEX idx_detection_time (detection_time),
    INDEX idx_confidence (confidence_score)
);

-- Tabla de histórico EPSS
CREATE TABLE IF NOT EXISTS epss_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    epss_score DECIMAL(6,5),
    percentile DECIMAL(6,5),
    date_recorded DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cve_date (cve_id, date_recorded),
    INDEX idx_date (date_recorded)
);

-- Tabla de alertas generadas
CREATE TABLE IF NOT EXISTS threat_alerts (
    id VARCHAR(36) PRIMARY KEY,
    alert_type ENUM('kev_addition','epss_spike','critical_vuln','ioc_detection','campaign_detected','wazuh_correlation') NOT NULL,
    priority ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    title VARCHAR(500),
    description TEXT,
    cve_list JSON,
    ioc_list JSON,
    affected_systems JSON,
    recommended_actions JSON,
    integration_urls JSON,
    distribution_status ENUM('pending','sent','failed','acknowledged') DEFAULT 'pending',
    distribution_channels JSON,
    acknowledged_by VARCHAR(100),
    acknowledged_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (alert_type),
    INDEX idx_priority (priority),
    INDEX idx_status (distribution_status),
    INDEX idx_created (created_at)
);

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    config_type ENUM('string','integer','boolean','json') DEFAULT 'string',
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    modified_by VARCHAR(100),
    INDEX idx_key (config_key)
);

-- Insertar configuración inicial
INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
('system_version', '1.0.3', 'string', 'Versión del sistema'),
('kev_check_interval', '30', 'integer', 'Intervalo de verificación KEV en minutos'),
('epss_check_interval', '240', 'integer', 'Intervalo de verificación EPSS en minutos'),
('epss_spike_threshold', '0.2', 'string', 'Umbral para detectar spikes EPSS'),
('max_iocs_active', '50000', 'integer', 'Máximo de IoCs activos'),
('alert_retention_days', '90', 'integer', 'Días de retención de alertas'),
('api_rate_limit', '100', 'integer', 'Límite de requests por minuto'),
('last_kev_sync', NULL, 'string', 'Última sincronización KEV'),
('last_epss_sync', NULL, 'string', 'Última sincronización EPSS');
EOF
    
    if [[ $? -eq 0 ]]; then
        log_success "Base de datos configurada correctamente"
    else
        log_error "Error configurando base de datos"
        exit 1
    fi
    
    echo
}

# Crear estructura de directorios
create_directory_structure() {
    log_header "CREACIÓN DE ESTRUCTURA DE DIRECTORIOS"
    
    # Crear usuario del sistema
    if ! id "$INSTALL_USER" &>/dev/null; then
        log_step "Creando usuario del sistema: $INSTALL_USER"
        useradd -r -s /bin/bash -m -d /home/$INSTALL_USER $INSTALL_USER
    fi
    
    # Crear directorios principales
    local directories=(
        "$INSTALL_DIR"
        "$INSTALL_DIR/modules"
        "$INSTALL_DIR/connectors"
        "$INSTALL_DIR/exporters"
        "$INSTALL_DIR/templates"
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$LOG_DIR/triggers"
        "$LOG_DIR/threats"
        "$LOG_DIR/api"
        "$DATA_DIR"
        "$DATA_DIR/scripts"
        "$DATA_DIR/rules/snort"
        "$DATA_DIR/rules/yara"
        "$DATA_DIR/rules/sigma"
        "$DATA_DIR/rules/wazuh"
        "$DATA_DIR/blocklists"
        "$DATA_DIR/api_exports"
        "$DATA_DIR/reports"
        "$DATA_DIR/webhooks"
        "$DATA_DIR/campaigns"
    )
    
    for dir in "${directories[@]}"; do
        log_step "Creando: $dir"
        mkdir -p "$dir"
    done
    
    # Establecer permisos
    chown -R $INSTALL_USER:$INSTALL_USER "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    chmod 750 "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    
    log_success "Estructura de directorios creada"
    echo
}

# Instalar entorno Python
setup_python_environment() {
    log_header "CONFIGURACIÓN DEL ENTORNO PYTHON"
    
    log_step "Creando entorno virtual..."
    sudo -u $INSTALL_USER python3 -m venv "$INSTALL_DIR/venv"
    
    log_step "Instalando dependencias Python..."
    
    # Crear requirements.txt
    cat > "$INSTALL_DIR/requirements.txt" << 'EOF'
# Core dependencies
requests>=2.31.0
mysql-connector-python>=8.2.0
schedule>=1.2.0
python-dotenv>=1.0.0
configparser>=6.0.0
urllib3>=2.0.0

# API Framework
flask>=3.0.0
flask-cors>=4.0.0
flask-limiter>=3.5.0
flask-caching>=2.1.0
waitress>=2.1.2

# Data processing
pandas>=2.0.0
numpy>=1.24.0
python-dateutil>=2.8.2
pytz>=2023.3

# Security & Crypto
cryptography>=41.0.0
pyjwt>=2.8.0
bcrypt>=4.1.0

# Monitoring & Logging
prometheus-client>=0.19.0
python-json-logger>=2.0.7

# Email
secure-smtplib>=0.1.1

# YAML/JSON processing
pyyaml>=6.0.1
jsonschema>=4.20.0

# HTTP client improvements
httpx>=0.25.0
tenacity>=8.2.0

# Performance
redis>=5.0.0
cachetools>=5.3.0

# Utilities
colorama>=0.4.6
tabulate>=0.9.0
tqdm>=4.66.0
click>=8.1.0
EOF
    
    chown $INSTALL_USER:$INSTALL_USER "$INSTALL_DIR/requirements.txt"
    
    # Instalar paquetes
    sudo -u $INSTALL_USER "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
    sudo -u $INSTALL_USER "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
    
    log_success "Entorno Python configurado"
    echo
}

# Crear scripts principales
create_main_scripts() {
    log_header "CREACIÓN DE SCRIPTS PRINCIPALES"
    
    # Script principal de monitoreo
    log_step "Creando script de monitoreo principal..."
    cat > "$DATA_DIR/scripts/ti_hub_monitor.py" << 'MONITOR_SCRIPT'
#!/usr/bin/env python3
"""
Threat Intel Hub - Monitor Principal v1.0.3
Sistema de monitoreo y correlación de inteligencia de amenazas
"""

import os
import sys
import time
import json
import logging
import schedule
import requests
import mysql.connector
import configparser
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Any

# Configuración de logging
LOG_FILE = '/var/log/threat-intel-hub/ti-hub.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=10485760, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ThreatIntelHub')

# Cargar configuración
CONFIG_FILE = '/etc/threat-intel-hub/config.ini'
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

class DatabaseManager:
    """Gestión de conexiones a base de datos"""
    
    def __init__(self):
        self.db_config = {
            'host': config.get('database', 'host'),
            'port': config.getint('database', 'port'),
            'database': config.get('database', 'database'),
            'user': config.get('database', 'user'),
            'password': config.get('database', 'password'),
            'autocommit': False
        }
        self.connection = None
    
    def connect(self):
        """Establecer conexión a BD"""
        try:
            self.connection = mysql.connector.connect(**self.db_config)
            return self.connection
        except Exception as e:
            logger.error(f"Error conectando a BD: {e}")
            return None
    
    def disconnect(self):
        """Cerrar conexión a BD"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
    
    def execute_query(self, query: str, params: tuple = None, commit: bool = False):
        """Ejecutar query con manejo de errores"""
        try:
            if not self.connection or not self.connection.is_connected():
                self.connect()
            
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params)
            
            if commit:
                self.connection.commit()
                return cursor.rowcount
            else:
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error ejecutando query: {e}")
            if self.connection:
                self.connection.rollback()
            return None
        finally:
            if cursor:
                cursor.close()

class KEVMonitor:
    """Monitor de CISA Known Exploited Vulnerabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.kev_url = config.get('sources', 'kev_url')
        logger.info("KEV Monitor inicializado")
    
    def fetch_kev_data(self) -> Optional[Dict]:
        """Obtener datos KEV de CISA"""
        try:
            logger.info("Obteniendo datos KEV de CISA...")
            response = requests.get(self.kev_url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error obteniendo KEV: {e}")
            return None
    
    def process_kev_data(self, data: Dict) -> int:
        """Procesar y almacenar datos KEV"""
        if not data or 'vulnerabilities' not in data:
            return 0
        
        new_count = 0
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            if not cve_id:
                continue
            
            # Verificar si es nueva
            check_query = "SELECT cve_id FROM kev_vulnerabilities WHERE cve_id = %s"
            existing = self.db.execute_query(check_query, (cve_id,))
            
            if not existing:
                # Insertar nueva vulnerabilidad KEV
                insert_query = """
                    INSERT INTO kev_vulnerabilities 
                    (cve_id, vendor_project, product, vulnerability_name,
                     date_added, short_description, required_action, due_date, known_ransomware)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                params = (
                    cve_id,
                    vuln.get('vendorProject'),
                    vuln.get('product'),
                    vuln.get('vulnerabilityName'),
                    vuln.get('dateAdded'),
                    vuln.get('shortDescription'),
                    vuln.get('requiredAction'),
                    vuln.get('dueDate'),
                    vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'
                )
                
                self.db.execute_query(insert_query, params, commit=True)
                new_count += 1
                
                # Actualizar estado KEV en tabla vulnerabilities
                update_query = "UPDATE vulnerabilities SET kev_status = TRUE WHERE cve_id = %s"
                self.db.execute_query(update_query, (cve_id,), commit=True)
                
                # Generar alerta para nueva KEV
                self.generate_kev_alert(cve_id, vuln)
        
        # Actualizar última sincronización
        self.db.execute_query(
            "UPDATE system_config SET config_value = %s WHERE config_key = 'last_kev_sync'",
            (datetime.now().isoformat(),),
            commit=True
        )
        
        logger.info(f"KEV procesado: {new_count} nuevas vulnerabilidades")
        return new_count
    
    def generate_kev_alert(self, cve_id: str, vuln_data: Dict):
        """Generar alerta para nueva vulnerabilidad KEV"""
        import uuid
        
        alert_id = str(uuid.uuid4())
        alert_data = {
            'id': alert_id,
            'alert_type': 'kev_addition',
            'priority': 'CRITICAL' if vuln_data.get('knownRansomwareCampaignUse') == 'Known' else 'HIGH',
            'title': f"Nueva KEV: {cve_id} - {vuln_data.get('vulnerabilityName', 'Unknown')}",
            'description': vuln_data.get('shortDescription', ''),
            'cve_list': json.dumps([cve_id]),
            'recommended_actions': json.dumps([vuln_data.get('requiredAction', 'Apply patches immediately')])
        }
        
        insert_query = """
            INSERT INTO threat_alerts 
            (id, alert_type, priority, title, description, cve_list, recommended_actions)
            VALUES (%(id)s, %(alert_type)s, %(priority)s, %(title)s, %(description)s, 
                    %(cve_list)s, %(recommended_actions)s)
        """
        
        self.db.execute_query(insert_query, alert_data, commit=True)
        logger.info(f"Alerta generada para KEV: {cve_id}")

class EPSSMonitor:
    """Monitor de EPSS (Exploit Prediction Scoring System)"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.epss_url = config.get('sources', 'epss_url')
        self.spike_threshold = config.getfloat('triggers', 'epss_spike_threshold', fallback=0.2)
        logger.info("EPSS Monitor inicializado")
    
    def fetch_epss_scores(self, limit: int = 1000) -> Optional[Dict]:
        """Obtener scores EPSS"""
        try:
            logger.info(f"Obteniendo top {limit} scores EPSS...")
            response = requests.get(f"{self.epss_url}?limit={limit}", timeout=60)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error obteniendo EPSS: {e}")
            return None
    
    def process_epss_data(self, data: Dict) -> int:
        """Procesar scores EPSS y detectar spikes"""
        if not data or 'data' not in data:
            return 0
        
        spikes_detected = 0
        epss_data = data.get('data', [])
        
        for item in epss_data:
            cve_id = item.get('cve')
            new_score = float(item.get('epss', 0))
            percentile = float(item.get('percentile', 0))
            
            # Obtener score anterior
            old_score_query = "SELECT epss_score FROM vulnerabilities WHERE cve_id = %s"
            result = self.db.execute_query(old_score_query, (cve_id,))
            
            old_score = result[0]['epss_score'] if result and result[0]['epss_score'] else 0
            
            # Detectar spike
            if old_score and (new_score - old_score) >= self.spike_threshold:
                self.generate_epss_spike_alert(cve_id, old_score, new_score)
                spikes_detected += 1
            
            # Actualizar score
            update_query = """
                UPDATE vulnerabilities 
                SET epss_score = %s, epss_percentile = %s, epss_date = CURDATE()
                WHERE cve_id = %s
            """
            self.db.execute_query(update_query, (new_score, percentile, cve_id), commit=True)
            
            # Guardar histórico
            history_query = """
                INSERT INTO epss_history (cve_id, epss_score, percentile, date_recorded)
                VALUES (%s, %s, %s, CURDATE())
            """
            self.db.execute_query(history_query, (cve_id, new_score, percentile), commit=True)
        
        logger.info(f"EPSS procesado: {spikes_detected} spikes detectados")
        return spikes_detected
    
    def generate_epss_spike_alert(self, cve_id: str, old_score: float, new_score: float):
        """Generar alerta por spike en EPSS"""
        import uuid
        
        alert_id = str(uuid.uuid4())
        delta = new_score - old_score
        
        alert_data = {
            'id': alert_id,
            'alert_type': 'epss_spike',
            'priority': 'HIGH' if new_score > 0.5 else 'MEDIUM',
            'title': f"EPSS Spike: {cve_id} (+{delta:.2%})",
            'description': f"Score EPSS aumentó de {old_score:.3f} a {new_score:.3f}",
            'cve_list': json.dumps([cve_id])
        }
        
        insert_query = """
            INSERT INTO threat_alerts 
            (id, alert_type, priority, title, description, cve_list)
            VALUES (%(id)s, %(alert_type)s, %(priority)s, %(title)s, %(description)s, %(cve_list)s)
        """
        
        self.db.execute_query(insert_query, alert_data, commit=True)
        logger.info(f"Alerta EPSS spike generada: {cve_id} (Δ={delta:.2%})")

class ThreatIntelHub:
    """Clase principal del sistema"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.kev_monitor = KEVMonitor(self.db)
        self.epss_monitor = EPSSMonitor(self.db)
        self.running = False
        logger.info("Threat Intel Hub v1.0.3 inicializado")
    
    def check_kev(self):
        """Verificar nuevas vulnerabilidades KEV"""
        try:
            logger.info("Iniciando verificación KEV...")
            data = self.kev_monitor.fetch_kev_data()
            if data:
                self.kev_monitor.process_kev_data(data)
        except Exception as e:
            logger.error(f"Error en verificación KEV: {e}")
    
    def check_epss(self):
        """Verificar cambios en scores EPSS"""
        try:
            logger.info("Iniciando verificación EPSS...")
            data = self.epss_monitor.fetch_epss_scores()
            if data:
                self.epss_monitor.process_epss_data(data)
        except Exception as e:
            logger.error(f"Error en verificación EPSS: {e}")
    
    def run(self):
        """Ejecutar monitor principal"""
        logger.info("=== THREAT INTEL HUB v1.0.3 INICIADO ===")
        self.running = True
        
        # Configurar programación
        kev_interval = config.getint('triggers', 'kev_check_minutes', fallback=30)
        epss_hours = config.getint('triggers', 'epss_check_hours', fallback=4)
        
        # Programar tareas
        schedule.every(kev_interval).minutes.do(self.check_kev)
        schedule.every(epss_hours).hours.do(self.check_epss)
        
        # Ejecutar verificación inicial
        self.check_kev()
        self.check_epss()
        
        # Loop principal
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Verificar cada minuto
            except KeyboardInterrupt:
                logger.info("Interrupción recibida, deteniendo...")
                self.stop()
            except Exception as e:
                logger.error(f"Error en loop principal: {e}")
                time.sleep(60)
    
    def stop(self):
        """Detener el monitor"""
        logger.info("Deteniendo Threat Intel Hub...")
        self.running = False
        if self.db:
            self.db.disconnect()
        logger.info("=== THREAT INTEL HUB DETENIDO ===")

if __name__ == "__main__":
    try:
        hub = ThreatIntelHub()
        hub.run()
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        sys.exit(1)
MONITOR_SCRIPT
    
    # Script API REST
    log_step "Creando API REST..."
    cat > "$DATA_DIR/scripts/ti_hub_api.py" << 'API_SCRIPT'
#!/usr/bin/env python3
"""
Threat Intel Hub - API REST v1.0.3
"""

import os
import json
import logging
import configparser
import mysql.connector
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException

# Configuración
CONFIG_FILE = '/etc/threat-intel-hub/config.ini'
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Flask app
app = Flask(__name__)
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ThreatIntelAPI')

def get_db_connection():
    """Obtener conexión a base de datos"""
    return mysql.connector.connect(
        host=config.get('database', 'host'),
        port=config.getint('database', 'port'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )

@app.errorhandler(Exception)
def handle_exception(e):
    """Manejo global de errores"""
    if isinstance(e, HTTPException):
        return jsonify(error=str(e)), e.code
    logger.error(f"Error no manejado: {e}")
    return jsonify(error="Error interno del servidor"), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return jsonify(status="healthy", database="connected"), 200
    except Exception as e:
        return jsonify(status="unhealthy", error=str(e)), 503

@app.route('/api/v1/dashboard', methods=['GET'])
def dashboard():
    """Dashboard con métricas principales"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Métricas KEV
        cursor.execute("SELECT COUNT(*) as total FROM kev_vulnerabilities")
        kev_total = cursor.fetchone()['total']
        
        cursor.execute("""
            SELECT COUNT(*) as recent 
            FROM kev_vulnerabilities 
            WHERE date_added >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        kev_24h = cursor.fetchone()['recent']
        
        # Métricas de alertas
        cursor.execute("""
            SELECT priority, COUNT(*) as count 
            FROM threat_alerts 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY priority
        """)
        alerts_by_priority = {row['priority']: row['count'] for row in cursor.fetchall()}
        
        # Métricas IoCs
        cursor.execute("SELECT COUNT(*) as total FROM iocs WHERE is_active = TRUE")
        active_iocs = cursor.fetchone()['total']
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'version': '1.0.3',
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'threats': {
                    'kev_total': kev_total,
                    'kev_added_24h': kev_24h,
                    'critical_alerts_active': alerts_by_priority.get('CRITICAL', 0),
                    'high_alerts_active': alerts_by_priority.get('HIGH', 0)
                },
                'intelligence': {
                    'active_iocs': active_iocs
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error en dashboard: {e}")
        return jsonify(error=str(e)), 500

@app.route('/api/v1/kev/recent', methods=['GET'])
def recent_kev():
    """Obtener KEVs recientes"""
    days = request.args.get('days', 7, type=int)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT cve_id, vendor_project, product, vulnerability_name,
                   date_added, known_ransomware
            FROM kev_vulnerabilities
            WHERE date_added >= DATE_SUB(NOW(), INTERVAL %s DAY)
            ORDER BY date_added DESC
        """, (days,))
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify({
            'count': len(results),
            'period_days': days,
            'vulnerabilities': results
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo KEVs recientes: {e}")
        return jsonify(error=str(e)), 500

@app.route('/api/v1/alerts', methods=['GET'])
def get_alerts():
    """Obtener alertas"""
    priority = request.args.get('priority')
    limit = request.args.get('limit', 50, type=int)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT id, alert_type, priority, title, description,
                   cve_list, ioc_list, created_at
            FROM threat_alerts
        """
        params = []
        
        if priority:
            query += " WHERE priority = %s"
            params.append(priority)
        
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        # Parsear JSON fields
        for alert in results:
            if alert['cve_list']:
                alert['cve_list'] = json.loads(alert['cve_list'])
            if alert['ioc_list']:
                alert['ioc_list'] = json.loads(alert['ioc_list'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'count': len(results),
            'alerts': results
        }), 200
        
    except Exception as e:
        logger.error(f"Error obteniendo alertas: {e}")
        return jsonify(error=str(e)), 500

if __name__ == '__main__':
    port = config.getint('api', 'port', fallback=8080)
    host = config.get('api', 'host', fallback='0.0.0.0')
    
    logger.info(f"Starting Threat Intel Hub API on {host}:{port}")
    app.run(host=host, port=port, debug=False)
API_SCRIPT
    
    # Hacer scripts ejecutables
    chmod +x "$DATA_DIR/scripts/ti_hub_monitor.py"
    chmod +x "$DATA_DIR/scripts/ti_hub_api.py"
    chown -R $INSTALL_USER:$INSTALL_USER "$DATA_DIR/scripts"
    
    log_success "Scripts principales creados"
    echo
}

# Configurar servicios systemd
setup_systemd_services() {
    log_header "CONFIGURACIÓN DE SERVICIOS SYSTEMD"
    
    # Servicio principal
    log_step "Creando servicio principal..."
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
Environment="PYTHONPATH=$INSTALL_DIR"
ExecStart=$INSTALL_DIR/venv/bin/python $DATA_DIR/scripts/ti_hub_monitor.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Servicio API
    log_step "Creando servicio API..."
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
Environment="PYTHONPATH=$INSTALL_DIR"
ExecStart=$INSTALL_DIR/venv/bin/python $DATA_DIR/scripts/ti_hub_api.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Recargar systemd
    systemctl daemon-reload
    
    log_success "Servicios systemd configurados"
    echo
}

# Crear comandos administrativos
create_admin_commands() {
    log_header "CREACIÓN DE COMANDOS ADMINISTRATIVOS"
    
    # Comando ti-hub-status
    log_step "Creando comando ti-hub-status..."
    cat > /usr/local/bin/ti-hub-status << 'EOF'
#!/bin/bash
echo "=== THREAT INTEL HUB STATUS ==="
systemctl status threat-intel-hub --no-pager
echo
systemctl status threat-intel-hub-api --no-pager
echo
echo "=== RECENT LOGS ==="
tail -n 10 /var/log/threat-intel-hub/ti-hub.log 2>/dev/null || echo "No logs available"
EOF
    
    # Comando ti-hub-admin
    log_step "Creando comando ti-hub-admin..."
    cp "$DATA_DIR/../ti_hub_installer.sh" /usr/local/bin/ti-hub-admin 2>/dev/null || {
        # Crear versión básica si no existe el archivo
        cat > /usr/local/bin/ti-hub-admin << 'EOF'
#!/bin/bash
# Threat Intel Hub Admin Tool v1.0.3

case "$1" in
    status)
        ti-hub-status
        ;;
    dashboard)
        curl -s http://localhost:8080/api/v1/dashboard | python3 -m json.tool
        ;;
    test-db)
        curl -s http://localhost:8080/health
        ;;
    logs)
        journalctl -u threat-intel-hub -u threat-intel-hub-api -f
        ;;
    *)
        echo "Uso: ti-hub-admin {status|dashboard|test-db|logs}"
        ;;
esac
EOF
    }
    
    chmod +x /usr/local/bin/ti-hub-status
    chmod +x /usr/local/bin/ti-hub-admin
    
    log_success "Comandos administrativos creados"
    echo
}

# Configurar el sistema
configure_system() {
    log_header "CONFIGURACIÓN DEL SISTEMA"
    
    # Obtener configuración interactiva
    echo "Configure las opciones del sistema:"
    echo
    
    # Email
    read -p "¿Configurar notificaciones por email? (y/N): " setup_email
    if [[ $setup_email =~ ^[Yy]$ ]]; then
        read -p "Servidor SMTP (ej: smtp.gmail.com): " SMTP_SERVER
        read -p "Puerto SMTP (ej: 587): " SMTP_PORT
        read -p "Email remitente: " SMTP_USER
        read -sp "Contraseña email: " SMTP_PASSWORD
        echo
        read -p "Email(s) destinatario(s) (separados por coma): " RECIPIENT_EMAIL
    fi
    
    # APIs de Threat Intelligence
    echo
    read -p "¿Tiene API Key de NVD? (y/N): " has_nvd
    if [[ $has_nvd =~ ^[Yy]$ ]]; then
        read -p "NVD API Key: " NVD_API_KEY
    fi
    
    read -p "¿Tiene API Key de AlienVault OTX? (y/N): " has_otx
    if [[ $has_otx =~ ^[Yy]$ ]]; then
        read -p "OTX API Key: " OTX_API_KEY
    fi
    
    # Wazuh
    echo
    read -p "¿Integrar con Wazuh SIEM? (y/N): " setup_wazuh
    if [[ $setup_wazuh =~ ^[Yy]$ ]]; then
        WAZUH_ENABLED="true"
        read -p "Wazuh Manager URL (ej: https://wazuh.local:55000): " WAZUH_MANAGER_URL
        read -p "Wazuh Usuario: " WAZUH_USER
        read -sp "Wazuh Contraseña: " WAZUH_PASSWORD
        echo
    fi
    
    # Crear archivo de configuración
    log_step "Creando archivo de configuración..."
    cat > "$CONFIG_DIR/config.ini" << EOF
[database]
host = localhost
port = 3306
database = $DB_NAME
user = $DB_USER
password = $DB_PASSWORD

[triggers]
kev_enabled = true
kev_check_minutes = 30
epss_enabled = true
epss_spike_threshold = 0.2
epss_check_hours = 4
misp_priority = false

[sources]
nvd_api_key = $NVD_API_KEY
nvd_base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
kev_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
epss_url = https://api.first.org/data/v1/epss
otx_api_key = $OTX_API_KEY
otx_base_url = https://otx.alienvault.com/api/v1

[wazuh]
enabled = $WAZUH_ENABLED
manager_url = $WAZUH_MANAGER_URL
manager_user = $WAZUH_USER
manager_password = $WAZUH_PASSWORD

[api]
enabled = true
host = 0.0.0.0
port = 8080
export_formats = paloalto,fortinet,cisco,snort,yara,stix,misp,csv
cors_enabled = true

[webhooks]
enabled = false
port = 9999

[email]
smtp_server = $SMTP_SERVER
smtp_port = $SMTP_PORT
sender_email = $SMTP_USER
sender_password = $SMTP_PASSWORD
recipient_email = $RECIPIENT_EMAIL
EOF
    
    # Proteger archivo de configuración
    chown $INSTALL_USER:$INSTALL_USER "$CONFIG_DIR/config.ini"
    chmod 640 "$CONFIG_DIR/config.ini"
    
    log_success "Sistema configurado"
    echo
}

# Iniciar servicios
start_services() {
    log_header "INICIANDO SERVICIOS"
    
    log_step "Habilitando servicios..."
    systemctl enable threat-intel-hub
    systemctl enable threat-intel-hub-api
    
    log_step "Iniciando servicios..."
    systemctl start threat-intel-hub
    systemctl start threat-intel-hub-api
    
    # Esperar a que los servicios inicien
    sleep 5
    
    # Verificar estado
    if systemctl is-active --quiet threat-intel-hub; then
        log_success "Servicio principal: ✅ Activo"
    else
        log_warn "Servicio principal: ⚠️ No activo"
    fi
    
    if systemctl is-active --quiet threat-intel-hub-api; then
        log_success "Servicio API: ✅ Activo"
    else
        log_warn "Servicio API: ⚠️ No activo"
    fi
    
    echo
}

# Mostrar resumen final
show_summary() {
    log_header "INSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}✅ Threat Intel Hub v$SCRIPT_VERSION instalado exitosamente${NC}"
    echo
    echo "📋 INFORMACIÓN DE ACCESO:"
    echo "────────────────────────"
    echo "API REST: http://$(hostname -I | awk '{print $1}'):8080"
    echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8080/api/v1/dashboard"
    echo
    echo "🔐 CREDENCIALES:"
    echo "────────────────"
    echo "Base de datos:"
    echo "  • Usuario: $DB_USER"
    echo "  • Contraseña: $DB_PASSWORD"
    echo "  • Base de datos: $DB_NAME"
    echo
    echo "📝 COMANDOS DISPONIBLES:"
    echo "──────────────────────"
    echo "  ti-hub-status      - Ver estado del sistema"
    echo "  ti-hub-admin       - Herramienta administrativa"
    echo
    echo "🚀 PRÓXIMOS PASOS:"
    echo "────────────────"
    echo "1. Verificar servicios: ti-hub-status"
    echo "2. Ver dashboard: ti-hub-admin dashboard"
    echo "3. Configurar fuentes adicionales en: $CONFIG_DIR/config.ini"
    echo "4. Ver logs: journalctl -u threat-intel-hub -f"
    echo
    echo "📚 DOCUMENTACIÓN:"
    echo "───────────────"
    echo "https://github.com/juanpadiaz/Threat-Intel-Hub"
    echo
    echo -e "${YELLOW}¡Gracias por instalar Threat Intel Hub!${NC}"
}

# Función principal
main() {
    show_welcome_banner
    
    read -p "¿Desea continuar con la instalación? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Instalación cancelada."
        exit 0
    fi
    
    check_system_requirements
    install_system_dependencies
    setup_database
    create_directory_structure
    setup_python_environment
    create_main_scripts
    setup_systemd_services
    create_admin_commands
    configure_system
    start_services
    show_summary
}

# Ejecutar instalación
main "$@"