#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Instalación v1.0.2
# Compatible con: Ubuntu 20.04+ LTS
# Incluye: NVD, KEV, VEX, EPSS, IoCs, Wazuh (opcional), MISP, Threat Intelligence
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
MONITOR_INTERVAL="4"
CURRENT_USER="${SUDO_USER:-$USER}"

# Variables para características
HAS_WAZUH="false"
OTX_API_KEY=""
MISP_URL=""
MISP_API_KEY=""
MISP_VERIFY_SSL="true"
MISP_ORG="Mi Organización"
MISP_DISTRIBUTION="1"
MISP_PUBLISHED_ONLY="true"
MISP_SYNC_INTERVAL="6"
VT_API_KEY=""
WAZUH_URL=""
WAZUH_USER=""
WAZUH_PASSWORD=""
WAZUH_INDEXER_URL=""
WAZUH_INDEXER_USER=""
WAZUH_INDEXER_PASSWORD=""
WAZUH_VERIFY_SSL="true"
WAZUH_IOC_INTERVAL="30"
WAZUH_HISTORY_DAYS="7"
WAZUH_QUERY_VULNS="false"
ENABLE_KEV="true"
ENABLE_EPSS="true"
ENABLE_VEX="true"
ENABLE_IOC="true"
TI_CONFIDENCE="0.3"
TI_MAX_IOCS="100"
TI_RETENTION="90"

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
    echo "     THREAT INTEL HUB INSTALLER v${SCRIPT_VERSION}"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${GREEN}Versión: ${SCRIPT_VERSION} - Threat Intelligence Platform${NC}"
    echo
    echo "Este instalador configurará:"
    echo "   ✅ Plataforma completa de Threat Intelligence"
    echo "   ✅ Base de datos centralizada (MariaDB/MySQL)"
    echo "   ✅ Monitor de vulnerabilidades NVD"
    echo "   ✅ Integración con CISA KEV (Known Exploited Vulnerabilities)"
    echo "   ✅ Soporte EPSS (Exploit Prediction Scoring System)"
    echo "   ✅ Capacidades VEX (Vulnerability Exploitability eXchange)"
    echo "   ✅ Sistema de alertas inteligentes"
    echo "   ✅ API REST para integración externa"
    echo
    echo "Integraciones opcionales:"
    echo "   • Wazuh SIEM (correlación CVE-IoC)"
    echo "   • AlienVault OTX"
    echo "   • MISP"
    echo "   • VirusTotal"
    echo
    read -p "¿Continuar con la instalación del Threat Intel Hub? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Instalación cancelada."
        exit 0
    fi
    echo
}

# Detección de Wazuh
detect_wazuh() {
    log_header "DETECCIÓN DE WAZUH"
    
    echo "Wazuh es un SIEM que permite correlacionar CVEs e IoCs con eventos de seguridad."
    echo
    read -p "¿Tiene Wazuh instalado en su infraestructura? (y/N): " has_wazuh
    
    if [[ $has_wazuh =~ ^[Yy]$ ]]; then
        HAS_WAZUH="true"
        log_info "Wazuh detectado - Se habilitará la correlación CVE-IoC"
        echo
        echo "Características que se habilitarán con Wazuh:"
        echo "   • Búsqueda automática de IoCs en logs de Wazuh"
        echo "   • Correlación de CVEs con vulnerabilidades detectadas"
        echo "   • Análisis de eventos de seguridad en tiempo real"
        echo "   • Detección de compromisos basada en threat intelligence"
        echo "   • Enriquecimiento de alertas con contexto de amenazas"
        echo
        read -p "Presione Enter para continuar..."
    else
        HAS_WAZUH="false"
        log_info "Sin Wazuh - El sistema funcionará sin correlación SIEM"
        echo
        echo "Nota: Puede agregar Wazuh más tarde editando la configuración."
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
    log_step "Verificando prerrequisitos del Threat Intel Hub..."
    
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
    
    log_success "Prerrequisitos OK para Threat Intel Hub"
}

# Instalar dependencias extendidas
install_dependencies() {
    log_step "Instalando dependencias del Threat Intel Hub..."
    
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
        log_info "Instalando MariaDB para Threat Intel Hub"
    fi
    
    local packages=(
        "python3-pip" "python3-venv" "python3-dev" "build-essential"
        "curl" "wget" "git" "logrotate" "systemd" "jq" "uuid-runtime"
        "libssl-dev" "libffi-dev" "libxml2-dev" "libxslt1-dev"
        "htop" "net-tools" "unzip"
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
    
    log_success "Dependencias del Threat Intel Hub configuradas"
}

# Crear usuario del sistema
create_system_user() {
    log_step "Creando usuario del Threat Intel Hub..."
    
    # Crear grupo primero
    if ! getent group "$INSTALL_USER" >/dev/null 2>&1; then
        groupadd "$INSTALL_USER"
        log_info "Grupo $INSTALL_USER creado"
    fi
    
    # Crear usuario
    if ! id "$INSTALL_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -g "$INSTALL_USER" -c "Threat Intel Hub Service User" "$INSTALL_USER"
        log_info "Usuario $INSTALL_USER creado"
    fi
    
    # Agregar el usuario actual al grupo para administración
    if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        usermod -a -G "$INSTALL_USER" "$CURRENT_USER"
        log_info "Usuario $CURRENT_USER agregado al grupo $INSTALL_USER"
    fi
    
    log_success "Usuario del Threat Intel Hub configurado"
}

# Crear directorios del sistema
create_directories() {
    log_step "Creando estructura de directorios..."
    
    local directories=(
        "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
        "$DATA_DIR/scripts" "$DATA_DIR/backups" "$DATA_DIR/cache"
        "$DATA_DIR/reports" "$DATA_DIR/vex_documents" "$DATA_DIR/ioc_feeds"
        "$DATA_DIR/threat_intel" "$DATA_DIR/correlations"
        "$INSTALL_DIR/modules" "$INSTALL_DIR/templates" "$INSTALL_DIR/schemas"
        "$INSTALL_DIR/connectors" "$INSTALL_DIR/analyzers" "$INSTALL_DIR/workflows"
        "$LOG_DIR/threat_intel" "$LOG_DIR/correlation" "$LOG_DIR/vex"
    )
    
    # Agregar directorios de Wazuh si está habilitado
    if [[ "$HAS_WAZUH" == "true" ]]; then
        directories+=(
            "$DATA_DIR/wazuh_data"
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
    
    log_success "Estructura de directorios del Threat Intel Hub creada"
}

# Configurar Python
setup_python() {
    log_step "Configurando entorno Python del Threat Intel Hub..."
    
    cd "$INSTALL_DIR"
    
    sudo -u "$INSTALL_USER" python3 -m venv venv
    
    # Crear requirements.txt base
    cat > requirements.txt << 'EOF'
# Core dependencies
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
tabulate>=0.9.0
python-dateutil>=2.8.2
colorama>=0.4.6

# Threat Intelligence dependencies
flask>=2.3.0
flask-restful>=0.3.10
pymisp>=2.4.170
stix2>=3.0.1
taxii2-client>=2.3.0

# Data processing
lxml>=4.9.2
beautifulsoup4>=4.12.0
pandas>=1.5.0

# Networking and APIs
urllib3>=2.0.0
certifi>=2023.5.7
python-whois>=0.8.0

# Validation and schemas
jsonschema>=4.17.0
marshmallow>=3.19.0

# Utilities
click>=8.1.0
tqdm>=4.65.0
cachetools>=5.3.0
rich>=13.3.0
EOF
    
    sudo -u "$INSTALL_USER" bash -c "
        source venv/bin/activate
        pip install --upgrade pip -q
        pip install -r requirements.txt -q
    "
    
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    log_success "Entorno Python del Threat Intel Hub configurado"
}

# Crear esquemas de datos
create_schemas() {
    log_step "Creando esquemas del Threat Intel Hub..."
    
    # Esquema VEX
    cat > "$INSTALL_DIR/schemas/vex_schema.json" << 'EOF'
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Threat Intel Hub - VEX Document Schema",
  "type": "object",
  "properties": {
    "document": {
      "type": "object",
      "properties": {
        "category": {"type": "string", "enum": ["csaf_vex"]},
        "csaf_version": {"type": "string"},
        "publisher": {
          "type": "object",
          "properties": {
            "category": {"type": "string"},
            "name": {"type": "string"},
            "namespace": {"type": "string"}
          }
        },
        "title": {"type": "string"},
        "tracking": {
          "type": "object",
          "properties": {
            "id": {"type": "string"},
            "status": {"type": "string"},
            "version": {"type": "string"}
          }
        }
      }
    },
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "cve": {"type": "string"},
          "product_status": {"type": "object"}
        }
      }
    }
  }
}
EOF

    # Esquema EPSS
    cat > "$INSTALL_DIR/schemas/epss_schema.json" << 'EOF'
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Threat Intel Hub - EPSS Data Schema",
  "type": "object",
  "properties": {
    "cve": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]+$"},
    "epss": {"type": "number", "minimum": 0, "maximum": 1},
    "percentile": {"type": "number", "minimum": 0, "maximum": 1},
    "date": {"type": "string", "format": "date"}
  },
  "required": ["cve", "epss", "percentile", "date"]
}
EOF

    # Esquema de IoCs
    cat > "$INSTALL_DIR/schemas/ioc_schema.json" << 'EOF'
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Threat Intel Hub - IoC Schema",
  "type": "object",
  "properties": {
    "indicator_value": {"type": "string"},
    "indicator_type": {
      "type": "string",
      "enum": ["ip_address", "domain", "url", "file_hash", "email"]
    },
    "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
    "source_feed": {"type": "string"},
    "first_seen": {"type": "string", "format": "date-time"},
    "last_seen": {"type": "string", "format": "date-time"}
  },
  "required": ["indicator_value", "indicator_type"]
}
EOF

    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR/schemas"
    log_success "Esquemas del Threat Intel Hub creados"
}

# Crear módulo de integración con Wazuh (solo si está habilitado)
create_wazuh_integration() {
    if [[ "$HAS_WAZUH" != "true" ]]; then
        log_info "Omitiendo creación de conector Wazuh (no detectado)"
        return
    fi
    
    log_step "Creando conector Wazuh para Threat Intel Hub..."
    
    cat > "$INSTALL_DIR/connectors/wazuh_connector.py" << 'EOF'
#!/usr/bin/env python3
"""Wazuh Connector for Threat Intel Hub v1.0.2"""

import requests
import json
import base64
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class WazuhConnector:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntelHub/1.0.2',
            'Content-Type': 'application/json'
        })
        
        # Wazuh configuration
        self.manager_url = config.get('wazuh', 'manager_url', fallback='')
        self.manager_user = config.get('wazuh', 'manager_user', fallback='')
        self.manager_password = config.get('wazuh', 'manager_password', fallback='')
        self.indexer_url = config.get('wazuh', 'indexer_url', fallback='')
        self.indexer_user = config.get('wazuh', 'indexer_user', fallback='')
        self.indexer_password = config.get('wazuh', 'indexer_password', fallback='')
        self.verify_ssl = config.getboolean('wazuh', 'verify_ssl', fallback=True)
        self.history_days = config.getint('wazuh', 'history_days', fallback=7)
        
        self.jwt_token = None
        self.token_expiry = None
    
    def authenticate_manager(self) -> bool:
        """Authenticate with Wazuh Manager API"""
        try:
            if not self.manager_url or not self.manager_user or not self.manager_password:
                logger.warning("Wazuh Manager credentials not configured")
                return False
            
            auth_url = f"{self.manager_url}/security/user/authenticate"
            auth_data = {
                "user": self.manager_user,
                "password": self.manager_password
            }
            
            response = self.session.post(
                auth_url,
                json=auth_data,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                self.jwt_token = data.get('data', {}).get('token')
                self.token_expiry = datetime.now() + timedelta(minutes=14)
                
                self.session.headers['Authorization'] = f'Bearer {self.jwt_token}'
                
                logger.info("✅ Wazuh Manager authentication successful")
                return True
            else:
                logger.error(f"❌ Wazuh Manager authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error authenticating with Wazuh Manager: {e}")
            return False
    
    def search_ioc_in_alerts(self, ioc_value: str, ioc_type: str) -> List[Dict]:
        """Search for IoC in Wazuh alerts"""
        try:
            if not self.indexer_url:
                logger.warning("Wazuh Indexer URL not configured")
                return []
            
            query = self._build_ioc_search_query(ioc_value, ioc_type)
            search_url = f"{self.indexer_url}/wazuh-alerts-*/_search"
            
            auth_string = f"{self.indexer_user}:{self.indexer_password}"
            auth_b64 = base64.b64encode(auth_string.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                search_url,
                json=query,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                
                results = []
                for hit in hits:
                    source = hit.get('_source', {})
                    results.append({
                        'timestamp': source.get('@timestamp'),
                        'agent_id': source.get('agent', {}).get('id'),
                        'agent_name': source.get('agent', {}).get('name'),
                        'rule_id': source.get('rule', {}).get('id'),
                        'rule_description': source.get('rule', {}).get('description'),
                        'full_log': source.get('full_log'),
                        'location': source.get('location'),
                        'data': source.get('data', {})
                    })
                
                logger.info(f"Found {len(results)} alerts for IoC {ioc_value}")
                return results
            else:
                logger.error(f"Error searching IoC in alerts: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error searching IoC {ioc_value}: {e}")
            return []
    
    def _build_ioc_search_query(self, ioc_value: str, ioc_type: str) -> Dict:
        """Build Elasticsearch query for IoC search"""
        
        end_time = datetime.now()
        start_time = end_time - timedelta(days=self.history_days)
        
        base_query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ],
                    "should": [],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        if ioc_type == 'ip_address':
            base_query["query"]["bool"]["should"].extend([
                {"wildcard": {"data.srcip": f"*{ioc_value}*"}},
                {"wildcard": {"data.dstip": f"*{ioc_value}*"}},
                {"wildcard": {"full_log": f"*{ioc_value}*"}}
            ])
        elif ioc_type == 'domain':
            base_query["query"]["bool"]["should"].extend([
                {"wildcard": {"data.url": f"*{ioc_value}*"}},
                {"wildcard": {"data.hostname": f"*{ioc_value}*"}},
                {"wildcard": {"full_log": f"*{ioc_value}*"}}
            ])
        else:
            base_query["query"]["bool"]["should"].append(
                {"wildcard": {"full_log": f"*{ioc_value}*"}}
            )
        
        return base_query
    
    def get_agent_vulnerabilities(self, agent_id: str) -> List[Dict]:
        """Get vulnerabilities for a specific Wazuh agent"""
        try:
            if not self.authenticate_manager():
                return []
            
            vuln_url = f"{self.manager_url}/vulnerability/{agent_id}"
            response = self.session.get(vuln_url, verify=self.verify_ssl, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('data', {}).get('affected_items', [])
                
                results = []
                for vuln in vulnerabilities:
                    results.append({
                        'cve': vuln.get('cve'),
                        'severity': vuln.get('severity'),
                        'cvss2_score': vuln.get('cvss2_score'),
                        'cvss3_score': vuln.get('cvss3_score'),
                        'package': vuln.get('package', {}).get('name'),
                        'version': vuln.get('package', {}).get('version'),
                        'architecture': vuln.get('architecture'),
                        'detection_time': vuln.get('detection_time')
                    })
                
                return results
            else:
                logger.error(f"Error getting vulnerabilities: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting agent vulnerabilities: {e}")
            return []
    
    def test_connection(self) -> Dict[str, bool]:
        """Test connection to Wazuh components"""
        results = {
            'manager': False,
            'indexer': False,
            'overall': False
        }
        
        if self.manager_url:
            try:
                if self.authenticate_manager():
                    info_url = f"{self.manager_url}/manager/info"
                    response = self.session.get(info_url, verify=self.verify_ssl, timeout=10)
                    if response.status_code == 200:
                        results['manager'] = True
                        logger.info("✅ Wazuh Manager connection successful")
            except Exception as e:
                logger.error(f"❌ Wazuh Manager connection error: {e}")
        
        if self.indexer_url:
            try:
                cluster_url = f"{self.indexer_url}/_cluster/health"
                auth_string = f"{self.indexer_user}:{self.indexer_password}"
                auth_b64 = base64.b64encode(auth_string.encode()).decode()
                
                headers = {'Authorization': f'Basic {auth_b64}'}
                response = requests.get(cluster_url, headers=headers, verify=self.verify_ssl, timeout=10)
                
                if response.status_code == 200:
                    results['indexer'] = True
                    logger.info("✅ Wazuh Indexer connection successful")
            except Exception as e:
                logger.error(f"❌ Wazuh Indexer connection error: {e}")
        
        results['overall'] = results['manager'] and results['indexer']
        return results
EOF
    
    chown "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR/connectors/wazuh_connector.py"
    log_success "Conector Wazuh del Threat Intel Hub creado"
}

# Crear plantillas
create_templates() {
    log_step "Creando plantillas del Threat Intel Hub..."
    
    # Plantilla VEX
    cat > "$INSTALL_DIR/templates/vex_template.json" << 'EOF'
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "publisher": {
      "category": "vendor",
      "name": "{{vendor_name}}",
      "namespace": "{{vendor_namespace}}"
    },
    "title": "Threat Intel Hub - VEX Document for {{cve_id}}",
    "tracking": {
      "id": "{{document_id}}",
      "status": "final",
      "version": "1.0.2",
      "revision_history": [
        {
          "date": "{{creation_date}}",
          "number": "1.0.2",
          "summary": "Generated by Threat Intel Hub"
        }
      ]
    }
  },
  "vulnerabilities": [
    {
      "cve": "{{cve_id}}",
      "product_status": {
        "under_investigation": ["{{product_name}}:{{version}}"]
      },
      "notes": [
        {
          "category": "description",
          "text": "Threat Intelligence analysis in progress"
        }
      ]
    }
  ]
}
EOF

    # Plantilla de reporte de amenazas
    cat > "$INSTALL_DIR/templates/threat_report_template.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Threat Intel Hub - Reporte de Amenazas</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; text-align: center; }
        .content { background: white; padding: 30px; margin: 20px 0; border-radius: 8px; }
        .threat-item { border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; background: #fff5f5; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat-card { background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Threat Intel Hub</h1>
        <h2>Reporte de Amenazas</h2>
        <p>{{report_date}}</p>
    </div>
    <div class="content">
        <div class="stats">
            <div class="stat-card">
                <h3>{{total_cves}}</h3>
                <p>CVEs Monitoreados</p>
            </div>
            <div class="stat-card">
                <h3>{{kev_count}}</h3>
                <p>Vulnerabilidades KEV</p>
            </div>
            <div class="stat-card">
                <h3>{{ioc_count}}</h3>
                <p>IoCs Correlacionados</p>
            </div>
            <div class="stat-card">
                <h3>{{wazuh_alerts}}</h3>
                <p>Alertas Wazuh</p>
            </div>
        </div>
        {{threat_details}}
    </div>
</body>
</html>
EOF

    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR/templates"
    log_success "Plantillas del Threat Intel Hub creadas"
}

# Configurar base de datos
setup_database() {
    log_step "Configurando base de datos del Threat Intel Hub..."
    
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
    
    # Crear script SQL para Threat Intel Hub
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
    composite_risk_score DECIMAL(5,2),
    affected_systems INT DEFAULT 0,
    wazuh_correlation JSON,
    threat_intel_enriched BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (cvss_severity),
    INDEX idx_published (published_date),
    INDEX idx_epss_score (epss_score),
    INDEX idx_composite_risk (composite_risk_score),
    INDEX idx_threat_enriched (threat_intel_enriched)
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
    wazuh_detections INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_date_added (date_added),
    INDEX idx_ransomware (known_ransomware),
    INDEX idx_threat_level (threat_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de IoCs (Indicators of Compromise)
CREATE TABLE IF NOT EXISTS iocs (
    id VARCHAR(36) PRIMARY KEY,
    indicator_value VARCHAR(2048) NOT NULL,
    indicator_type ENUM(
        'ip_address', 'domain', 'url', 'file_hash_md5', 
        'file_hash_sha1', 'file_hash_sha256', 'file_hash_sha512',
        'email_address', 'mutex', 'registry_key', 'filename',
        'user_agent', 'certificate_fingerprint'
    ) NOT NULL,
    confidence_score DECIMAL(3,2) DEFAULT 0.50,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_feed VARCHAR(255),
    source_organization VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    kill_chain_phase VARCHAR(100),
    malware_family VARCHAR(255),
    campaign_name VARCHAR(255),
    threat_actor VARCHAR(255),
    description TEXT,
    misp_event_id VARCHAR(50),
    otx_pulse_id VARCHAR(50),
    wazuh_detections INT DEFAULT 0,
    last_detection TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_indicator_type (indicator_type),
    INDEX idx_confidence (confidence_score),
    INDEX idx_source (source_feed),
    INDEX idx_campaign (campaign_name),
    INDEX idx_threat_actor (threat_actor),
    INDEX idx_wazuh_detections (wazuh_detections)
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
    attribution_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_cve_ioc (cve_id, ioc_id, relationship_type),
    INDEX idx_cve_id (cve_id),
    INDEX idx_ioc_id (ioc_id),
    INDEX idx_relationship (relationship_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de campañas de amenazas
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
    wazuh_detections INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_threat_actor (threat_actor),
    INDEX idx_last_activity (last_activity),
    INDEX idx_sophistication (sophistication_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de documentos VEX
CREATE TABLE IF NOT EXISTS vex_statements (
    id VARCHAR(36) PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    product_name VARCHAR(255),
    product_version VARCHAR(100),
    vendor VARCHAR(255),
    status ENUM('affected', 'not_affected', 'fixed', 'under_investigation'),
    justification TEXT,
    impact_statement TEXT,
    action_statement TEXT,
    document_path VARCHAR(500),
    vex_document_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve_vex (cve_id),
    INDEX idx_status (status),
    INDEX idx_vendor (vendor)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de historial EPSS
CREATE TABLE IF NOT EXISTS epss_history (
    cve_id VARCHAR(20),
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,4),
    date_recorded DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cve_id, date_recorded),
    INDEX idx_date_recorded (date_recorded)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQLEOF

    # Agregar tablas de Wazuh si está habilitado
    if [[ "$HAS_WAZUH" == "true" ]]; then
        cat >> /tmp/ti_hub_setup.sql << 'SQLEOF'

-- Tabla de correlaciones Wazuh (solo si Wazuh está habilitado)
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

-- Tabla de agentes Wazuh monitoreados
CREATE TABLE IF NOT EXISTS wazuh_agents (
    agent_id VARCHAR(10) PRIMARY KEY,
    agent_name VARCHAR(255),
    agent_ip VARCHAR(45),
    os_platform VARCHAR(100),
    os_version VARCHAR(100),
    last_keep_alive TIMESTAMP,
    status VARCHAR(20),
    vulnerability_count INT DEFAULT 0,
    critical_vulns INT DEFAULT 0,
    high_vulns INT DEFAULT 0,
    ioc_detections INT DEFAULT 0,
    last_vulnerability_scan TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_critical (critical_vulns)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQLEOF
    fi

    # Agregar resto de tablas comunes
    cat >> /tmp/ti_hub_setup.sql << 'SQLEOF'

-- Tabla de eventos de threat intelligence
CREATE TABLE IF NOT EXISTS threat_intel_events (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(50),
    source_system VARCHAR(50),
    event_data JSON,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
    status ENUM('new', 'investigating', 'confirmed', 'false_positive', 'resolved'),
    assigned_to VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_event_type (event_type),
    INDEX idx_source (source_system),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tablas de sistema
CREATE TABLE IF NOT EXISTS monitoring_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vulnerabilities_found INT DEFAULT 0,
    new_vulnerabilities INT DEFAULT 0,
    kev_vulnerabilities INT DEFAULT 0,
    epss_updates INT DEFAULT 0,
    ioc_correlations INT DEFAULT 0,
    wazuh_correlations INT DEFAULT 0,
    misp_events_processed INT DEFAULT 0,
    otx_pulses_processed INT DEFAULT 0,
    status VARCHAR(50),
    message TEXT,
    execution_time_seconds DECIMAL(8,2),
    INDEX idx_timestamp (timestamp),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    recipient_email VARCHAR(255),
    subject VARCHAR(255),
    vulnerabilities_count INT,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    kev_count INT DEFAULT 0,
    ioc_count INT DEFAULT 0,
    wazuh_alerts INT DEFAULT 0,
    notification_type VARCHAR(50) DEFAULT 'threat_alert',
    status VARCHAR(50),
    INDEX idx_sent_date (sent_date),
    INDEX idx_status (status),
    INDEX idx_type (notification_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Vista consolidada para dashboard
CREATE OR REPLACE VIEW threat_intelligence_dashboard AS
SELECT 
    v.cve_id,
    v.description,
    v.cvss_score,
    v.cvss_severity,
    v.published_date,
    v.epss_score,
    v.epss_percentile,
    v.composite_risk_score,
    v.affected_systems,
    
    -- KEV information
    k.date_added as kev_date_added,
    k.known_ransomware,
    k.threat_level as kev_threat_level,
    
    -- IoC counts by type
    COUNT(DISTINCT CASE WHEN i.indicator_type IN ('ip_address', 'domain', 'url') THEN i.id END) as network_iocs,
    COUNT(DISTINCT CASE WHEN i.indicator_type LIKE 'file_hash%' THEN i.id END) as file_iocs,
    
    -- Campaign information
    COUNT(DISTINCT tc.id) as associated_campaigns,
    GROUP_CONCAT(DISTINCT tc.campaign_name SEPARATOR ', ') as campaign_names,
    
    -- Overall threat score
    GREATEST(
        COALESCE(v.composite_risk_score, 0),
        CASE WHEN k.cve_id IS NOT NULL THEN 9.0 ELSE 0 END,
        CASE WHEN v.affected_systems > 0 THEN 8.0 ELSE 0 END
    ) as overall_threat_score

FROM vulnerabilities v
LEFT JOIN kev_vulnerabilities k ON v.cve_id = k.cve_id
LEFT JOIN cve_ioc_relationships cir ON v.cve_id = cir.cve_id
LEFT JOIN iocs i ON cir.ioc_id = i.id
LEFT JOIN threat_campaigns tc ON i.campaign_name = tc.campaign_name
GROUP BY v.cve_id;

-- Insertar configuración inicial
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('installation_date', NOW(), 'Fecha de instalación del Threat Intel Hub'),
('database_version', '1.0.2', 'Versión del esquema de base de datos'),
('platform_version', '1.0.2', 'Versión de la plataforma Threat Intel Hub'),
('wazuh_integration', '${HAS_WAZUH}', 'Estado de integración con Wazuh'),
('last_nvd_check', NULL, 'Última verificación de vulnerabilidades NVD'),
('last_kev_sync', NULL, 'Última sincronización KEV'),
('last_epss_update', NULL, 'Última actualización EPSS'),
('total_vulnerabilities', '0', 'Total de vulnerabilidades monitoreadas'),
('total_kev_vulnerabilities', '0', 'Total de vulnerabilidades KEV'),
('total_iocs', '0', 'Total de IoCs almacenados'),
('total_campaigns', '0', 'Total de campañas de amenazas');
SQLEOF
    
    # Ejecutar script
    $mysql_cmd < /tmp/ti_hub_setup.sql || {
        log_error "Error ejecutando comandos SQL del Threat Intel Hub"
        rm -f /tmp/ti_hub_setup.sql
        exit 1
    }
    
    rm -f /tmp/ti_hub_setup.sql
    
    log_success "Base de datos ti_hub configurada correctamente"
    
    # Verificar conexión
    if mysql -u ti_hub_user -p"${DB_PASSWORD}" ti_hub -e "SELECT COUNT(*) FROM system_config;" &>/dev/null; then
        log_success "Usuario ti_hub_user verificado"
    else
        log_error "Error verificando usuario ti_hub_user"
        exit 1
    fi
}

# Configuración de API Key NVD
configure_api_key() {
    log_header "CONFIGURACIÓN DE API KEY NVD"
    
    echo "API Key de NVD (opcional pero recomendado):"
    echo "   • Sin API key: 5 requests/30 segundos"
    echo "   • Con API key: 50 requests/30 segundos"
    echo "   • Obtener en: https://nvd.nist.gov/developers/request-an-api-key"
    echo
    
    read -p "¿Configurar API key ahora? (y/N): " configure_api
    if [[ $configure_api =~ ^[Yy]$ ]]; then
        read -p "Ingrese su API key de NVD: " API_KEY
        if [[ -n "$API_KEY" ]]; then
            log_success "API key de NVD configurada"
        else
            API_KEY=""
        fi
    else
        API_KEY=""
        log_info "API key omitida (puede configurarla después)"
    fi
}

# Configuración de email
configure_email() {
    log_header "CONFIGURACIÓN DE NOTIFICACIONES EMAIL"
    
    echo "Notificaciones por email para alertas del Threat Intel Hub"
    echo
    
    read -p "¿Configurar notificaciones por email? (y/N): " configure_mail
    if [[ $configure_mail =~ ^[Yy]$ ]]; then
        
        # Servidor SMTP
        echo
        echo "SERVIDOR SMTP:"
        echo "Ejemplos comunes:"
        echo "  • Gmail: smtp.gmail.com (puerto 587)"
        echo "  • Outlook: smtp-mail.outlook.com (puerto 587)"
        echo "  • Office 365: smtp.office365.com (puerto 587)"
        read -p "Servidor SMTP [smtp.gmail.com]: " smtp_input
        SMTP_SERVER=${smtp_input:-smtp.gmail.com}
        
        read -p "Puerto SMTP [587]: " port_input
        SMTP_PORT=${port_input:-587}
        
        # Email remitente
        echo
        while true; do
            read -p "Email remitente: " SENDER_EMAIL
            if validate_email "$SENDER_EMAIL"; then
                break
            else
                echo "❌ Email inválido"
            fi
        done
        
        # Contraseña del remitente
        read -s -p "Contraseña del remitente: " SENDER_PASSWORD
        echo
        
        # Emails destinatarios
        echo
        echo "DESTINATARIOS DE ALERTAS:"
        echo "Puede ingresar múltiples emails separados por comas"
        
        while true; do
            read -p "Email(s) destinatario(s): " recipient_input
            
            if [[ -z "$recipient_input" ]]; then
                echo "❌ Debe ingresar al menos un email"
                continue
            fi
            
            IFS=',' read -ra emails <<< "$recipient_input"
            valid_emails=()
            
            for email in "${emails[@]}"; do
                email=$(echo "$email" | xargs)
                if validate_email "$email"; then
                    valid_emails+=("$email")
                else
                    echo "❌ Email inválido: $email"
                fi
            done
            
            if [ ${#valid_emails[@]} -gt 0 ]; then
                RECIPIENT_EMAIL=$(IFS=','; echo "${valid_emails[*]}")
                echo "✅ Emails configurados: $RECIPIENT_EMAIL"
                break
            else
                echo "❌ No se ingresaron emails válidos"
            fi
        done
        
        log_success "Notificaciones por email configuradas"
    else
        SENDER_EMAIL=""
        SENDER_PASSWORD=""
        RECIPIENT_EMAIL=""
        log_info "Notificaciones por email omitidas"
    fi
}

# Configuración de Wazuh (solo si está habilitado)
configure_wazuh_integration() {
    if [[ "$HAS_WAZUH" != "true" ]]; then
        return
    fi
    
    log_header "CONFIGURACIÓN DE INTEGRACIÓN WAZUH"
    
    echo "Configure los detalles de conexión con Wazuh:"
    echo "   • API del Wazuh Manager para consultas"
    echo "   • Wazuh Indexer (OpenSearch) para búsquedas de IoCs"
    echo
    
    # Configuración Wazuh Manager
    echo "WAZUH MANAGER API:"
    while true; do
        read -p "URL del Wazuh Manager (ej: https://wazuh.local:55000): " WAZUH_URL
        if [[ $WAZUH_URL =~ ^https?:// ]]; then
            break
        else
            echo "❌ URL inválida. Debe comenzar con http:// o https://"
        fi
    done
    
    read -p "Usuario Wazuh API [wazuh]: " wazuh_user
    WAZUH_USER=${wazuh_user:-"wazuh"}
    
    read -s -p "Contraseña Wazuh API: " WAZUH_PASSWORD
    echo
    
    echo
    echo "WAZUH INDEXER (OpenSearch):"
    read -p "URL Wazuh Indexer (ej: https://wazuh-indexer.local:9200): " WAZUH_INDEXER_URL
    
    if [[ -n "$WAZUH_INDEXER_URL" ]]; then
        read -p "Usuario Indexer [admin]: " wazuh_indexer_user
        WAZUH_INDEXER_USER=${wazuh_indexer_user:-"admin"}
        read -s -p "Contraseña Indexer: " WAZUH_INDEXER_PASSWORD
        echo
    fi
    
    echo
    echo "CONFIGURACIÓN SSL:"
    read -p "¿Verificar certificado SSL de Wazuh? (Y/n): " wazuh_verify_ssl
    WAZUH_VERIFY_SSL=$([[ $wazuh_verify_ssl =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    echo
    echo "CONFIGURACIÓN DE CONSULTAS:"
    read -p "Intervalo de consulta IoCs (minutos) [30]: " ioc_query_interval
    WAZUH_IOC_INTERVAL=${ioc_query_interval:-30}
    
    read -p "Días de historial para búsquedas [7]: " wazuh_history_days
    WAZUH_HISTORY_DAYS=${wazuh_history_days:-7}
    
    read -p "¿Consultar vulnerabilidades de agentes? (Y/n): " query_vulns
    WAZUH_QUERY_VULNS=$([[ $query_vulns =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    log_success "Configuración Wazuh completada"
}

# Configuración de Threat Intelligence (sin Wazuh)
configure_threat_intelligence() {
    log_header "CONFIGURACIÓN DE FUENTES DE THREAT INTELLIGENCE"
    
    echo "Configuración de fuentes externas de Threat Intelligence:"
    echo "   • AlienVault OTX: Pulsos de amenazas y IoCs"
    echo "   • MISP: Plataforma de intercambio de amenazas"
    echo "   • VirusTotal: Enriquecimiento de IoCs"
    echo
    
    read -p "¿Configurar fuentes de Threat Intelligence adicionales? (y/N): " configure_ti
    if [[ $configure_ti =~ ^[Yy]$ ]]; then
        
        # AlienVault OTX
        echo
        echo "ALIENVAULT OTX:"
        echo "   Obtener API Key gratuita en: https://otx.alienvault.com/api"
        read -p "API Key de AlienVault OTX (opcional): " OTX_API_KEY
        
        # MISP Configuration
        echo
        echo "MISP (Malware Information Sharing Platform):"
        read -p "¿Configurar conexión MISP? (y/N): " configure_misp
        if [[ $configure_misp =~ ^[Yy]$ ]]; then
            while true; do
                read -p "URL de MISP (ej: https://misp.empresa.com): " MISP_URL
                if [[ $MISP_URL =~ ^https?:// ]]; then
                    break
                else
                    echo "❌ URL inválida. Debe comenzar con http:// o https://"
                fi
            done
            
            read -p "API Key de MISP: " MISP_API_KEY
            read -p "¿Verificar certificado SSL? (Y/n): " verify_ssl
            MISP_VERIFY_SSL=$([[ $verify_ssl =~ ^[Nn]$ ]] && echo "false" || echo "true")
        fi
        
        # VirusTotal
        echo
        echo "VIRUSTOTAL:"
        echo "   Obtener API Key gratuita en: https://www.virustotal.com/gui/my-apikey"
        read -p "API Key de VirusTotal (opcional): " VT_API_KEY
        
        log_success "Fuentes de Threat Intelligence configuradas"
    else
        log_info "Configuración de Threat Intelligence omitida"
    fi
}

# Configuración de características
configure_features() {
    log_header "CONFIGURACIÓN DE CARACTERÍSTICAS DEL THREAT INTEL HUB"
    
    echo "Habilitar características avanzadas:"
    echo
    
    read -p "¿Habilitar integración KEV (CISA Known Exploited Vulnerabilities)? (Y/n): " enable_kev
    ENABLE_KEV=$([[ $enable_kev =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    read -p "¿Habilitar integración EPSS (Exploit Prediction Scoring)? (Y/n): " enable_epss
    ENABLE_EPSS=$([[ $enable_epss =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    read -p "¿Habilitar capacidades VEX (Vulnerability Exploitability eXchange)? (Y/n): " enable_vex
    ENABLE_VEX=$([[ $enable_vex =~ ^[Nn]$ ]] && echo "false" || echo "true")
    
    if [[ "$HAS_WAZUH" == "true" ]]; then
        log_info "Correlación de IoCs habilitada automáticamente (Wazuh detectado)"
        ENABLE_IOC="true"
    else
        read -p "¿Habilitar correlación de IoCs? (Y/n): " enable_ioc
        ENABLE_IOC=$([[ $enable_ioc =~ ^[Nn]$ ]] && echo "false" || echo "true")
    fi
    
    log_success "Características del Threat Intel Hub configuradas"
}

# Crear archivo de configuración del Threat Intel Hub
create_extended_config_file() {
    log_step "Creando archivo de configuración del Threat Intel Hub..."
    
    cat > "$CONFIG_DIR/config.ini" << CONFEOF
# =============================================================================
# Threat Intel Hub Configuration v1.0.2
# =============================================================================

[database]
host = localhost
port = 3306
database = ti_hub
user = ti_hub_user
password = ${DB_PASSWORD}

[nvd]
api_key = ${API_KEY}
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0

[email]
smtp_server = ${SMTP_SERVER}
smtp_port = ${SMTP_PORT}
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_email = ${RECIPIENT_EMAIL}

[monitoring]
check_interval_hours = ${MONITOR_INTERVAL}
results_per_page = 200
days_back = 7

[logging]
level = INFO
file = /var/log/threat-intel-hub/ti-hub.log
max_size = 10485760
backup_count = 5

[features]
enable_kev = ${ENABLE_KEV}
enable_epss = ${ENABLE_EPSS}
enable_vex = ${ENABLE_VEX}
enable_ioc = ${ENABLE_IOC}

[threat_intelligence]
confidence_threshold = ${TI_CONFIDENCE}
max_iocs_per_cve = ${TI_MAX_IOCS}
retention_days = ${TI_RETENTION}

[otx]
api_key = ${OTX_API_KEY}
base_url = https://otx.alienvault.com/api/v1
enable = $([ -n "${OTX_API_KEY}" ] && echo "true" || echo "false")

[misp]
url = ${MISP_URL}
api_key = ${MISP_API_KEY}
verify_ssl = ${MISP_VERIFY_SSL}
organization = ${MISP_ORG}
distribution = ${MISP_DISTRIBUTION}
published_only = ${MISP_PUBLISHED_ONLY}
sync_interval_hours = ${MISP_SYNC_INTERVAL}
enable = $([ -n "${MISP_API_KEY}" ] && echo "true" || echo "false")

[virustotal]
api_key = ${VT_API_KEY}
base_url = https://www.virustotal.com/api/v3
enable = $([ -n "${VT_API_KEY}" ] && echo "true" || echo "false")

[wazuh]
manager_url = ${WAZUH_URL}
manager_user = ${WAZUH_USER}
manager_password = ${WAZUH_PASSWORD}
indexer_url = ${WAZUH_INDEXER_URL}
indexer_user = ${WAZUH_INDEXER_USER}
indexer_password = ${WAZUH_INDEXER_PASSWORD}
verify_ssl = ${WAZUH_VERIFY_SSL}
ioc_check_interval_minutes = ${WAZUH_IOC_INTERVAL}
history_days = ${WAZUH_HISTORY_DAYS}
query_vulnerabilities = ${WAZUH_QUERY_VULNS}
enable = ${HAS_WAZUH}

[api]
host = 0.0.0.0
port = 8080
debug = false
cors_enabled = true

[cache]
enabled = true
ttl_seconds = 3600
max_entries = 10000
CONFEOF
    
    chmod 640 "$CONFIG_DIR/config.ini"
    chown root:"$INSTALL_USER" "$CONFIG_DIR/config.ini"
    
    log_success "Archivo de configuración del Threat Intel Hub creado"
}

# Crear script principal del monitor
create_main_monitor_script() {
    log_step "Creando script principal del Threat Intel Hub..."
    
    cat > "$DATA_DIR/scripts/ti_hub_monitor.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Threat Intel Hub - Monitor Principal v1.0.2
Sistema completo de Threat Intelligence
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

# Añadir directorio de módulos al path
sys.path.insert(0, '/opt/threat-intel-hub')
sys.path.insert(0, '/opt/threat-intel-hub/connectors')

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/threat-intel-hub/ti-hub.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ThreatIntelHub')

class ThreatIntelHub:
    """Clase principal del Threat Intel Hub"""
    
    def __init__(self, config_file='/etc/threat-intel-hub/config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.db = None
        self.wazuh_connector = None
        self.wazuh_enabled = self.config.getboolean('wazuh', 'enable', fallback=False)
        self.stats = {
            'vulnerabilities_found': 0,
            'new_vulnerabilities': 0,
            'kev_vulnerabilities': 0,
            'epss_updates': 0,
            'ioc_correlations': 0,
            'wazuh_correlations': 0
        }
        
        self.init_database()
        self.init_connectors()
    
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
            logger.info("✅ Conexión a base de datos establecida")
        except Exception as e:
            logger.error(f"❌ Error conectando a base de datos: {e}")
            sys.exit(1)
    
    def init_connectors(self):
        """Inicializar conectores externos"""
        # Inicializar Wazuh solo si está habilitado
        if self.wazuh_enabled:
            try:
                from wazuh_connector import WazuhConnector
                self.wazuh_connector = WazuhConnector(self.config)
                logger.info("✅ Conector Wazuh inicializado")
            except Exception as e:
                logger.warning(f"⚠️ No se pudo inicializar Wazuh: {e}")
                self.wazuh_enabled = False
    
    def check_nvd_vulnerabilities(self):
        """Verificar vulnerabilidades desde NVD"""
        logger.info("🔍 Iniciando verificación NVD...")
        
        api_key = self.config.get('nvd', 'api_key', fallback='')
        base_url = self.config.get('nvd', 'base_url')
        
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        
        # Calcular rango de fechas
        days_back = self.config.getint('monitoring', 'days_back', fallback=7)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            'resultsPerPage': 200,
            'startIndex': 0,
            'lastModStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'lastModEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        }
        
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                logger.info(f"📊 {len(vulnerabilities)} vulnerabilidades encontradas")
                
                for vuln in vulnerabilities:
                    self.process_vulnerability(vuln)
                
                self.stats['vulnerabilities_found'] = len(vulnerabilities)
                
                # Verificar KEV si está habilitado
                if self.config.getboolean('features', 'enable_kev', fallback=True):
                    self.check_kev_vulnerabilities()
                
                # Verificar EPSS si está habilitado
                if self.config.getboolean('features', 'enable_epss', fallback=True):
                    self.update_epss_scores()
                
                # Correlacionar IoCs si está habilitado
                if self.config.getboolean('features', 'enable_ioc', fallback=True):
                    self.correlate_iocs()
                
                return True
            else:
                logger.error(f"❌ Error en API NVD: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error verificando NVD: {e}")
            return False
    
    def process_vulnerability(self, vuln_data):
        """Procesar una vulnerabilidad individual"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id')
            
            # Extraer información básica
            published = cve.get('published')
            modified = cve.get('lastModified')
            
            # Descripción
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
            
            # CVSS Score
            cvss_score = 0.0
            cvss_severity = 'UNKNOWN'
            
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Referencias
            references = cve.get('references', [])
            reference_urls = json.dumps([ref.get('url') for ref in references[:10]])
            
            # Productos afectados
            configurations = cve.get('configurations', [])
            affected_products = self.extract_affected_products(configurations)
            
            # Calcular risk score compuesto
            composite_risk = self.calculate_composite_risk(cvss_score, cvss_severity)
            
            # Insertar o actualizar en base de datos
            cursor = self.db.cursor()
            
            query = """
                INSERT INTO vulnerabilities 
                (cve_id, published_date, last_modified, cvss_score, cvss_severity, 
                 description, reference_urls, affected_products, composite_risk_score)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                last_modified = VALUES(last_modified),
                cvss_score = VALUES(cvss_score),
                cvss_severity = VALUES(cvss_severity),
                description = VALUES(description),
                reference_urls = VALUES(reference_urls),
                affected_products = VALUES(affected_products),
                composite_risk_score = VALUES(composite_risk_score),
                updated_at = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (
                cve_id, published, modified, cvss_score, cvss_severity,
                description[:5000], reference_urls, json.dumps(affected_products),
                composite_risk
            ))
            
            if cursor.rowcount == 1:
                self.stats['new_vulnerabilities'] += 1
                logger.info(f"✅ Nueva vulnerabilidad: {cve_id} (CVSS: {cvss_score})")
            
            self.db.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"❌ Error procesando vulnerabilidad: {e}")
    
    def extract_affected_products(self, configurations):
        """Extraer productos afectados de configuraciones"""
        products = []
        
        for config in configurations:
            if 'nodes' in config:
                for node in config['nodes']:
                    if 'cpeMatch' in node:
                        for cpe in node['cpeMatch']:
                            if cpe.get('vulnerable'):
                                products.append(cpe.get('criteria', ''))
        
        return products[:50]  # Limitar a 50 productos
    
    def calculate_composite_risk(self, cvss_score, severity):
        """Calcular score de riesgo compuesto"""
        base_score = cvss_score
        
        # Ajustes por severidad
        severity_multipliers = {
            'CRITICAL': 1.5,
            'HIGH': 1.2,
            'MEDIUM': 1.0,
            'LOW': 0.8,
            'UNKNOWN': 0.9
        }
        
        multiplier = severity_multipliers.get(severity, 1.0)
        composite = base_score * multiplier
        
        return min(10.0, composite)
    
    def check_kev_vulnerabilities(self):
        """Verificar vulnerabilidades KEV de CISA"""
        logger.info("🎯 Verificando vulnerabilidades KEV...")
        
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                cursor = self.db.cursor()
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get('cveID')
                    
                    query = """
                        INSERT INTO kev_vulnerabilities
                        (cve_id, vendor_project, product, vulnerability_name,
                         date_added, short_description, required_action, due_date,
                         known_ransomware, notes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        updated_at = CURRENT_TIMESTAMP
                    """
                    
                    cursor.execute(query, (
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
                
                self.db.commit()
                cursor.close()
                
                self.stats['kev_vulnerabilities'] = len(vulnerabilities)
                logger.info(f"✅ {len(vulnerabilities)} vulnerabilidades KEV procesadas")
                
        except Exception as e:
            logger.error(f"❌ Error verificando KEV: {e}")
    
    def update_epss_scores(self):
        """Actualizar scores EPSS"""
        logger.info("📈 Actualizando scores EPSS...")
        
        try:
            # URL del CSV de EPSS
            url = "https://api.first.org/data/v1/epss"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                cursor = self.db.cursor()
                updates = 0
                
                for item in data.get('data', []):
                    cve_id = item.get('cve')
                    epss_score = float(item.get('epss', 0))
                    percentile = float(item.get('percentile', 0))
                    
                    # Actualizar vulnerability
                    update_query = """
                        UPDATE vulnerabilities 
                        SET epss_score = %s, epss_percentile = %s, epss_date = CURDATE()
                        WHERE cve_id = %s
                    """
                    cursor.execute(update_query, (epss_score, percentile, cve_id))
                    
                    if cursor.rowcount > 0:
                        updates += 1
                        
                        # Insertar en historial
                        history_query = """
                            INSERT INTO epss_history (cve_id, epss_score, epss_percentile, date_recorded)
                            VALUES (%s, %s, %s, CURDATE())
                            ON DUPLICATE KEY UPDATE
                            epss_score = VALUES(epss_score),
                            epss_percentile = VALUES(epss_percentile)
                        """
                        cursor.execute(history_query, (cve_id, epss_score, percentile))
                
                self.db.commit()
                cursor.close()
                
                self.stats['epss_updates'] = updates
                logger.info(f"✅ {updates} scores EPSS actualizados")
                
        except Exception as e:
            logger.error(f"❌ Error actualizando EPSS: {e}")
    
    def correlate_iocs(self):
        """Correlacionar IoCs con vulnerabilidades y Wazuh"""
        logger.info("🔗 Correlacionando IoCs...")
        
        # Si Wazuh no está habilitado, omitir correlación
        if not self.wazuh_enabled:
            logger.info("⚠️ Correlación de IoCs con Wazuh deshabilitada")
            return
        
        try:
            # Obtener IoCs activos
            cursor = self.db.cursor(dictionary=True)
            
            query = """
                SELECT id, indicator_value, indicator_type, confidence_score
                FROM iocs
                WHERE is_active = TRUE
                AND last_seen >= DATE_SUB(NOW(), INTERVAL %s DAY)
                ORDER BY confidence_score DESC
                LIMIT 1000
            """
            
            retention_days = self.config.getint('threat_intelligence', 'retention_days', fallback=90)
            cursor.execute(query, (retention_days,))
            
            iocs = cursor.fetchall()
            correlations = 0
            
            for ioc in iocs:
                # Buscar en Wazuh si está disponible
                if self.wazuh_connector:
                    wazuh_alerts = self.wazuh_connector.search_ioc_in_alerts(
                        ioc['indicator_value'],
                        ioc['indicator_type']
                    )
                    
                    if wazuh_alerts:
                        correlations += self.process_wazuh_correlations(ioc, wazuh_alerts)
            
            cursor.close()
            
            self.stats['ioc_correlations'] = correlations
            logger.info(f"✅ {correlations} correlaciones de IoCs procesadas")
            
        except Exception as e:
            logger.error(f"❌ Error correlacionando IoCs: {e}")
    
    def process_wazuh_correlations(self, ioc, alerts):
        """Procesar correlaciones con Wazuh"""
        correlations = 0
        
        try:
            cursor = self.db.cursor()
            
            for alert in alerts:
                correlation_id = str(uuid.uuid4())
                
                query = """
                    INSERT INTO wazuh_correlations
                    (id, correlation_type, target_id, agent_id, agent_name,
                     rule_id, rule_description, timestamp, correlation_data,
                     confidence_score)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                cursor.execute(query, (
                    correlation_id,
                    'ioc',
                    ioc['id'],
                    alert.get('agent_id'),
                    alert.get('agent_name'),
                    alert.get('rule_id'),
                    alert.get('rule_description'),
                    alert.get('timestamp'),
                    json.dumps(alert),
                    ioc['confidence_score']
                ))
                
                correlations += 1
            
            # Actualizar contador de detecciones en IoC
            update_query = """
                UPDATE iocs 
                SET wazuh_detections = wazuh_detections + %s,
                    last_detection = NOW()
                WHERE id = %s
            """
            cursor.execute(update_query, (len(alerts), ioc['id']))
            
            self.db.commit()
            cursor.close()
            
            self.stats['wazuh_correlations'] += correlations
            
        except Exception as e:
            logger.error(f"❌ Error procesando correlaciones Wazuh: {e}")
        
        return correlations
    
    def generate_threat_report(self):
        """Generar reporte de amenazas"""
        logger.info("📊 Generando reporte de amenazas...")
        
        try:
            cursor = self.db.cursor(dictionary=True)
            
            # Construir query base
            base_query = """
                SELECT 
                    COUNT(DISTINCT v.cve_id) as total_cves,
                    COUNT(DISTINCT k.cve_id) as kev_count,
                    COUNT(DISTINCT i.id) as ioc_count,
                    SUM(CASE WHEN v.cvss_severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN v.cvss_severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
                FROM vulnerabilities v
                LEFT JOIN kev_vulnerabilities k ON v.cve_id = k.cve_id
                LEFT JOIN cve_ioc_relationships cir ON v.cve_id = cir.cve_id
                LEFT JOIN iocs i ON cir.ioc_id = i.id
            """
            
            # Agregar join de Wazuh solo si está habilitado
            if self.wazuh_enabled:
                stats_query = base_query + """
                    LEFT JOIN wazuh_correlations w ON v.cve_id = w.target_id
                    WHERE v.published_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                """
            else:
                stats_query = base_query + """
                    WHERE v.published_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                """
            
            cursor.execute(stats_query)
            stats = cursor.fetchone()
            
            # Agregar campo wazuh_alerts
            if not self.wazuh_enabled:
                stats['wazuh_alerts'] = 0
            else:
                # Obtener conteo de alertas Wazuh
                wazuh_query = """
                    SELECT COUNT(DISTINCT id) as wazuh_alerts
                    FROM wazuh_correlations
                    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                """
                cursor.execute(wazuh_query)
                wazuh_stats = cursor.fetchone()
                stats['wazuh_alerts'] = wazuh_stats['wazuh_alerts'] if wazuh_stats else 0
            
            # Obtener top amenazas
            threats_query = """
                SELECT 
                    v.cve_id,
                    v.cvss_score,
                    v.cvss_severity,
                    v.description,
                    v.epss_score,
                    k.known_ransomware,
                    COUNT(DISTINCT i.id) as ioc_count
                FROM vulnerabilities v
                LEFT JOIN kev_vulnerabilities k ON v.cve_id = k.cve_id
                LEFT JOIN cve_ioc_relationships cir ON v.cve_id = cir.cve_id
                LEFT JOIN iocs i ON cir.ioc_id = i.id
                WHERE v.cvss_severity IN ('CRITICAL', 'HIGH')
                GROUP BY v.cve_id
                ORDER BY v.cvss_score DESC, v.epss_score DESC
                LIMIT 10
            """
            
            cursor.execute(threats_query)
            top_threats = cursor.fetchall()
            
            # Agregar detecciones Wazuh si está habilitado
            if self.wazuh_enabled:
                for threat in top_threats:
                    wazuh_count_query = """
                        SELECT COUNT(*) as wazuh_detections
                        FROM wazuh_correlations
                        WHERE target_id = %s AND correlation_type = 'cve'
                    """
                    cursor.execute(wazuh_count_query, (threat['cve_id'],))
                    wazuh_count = cursor.fetchone()
                    threat['wazuh_detections'] = wazuh_count['wazuh_detections'] if wazuh_count else 0
            else:
                for threat in top_threats:
                    threat['wazuh_detections'] = 0
            
            cursor.close()
            
            # Generar HTML del reporte
            threat_details = self.format_threat_details(top_threats)
            
            # Cargar plantilla
            template_path = Path('/opt/threat-intel-hub/templates/threat_report_template.html')
            if template_path.exists():
                template = template_path.read_text()
                
                # Reemplazar variables
                report_html = template.replace('{{report_date}}', datetime.now().strftime('%Y-%m-%d %H:%M'))
                report_html = report_html.replace('{{total_cves}}', str(stats['total_cves']))
                report_html = report_html.replace('{{kev_count}}', str(stats['kev_count']))
                report_html = report_html.replace('{{ioc_count}}', str(stats['ioc_count']))
                report_html = report_html.replace('{{wazuh_alerts}}', str(stats['wazuh_alerts']))
                report_html = report_html.replace('{{threat_details}}', threat_details)
                
                # Guardar reporte
                report_file = f"/var/lib/threat-intel-hub/reports/threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                Path(report_file).write_text(report_html)
                
                logger.info(f"✅ Reporte generado: {report_file}")
                
                return report_html, stats
            
        except Exception as e:
            logger.error(f"❌ Error generando reporte: {e}")
            return None, None
    
    def format_threat_details(self, threats):
        """Formatear detalles de amenazas para HTML"""
        html = "<h2>Top Amenazas Detectadas</h2>"
        
        for threat in threats:
            risk_badge = "🔴" if threat['cvss_severity'] == 'CRITICAL' else "🟠"
            ransomware_badge = "🔓" if threat.get('known_ransomware') else ""
            
            wazuh_info = ""
            if self.wazuh_enabled and threat['wazuh_detections'] > 0:
                wazuh_info = f"<p><strong>Detecciones Wazuh:</strong> {threat['wazuh_detections']}</p>"
            
            html += f"""
            <div class="threat-item">
                <h3>{risk_badge} {threat['cve_id']} {ransomware_badge}</h3>
                <p><strong>CVSS Score:</strong> {threat['cvss_score']}</p>
                <p><strong>EPSS Score:</strong> {threat.get('epss_score', 'N/A')}</p>
                <p><strong>IoCs Asociados:</strong> {threat['ioc_count']}</p>
                {wazuh_info}
                <p>{threat['description'][:300]}...</p>
            </div>
            """
        
        return html
    
    def send_notification(self):
        """Enviar notificación por email"""
        if not self.config.get('email', 'sender_email'):
            logger.info("📧 Notificaciones por email no configuradas")
            return
        
        logger.info("📧 Enviando notificación por email...")
        
        try:
            # Generar reporte
            report_html, stats = self.generate_threat_report()
            
            if not report_html:
                return
            
            # Configurar email
            msg = MIMEMultipart('alternative')
            
            # Crear asunto descriptivo
            subject_parts = [f"{stats['total_cves']} CVEs"]
            if stats['kev_count'] > 0:
                subject_parts.append(f"{stats['kev_count']} KEV")
            if stats['ioc_count'] > 0:
                subject_parts.append(f"{stats['ioc_count']} IoCs")
            if self.wazuh_enabled and stats['wazuh_alerts'] > 0:
                subject_parts.append(f"{stats['wazuh_alerts']} Wazuh")
            
            msg['Subject'] = f"Threat Intel Hub - {' | '.join(subject_parts)}"
            msg['From'] = self.config.get('email', 'sender_email')
            msg['To'] = self.config.get('email', 'recipient_email')
            
            # Añadir contenido HTML
            html_part = MIMEText(report_html, 'html')
            msg.attach(html_part)
            
            # Enviar email
            with smtplib.SMTP(self.config.get('email', 'smtp_server'), 
                             self.config.getint('email', 'smtp_port')) as server:
                server.starttls()
                server.login(
                    self.config.get('email', 'sender_email'),
                    self.config.get('email', 'sender_password')
                )
                
                recipients = self.config.get('email', 'recipient_email').split(',')
                server.send_message(msg, to_addrs=recipients)
            
            # Registrar notificación
            cursor = self.db.cursor()
            query = """
                INSERT INTO email_notifications
                (recipient_email, subject, vulnerabilities_count, critical_count,
                 high_count, kev_count, ioc_count, wazuh_alerts, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'sent')
            """
            
            cursor.execute(query, (
                self.config.get('email', 'recipient_email'),
                msg['Subject'],
                stats['total_cves'],
                stats.get('critical_count', 0),
                stats.get('high_count', 0),
                stats['kev_count'],
                stats['ioc_count'],
                stats['wazuh_alerts']
            ))
            
            self.db.commit()
            cursor.close()
            
            logger.info("✅ Notificación enviada exitosamente")
            
        except Exception as e:
            logger.error(f"❌ Error enviando notificación: {e}")
    
    def log_monitoring(self):
        """Registrar actividad de monitoreo"""
        try:
            cursor = self.db.cursor()
            
            query = """
                INSERT INTO monitoring_logs
                (vulnerabilities_found, new_vulnerabilities, kev_vulnerabilities,
                 epss_updates, ioc_correlations, wazuh_correlations, status, message)
                VALUES (%s, %s, %s, %s, %s, %s, 'completed', 'Monitoreo completado')
            """
            
            cursor.execute(query, (
                self.stats['vulnerabilities_found'],
                self.stats['new_vulnerabilities'],
                self.stats['kev_vulnerabilities'],
                self.stats['epss_updates'],
                self.stats['ioc_correlations'],
                self.stats['wazuh_correlations']
            ))
            
            self.db.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"❌ Error registrando monitoreo: {e}")
    
    def run_monitoring_cycle(self):
        """Ejecutar ciclo completo de monitoreo"""
        logger.info("="*60)
        logger.info("THREAT INTEL HUB - Iniciando ciclo de monitoreo")
        if self.wazuh_enabled:
            logger.info("✅ Integración Wazuh HABILITADA")
        else:
            logger.info("⚠️ Integración Wazuh DESHABILITADA")
        logger.info("="*60)
        
        start_time = time.time()
        
        # Reiniciar estadísticas
        self.stats = {
            'vulnerabilities_found': 0,
            'new_vulnerabilities': 0,
            'kev_vulnerabilities': 0,
            'epss_updates': 0,
            'ioc_correlations': 0,
            'wazuh_correlations': 0
        }
        
        # Ejecutar verificaciones
        success = self.check_nvd_vulnerabilities()
        
        if success:
            # Registrar monitoreo
            self.log_monitoring()
            
            # Enviar notificación si hay hallazgos importantes
            if (self.stats['new_vulnerabilities'] > 0 or 
                self.stats['kev_vulnerabilities'] > 0 or
                (self.wazuh_enabled and self.stats['wazuh_correlations'] > 0)):
                self.send_notification()
        
        elapsed_time = time.time() - start_time
        
        logger.info("="*60)
        logger.info(f"📊 Resumen del ciclo:")
        logger.info(f"   • Vulnerabilidades encontradas: {self.stats['vulnerabilities_found']}")
        logger.info(f"   • Nuevas vulnerabilidades: {self.stats['new_vulnerabilities']}")
        logger.info(f"   • Vulnerabilidades KEV: {self.stats['kev_vulnerabilities']}")
        logger.info(f"   • Actualizaciones EPSS: {self.stats['epss_updates']}")
        if self.wazuh_enabled:
            logger.info(f"   • Correlaciones IoC: {self.stats['ioc_correlations']}")
            logger.info(f"   • Correlaciones Wazuh: {self.stats['wazuh_correlations']}")
        logger.info(f"   • Tiempo de ejecución: {elapsed_time:.2f} segundos")
        logger.info("="*60)
    
    def run_scheduler(self):
        """Ejecutar el scheduler principal"""
        # Ejecutar inmediatamente
        self.run_monitoring_cycle()
        
        # Programar ejecuciones periódicas
        interval = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        schedule.every(interval).hours.do(self.run_monitoring_cycle)
        
        logger.info(f"⏰ Scheduler configurado cada {interval} horas")
        
        while True:
            schedule.run_pending()
            time.sleep(60)

def main():
    """Función principal"""
    try:
        hub = ThreatIntelHub()
        hub.run_scheduler()
    except KeyboardInterrupt:
        logger.info("\nThreat Intel Hub detenido por el usuario")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
PYEOF
    
    chmod +x "$DATA_DIR/scripts/ti_hub_monitor.py"
    chown "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR/scripts/ti_hub_monitor.py"
    
    log_success "Script principal del Threat Intel Hub creado"
}

# Crear servicio systemd
create_systemd_service() {
    log_step "Creando servicio systemd del Threat Intel Hub..."
    
    cat > /etc/systemd/system/threat-intel-hub.service << 'SVCEOF'
[Unit]
Description=Threat Intel Hub - Threat Intelligence Platform
Documentation=https://github.com/threat-intel-hub
After=network.target mysql.service mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=ti-hub
Group=ti-hub
WorkingDirectory=/opt/threat-intel-hub
Environment="PATH=/opt/threat-intel-hub/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/threat-intel-hub/venv/bin/python /var/lib/threat-intel-hub/scripts/ti_hub_monitor.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=threat-intel-hub

# Seguridad
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/threat-intel-hub /var/log/threat-intel-hub
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
SVCEOF
    
    systemctl daemon-reload
    systemctl enable threat-intel-hub.service
    
    log_success "Servicio systemd del Threat Intel Hub creado"
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

# Test de conectividad
test_connectivity() {
    log_step "Probando conectividad del Threat Intel Hub..."
    
    # Test de base de datos
    if mysql -u ti_hub_user -p"${DB_PASSWORD}" ti_hub -e "SELECT 1;" &>/dev/null; then
        log_success "Conexión a base de datos OK"
    else
        log_error "Error de conexión a base de datos"
    fi
    
    # Test de API NVD
    if curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1" > /dev/null; then
        log_success "Conexión a API NVD OK"
    else
        log_warn "No se pudo conectar a API NVD"
    fi
    
    # Test de email si está configurado
    if [[ -n "$SENDER_EMAIL" ]]; then
        cat > /tmp/test_email.py << TESTEOF
import smtplib
import sys

try:
    server = smtplib.SMTP('${SMTP_SERVER}', ${SMTP_PORT})
    server.starttls()
    server.login('${SENDER_EMAIL}', '${SENDER_PASSWORD}')
    server.quit()
    print("✅ Conexión SMTP OK")
    sys.exit(0)
except Exception as e:
    print(f"❌ Error SMTP: {e}")
    sys.exit(1)
TESTEOF
        
        if python3 /tmp/test_email.py; then
            log_success "Configuración de email verificada"
        else
            log_warn "Error verificando configuración de email"
        fi
        
        rm -f /tmp/test_email.py
    fi
    
    # Test de Wazuh si está configurado
    if [[ "$HAS_WAZUH" == "true" ]] && [[ -n "$WAZUH_URL" ]]; then
        log_info "Probando conexión con Wazuh..."
        # Test básico de conectividad (sin autenticación)
        if curl -sk --connect-timeout 5 "$WAZUH_URL" > /dev/null 2>&1; then
            log_success "Conexión a Wazuh Manager OK"
        else
            log_warn "No se pudo conectar a Wazuh Manager"
        fi
    fi
}

# Resumen de instalación
show_summary() {
    log_header "RESUMEN DE INSTALACIÓN DEL THREAT INTEL HUB"
    
    echo -e "${GREEN}✅ Instalación completada exitosamente!${NC}"
    echo
    echo "📋 INFORMACIÓN DEL SISTEMA:"
    echo "   • Versión: ${SCRIPT_VERSION}"
    echo "   • Usuario del servicio: ${INSTALL_USER}"
    echo "   • Directorio de instalación: ${INSTALL_DIR}"
    echo "   • Archivo de configuración: ${CONFIG_DIR}/config.ini"
    echo "   • Logs: ${LOG_DIR}"
    echo "   • Datos: ${DATA_DIR}"
    echo
    echo "🔐 CREDENCIALES DE BASE DE DATOS:"
    echo "   • Base de datos: ti_hub"
    echo "   • Usuario: ti_hub_user"
    echo "   • Contraseña: ${DB_PASSWORD}"
    echo "   ${YELLOW}⚠️  Guarde esta contraseña en un lugar seguro${NC}"
    echo
    
    if [[ -n "$API_KEY" ]]; then
        echo "🔑 API KEY NVD:"
        echo "   • Configurada (50 req/30s)"
    else
        echo "🔑 API KEY NVD:"
        echo "   • No configurada (5 req/30s)"
        echo "   • Puede agregarla en: ${CONFIG_DIR}/config.ini"
    fi
    echo
    
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "📧 NOTIFICACIONES EMAIL:"
        echo "   • Servidor: ${SMTP_SERVER}:${SMTP_PORT}"
        echo "   • Remitente: ${SENDER_EMAIL}"
        echo "   • Destinatarios: ${RECIPIENT_EMAIL}"
    else
        echo "📧 NOTIFICACIONES EMAIL:"
        echo "   • No configuradas"
    fi
    echo
    
    echo "🎯 INTEGRACIONES:"
    if [[ "$HAS_WAZUH" == "true" ]]; then
        echo "   • Wazuh: ✅ HABILITADO"
        if [[ -n "$WAZUH_URL" ]]; then
            echo "     - Manager: ${WAZUH_URL}"
            echo "     - Correlación CVE-IoC: ✅ Activa"
        else
            echo "     - Pendiente configuración manual en ${CONFIG_DIR}/config.ini"
        fi
    else
        echo "   • Wazuh: ❌ No detectado"
    fi
    
    if [[ -n "$OTX_API_KEY" ]]; then
        echo "   • AlienVault OTX: ✅ Configurado"
    fi
    if [[ -n "$MISP_API_KEY" ]]; then
        echo "   • MISP: ✅ Configurado (${MISP_URL})"
    fi
    if [[ -n "$VT_API_KEY" ]]; then
        echo "   • VirusTotal: ✅ Configurado"
    fi
    echo
    
    echo "⚙️ CARACTERÍSTICAS:"
    echo "   • KEV (CISA): $([[ "$ENABLE_KEV" == "true" ]] && echo "✅ Habilitado" || echo "❌ Deshabilitado")"
    echo "   • EPSS: $([[ "$ENABLE_EPSS" == "true" ]] && echo "✅ Habilitado" || echo "❌ Deshabilitado")"
    echo "   • VEX: $([[ "$ENABLE_VEX" == "true" ]] && echo "✅ Habilitado" || echo "❌ Deshabilitado")"
    echo "   • IoC Correlation: $([[ "$ENABLE_IOC" == "true" ]] && echo "✅ Habilitado" || echo "❌ Deshabilitado")"
    echo
    
    echo "🎮 COMANDOS DISPONIBLES:"
    echo "   • Iniciar servicio:    ${GREEN}sudo systemctl start threat-intel-hub${NC}"
    echo "   • Detener servicio:    ${YELLOW}sudo systemctl stop threat-intel-hub${NC}"
    echo "   • Ver estado:          ${BLUE}sudo systemctl status threat-intel-hub${NC}"
    echo "   • Ver logs:            ${PURPLE}sudo journalctl -u threat-intel-hub -f${NC}"
    echo "   • Editar config:       ${CYAN}sudo nano ${CONFIG_DIR}/config.ini${NC}"
    echo
    
    echo "📊 MONITOREO:"
    echo "   • Intervalo de verificación: cada ${MONITOR_INTERVAL} horas"
    echo "   • Dashboard: http://localhost:8080 (próximamente)"
    echo
    
    if [[ "$HAS_WAZUH" == "true" ]] && [[ -z "$WAZUH_URL" ]]; then
        echo "⚠️ CONFIGURACIÓN PENDIENTE - WAZUH:"
        echo "   Wazuh fue detectado pero no configurado."
        echo "   Para habilitar la integración:"
        echo "   1. Edite: ${CONFIG_DIR}/config.ini"
        echo "   2. Configure las credenciales de Wazuh en la sección [wazuh]"
        echo "   3. Reinicie el servicio: sudo systemctl restart threat-intel-hub"
        echo
    fi
    
    echo "🚀 PRÓXIMOS PASOS:"
    echo "   1. Inicie el servicio con: ${GREEN}sudo systemctl start threat-intel-hub${NC}"
    echo "   2. Verifique el estado con: ${BLUE}sudo systemctl status threat-intel-hub${NC}"
    echo "   3. Monitoree los logs con: ${PURPLE}sudo journalctl -u threat-intel-hub -f${NC}"
    if [[ "$HAS_WAZUH" == "true" ]] && [[ -z "$WAZUH_URL" ]]; then
        echo "   4. Configure Wazuh en: ${CONFIG_DIR}/config.ini"
    fi
    echo
    
    echo -e "${YELLOW}⚠️  IMPORTANTE:${NC}"
    echo "   • Guarde las credenciales de base de datos en un lugar seguro"
    echo "   • Configure un backup regular de la base de datos ti_hub"
    echo "   • Revise y ajuste la configuración según sus necesidades"
    echo
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
    create_schemas
    
    # Solo crear integración Wazuh si fue detectado
    if [[ "$HAS_WAZUH" == "true" ]]; then
        create_wazuh_integration
    fi
    
    create_templates
    setup_database
    configure_api_key
    configure_email
    
    # Configurar Wazuh si fue detectado
    if [[ "$HAS_WAZUH" == "true" ]]; then
        configure_wazuh_integration
    fi
    
    configure_threat_intelligence
    configure_features
    create_extended_config_file
    create_main_monitor_script
    create_systemd_service
    setup_logrotate
    test_connectivity
    show_summary
    
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       THREAT INTEL HUB INSTALADO EXITOSAMENTE             ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    read -p "¿Desea iniciar el servicio ahora? (Y/n): " start_now
    if [[ ! $start_now =~ ^[Nn]$ ]]; then
        systemctl start threat-intel-hub
        sleep 2
        systemctl status threat-intel-hub --no-pager
    fi
}

# Ejecutar función principal
main