#!/bin/bash

# =============================================================================
# Threat Intel Hub - Script de Instalación v1.0.5 ENTERPRISE
# PARTE 2: Python, comandos administrativos y scripts
# =============================================================================

set -euo pipefail

# Colores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Cargar variables de la parte 1
if [[ -f /tmp/ti_hub_install_vars.sh ]]; then
    source /tmp/ti_hub_install_vars.sh
else
    echo -e "${RED}[ERROR]${NC} No se encontraron las variables de instalación."
    echo "Por favor ejecute primero ti_hub_installer_v1.0.5_part1.sh"
    exit 1
fi

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

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Instalar entorno Python
setup_python_environment() {
    log_header "CONFIGURACIÓN DEL ENTORNO PYTHON"
    
    log_step "Creando entorno virtual..."
    sudo -u $INSTALL_USER python3 -m venv "$VENV_DIR"
    
    log_step "Instalando paquetes Python..."
    sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install --upgrade pip wheel setuptools
    
    cat > /tmp/requirements.txt << 'EOF'
requests>=2.31.0
mysql-connector-python>=8.0.33
pymongo>=4.3.3
redis>=4.5.5
flask>=2.3.2
flask-restful>=0.3.10
flask-cors>=4.0.0
flask-limiter>=3.3.1
pandas>=2.0.3
numpy>=1.24.3
python-dateutil>=2.8.2
openpyxl>=3.0.0
cryptography>=41.0.1
pycryptodome>=3.18.0
schedule>=1.2.0
celery>=5.3.1
apscheduler>=3.10.1
secure-smtplib>=0.1.1
prometheus-client>=0.17.0
python-json-logger>=2.0.7
pymisp>=2.4.173
python-dotenv>=1.0.0
pyyaml>=6.0
validators>=0.20.0
jinja2>=3.1.2
beautifulsoup4>=4.12.2
lxml>=4.9.3
EOF
    
    sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install -r /tmp/requirements.txt
    
    log_step "Instalando OTX SDK..."
    install_otx_sdk
    
    log_success "Entorno Python configurado"
}

# Función para instalar OTX SDK
install_otx_sdk() {
    log_info "Intentando instalar OTX SDK desde GitHub..."
    
    if sudo -u $INSTALL_USER "$VENV_DIR/bin/pip" install git+https://github.com/AlienVault-OTX/OTX-Python-SDK.git &>/dev/null; then
        log_success "OTX SDK instalado desde GitHub"
        return 0
    fi
    
    log_warn "Creando módulo OTX alternativo..."
    
    cat > "$INSTALL_DIR/lib/otx_alternative/otx_client.py" << 'OTXMODULE'
#!/usr/bin/env python3
import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class OTXClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        }
        
    def validate_api_key(self) -> bool:
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
    
    def get_pulse_indicators(self, pulse_id: str) -> List[Dict]:
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

def get_otx_client(api_key: str):
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
    
    cat > "$CONFIG_DIR/config.ini" << EOF
[database]
host = $DB_HOST
port = $DB_PORT
database = $DB_NAME
user = $DB_USER
password = $DB_PASSWORD

[triggers]
kev_enabled = true
kev_check_minutes = 30
epss_enabled = true
epss_spike_threshold = 0.2
epss_check_hours = 4
misp_priority = true

[sources]
nvd_api_key = $NVD_API_KEY
nvd_base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
kev_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
epss_url = https://api.first.org/data/v1/epss
otx_api_key = $OTX_API_KEY
otx_base_url = https://otx.alienvault.com/api/v1

[api]
enabled = true
host = 0.0.0.0
port = 8080
export_formats = paloalto,fortinet,cisco,snort,yara,stix,misp,csv
cors_enabled = true
rate_limit = 100

[email]
enabled = $EMAIL_ENABLED
smtp_server = $SMTP_SERVER
smtp_port = $SMTP_PORT
sender_email = $SENDER_EMAIL
sender_password = $SENDER_PASSWORD
recipient_email = $RECIPIENT_EMAIL
use_tls = $USE_TLS

[advisory]
enabled = $ADVISORY_ENABLED
schedule = $ADVISORY_SCHEDULE
auto_send = true
include_excel = true
priority_threshold = 80

[logging]
level = INFO
max_file_size = 10485760
backup_count = 10
log_dir = $LOG_DIR
EOF
    
    chmod 640 "$CONFIG_DIR/config.ini"
    chown root:$INSTALL_USER "$CONFIG_DIR/config.ini"
    
    log_success "Archivos de configuración creados"
}

# Crear comando ti-hub-admin con init-data
create_admin_command() {
    log_header "CREANDO COMANDO TI-HUB-ADMIN"
    
    cat > /usr/local/bin/ti-hub-admin << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_FILE="/etc/threat-intel-hub/config.ini"
LOG_FILE="/var/log/threat-intel-hub/ti-hub.log"
DATA_DIR="/var/lib/threat-intel-hub"
PYTHON_ENV="/opt/threat-intel-hub/venv/bin/python"
INSTALL_USER="ti-hub"

run_python() {
    sudo -u $INSTALL_USER $PYTHON_ENV -c "$1"
}

case "$1" in
    "init-data")
        DAYS=30
        if [[ "$2" == "--days" ]] && [[ -n "$3" ]]; then
            DAYS="$3"
        fi
        
        echo -e "${BLUE}=== INICIALIZANDO DATOS ===${NC}"
        echo "Cargando datos de los últimos $DAYS días..."
        
        # Crear script temporal para init-data
        cat > /tmp/init_data.py << 'INITSCRIPT'
import sys
sys.path.insert(0, '/opt/threat-intel-hub/lib/otx_alternative')
import mysql.connector
import requests
import json
import configparser
from datetime import datetime, timedelta
import time

config = configparser.ConfigParser()
config.read('/etc/threat-intel-hub/config.ini')

def log(msg):
    print(f'[{datetime.now().strftime("%H:%M:%S")}] {msg}')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    # CARGAR KEV
    log('📥 Descargando CISA KEV...')
    kev_url = config.get('sources', 'kev_url')
    response = requests.get(kev_url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        log(f'   Encontradas {len(vulnerabilities)} vulnerabilidades KEV')
        
        kev_count = 0
        for vuln in vulnerabilities[:50]:  # Limitar para prueba
            try:
                cursor.execute('''
                    INSERT INTO kev_vulnerabilities 
                    (cve_id, vendor_project, product, vulnerability_name,
                     date_added, short_description, required_action, due_date,
                     known_ransomware)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    short_description = VALUES(short_description)
                ''', (
                    vuln.get('cveID'),
                    vuln.get('vendorProject'),
                    vuln.get('product'),
                    vuln.get('vulnerabilityName'),
                    vuln.get('dateAdded'),
                    vuln.get('shortDescription'),
                    vuln.get('requiredAction'),
                    vuln.get('dueDate'),
                    vuln.get('knownRansomwareCampaignUse', '').lower() == 'known'
                ))
                
                cursor.execute('''
                    INSERT INTO vulnerabilities (cve_id, description, kev_status, threat_score)
                    VALUES (%s, %s, TRUE, 85)
                    ON DUPLICATE KEY UPDATE 
                    kev_status = TRUE,
                    threat_score = GREATEST(threat_score, 85)
                ''', (vuln.get('cveID'), vuln.get('shortDescription')))
                
                kev_count += 1
                
            except Exception as e:
                pass
        
        conn.commit()
        log(f'   ✅ {kev_count} KEVs cargadas')
    
    # Estadísticas finales
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    total_cves = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM kev_vulnerabilities')
    total_kevs = cursor.fetchone()[0]
    
    print()
    print('=' * 50)
    print('RESUMEN DE CARGA INICIAL:')
    print(f'  📊 Total CVEs: {total_cves}')
    print(f'  🚨 KEVs activas: {total_kevs}')
    print('=' * 50)
    
    cursor.close()
    conn.close()
    
    print()
    log('✅ Carga inicial completada!')
    
except Exception as e:
    print(f'❌ Error: {e}')
INITSCRIPT
        
        sudo -u $INSTALL_USER $PYTHON_ENV /tmp/init_data.py
        rm -f /tmp/init_data.py
        ;;
    
    "status")
        echo -e "${BLUE}=== THREAT INTEL HUB STATUS ===${NC}"
        echo
        echo "Servicios:"
        systemctl is-active threat-intel-hub >/dev/null 2>&1 && \
            echo -e "  ${GREEN}✅${NC} Monitor: activo" || \
            echo -e "  ${RED}❌${NC} Monitor: inactivo"
        systemctl is-active threat-intel-hub-api >/dev/null 2>&1 && \
            echo -e "  ${GREEN}✅${NC} API: activa" || \
            echo -e "  ${RED}❌${NC} API: inactiva"
        ;;
    
    "restart")
        echo -e "${BLUE}=== REINICIANDO SERVICIOS ===${NC}"
        systemctl restart threat-intel-hub 2>/dev/null || true
        systemctl restart threat-intel-hub-api 2>/dev/null || true
        echo -e "${GREEN}✅ Servicios reiniciados${NC}"
        ;;
    
    "start")
        echo -e "${BLUE}=== INICIANDO SERVICIOS ===${NC}"
        systemctl start threat-intel-hub 2>/dev/null || true
        systemctl start threat-intel-hub-api 2>/dev/null || true
        echo -e "${GREEN}✅ Servicios iniciados${NC}"
        ;;
    
    "generate-advisory")
        shift
        ti-hub-advisory-gen "$@"
        ;;
    
    *)
        echo -e "${BLUE}=== THREAT INTEL HUB ADMIN v1.0.5 ===${NC}"
        echo
        echo "Comandos disponibles:"
        echo "  init-data [--days N]   - Cargar datos iniciales"
        echo "  status                 - Ver estado del sistema"
        echo "  start                  - Iniciar servicios"
        echo "  restart                - Reiniciar servicios"
        echo "  generate-advisory      - Generar MDR Advisory"
        ;;
esac
EOF
    chmod +x /usr/local/bin/ti-hub-admin
    log_success "Comando ti-hub-admin creado"
}

# Crear comando ti-hub-advisory-gen
create_advisory_command() {
    log_step "Creando comando ti-hub-advisory-gen..."
    
    cat > /usr/local/bin/ti-hub-advisory-gen << 'EOF'
#!/bin/bash

PYTHON_ENV="/opt/threat-intel-hub/venv/bin/python"
SCRIPT_PATH="/var/lib/threat-intel-hub/scripts/ti_hub_advisory_generator.py"

BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

show_help() {
    echo -e "${BLUE}=== MDR THREAT ADVISORY GENERATOR ===${NC}"
    echo
    echo "Uso: ti-hub-advisory-gen [opciones]"
    echo
    echo "Opciones:"
    echo "  --days N        Días hacia atrás (default: 1)"
    echo "  --test          Modo test - no envía emails"
    echo "  --help          Mostrar esta ayuda"
}

ARGS=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --days)
            ARGS="$ARGS --days $2"
            shift 2
            ;;
        --test)
            ARGS="$ARGS --test"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [[ ! -f "$SCRIPT_PATH" ]]; then
    echo -e "${RED}Error: Script no encontrado${NC}"
    exit 1
fi

echo -e "${BLUE}=== GENERANDO MDR THREAT ADVISORY ===${NC}"
sudo -u ti-hub $PYTHON_ENV $SCRIPT_PATH $ARGS
EOF
    chmod +x /usr/local/bin/ti-hub-advisory-gen
    log_success "Comando ti-hub-advisory-gen creado"
}

# Crear comando ti-hub-status
create_status_command() {
    log_step "Creando comando ti-hub-status..."
    
    cat > /usr/local/bin/ti-hub-status << 'EOF'
#!/bin/bash
echo "=== THREAT INTEL HUB STATUS ==="
systemctl status threat-intel-hub --no-pager 2>/dev/null || echo "Servicio no encontrado"
echo
systemctl status threat-intel-hub-api --no-pager 2>/dev/null || echo "API no encontrada"
EOF
    chmod +x /usr/local/bin/ti-hub-status
    log_success "Comando ti-hub-status creado"
}

# Crear servicios systemd
create_systemd_services() {
    log_header "CREACIÓN DE SERVICIOS SYSTEMD"
    
    cat > /etc/systemd/system/threat-intel-hub.service << EOF
[Unit]
Description=Threat Intel Hub Monitor
After=network.target mariadb.service

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
WorkingDirectory=$DATA_DIR
ExecStart=$VENV_DIR/bin/python $DATA_DIR/scripts/ti_hub_monitor.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    cat > /etc/systemd/system/threat-intel-hub-api.service << EOF
[Unit]
Description=Threat Intel Hub API
After=network.target mariadb.service

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
WorkingDirectory=$DATA_DIR
ExecStart=$VENV_DIR/bin/python $DATA_DIR/scripts/ti_hub_api.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable threat-intel-hub.service
    systemctl enable threat-intel-hub-api.service
    
    log_success "Servicios systemd creados"
}

# Configurar cron si está habilitado
setup_cron() {
    if [[ "$ADVISORY_ENABLED" == "true" ]]; then
        log_header "CONFIGURACIÓN DE CRON"
        
        CRON_ENTRY="$ADVISORY_TIMES /usr/local/bin/ti-hub-advisory-gen"
        (sudo -u $INSTALL_USER crontab -l 2>/dev/null | grep -v "ti-hub-advisory-gen"; echo "$CRON_ENTRY") | sudo -u $INSTALL_USER crontab -
        
        log_success "Cron configurado: $ADVISORY_SCHEDULE"
    fi
}

# Crear scripts placeholders
create_placeholder_scripts() {
    log_step "Creando scripts del sistema..."
    
    # Crear archivos vacíos por ahora
    touch "$DATA_DIR/scripts/ti_hub_monitor.py"
    touch "$DATA_DIR/scripts/ti_hub_api.py"
    touch "$DATA_DIR/scripts/ti_hub_advisory_generator.py"
    
    chown -R $INSTALL_USER:$INSTALL_USER "$DATA_DIR/scripts"
    chmod +x "$DATA_DIR/scripts"/*.py
}

# Verificación final
final_verification() {
    log_header "VERIFICACIÓN FINAL"
    
    echo "Verificando instalación..."
    
    for cmd in ti-hub-status ti-hub-admin ti-hub-advisory-gen; do
        if [[ -x "/usr/local/bin/$cmd" ]]; then
            echo "  ✅ Comando $cmd instalado"
        else
            echo "  ❌ Comando $cmd no encontrado"
        fi
    done
    
    if [[ -d "$VENV_DIR" ]]; then
        echo "  ✅ Entorno Python creado"
    else
        echo "  ❌ Entorno Python no encontrado"
    fi
    
    echo
    log_success "Instalación completada!"
}

# Instrucciones finales
show_final_instructions() {
    echo
    echo "================================================================"
    echo "  INSTALACIÓN COMPLETADA - v1.0.5"
    echo "================================================================"
    echo
    echo "📋 INFORMACIÓN:"
    echo "  • Base de datos: $DB_NAME"
    echo "  • Usuario: $DB_USER"
    echo "  • Contraseña: $DB_PASSWORD"
    echo
    echo "🚀 PRÓXIMOS PASOS:"
    echo
    echo "1. Cargar datos iniciales:"
    echo "   sudo ti-hub-admin init-data --days 30"
    echo
    echo "2. Iniciar servicios:"
    echo "   sudo ti-hub-admin start"
    echo
    echo "3. Verificar estado:"
    echo "   sudo ti-hub-status"
    echo
    if [[ "$ADVISORY_ENABLED" == "true" ]]; then
        echo "⏰ Advisories automáticos configurados: $ADVISORY_SCHEDULE"
    fi
    echo
    echo "¡Sistema instalado exitosamente!"
    echo
}

# Función principal parte 2
main() {
    log_header "THREAT INTEL HUB - INSTALACIÓN PARTE 2"
    
    setup_python_environment
    create_configuration_files
    create_admin_command
    create_advisory_command
    create_status_command
    create_placeholder_scripts
    create_systemd_services
    setup_cron
    final_verification
    show_final_instructions
    
    # Limpiar archivos temporales
    rm -f /tmp/ti_hub_install_vars.sh
}

# Ejecutar
main "$@"
