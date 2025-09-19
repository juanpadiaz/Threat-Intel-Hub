#!/bin/bash

# =============================================================================
# Threat Intel Hub - Herramientas Administrativas COMPLETAS v1.0.5
# Incluye TODOS los comandos incluyendo init-data y generate-advisory
# =============================================================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variables de configuración
CONFIG_FILE="/etc/threat-intel-hub/config.ini"
LOG_FILE="/var/log/threat-intel-hub/ti-hub.log"
DATA_DIR="/var/lib/threat-intel-hub"
PYTHON_ENV="/opt/threat-intel-hub/venv/bin/python"
INSTALL_USER="ti-hub"

# Funciones de logging
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# Función para ejecutar Python con el entorno virtual
run_python() {
    local script="$1"
    sudo -u $INSTALL_USER $PYTHON_ENV -c "$script"
}

# Función principal de procesamiento de comandos
case "$1" in
    # === ESTADO Y MONITOREO ===
    "status")
        echo -e "${BLUE}=== THREAT INTEL HUB STATUS ===${NC}"
        echo
        echo "Servicios:"
        systemctl is-active threat-intel-hub >/dev/null 2>&1 && \
            echo -e "  ${GREEN}✅${NC} Monitor: $(systemctl is-active threat-intel-hub)" || \
            echo -e "  ${RED}❌${NC} Monitor: inactive"
        systemctl is-active threat-intel-hub-api >/dev/null 2>&1 && \
            echo -e "  ${GREEN}✅${NC} API: $(systemctl is-active threat-intel-hub-api)" || \
            echo -e "  ${RED}❌${NC} API: inactive"
        
        echo
        echo "Últimas entradas del log:"
        if [[ -f "$LOG_FILE" ]]; then
            tail -n 5 "$LOG_FILE" 2>/dev/null | sed 's/^/  /'
        else
            echo "  No hay logs disponibles"
        fi
        ;;
    
    "dashboard")
        echo -e "${BLUE}=== THREAT INTEL DASHBOARD ===${NC}"
        if curl -s http://localhost:8080/api/v1/dashboard >/dev/null 2>&1; then
            curl -s http://localhost:8080/api/v1/dashboard | python3 -m json.tool
        else
            log_warn "API no responde. Consultando base de datos directamente..."
            run_python "
import mysql.connector
import json
from datetime import datetime, timedelta
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    stats = {}
    
    # Total CVEs
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    stats['total_cves'] = cursor.fetchone()[0]
    
    # KEVs activas
    cursor.execute('SELECT COUNT(*) FROM kev_vulnerabilities')
    stats['total_kevs'] = cursor.fetchone()[0]
    
    # CVEs críticas
    cursor.execute(\"SELECT COUNT(*) FROM vulnerabilities WHERE cvss_severity = 'CRITICAL'\")
    stats['critical_cves'] = cursor.fetchone()[0]
    
    # IoCs
    cursor.execute('SELECT COUNT(*) FROM threat_iocs')
    stats['total_iocs'] = cursor.fetchone()[0]
    
    # Alertas pendientes
    cursor.execute(\"SELECT COUNT(*) FROM threat_alerts WHERE distribution_status = 'pending'\")
    stats['pending_alerts'] = cursor.fetchone()[0]
    
    # KEVs últimas 24h
    yesterday = datetime.now() - timedelta(days=1)
    cursor.execute('SELECT COUNT(*) FROM kev_vulnerabilities WHERE created_at >= %s', (yesterday,))
    stats['kevs_24h'] = cursor.fetchone()[0]
    
    print(json.dumps(stats, indent=2))
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f'Error: {e}')
"
        fi
        ;;
    
    "health-check")
        echo -e "${BLUE}=== HEALTH CHECK COMPLETO ===${NC}"
        echo
        echo "1. Servicios:"
        systemctl is-active threat-intel-hub >/dev/null 2>&1 && \
            echo -e "  ${GREEN}✅${NC} Monitor activo" || echo -e "  ${RED}❌${NC} Monitor inactivo"
        systemctl is-active threat-intel-hub-api >/dev/null 2>&1 && \
            echo -e "  ${GREEN}✅${NC} API activa" || echo -e "  ${RED}❌${NC} API inactiva"
        
        echo "2. Base de datos:"
        run_python "
import mysql.connector
import configparser
config = configparser.ConfigParser()
config.read('$CONFIG_FILE')
try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    print('  ✅ Conexión exitosa')
    conn.close()
except:
    print('  ❌ Error de conexión')
"
        
        echo "3. Espacio en disco:"
        df -h "$DATA_DIR" | tail -1 | awk '{print "  Usado: "$3" de "$2" ("$5")"}'
        
        echo "4. Archivos de configuración:"
        [[ -f "$CONFIG_FILE" ]] && echo -e "  ${GREEN}✅${NC} config.ini presente" || \
            echo -e "  ${RED}❌${NC} config.ini faltante"
        
        echo "5. Automatización de advisories:"
        if sudo -u $INSTALL_USER crontab -l 2>/dev/null | grep -q "ti-hub-advisory-gen"; then
            echo -e "  ${GREEN}✅${NC} Cron configurado"
            sudo -u $INSTALL_USER crontab -l | grep "ti-hub-advisory-gen" | sed 's/^/     /'
        else
            echo -e "  ⚠️  Sin automatización configurada"
        fi
        ;;
    
    # === GESTIÓN DE DATOS - COMANDO CRÍTICO init-data ===
    "init-data")
        DAYS=30
        if [[ "$2" == "--days" ]] && [[ -n "$3" ]]; then
            DAYS="$3"
        fi
        
        echo -e "${BLUE}=== INICIALIZANDO DATOS DE THREAT INTELLIGENCE ===${NC}"
        echo "Cargando datos de los últimos $DAYS días..."
        echo
        
        # Script Python para cargar datos iniciales
        run_python "
import sys
sys.path.insert(0, '/opt/threat-intel-hub/lib/otx_alternative')
import mysql.connector
import requests
import json
import configparser
from datetime import datetime, timedelta
import time

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

def log(msg):
    print(f'[{datetime.now().strftime(\"%H:%M:%S\")}] {msg}')

try:
    # Conectar a BD
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    # 1. CARGAR KEV (CISA Known Exploited Vulnerabilities)
    log('📥 Descargando CISA KEV...')
    kev_url = config.get('sources', 'kev_url')
    response = requests.get(kev_url, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        log(f'   Encontradas {len(vulnerabilities)} vulnerabilidades KEV')
        
        kev_count = 0
        for vuln in vulnerabilities:
            try:
                # Verificar si es de los últimos N días
                date_added = datetime.strptime(vuln.get('dateAdded'), '%Y-%m-%d')
                if date_added >= datetime.now() - timedelta(days=$DAYS):
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
                    
                    # También insertar en tabla principal
                    cursor.execute('''
                        INSERT INTO vulnerabilities (cve_id, description, kev_status, threat_score)
                        VALUES (%s, %s, TRUE, 85)
                        ON DUPLICATE KEY UPDATE 
                        kev_status = TRUE,
                        threat_score = GREATEST(threat_score, 85)
                    ''', (vuln.get('cveID'), vuln.get('shortDescription')))
                    
                    kev_count += 1
                    
            except Exception as e:
                log(f'   Error procesando {vuln.get(\"cveID\")}: {e}')
        
        conn.commit()
        log(f'   ✅ {kev_count} KEVs cargadas (últimos {$DAYS} días)')
    else:
        log(f'   ❌ Error descargando KEV: HTTP {response.status_code}')
    
    # 2. CARGAR DATOS NVD (Si hay API key)
    nvd_key = config.get('sources', 'nvd_api_key', fallback='')
    if nvd_key:
        log('📥 Descargando CVEs de NVD...')
        
        # Calcular fecha de inicio
        start_date = (datetime.now() - timedelta(days=$DAYS)).strftime('%Y-%m-%dT00:00:00.000')
        end_date = datetime.now().strftime('%Y-%m-%dT23:59:59.999')
        
        headers = {'apiKey': nvd_key} if nvd_key else {}
        nvd_url = f\"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start_date}&lastModEndDate={end_date}\"
        
        try:
            response = requests.get(nvd_url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                total = data.get('totalResults', 0)
                log(f'   Encontradas {total} CVEs modificadas en los últimos {$DAYS} días')
                
                cve_count = 0
                for item in data.get('vulnerabilities', [])[:100]:  # Limitar a 100
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    
                    # Extraer CVSS
                    cvss_score = 0
                    cvss_severity = 'NONE'
                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0)
                        cvss_severity = cvss_data.get('baseSeverity', 'NONE')
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0)
                        cvss_severity = cvss_data.get('baseSeverity', 'NONE')
                    
                    # Descripción
                    descriptions = cve.get('descriptions', [])
                    description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
                    
                    # Insertar en BD
                    cursor.execute('''
                        INSERT INTO vulnerabilities 
                        (cve_id, published_date, last_modified, description, 
                         cvss_v3_score, cvss_severity)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        last_modified = VALUES(last_modified),
                        cvss_v3_score = VALUES(cvss_v3_score),
                        cvss_severity = VALUES(cvss_severity)
                    ''', (
                        cve_id,
                        cve.get('published'),
                        cve.get('lastModified'),
                        description[:1000],
                        cvss_score,
                        cvss_severity
                    ))
                    cve_count += 1
                
                conn.commit()
                log(f'   ✅ {cve_count} CVEs cargadas desde NVD')
                
                # Esperar para no exceder rate limit
                time.sleep(6)  # NVD requiere 6 segundos entre requests con API key
                
        except Exception as e:
            log(f'   ❌ Error con NVD: {e}')
    else:
        log('   ⚠️  NVD API Key no configurada, omitiendo...')
    
    # 3. CARGAR SCORES EPSS
    if config.getboolean('triggers', 'epss_enabled', fallback=True):
        log('📥 Descargando scores EPSS...')
        
        try:
            # Obtener todos los CVE IDs de la BD
            cursor.execute('SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL LIMIT 100')
            cve_ids = [row[0] for row in cursor.fetchall()]
            
            if cve_ids:
                # EPSS API acepta múltiples CVEs
                cve_param = ','.join(cve_ids)
                epss_url = f\"https://api.first.org/data/v1/epss?cve={cve_param}\"
                
                response = requests.get(epss_url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    epss_count = 0
                    
                    for item in data.get('data', []):
                        cursor.execute('''
                            UPDATE vulnerabilities 
                            SET epss_score = %s, 
                                epss_percentile = %s,
                                epss_date = %s
                            WHERE cve_id = %s
                        ''', (
                            item.get('epss'),
                            item.get('percentile'),
                            item.get('date'),
                            item.get('cve')
                        ))
                        epss_count += 1
                    
                    conn.commit()
                    log(f'   ✅ {epss_count} scores EPSS actualizados')
                else:
                    log(f'   ❌ Error EPSS: HTTP {response.status_code}')
            else:
                log('   ℹ️  No hay CVEs para actualizar EPSS')
                
        except Exception as e:
            log(f'   ❌ Error con EPSS: {e}')
    
    # 4. CARGAR IoCs de OTX (si está configurado)
    otx_key = config.get('sources', 'otx_api_key', fallback='')
    if otx_key:
        log('📥 Descargando IoCs de AlienVault OTX...')
        
        try:
            # Intentar usar el cliente OTX
            from otx_client import get_otx_client
            otx = get_otx_client(otx_key)
            
            if otx.validate_api_key():
                # Obtener pulsos recientes
                since = datetime.now() - timedelta(days=$DAYS)
                pulses = otx.get_pulses_subscribed(modified_since=since)
                
                ioc_count = 0
                for pulse in pulses[:10]:  # Limitar a 10 pulsos
                    indicators = otx.get_pulse_indicators(pulse.get('id'))
                    
                    for indicator in indicators:
                        try:
                            cursor.execute('''
                                INSERT INTO threat_iocs
                                (ioc_type, ioc_value, source, threat_type, 
                                 confidence_score, first_seen, last_seen)
                                VALUES (%s, %s, 'OTX', %s, 0.75, NOW(), NOW())
                                ON DUPLICATE KEY UPDATE
                                last_seen = NOW(),
                                times_seen = times_seen + 1
                            ''', (
                                indicator.get('type', 'unknown').lower(),
                                indicator.get('indicator', '')[:500],
                                pulse.get('name', 'Unknown')[:100]
                            ))
                            ioc_count += 1
                        except:
                            pass
                
                conn.commit()
                log(f'   ✅ {ioc_count} IoCs cargados desde OTX')
            else:
                log('   ❌ API Key de OTX inválida')
                
        except Exception as e:
            log(f'   ⚠️  OTX no disponible: {e}')
    else:
        log('   ⚠️  OTX API Key no configurada, omitiendo...')
    
    # 5. Calcular threat scores
    log('🔄 Calculando threat scores...')
    cursor.execute('''
        UPDATE vulnerabilities 
        SET threat_score = CASE
            WHEN kev_status = TRUE THEN 90
            WHEN cvss_severity = 'CRITICAL' AND epss_score > 0.5 THEN 85
            WHEN cvss_severity = 'CRITICAL' THEN 75
            WHEN cvss_severity = 'HIGH' AND epss_score > 0.3 THEN 70
            WHEN cvss_severity = 'HIGH' THEN 60
            WHEN epss_score > 0.7 THEN 65
            ELSE 30
        END
        WHERE threat_score IS NULL OR threat_score = 0
    ''')
    conn.commit()
    
    # 6. Generar estadísticas finales
    log('📊 Generando estadísticas...')
    
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    total_cves = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM kev_vulnerabilities')
    total_kevs = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM threat_iocs')
    total_iocs = cursor.fetchone()[0]
    
    cursor.execute(\"SELECT COUNT(*) FROM vulnerabilities WHERE cvss_severity = 'CRITICAL'\")
    critical_cves = cursor.fetchone()[0]
    
    print()
    print('=' * 50)
    print('RESUMEN DE CARGA INICIAL:')
    print(f'  📊 Total CVEs: {total_cves}')
    print(f'  🚨 KEVs activas: {total_kevs}')
    print(f'  🎯 IoCs: {total_iocs}')
    print(f'  ⚠️  CVEs críticas: {critical_cves}')
    print('=' * 50)
    
    # Generar alerta inicial si hay KEVs críticas
    if total_kevs > 0:
        print()
        log('🚨 Generando alerta inicial por KEVs detectadas...')
        
        alert_id = f'init-{datetime.now().strftime(\"%Y%m%d%H%M%S\")}'
        cursor.execute('''
            INSERT INTO threat_alerts
            (id, alert_type, priority, title, description, distribution_status)
            VALUES (%s, 'manual', 'HIGH', %s, %s, 'pending')
        ''', (
            alert_id,
            f'Sistema inicializado: {total_kevs} KEVs activas detectadas',
            f'Se han cargado {total_kevs} vulnerabilidades conocidas siendo explotadas activamente. Revisar acciones requeridas.'
        ))
        conn.commit()
        print(f'   ✅ Alerta {alert_id} generada')
    
    cursor.close()
    conn.close()
    
    print()
    log('✅ Carga inicial completada exitosamente!')
    print()
    print('Próximos pasos:')
    print('  1. Los servicios comenzarán el monitoreo automático')
    print('  2. KEV se verificará cada 30 minutos')
    print('  3. EPSS se actualizará cada 4 horas')
    print('  4. Use \"ti-hub-advisory-gen\" para generar un advisory')
    
except Exception as e:
    print(f'❌ Error crítico: {e}')
    import traceback
    traceback.print_exc()
"
        ;;
    
    "sync-kev")
        echo -e "${BLUE}=== SINCRONIZANDO CISA KEV ===${NC}"
        run_python "
import requests
import mysql.connector
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    print('Descargando KEV...')
    response = requests.get(config.get('sources', 'kev_url'), timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        print(f'Encontradas {len(vulnerabilities)} KEVs')
        
        new_kevs = 0
        for vuln in vulnerabilities:
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
            
            if cursor.rowcount > 0:
                new_kevs += 1
        
        conn.commit()
        print(f'✅ Sincronización completada: {new_kevs} nuevas KEVs')
    else:
        print(f'❌ Error: HTTP {response.status_code}')
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    "sync-epss")
        echo -e "${BLUE}=== ACTUALIZANDO SCORES EPSS ===${NC}"
        run_python "
import requests
import mysql.connector
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    # Obtener CVEs sin EPSS score
    cursor.execute('SELECT cve_id FROM vulnerabilities WHERE epss_score IS NULL LIMIT 50')
    cve_ids = [row[0] for row in cursor.fetchall()]
    
    if cve_ids:
        print(f'Actualizando {len(cve_ids)} CVEs...')
        cve_param = ','.join(cve_ids)
        
        response = requests.get(f'https://api.first.org/data/v1/epss?cve={cve_param}', timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            updated = 0
            
            for item in data.get('data', []):
                cursor.execute('''
                    UPDATE vulnerabilities 
                    SET epss_score = %s, epss_percentile = %s, epss_date = %s
                    WHERE cve_id = %s
                ''', (
                    item.get('epss'),
                    item.get('percentile'),
                    item.get('date'),
                    item.get('cve')
                ))
                updated += cursor.rowcount
            
            conn.commit()
            print(f'✅ {updated} scores EPSS actualizados')
        else:
            print(f'❌ Error: HTTP {response.status_code}')
    else:
        print('ℹ️ No hay CVEs pendientes de actualizar')
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    # === TESTING ===
    "test-sources")
        echo -e "${BLUE}=== PROBANDO FUENTES DE THREAT INTELLIGENCE ===${NC}"
        echo
        run_python "
import sys
sys.path.insert(0, '/opt/threat-intel-hub/lib/otx_alternative')
import requests
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

print('Probando conectividad con fuentes de Threat Intelligence...')
print('=' * 50)

# Test NVD
try:
    nvd_key = config.get('sources', 'nvd_api_key', fallback='')
    headers = {'apiKey': nvd_key} if nvd_key else {}
    response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', 
                           headers=headers, timeout=10)
    if response.status_code == 200:
        print(f'✅ NVD: OK {\"(con API key)\" if nvd_key else \"(sin API key)\"}')
    else:
        print(f'❌ NVD: HTTP {response.status_code}')
except Exception as e:
    print(f'❌ NVD: {str(e)[:50]}')

# Test KEV
try:
    response = requests.get(config.get('sources', 'kev_url'), timeout=10)
    if response.status_code == 200:
        data = response.json()
        count = len(data.get('vulnerabilities', []))
        print(f'✅ CISA KEV: OK ({count} vulnerabilidades)')
    else:
        print(f'❌ CISA KEV: HTTP {response.status_code}')
except Exception as e:
    print(f'❌ CISA KEV: {str(e)[:50]}')

# Test EPSS
try:
    response = requests.get('https://api.first.org/data/v1/epss?limit=1', timeout=10)
    if response.status_code == 200:
        print(f'✅ FIRST EPSS: OK')
    else:
        print(f'❌ FIRST EPSS: HTTP {response.status_code}')
except Exception as e:
    print(f'❌ FIRST EPSS: {str(e)[:50]}')

# Test OTX
otx_key = config.get('sources', 'otx_api_key', fallback='')
if otx_key:
    try:
        from otx_client import get_otx_client
        otx = get_otx_client(otx_key)
        if otx.validate_api_key():
            print('✅ AlienVault OTX: OK (API key válida)')
        else:
            print('❌ AlienVault OTX: API key inválida')
    except Exception as e:
        print(f'⚠️ AlienVault OTX: {str(e)[:50]}')
else:
    print('⚠️ AlienVault OTX: No configurado')

# Test MISP
if config.getboolean('misp', 'enabled', fallback=False):
    try:
        misp_url = config.get('misp', 'url')
        misp_key = config.get('misp', 'api_key')
        headers = {'Authorization': misp_key, 'Accept': 'application/json'}
        response = requests.get(f'{misp_url}/servers/getVersion', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            print('✅ MISP: OK')
        else:
            print(f'❌ MISP: HTTP {response.status_code}')
    except Exception as e:
        print(f'❌ MISP: {str(e)[:50]}')
else:
    print('⚠️ MISP: No configurado')

# Test VirusTotal
vt_key = config.get('virustotal', 'api_key', fallback='')
if vt_key:
    try:
        headers = {'x-apikey': vt_key}
        response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', 
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print('✅ VirusTotal: OK')
        else:
            print(f'❌ VirusTotal: HTTP {response.status_code}')
    except Exception as e:
        print(f'❌ VirusTotal: {str(e)[:50]}')
else:
    print('⚠️ VirusTotal: No configurado')

print('=' * 50)
print('Test completado')
"
        ;;
    
    "test-alert")
        TYPE="${3:-kev}"
        echo -e "${BLUE}=== GENERANDO ALERTA DE PRUEBA ===${NC}"
        run_python "
import mysql.connector
import configparser
import json
from datetime import datetime
import uuid

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    alert_id = f'test-{uuid.uuid4().hex[:8]}'
    
    cursor.execute('''
        INSERT INTO threat_alerts
        (id, alert_type, priority, title, description, alert_data, distribution_status)
        VALUES (%s, %s, 'HIGH', %s, %s, %s, 'pending')
    ''', (
        alert_id,
        '$TYPE',
        f'Alerta de prueba - Tipo: $TYPE',
        'Esta es una alerta de prueba generada manualmente para verificar el sistema',
        json.dumps({'test': True, 'timestamp': datetime.now().isoformat()})
    ))
    
    conn.commit()
    print(f'✅ Alerta de prueba {alert_id} generada')
    print('   Tipo: $TYPE')
    print('   Prioridad: HIGH')
    print('   Estado: pending')
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    # === ALERTAS Y ADVISORIES ===
    "generate-advisory")
        shift  # Quitar 'generate-advisory' de los argumentos
        ti-hub-advisory-gen "$@"
        ;;
    
    "list-alerts")
        PRIORITY="${3:-ALL}"
        echo -e "${BLUE}=== LISTANDO ALERTAS ===${NC}"
        run_python "
import mysql.connector
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    if '$PRIORITY' == 'ALL':
        cursor.execute('''
            SELECT id, alert_type, priority, title, distribution_status, created_at
            FROM threat_alerts
            ORDER BY created_at DESC
            LIMIT 20
        ''')
    else:
        cursor.execute('''
            SELECT id, alert_type, priority, title, distribution_status, created_at
            FROM threat_alerts
            WHERE priority = %s
            ORDER BY created_at DESC
            LIMIT 20
        ''', ('$PRIORITY',))
    
    alerts = cursor.fetchall()
    
    if alerts:
        print(f'Encontradas {len(alerts)} alertas:')
        print('-' * 80)
        for alert in alerts:
            print(f'ID: {alert[0]}')
            print(f'  Tipo: {alert[1]} | Prioridad: {alert[2]}')
            print(f'  Título: {alert[3]}')
            print(f'  Estado: {alert[4]} | Fecha: {alert[5]}')
            print('-' * 80)
    else:
        print('No hay alertas')
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f'❌ Error: {e}')
"
        ;;
    
    # === SERVICIOS ===
    "restart")
        echo -e "${BLUE}=== REINICIANDO SERVICIOS ===${NC}"
        systemctl restart threat-intel-hub
        systemctl restart threat-intel-hub-api
        echo -e "${GREEN}✅ Servicios reiniciados${NC}"
        ;;
    
    "stop")
        echo -e "${BLUE}=== DETENIENDO SERVICIOS ===${NC}"
        systemctl stop threat-intel-hub
        systemctl stop threat-intel-hub-api
        echo -e "${YELLOW}⏸️ Servicios detenidos${NC}"
        ;;
    
    "start")
        echo -e "${BLUE}=== INICIANDO SERVICIOS ===${NC}"
        systemctl start threat-intel-hub
        systemctl start threat-intel-hub-api
        echo -e "${GREEN}✅ Servicios iniciados${NC}"
        ;;
    
    # === LOGS ===
    "logs")
        N="${2:-20}"
        echo -e "${BLUE}=== ÚLTIMAS $N LÍNEAS DEL LOG ===${NC}"
        tail -n "$N" "$LOG_FILE" 2>/dev/null || echo "No hay logs disponibles"
        ;;
    
    "tail")
        echo -e "${BLUE}=== SIGUIENDO LOG EN TIEMPO REAL ===${NC}"
        echo "Presiona Ctrl+C para salir"
        tail -f "$LOG_FILE"
        ;;
    
    # === AYUDA ===
    *)
        echo -e "${BLUE}=== THREAT INTEL HUB - ADMINISTRACIÓN v1.0.5 ===${NC}"
        echo
        echo "Uso: ti-hub-admin <comando> [opciones]"
        echo
        echo -e "${CYAN}COMANDOS PRINCIPALES:${NC}"
        echo "  init-data [--days N]        🚀 Cargar datos iniciales (IMPORTANTE)"
        echo "  status                      📊 Ver estado del sistema"
        echo "  dashboard                   📈 Ver métricas y estadísticas"
        echo "  health-check                🔍 Verificación completa del sistema"
        echo
        echo -e "${CYAN}SINCRONIZACIÓN:${NC}"
        echo "  sync-kev                    🔄 Sincronizar CISA KEV"
        echo "  sync-epss                   📊 Actualizar scores EPSS"
        echo
        echo -e "${CYAN}ADVISORIES:${NC}"
        echo "  generate-advisory [opts]    📧 Generar MDR Advisory"
        echo "                              Use: ti-hub-advisory-gen --help"
        echo
        echo -e "${CYAN}TESTING:${NC}"
        echo "  test-sources                🧪 Probar todas las fuentes"
        echo "  test-alert [--type TYPE]    🔔 Generar alerta de prueba"
        echo
        echo -e "${CYAN}ALERTAS:${NC}"
        echo "  list-alerts [--priority]    📋 Listar alertas (ALL/HIGH/CRITICAL)"
        echo
        echo -e "${CYAN}SERVICIOS:${NC}"
        echo "  start                       ▶️  Iniciar servicios"
        echo "  stop                        ⏸️  Detener servicios"
        echo "  restart                     🔄 Reiniciar servicios"
        echo
        echo -e "${CYAN}LOGS:${NC}"
        echo "  logs [N]                    📝 Ver últimas N líneas del log"
        echo "  tail                        📜 Seguir log en tiempo real"
        echo
        echo -e "${YELLOW}💡 IMPORTANTE:${NC}"
        echo "   Ejecute primero 'ti-hub-admin init-data' después de la instalación"
        echo "   para cargar datos iniciales y comenzar a recibir alertas."
        echo
        echo -e "${GREEN}Para más ayuda sobre advisories:${NC}"
        echo "   ti-hub-advisory-gen --help"
        ;;
esac
