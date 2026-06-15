Guion Final — Demo SDN Zero Trust
Setup previo (no grabar):

T-A = terminal en controller
T-B = terminal en H1 (Telecom)
T-C = terminal en H2 (Informatica)
Browser = ONOS UI con túnel SSH activo
ESCENA 1 — Introducción y Topología ONOS [Browser] (40 seg)
Mostrar http://127.0.0.1:8181/onos/ui/#/topo2

"Este es el sistema SDN Zero Trust implementado sobre ONOS 2.7.0 con OpenFlow 1.3. La topología tiene 3 switches virtuales OVS: SW1 como núcleo, SW2 para acceso de hosts, SW3 para acceso a servidores."

Clic en cada switch → mostrar DPID y número de flows.
Clic en un host → mostrar MAC e IP descubierta.

"ONOS descubre hosts automáticamente vía ARP y LLDP. 5 hosts registrados, 60 flows proactivos ya instalados por el módulo M6 al arrancar."

ESCENA 2 — Descubrimiento DHCP dinámico [T-A + T-C] (30 seg)
[T-C] desde H2:


ip addr show | grep "192.168"
[T-A] desde controller:


curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/hosts | python3 -c "
import json, sys
for h in json.load(sys.stdin)['hosts']:
    mac = h['mac']
    ips = h.get('ipAddresses', [])
    loc = h.get('locations', [{}])[0]
    print(f'MAC: {mac}  IP: {ips}  Switch: {loc.get(\"elementId\",\"\")[-4:]}  Puerto: {loc.get(\"port\",\"\")}')
"
"H2 obtuvo su IP dinámicamente del servidor DHCP de ONOS. ONOS registró automáticamente su MAC, IP y puerto de acceso — sin configuración manual en el host. M6 usa esta información para instalar flows por sesión."

ESCENA 3 — Flows proactivos de cuarentena [T-A] (45 seg)

echo "=== SW2 — Cuarentena y redirección al portal ===" 
ovs-ofctl dump-flows sw2 -O OpenFlow13 | grep -E "priority=1[0-9]{3}" | head -12

echo "=== SW1 — Table-miss NORMAL (tránsito) ==="
ovs-ofctl dump-flows sw1 -O OpenFlow13 | grep "priority=500"

echo "=== SW3 — Table-miss NORMAL (tránsito) ==="
ovs-ofctl dump-flows sw3 -O OpenFlow13 | grep "priority=500"
"M6 instala flows proactivos al arrancar. En SW2: push VLAN 90 a hosts en cuarentena, redirección del tráfico HTTP al portal cautivo. En SW1 y SW3: table-miss NORMAL para tránsito. Sin autenticación, ningún host llega a los servidores."

Verificar bloqueo pre-auth desde H1:
[T-B]


curl -s --max-time 3 http://192.168.100.200/ && echo "ABIERTO" || echo "BLOQUEADO — sin autenticacion"
ESCENA 4 — Login H1 (Estudiante Telecom) [T-B + T-A] (90 seg)
[T-A] dejar corriendo en paralelo para ver flows en tiempo real:


watch -n 1 "ovs-ofctl dump-flows sw2 -O OpenFlow13 2>/dev/null | grep 'priority=35000' | wc -l"
[T-B] login vía portal SSH:


ssh <usuario>@192.168.100.1
# Ingresar código PUCP y password del estudiante Telecom
"El portal cautivo autentica contra FreeRADIUS. Verificada la identidad, consulta las políticas RBAC en MySQL: Estudiante Telecom tiene ALLOW a H3 y DENY explícito a H4. M6 instala los flows de sesión en tiempo real."

Observar cómo el contador sube en T-A.

[T-B] verificar acceso H1 → H3 ✓:


echo "=== HTTP ===" && curl -s http://192.168.100.200/ | grep -E "<h1>|HTTPS|TLS"
echo "=== HTTPS ===" && curl -sk https://192.168.100.200/ | grep -E "<h1>|HTTPS|TLS"
[T-B] verificar bloqueo H1 → H4 ✗:


curl -sk --max-time 3 https://192.168.100.201/ | grep "<h1>" && echo "ABIERTO" || echo "BLOQUEADO por politica Zero Trust"
"Telecom accede a su servidor en HTTP y HTTPS. H4 de Informatica — denegado por política Zero Trust. El DENY está instalado como flow explícito de descarte, no como ausencia de ruta."

ESCENA 5 — Login H2 (Estudiante Informatica) [T-C] (60 seg)
[T-C] login:


ssh <usuario>@192.168.100.1
# Ingresar código PUCP y password del estudiante Informatica
[T-C] verificar acceso H2 → H4 ✓:


echo "=== HTTP ===" && curl -s http://192.168.100.201/ | grep -E "<h1>|HTTPS|TLS"
echo "=== HTTPS ===" && curl -sk https://192.168.100.201/ | grep -E "<h1>|HTTPS|TLS"
[T-C] verificar bloqueo H2 → H3 ✗:


curl -sk --max-time 3 https://192.168.100.200/ | grep "<h1>" && echo "ABIERTO" || echo "BLOQUEADO por politica Zero Trust"
"Informatica accede solo a H4. H3 de Telecom — bloqueado. Dos sesiones concurrentes activas, cada una con su propio conjunto de flows y aislamiento completo entre carreras."

ESCENA 6 — Inspección de flows por sesión [T-A] (60 seg)

echo "=== T0 — Enforcement por sesión (ALLOW + DENY) ==="
ovs-ofctl dump-flows sw2 -O OpenFlow13 | grep "priority=35000"

echo "=== T1 — VLAN pop post-auth ==="
ovs-ofctl dump-flows sw2 -O OpenFlow13 | grep "table=1.*priority=40000"

echo "=== T2 — ALLOW proactivo por VLAN ==="
ovs-ofctl dump-flows sw2 -O OpenFlow13 | grep "table=2"

echo "=== T3 — DENY de sesión ==="
ovs-ofctl dump-flows sw2 -O OpenFlow13 | grep "table=3"
"Pipeline multi-tabla OpenFlow 1.3. T0 hace enforcement MAC+IP por sesión con timeout de 8 horas. T1 elimina VLAN de cuarentena post-autenticación. T2 tiene los ALLOW proactivos por VLAN de rol. T3 registra DENYs explícitos de sesión."


echo "=== Total flows activos ==="
for sw in sw1 sw2 sw3; do
    echo -n "$sw: "
    ovs-ofctl dump-flows $sw -O OpenFlow13 2>/dev/null | grep -c "priority"
done
ESCENA 7 — Validación vía ONOS REST API [T-A] (30 seg)

curl -s -u onos:rocks http://127.0.0.1:8181/onos/v1/flows | python3 -c "
import json, sys
flows = json.load(sys.stdin)['flows']
por_tabla = {}
for f in flows:
    t = f.get('tableId', '?')
    por_tabla[t] = por_tabla.get(t, 0) + 1
print(f'Total flows en ONOS: {len(flows)}')
for t in sorted(por_tabla): print(f'  Tabla {t}: {por_tabla[t]} flows')
"
"ONOS confirma los flows instalados directamente vía REST API, sin usar Intents. Elegimos flows directos para tener control preciso sobre el pipeline multi-tabla y los timeouts por sesión — algo que la abstracción de Intents no permite."

ESCENA 8 — Logout y limpieza [T-B + T-A] (30 seg)
[T-B] cerrar sesión H1:


exit   # salir del portal SSH — M6 elimina flows automáticamente
[T-A] confirmar eliminación de flows:


sleep 2
echo "=== Flows de sesión tras logout ==="
ovs-ofctl dump-flows sw2 -O OpenFlow13 | grep "priority=35000"
echo "H1 volvio a cuarentena"
"Al cerrar la sesión SSH, M6 elimina todos los flows asociados a H1. El host vuelve automáticamente a cuarentena VLAN 90. Principio Zero Trust: acceso mínimo necesario, revocado inmediatamente al cerrar sesión."

Cierre [Browser] (20 seg)
Volver a ONOS UI — mostrar topología general.

"Sistema SDN Zero Trust completamente funcional: autenticación RADIUS, políticas RBAC por rol y carrera, enforcement dinámico con OpenFlow 1.3, HTTPS en servidores, y revocación de acceso en tiempo real. Todo gestionado por el módulo M6 sobre ONOS."

Duración total estimada: 6-7 minutos
